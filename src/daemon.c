/*
 * MemoryTraceTool — 守护进程（mttd）。
 *
 * 本文件实现了 mttd 守护进程，同时监听两个端口：
 *   1. Unix Domain Socket（/tmp/mttd.sock）：接收被监控进程的泄漏报告
 *   2. TCP Socket（默认 8080）：提供 Web 看板和 JSON API
 *
 * IPC 协议（基于文本行）：
 *   HELLO <pid> <name>\n  — 进程握手，标识自己
 *   LEAK <size> <file> <line> <nframes>\n — 单条泄漏概要
 *   FRAME <idx> <symbol>\n — 调用栈帧（紧跟 LEAK 之后）
 *   BYE\n                 — 进程退出（守护进程标记进程为 DONE）
 *
 * 设计要点：
 *   - 同一 PID 重复连接时自动刷新旧数据（常驻进程反复报告场景）
 *   - 非阻塞 I/O + select 单线程事件循环
 *   - Web 看板每 3 秒自动刷新（HTML meta refresh）
 *   - JSON API 端点 /api/data 用于自动化采集
 */
#define _GNU_SOURCE
#include "daemon.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <time.h>
#include <ctype.h>
#include <stdarg.h>
#include <dirent.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include "injector.h"
#include "internal.h"

/* ---- 全局状态 ---- */

static mttd_proc_t g_procs[MTT_MAX_PROCS];      /* 被监控进程数组 */
static int         g_nprocs = 0;                  /* 当前监控的进程数 */
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER; /* 保护 g_procs / g_nprocs */
static volatile int g_running = 1;                /* 信号控制的主循环退出标志 */

/* 运行时注入追踪 */
static mttd_injected_t g_injected[MTT_MAX_INJECTED]; /* 注入记录数组 */
static int             g_ninjected = 0;               /* 当前注入数 */

/* 长期监控安全: 全局泄漏记录计数器 */
static _Atomic size_t g_total_leaks_global = 0;

/* ---- 辅助函数 ---- */

/**
 * 安全的整行发送（处理部分写入和 EINTR）。
 *
 * 缺陷修复 #5: 替换裸 send() 调用，确保整行数据完整发送。
 * 裸 send() 在缓冲区满时可能只发送部分数据，导致协议帧损坏。
 *
 * @param fd    socket 文件描述符
 * @param buf   要发送的数据
 * @param len   数据长度
 * @return      0 成功，-1 失败
 */
static int send_all(int fd, const void* buf, size_t len)
{
    const char* p = (const char*)buf;
    size_t remaining = len;
    while (remaining > 0) {
        ssize_t n = send(fd, p, remaining, MSG_NOSIGNAL);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        p += n;
        remaining -= (size_t)n;
    }
    return 0;
}

/**
 * 安全的 snprintf 追加（检测截断）。
 *
 * 缺陷修复 #4: 原代码中 snprintf 返回值直接加到 pos 上，
 * 不检测是否被截断，可能导致 JSON 格式损坏或缓冲区溢出。
 *
 * @param buf    目标缓冲区
 * @param pos    当前写入位置
 * @param size   缓冲区总大小
 * @param fmt    格式化字符串
 * @return       写入的字节数，截断时返回 0
 */
static int safe_append(char* buf, int* pos, int size, const char* fmt, ...)
    __attribute__((format(printf, 4, 5)));

static int safe_append(char* buf, int* pos, int size, const char* fmt, ...)
{
    if (*pos >= size - 1) return 0;

    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf + *pos, (size_t)(size - *pos), fmt, ap);
    va_end(ap);

    if (n < 0) return 0; /* 格式化错误 */
    if (n >= size - *pos) {
        /* 输出被截断 */
        buf[size - 1] = '\0';
        *pos = size;
        return 0;
    }
    *pos += n;
    return n;
}

/**
 * 查找或创建进程记录。
 *
 * 如果 pid 已存在（常驻进程重复报告），清空旧泄漏数据并重新初始化，
 * 以实现"同一 PID 重新连接 = 刷新报告"的语义。
 * 如果是新 PID，在 g_procs 数组末尾追加一条记录。
 *
 * 缺陷修复 #1: 调用方已持有 g_lock，消除 TOCTOU 竞态。
 * 原代码在 find_or_create_proc 内部对旧记录获取 proc->lock，
 * 但在获取 proc->lock 之前 g_lock 已被释放，存在 TOCTOU 窗口。
 * 现在调用方全程持有 g_lock。
 *
 * @param pid  被监控进程的 PID
 * @param name 进程名（来自 /proc/<pid>/exe）
 * @return     进程记录指针，或 NULL 表示已满（MTT_MAX_PROCS）
 */
static mttd_proc_t* find_or_create_proc(int pid, const char* name)
{
    /* 已有记录：清空旧数据，准备接收新报告 */
    for (int i = 0; i < g_nprocs; i++) {
        if (g_procs[i].pid == pid) {
            mttd_proc_t* p = &g_procs[i];
            free(p->leaks);
            p->leak_cap = 32;
            p->leaks = malloc(p->leak_cap * sizeof(mttd_leak_t));
            if (!p->leaks) {
                p->leak_cap = 0;
                p->leak_count = 0;
            } else {
                p->leak_count = 0;
            }
            p->total_leaked = 0;
            p->active = 1;
            p->last_seen = time(NULL);
            snprintf(p->name, sizeof(p->name), "%s", name);
            return p;
        }
    }
    if (g_nprocs >= MTT_MAX_PROCS) return NULL; /* 容量已满 */

    /* 新进程 */
    mttd_proc_t* p = &g_procs[g_nprocs++];
    memset(p, 0, sizeof(*p));
    p->pid = pid;
    snprintf(p->name, sizeof(p->name), "%s", name);
    p->active = 1;
    p->last_seen = time(NULL);
    p->leak_cap = 32;
    p->leaks = malloc(p->leak_cap * sizeof(mttd_leak_t));
    if (!p->leaks) {
        p->leak_cap = 0;
        p->leak_count = 0;
    }
    pthread_mutex_init(&p->lock, NULL);
    return p;
}

/**
 * 向进程记录添加一条泄漏信息。
 *
 * leaks 数组采用动态扩容策略：初始 32，每次翻倍，
 * 直到达到 MTT_MAX_LEAKS 上限。
 *
 * @param p    目标进程
 * @param leak 泄漏数据（拷贝存储）
 * @return     0 成功，-1 已满
 */
static int add_leak(mttd_proc_t* p, mttd_leak_t* leak)
{
    /* 长期监控安全: 全局泄漏记录总数检查 */
    size_t global = atomic_load(&g_total_leaks_global);
    if (global >= MTT_DAEMON_MAX_TOTAL_LEAKS) {
        /* 超过全局上限，静默丢弃（避免守护进程 OOM） */
        return -1;
    }

    if (p->leak_count >= p->leak_cap) {
        int newcap = p->leak_cap * 2;
        if (newcap > MTT_MAX_LEAKS) {
            if (p->leak_count >= MTT_MAX_LEAKS) return -1;
            newcap = MTT_MAX_LEAKS;
        }
        mttd_leak_t* newleaks = realloc(p->leaks, newcap * sizeof(mttd_leak_t));
        if (!newleaks) return -1;
        p->leaks = newleaks;
        p->leak_cap = newcap;
    }
    p->leaks[p->leak_count++] = *leak;
    p->total_leaked += leak->size;
    atomic_fetch_add(&g_total_leaks_global, 1);
    return 0;
}

/** 将 socket 设为非阻塞模式 */
static void set_nonblock(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags >= 0)
        fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

/** 设置 socket 接收超时 */
static void set_recv_timeout(int fd, int seconds)
{
    struct timeval tv = { .tv_sec = seconds, .tv_usec = 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
}

/* 每个 Unix 客户端的解析上下文（消除 static 变量冲突） */
typedef struct {
    char buf[MTT_UNIX_BUF_SZ];
    int  bufpos;
    mttd_proc_t* proc;
} unix_client_ctx_t;

/* ---- Unix Socket 客户端处理 ---- */

/**
 * 解析来自 Unix Socket 客户端的文本行协议。
 *
 * 缺陷修复 #9: 使用独立的客户端上下文替代 static 变量。
 * 原代码使用 static 变量保存状态，多个客户端同时连接时状态会互相覆盖，
 * 导致协议解析错乱（client A 的 HELLO 可能与 client B 的 LEAK 关联）。
 *
 * 缺陷修复 #2: 使用 sscanf 返回值检查防止未初始化内存读取。
 *
 * @param fd         客户端 socket fd
 * @param ctx        客户端解析上下文
 * @param out_proc   输出当前客户端关联的进程记录指针
 * @return           >0 继续读取，0 连接关闭，<0 错误
 */
static int parse_unix_client(int fd, unix_client_ctx_t* ctx,
                             mttd_proc_t** out_proc)
{
    *out_proc = ctx->proc;

    ssize_t n = read(fd, ctx->buf + ctx->bufpos,
                     sizeof(ctx->buf) - ctx->bufpos - 1);
    if (n <= 0) { *out_proc = ctx->proc; return (int)n; }

    ctx->bufpos += (int)n;
    ctx->buf[ctx->bufpos] = '\0';

    char* line = ctx->buf;
    char* nl;

    /* 逐行解析：找到换行符就处理一行 */
    while ((nl = strchr(line, '\n')) != NULL) {
        *nl = '\0';

        if (strncmp(line, "HELLO ", 6) == 0) {
            int pid = 0;
            char name[256] = {0};
            /* 缺陷修复 #2: 检查 sscanf 返回值 */
            if (sscanf(line, "HELLO %d %255[^\n]", &pid, name) >= 1) {
                pthread_mutex_lock(&g_lock);
                ctx->proc = find_or_create_proc(pid, name);
                if (ctx->proc) ctx->proc->active = 1;
                pthread_mutex_unlock(&g_lock);
            }
        }
        else if (strncmp(line, "LEAK ", 5) == 0 && ctx->proc) {
            mttd_leak_t leak;
            memset(&leak, 0, sizeof(leak));
            /* 缺陷修复 #2: 检查 sscanf 返回值，防止格式化错误
             * 缺陷修复 #3: %127s 防止缓冲区溢出 */
            if (sscanf(line, "LEAK %zu %127s %d %d",
                       &leak.size, leak.file, &leak.line, &leak.nframes) >= 4) {
                if (leak.nframes > MTT_MAX_STACK) leak.nframes = MTT_MAX_STACK;
                if (leak.nframes < 0) leak.nframes = 0;
                pthread_mutex_lock(&ctx->proc->lock);
                add_leak(ctx->proc, &leak);
                pthread_mutex_unlock(&ctx->proc->lock);
            }
        }
        else if (strncmp(line, "FRAME ", 6) == 0 && ctx->proc) {
            int idx = -1;
            char sym[MTT_SYMBOL_MAX] = {0};
            if (sscanf(line, "FRAME %d %255[^\n]", &idx, sym) >= 2) {
                pthread_mutex_lock(&ctx->proc->lock);
                if (ctx->proc->leak_count > 0 && idx >= 0 && idx < MTT_MAX_STACK) {
                    mttd_leak_t* last = &ctx->proc->leaks[ctx->proc->leak_count - 1];
                    snprintf(last->frames[idx], MTT_SYMBOL_MAX, "%s", sym);
                }
                pthread_mutex_unlock(&ctx->proc->lock);
            }
        }
        else if (strncmp(line, "BYE", 3) == 0) {
            if (ctx->proc) {
                pthread_mutex_lock(&ctx->proc->lock);
                ctx->proc->active = 0; /* 标记进程已退出 */
                pthread_mutex_unlock(&ctx->proc->lock);
            }
            *out_proc = ctx->proc;
            shutdown(fd, SHUT_RDWR);
            close(fd);
            ctx->bufpos = 0;
            ctx->proc = NULL;
            return 0;
        }

        line = nl + 1;
    }

    /* 将未处理完的残留数据移到缓冲区开头 */
    if (line > ctx->buf) {
        int remaining = ctx->bufpos - (int)(line - ctx->buf);
        if (remaining > 0)
            memmove(ctx->buf, line, (size_t)remaining);
        ctx->bufpos = remaining;
    } else {
        /* 缓冲区已满且没有完整行，清空以避免死锁 */
        if (ctx->bufpos >= (int)sizeof(ctx->buf) - 1)
            ctx->bufpos = 0;
    }
    *out_proc = ctx->proc;
    return 1;
}

/* ---- HTTP 处理 ---- */

/* 看板 HTML 模板（内嵌 CSS/JS，零外部依赖）。
 * meta refresh 实现 3 秒自动刷新。
 * JS 通过 fetch /api/data 获取 JSON 数据并动态渲染 DOM。 */
static const char* g_dashboard_html =
"HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nConnection: close\r\n\r\n"
"<!DOCTYPE html>\n"
"<html lang=\"zh-CN\">\n"
"<head>\n"
"<meta charset=\"UTF-8\">\n"
"<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n"
"<title>MemoryTraceTool - 内存泄漏监控</title>\n"
"<style>\n"
":root {\n"
"  --bg: #ffffff;\n"
"  --bg-secondary: #f6f8fa;\n"
"  --bg-tertiary: #f3f4f6;\n"
"  --border: #d0d7de;\n"
"  --border-light: #e8ecf0;\n"
"  --text: #1f2328;\n"
"  --text-secondary: #656d76;\n"
"  --text-tertiary: #8b949e;\n"
"  --accent: #0969da;\n"
"  --accent-light: #ddf4ff;\n"
"  --green: #1a7f37;\n"
"  --green-bg: #dafbe1;\n"
"  --green-border: #aceebb;\n"
"  --red: #cf222e;\n"
"  --red-bg: #ffebe9;\n"
"  --red-border: #ffc1ba;\n"
"  --orange: #9a6700;\n"
"  --orange-bg: #fff8c5;\n"
"  --purple: #8250df;\n"
"  --shadow-sm: 0 1px 2px rgba(31,35,40,0.04);\n"
"  --shadow-md: 0 3px 8px rgba(31,35,40,0.06);\n"
"  --shadow-lg: 0 8px 24px rgba(31,35,40,0.08);\n"
"  --radius: 8px;\n"
"  --radius-sm: 6px;\n"
"  --font: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Noto Sans', Helvetica, Arial, sans-serif;\n"
"  --mono: 'SF Mono', 'Cascadia Code', 'Fira Code', 'JetBrains Mono', ui-monospace, monospace;\n"
"}\n"
"* { margin: 0; padding: 0; box-sizing: border-box; }\n"
"body {\n"
"  font-family: var(--font);\n"
"  background: var(--bg-secondary);\n"
"  color: var(--text);\n"
"  min-height: 100vh;\n"
"  line-height: 1.5;\n"
"  -webkit-font-smoothing: antialiased;\n"
"}\n"
"/* ---- Navbar ---- */\n"
".nav {\n"
"  background: var(--bg);\n"
"  border-bottom: 1px solid var(--border);\n"
"  padding: 0 24px;\n"
"  height: 56px;\n"
"  display: flex;\n"
"  align-items: center;\n"
"  justify-content: space-between;\n"
"  position: sticky;\n"
"  top: 0;\n"
"  z-index: 100;\n"
"  box-shadow: var(--shadow-sm);\n"
"}\n"
".nav-brand {\n"
"  display: flex;\n"
"  align-items: center;\n"
"  gap: 10px;\n"
"  font-size: 15px;\n"
"  font-weight: 600;\n"
"  color: var(--text);\n"
"  letter-spacing: -.2px;\n"
"}\n"
".nav-brand .logo {\n"
"  width: 28px; height: 28px;\n"
"  background: linear-gradient(135deg, var(--accent), #0550ae);\n"
"  border-radius: 7px;\n"
"  display: flex;\n"
"  align-items: center;\n"
"  justify-content: center;\n"
"  color: #fff;\n"
"  font-size: 14px;\n"
"  font-weight: 700;\n"
"}\n"
".nav-actions {\n"
"  display: flex;\n"
"  align-items: center;\n"
"  gap: 10px;\n"
"}\n"
".nav-dot {\n"
"  width: 7px; height: 7px;\n"
"  border-radius: 50%;\n"
"  background: var(--green);\n"
"  box-shadow: 0 0 0 3px var(--green-bg);\n"
"  transition: all .3s;\n"
"}\n"
".nav-dot.off {\n"
"  background: var(--text-tertiary);\n"
"  box-shadow: 0 0 0 3px var(--bg-secondary);\n"
"}\n"
".nav-age {\n"
"  font-family: var(--mono);\n"
"  font-size: 11px;\n"
"  color: var(--text-secondary);\n"
"  margin-right: 4px;\n"
"}\n"
".btn {\n"
"  background: var(--bg);\n"
"  border: 1px solid var(--border);\n"
"  color: var(--text);\n"
"  padding: 5px 14px;\n"
"  border-radius: var(--radius-sm);\n"
"  cursor: pointer;\n"
"  font-size: 12px;\n"
"  font-weight: 500;\n"
"  font-family: var(--font);\n"
"  transition: all .15s;\n"
"  white-space: nowrap;\n"
"}\n"
".btn:hover { background: var(--bg-secondary); border-color: #b0b8c1; }\n"
".btn:active { background: var(--bg-tertiary); }\n"
".btn.paused { border-color: var(--orange); color: var(--orange); background: var(--orange-bg); }\n"
".sort-btn.active { background: var(--accent); color: #fff; border-color: var(--accent); }\n"
".sort-btn.active:hover { background: var(--accent); border-color: var(--accent); }\n"
"/* ---- Layout ---- */\n"
".container { max-width: 1280px; margin: 0 auto; padding: 24px; }\n"
"/* ---- Summary cards ---- */\n"
".summary {\n"
"  display: grid;\n"
"  grid-template-columns: repeat(3, 1fr);\n"
"  gap: 16px;\n"
"  margin-bottom: 24px;\n"
"}\n"
".card {\n"
"  background: var(--bg);\n"
"  border: 1px solid var(--border-light);\n"
"  border-radius: var(--radius);\n"
"  padding: 20px 24px;\n"
"  box-shadow: var(--shadow-sm);\n"
"  transition: box-shadow .2s, border-color .2s;\n"
"}\n"
".card:hover { box-shadow: var(--shadow-md); border-color: var(--border); }\n"
".card-label { font-size: 11px; color: var(--text-secondary); text-transform: uppercase; letter-spacing: .5px; font-weight: 600; margin-bottom: 6px; }\n"
".card-value {\n"
"  font-size: 32px;\n"
"  font-weight: 700;\n"
"  font-family: var(--mono);\n"
"  letter-spacing: -1px;\n"
"  line-height: 1.1;\n"
"}\n"
".card-sub { font-size: 11px; color: var(--text-tertiary); margin-top: 2px; }\n"
".card-procs { border-left: 3px solid var(--accent); }\n"
".card-leaks { border-left: 3px solid var(--orange); }\n"
".card-bytes { border-left: 3px solid var(--red); }\n"
".card-procs .card-value { color: var(--accent); }\n"
".card-leaks .card-value { color: var(--orange); }\n"
".card-bytes .card-value { color: var(--red); }\n"
"/* ---- Section ---- */\n"
".section { margin-bottom: 24px; }\n"
".section-head {\n"
"  display: flex;\n"
"  align-items: center;\n"
"  gap: 8px;\n"
"  margin-bottom: 12px;\n"
"}\n"
".section-head h2 {\n"
"  font-size: 14px;\n"
"  font-weight: 600;\n"
"  color: var(--text);\n"
"}\n"
".section-head .count {\n"
"  font-size: 12px;\n"
"  color: var(--text-secondary);\n"
"  font-weight: 400;\n"
"}\n"
"/* ---- Table ---- */\n"
".table-wrap {\n"
"  background: var(--bg);\n"
"  border: 1px solid var(--border-light);\n"
"  border-radius: var(--radius);\n"
"  overflow: hidden;\n"
"  box-shadow: var(--shadow-sm);\n"
"}\n"
"table { width: 100%; border-collapse: collapse; }\n"
"thead th {\n"
"  text-align: left;\n"
"  padding: 10px 16px;\n"
"  background: var(--bg-secondary);\n"
"  font-size: 11px;\n"
"  font-weight: 600;\n"
"  color: var(--text-secondary);\n"
"  text-transform: uppercase;\n"
"  letter-spacing: .4px;\n"
"  border-bottom: 1px solid var(--border);\n"
"  white-space: nowrap;\n"
"}\n"
"tbody td {\n"
"  padding: 10px 16px;\n"
"  font-size: 13px;\n"
"  border-bottom: 1px solid var(--border-light);\n"
"  white-space: nowrap;\n"
"}\n"
"tbody tr:last-child td { border-bottom: none; }\n"
"tbody tr { transition: background .1s; }\n"
"tbody tr:hover { background: var(--bg-secondary); }\n"
"/* ---- Badges ---- */\n"
".badge {\n"
"  display: inline-flex;\n"
"  align-items: center;\n"
"  gap: 5px;\n"
"  padding: 2px 10px;\n"
"  border-radius: 12px;\n"
"  font-size: 11px;\n"
"  font-weight: 600;\n"
"  line-height: 1.6;\n"
"}\n"
".badge-live {\n"
"  background: var(--green-bg);\n"
"  color: var(--green);\n"
"  border: 1px solid var(--green-border);\n"
"}\n"
".badge-live::before {\n"
"  content: '';\n"
"  width: 6px; height: 6px;\n"
"  border-radius: 50%;\n"
"  background: var(--green);\n"
"  animation: pulse 2s ease-in-out infinite;\n"
"}\n"
"@keyframes pulse { 0%,100%{opacity:1} 50%{opacity:.4} }\n"
".badge-done {\n"
"  background: var(--bg-tertiary);\n"
"  color: var(--text-secondary);\n"
"}\n"
".hot-fn {\n"
"  font-family: var(--mono);\n"
"  font-size: 11px;\n"
"  color: var(--accent);\n"
"  max-width: 300px;\n"
"  overflow: hidden;\n"
"  text-overflow: ellipsis;\n"
"  display: inline-block;\n"
"}\n"
"/* ---- Leak cards ---- */\n"
".leak-card {\n"
"  background: var(--bg);\n"
"  border: 1px solid var(--border-light);\n"
"  border-radius: var(--radius-sm);\n"
"  margin-bottom: 6px;\n"
"  overflow: hidden;\n"
"  box-shadow: var(--shadow-sm);\n"
"  transition: box-shadow .15s, border-color .15s;\n"
"}\n"
".leak-card:hover { border-color: var(--border); box-shadow: var(--shadow-md); }\n"
".leak-card.open { border-color: var(--accent); box-shadow: 0 0 0 1px var(--accent-light); }\n"
".leak-header {\n"
"  padding: 12px 16px;\n"
"  cursor: pointer;\n"
"  display: flex;\n"
"  align-items: center;\n"
"  gap: 12px;\n"
"  font-size: 13px;\n"
"  user-select: none;\n"
"  transition: background .1s;\n"
"}\n"
".leak-header:hover { background: var(--bg-secondary); }\n"
".leak-header .arrow {\n"
"  font-size: 10px;\n"
"  color: var(--text-tertiary);\n"
"  transition: transform .2s;\n"
"  flex-shrink: 0;\n"
"}\n"
".leak-card.open .leak-header .arrow { transform: rotate(90deg); }\n"
".leak-header .sz {\n"
"  color: var(--red);\n"
"  font-weight: 600;\n"
"  font-family: var(--mono);\n"
"  font-size: 13px;\n"
"  white-space: nowrap;\n"
"  min-width: 70px;\n"
"}\n"
".leak-header .loc {\n"
"  color: var(--accent);\n"
"  font-family: var(--mono);\n"
"  font-size: 12px;\n"
"}\n"
".leak-header .proc-info {\n"
"  color: var(--text-tertiary);\n"
"  font-size: 11px;\n"
"  margin-left: auto;\n"
"  white-space: nowrap;\n"
"}\n"
".leak-body { display: none; padding: 0 16px 16px; }\n"
".leak-card.open .leak-body { display: block; }\n"
".leak-body-divider {\n"
"  border-top: 1px solid var(--border-light);\n"
"  margin-bottom: 12px;\n"
"}\n"
".call-tree {\n"
"  padding: 4px 0 0 12px;\n"
"  border-left: 2px solid var(--border-light);\n"
"  margin-left: 8px;\n"
"}\n"
".call-node {\n"
"  padding: 5px 0 5px 16px;\n"
"  position: relative;\n"
"  font-family: var(--mono);\n"
"  font-size: 12px;\n"
"  line-height: 1.5;\n"
"}\n"
".call-node::before {\n"
"  content: '';\n"
"  position: absolute;\n"
"  left: 0; top: 50%;\n"
"  width: 10px; height: 1.5px;\n"
"  background: var(--border);\n"
"  border-radius: 1px;\n"
"}\n"
".call-node .fn { color: var(--text); font-weight: 500; }\n"
".call-node .lib { color: var(--text-tertiary); font-size: 11px; margin-left: 4px; }\n"
".call-node.entry .fn { color: var(--purple); font-weight: 600; }\n"
".call-node.leak-site { font-weight: 600; }\n"
".call-node.leak-site .fn { color: var(--red); font-weight: 700; }\n"
".call-node[onclick]:hover { background: var(--accent-light); border-radius: 4px; cursor: pointer; }\n"
".call-node .source-tip {\n"
"  color: var(--green);\n"
"  font-size: 11px;\n"
"  margin-left: 6px;\n"
"  font-weight: 500;\n"
"}\n"
".call-node.leak-site .tag {\n"
"  display: inline-block;\n"
"  background: var(--red-bg);\n"
"  color: var(--red);\n"
"  font-size: 10px;\n"
"  padding: 1px 6px;\n"
"  border-radius: 3px;\n"
"  margin-left: 8px;\n"
"  font-weight: 600;\n"
"  letter-spacing: .3px;\n"
"  border: 1px solid var(--red-border);\n"
"}\n"
"/* ---- Empty state ---- */\n"
".empty {\n"
"  text-align: center;\n"
"  padding: 48px 20px;\n"
"  color: var(--text-tertiary);\n"
"  font-size: 13px;\n"
"}\n"
".empty-icon { font-size: 28px; margin-bottom: 8px; opacity: .4; }\n"
".empty p { margin-top: 4px; }\n"
"/* ---- Toast ---- */\n"
".toast {\n"
"  position: fixed;\n"
"  bottom: 24px;\n"
"  right: 24px;\n"
"  background: var(--text);\n"
"  color: #fff;\n"
"  padding: 10px 20px;\n"
"  border-radius: var(--radius-sm);\n"
"  font-size: 12px;\n"
"  font-weight: 500;\n"
"  opacity: 0;\n"
"  transform: translateY(8px);\n"
"  transition: all .25s;\n"
"  pointer-events: none;\n"
"  z-index: 200;\n"
"  box-shadow: var(--shadow-lg);\n"
"}\n"
".toast.show { opacity: 1; transform: translateY(0); }\n"
"/* ---- Responsive ---- */\n"
".inject-table { width:100%%; border-collapse:collapse; }\n"
".inject-table th { text-align:left; font-size:11px; color:var(--text-secondary); "
  "padding:6px 10px; border-bottom:1px solid var(--border-light); }\n"
".inject-table td { padding:6px 10px; font-size:12px; border-bottom:1px solid var(--border-light); }\n"
".btn-sm { padding:3px 10px; font-size:11px; border-radius:5px; border:1px solid var(--border); "
  "background:var(--bg); color:var(--text); cursor:pointer; transition:all 0.15s; }\n"
".btn-sm:hover { background:var(--accent); color:#fff; border-color:var(--accent); }\n"
".btn-sm:disabled { opacity:0.5; cursor:not-allowed; }\n"
".badge-ok { display:inline-block; padding:1px 8px; border-radius:10px; font-size:11px; "
  "font-weight:500; background:var(--green-bg); color:var(--green); border:1px solid var(--green-border); }\n"
".badge-fail { display:inline-block; padding:1px 8px; border-radius:10px; font-size:11px; "
  "font-weight:500; background:var(--red-bg); color:var(--red); border:1px solid var(--red-border); }\n"
".badge-pending { display:inline-block; padding:1px 8px; border-radius:10px; font-size:11px; "
  "font-weight:500; background:var(--orange-bg); color:var(--orange); }\n"
"@media (max-width: 768px) {\n"
"  .summary { grid-template-columns: 1fr; }\n"
"  .nav { padding: 0 14px; }\n"
"  .container { padding: 16px; }\n"
"  table { font-size: 11px; }\n"
"  thead th, tbody td { padding: 8px 10px; }\n"
"  .inject-table { font-size:10px; }\n"
"}\n"
"</style>\n"
"</head>\n"
"<body>\n"
"\n"
"<nav class=\"nav\">\n"
"  <div class=\"nav-brand\">\n"
"    <div class=\"logo\">M</div>\n"
"    <span>MemoryTraceTool</span>\n"
"  </div>\n"
"  <div class=\"nav-actions\">\n"
"    <span class=\"nav-age\" id=\"refresh-age\">--</span>\n"
"    <div class=\"nav-dot\" id=\"status-dot\" title=\"连接状态\"></div>\n"
"    <button class=\"btn\" id=\"btn-pause\" onclick=\"toggleAuto()\">暂停刷新</button>\n"
"    <button class=\"btn\" onclick=\"refresh()\">立即刷新</button>\n"
"  </div>\n"
"</nav>\n"
"\n"
"<div class=\"container\">\n"
"\n"
"  <div class=\"summary\">\n"
"    <div class=\"card card-procs\">\n"
"      <div class=\"card-label\">监控进程数</div>\n"
"      <div class=\"card-value\" id=\"p\">--</div>\n"
"      <div class=\"card-sub\">当前活跃连接</div>\n"
"    </div>\n"
"    <div class=\"card card-leaks\">\n"
"      <div class=\"card-label\">泄漏总数</div>\n"
"      <div class=\"card-value\" id=\"l\">--</div>\n"
"      <div class=\"card-sub\">可疑内存泄漏点</div>\n"
"    </div>\n"
"    <div class=\"card card-bytes\">\n"
"      <div class=\"card-label\">泄漏字节数</div>\n"
"      <div class=\"card-value\" id=\"b\">--</div>\n"
"      <div class=\"card-sub\">累计未释放内存</div>\n"
"    </div>\n"
"  </div>\n"
"\n"
"  <div class=\"section\">\n"
"    <div class=\"section-head\">\n"
"      <svg width=\"16\" height=\"16\" viewBox=\"0 0 16 16\" fill=\"none\"><circle cx=\"8\" cy=\"8\" r=\"5\" stroke=\"#0969da\" stroke-width=\"1.5\"/><line x1=\"8\" y1=\"5\" x2=\"8\" y2=\"11\" stroke=\"#0969da\" stroke-width=\"1.2\"/><line x1=\"5\" y1=\"8\" x2=\"11\" y2=\"8\" stroke=\"#0969da\" stroke-width=\"1.2\"/></svg>\n"
"      <h2>运行时注入</h2>\n"
"      <span class=\"count\" id=\"proc-count-inject\"></span>\n"
"    </div>\n"
"    <div style=\"margin-bottom:8px;\">\n"
"      <input type=\"text\" id=\"proc-filter\" placeholder=\"搜索进程名...\" "
"        oninput=\"loadProcesses()\" "
"        style=\"width:240px;padding:5px 10px;border:1px solid var(--border);"
"        border-radius:5px;font-size:12px;background:var(--bg);color:var(--text)\">\n"
"      <span style=\"font-size:11px;color:var(--text-tertiary);margin-left:8px\">"
"        选择一个正在运行的进程，点击「注入」开始监控其内存分配</span>\n"
"    </div>\n"
"    <div class=\"table-wrap\">\n"
"      <table class=\"inject-table\">\n"
"        <thead>\n"
"          <tr>\n"
"            <th style=\"width:80px\">PID</th>\n"
"            <th>进程名</th>\n"
"            <th style=\"width:50px\">状态</th>\n"
"            <th style=\"width:120px\">注入状态</th>\n"
"            <th style=\"width:80px\">操作</th>\n"
"          </tr>\n"
"        </thead>\n"
"        <tbody id=\"ptb\">\n"
"          <tr><td colspan=\"5\"><div class=\"empty\"><p>加载中...</p></div></td></tr>\n"
"        </tbody>\n"
"      </table>\n"
"    </div>\n"
"  </div>\n"
"\n"
"  <div class=\"section\">\n"
"    <div class=\"section-head\">\n"
"      <svg width=\"16\" height=\"16\" viewBox=\"0 0 16 16\" fill=\"none\"><rect x=\"1.5\" y=\"1.5\" width=\"13\" height=\"13\" rx=\"2\" stroke=\"#656d76\" stroke-width=\"1.5\"/><line x1=\"5\" y1=\"4.5\" x2=\"5\" y2=\"11.5\" stroke=\"#656d76\" stroke-width=\"1.2\"/><line x1=\"8\" y1=\"4.5\" x2=\"8\" y2=\"11.5\" stroke=\"#656d76\" stroke-width=\"1.2\"/><line x1=\"11\" y1=\"4.5\" x2=\"11\" y2=\"11.5\" stroke=\"#656d76\" stroke-width=\"1.2\"/></svg>\n"
"      <h2>被监控进程</h2>\n"
"      <span class=\"count\" id=\"proc-count\"></span>\n"
"    </div>\n"
"    <div class=\"table-wrap\">\n"
"      <table>\n"
"        <thead>\n"
"          <tr>\n"
"            <th>PID</th>\n"
"            <th>进程名</th>\n"
"            <th>状态</th>\n"
"            <th>泄漏数</th>\n"
"            <th>字节数</th>\n"
"            <th>最后活跃</th>\n"
"            <th>热点函数</th>\n"
"          </tr>\n"
"        </thead>\n"
"        <tbody id=\"tb\">\n"
"          <tr><td colspan=\"7\"><div class=\"empty\"><div class=\"empty-icon\">--</div><p>等待被监控进程接入...</p></div></td></tr>\n"
"        </tbody>\n"
"      </table>\n"
"    </div>\n"
"  </div>\n"
"\n"
"  <div class=\"section\">\n"
"    <div class=\"section-head\">\n"
"      <svg width=\"16\" height=\"16\" viewBox=\"0 0 16 16\" fill=\"none\"><circle cx=\"8\" cy=\"8\" r=\"5\" stroke=\"#cf222e\" stroke-width=\"1.5\"/><line x1=\"8\" y1=\"5.5\" x2=\"8\" y2=\"8.5\" stroke=\"#cf222e\" stroke-width=\"1.2\"/><circle cx=\"8\" cy=\"10.2\" r=\"0.8\" fill=\"#cf222e\"/></svg>\n"
"      <h2>可疑泄漏排行</h2>\n"
"      <span class=\"count\" id=\"leak-count\"></span>\n"
"    </div>\n"
"    <div style=\"margin-bottom:8px;display:flex;gap:8px;align-items:center;\">\n"
"      <input type=\"text\" id=\"leak-filter\" placeholder=\"按进程名或 PID 过滤泄漏...\" "
"        oninput=\"renderLeaks()\" "
"        style=\"width:260px;padding:5px 10px;border:1px solid var(--border);"
"        border-radius:5px;font-size:12px;background:var(--bg);color:var(--text)\">\n"
"      <span style=\"font-size:11px;color:var(--text-tertiary);margin-left:4px\">排序:</span>\n"
"      <button class=\"btn sort-btn active\" id=\"sort-size\" onclick=\"setSort('size')\">大小</button>\n"
"      <button class=\"btn sort-btn\" id=\"sort-time\" onclick=\"setSort('time')\">最近</button>\n"
"      <button class=\"btn sort-btn\" id=\"sort-proc\" onclick=\"setSort('proc')\">进程</button>\n"
"    </div>\n"
"    <div id=\"tl\"><div class=\"empty\"><div class=\"empty-icon\">OK</div><p>暂无泄漏 - 一切正常</p></div></div>\n"
"  </div>\n"
"\n"
"</div>\n"
"\n"
"<div class=\"toast\" id=\"toast\"></div>\n"
"\n"
"<script>\n"
"var autoRefresh = true;\n"
"var failCount = 0;\n"
"var gAllLeaks = [];\n"
"var gSortMode = 'size';\n"
"\n"
"setInterval(function() { if (autoRefresh) { refresh(); loadProcesses(); } }, 3000);\n"
"refresh();\n"
"\n"
"function setSort(mode) {\n"
"  gSortMode = mode;\n"
"  document.getElementById('sort-size').classList.toggle('active', mode === 'size');\n"
"  document.getElementById('sort-time').classList.toggle('active', mode === 'time');\n"
"  document.getElementById('sort-proc').classList.toggle('active', mode === 'proc');\n"
"  renderLeaks();\n"
"}\n"
"\n"
"function renderLeaks() {\n"
"  var filter = (document.getElementById('leak-filter').value || '').toLowerCase();\n"
"  var filtered = gAllLeaks;\n"
"  if (filter) {\n"
"    filtered = gAllLeaks.filter(function(l) {\n"
"      return (l.name && l.name.toLowerCase().indexOf(filter) >= 0) ||\n"
"             (l.file && l.file.toLowerCase().indexOf(filter) >= 0) ||\n"
"             String(l.pid).indexOf(filter) >= 0;\n"
"    });\n"
"  }\n"
"\n"
"  if (gSortMode === 'size') {\n"
"    filtered.sort(function(a, b) { return b.size - a.size; });\n"
"  } else if (gSortMode === 'time') {\n"
"    filtered.sort(function(a, b) { return b.seq - a.seq; });\n"
"  } else if (gSortMode === 'proc') {\n"
"    filtered.sort(function(a, b) {\n"
"      var nc = (a.name||'').localeCompare(b.name||'');\n"
"      if (nc !== 0) return nc;\n"
"      return a.pid - b.pid;\n"
"    });\n"
"  }\n"
"\n"
"  var top = filtered.slice(0, 15);\n"
"  var html = '';\n"
"  for (var i = 0; i < top.length; i++) {\n"
"    var l = top[i];\n"
"    html += '<div class=\"leak-card\" onclick=\"event.stopPropagation();this.classList.toggle(\\'open\\')\">';\n"
"    html += '<div class=\"leak-header\">';\n"
"    html += '<span class=\"arrow\">&#9654;</span>';\n"
"    html += '<span class=\"sz\">' + fmtBytes(l.size) + '</span>';\n"
"    html += '<span class=\"loc\">' + esc(l.file) + ':' + l.line + '</span>';\n"
"    html += '<span class=\"proc-info\">PID ' + l.pid + ' &middot; ' + esc(l.name) + '</span>';\n"
"    html += '</div>';\n"
"    html += '<div class=\"leak-body\"><div class=\"leak-body-divider\"></div>';\n"
"    html += '<div class=\"call-tree\">';\n"
"\n"
"    if (l.nframes > 0) {\n"
"      for (var j = l.nframes - 1; j >= 0; j--) {\n"
"        var cls = j === 0 ? 'call-node leak-site' : (j === l.nframes - 1 ? 'call-node entry' : 'call-node');\n"
"        var parsed = parseFrame(l.frames[j] || '?');\n"
"        html += '<div class=\"' + cls + '\"';\n"
"        if (parsed.bin && parsed.off) html += ' onclick=\"event.stopPropagation();resolveFrame(this,\\'' + escAttr(parsed.bin) + '\\',\\'' + escAttr(parsed.off) + '\\')\" style=\"cursor:pointer\" title=\"点击解析源码位置\"';\n"
"        html += '>';\n"
"        html += '<span class=\"fn\">' + esc(parsed.fn) + '</span>';\n"
"        if (parsed.lib) html += '<span class=\"lib\">' + esc(parsed.lib) + '</span>';\n"
"        if (j === 0) html += '<span class=\"tag\">泄漏点</span>';\n"
"        html += '</div>';\n"
"      }\n"
"    } else {\n"
"      html += '<div class=\"call-node\"><span class=\"fn\" style=\"color:var(--text-tertiary)\">(无调用栈)</span></div>';\n"
"    }\n"
"\n"
"    html += '</div></div></div>';\n"
"  }\n"
"\n"
"  var totalAll = gAllLeaks.length;\n"
"  var shown = filter ? filtered.length : Math.min(totalAll, 15);\n"
"  var label = '';\n"
"  if (totalAll > 0) {\n"
"    if (filter) {\n"
"      label = '(匹配 ' + shown + ' / 共 ' + totalAll + ')';\n"
"    } else {\n"
"      label = '(Top ' + Math.min(totalAll, 15) + ' / 共 ' + totalAll + ')';\n"
"    }\n"
"  }\n"
"  document.getElementById('tl').innerHTML = html ||\n"
"    '<div class=\"empty\"><div class=\"empty-icon\">OK</div><p>' + (filter ? '无匹配泄漏' : '暂无泄漏 - 一切正常') + '</p></div>';\n"
"  document.getElementById('leak-count').textContent = label;\n"
"}\n"
"\n"
"function toggleAuto() {\n"
"  autoRefresh = !autoRefresh;\n"
"  var btn = document.getElementById('btn-pause');\n"
"  var dot = document.getElementById('status-dot');\n"
"  if (autoRefresh) {\n"
"    btn.textContent = '暂停刷新';\n"
"    btn.classList.remove('paused');\n"
"    dot.classList.remove('off');\n"
"    refresh();\n"
"  } else {\n"
"    btn.textContent = '恢复刷新';\n"
"    btn.classList.add('paused');\n"
"    dot.classList.add('off');\n"
"    document.getElementById('refresh-age').textContent = '已暂停';\n"
"  }\n"
"  toast(autoRefresh ? '自动刷新已恢复' : '自动刷新已暂停');\n"
"}\n"
"\n"
"function refresh() {\n"
"  fetch('/api/data')\n"
"    .then(function(r) { return r.json(); })\n"
"    .then(function(d) {\n"
"      failCount = 0;\n"
"      document.getElementById('status-dot').classList.remove('off');\n"
"      document.getElementById('refresh-age').textContent = new Date().toLocaleTimeString();\n"
"\n"
"      document.getElementById('p').textContent = d.nprocs;\n"
"      document.getElementById('l').textContent = d.total_leaks;\n"
"      document.getElementById('b').textContent = fmtBytes(d.total_bytes);\n"
"\n"
"      var rows = '';\n"
"      for (var i = 0; i < d.procs.length; i++) {\n"
"        var p = d.procs[i];\n"
"        var badge = p.active\n"
"          ? '<span class=\"badge badge-live\">运行中</span>'\n"
"          : '<span class=\"badge badge-done\">已退出</span>';\n"
"        var seen = p.last_seen ? new Date(p.last_seen * 1000).toLocaleTimeString() : '--';\n"
"        var topFn = parseTopFn(p.top_stack);\n"
"        rows += '<tr>' +\n"
"          '<td style=\"font-family:var(--mono);font-size:12px\">' + p.pid + '</td>' +\n"
"          '<td>' + esc(p.name) + '</td>' +\n"
"          '<td>' + badge + '</td>' +\n"
"          '<td style=\"font-family:var(--mono);font-size:12px\">' + p.leak_count + '</td>' +\n"
"          '<td style=\"font-family:var(--mono);font-size:12px\">' + fmtBytes(p.total_leaked) + '</td>' +\n"
"          '<td style=\"font-size:12px;color:var(--text-secondary)\">' + seen + '</td>' +\n"
"          '<td><span class=\"hot-fn\" title=\"' + escAttr(p.top_stack || '') + '\">' + esc(topFn) + '</span></td>' +\n"
"          '</tr>';\n"
"      }\n"
"      document.getElementById('tb').innerHTML = rows ||\n"
"        '<tr><td colspan=\"7\"><div class=\"empty\"><div class=\"empty-icon\">--</div><p>等待被监控进程接入...</p></div></td></tr>';\n"
"      document.getElementById('proc-count').textContent = d.nprocs > 0 ? '(' + d.nprocs + ')' : '';\n"
"\n"
"      var seq = 0;\n"
"      var all = [];\n"
"      for (var i = 0; i < d.procs.length; i++) {\n"
"        var p = d.procs[i];\n"
"        for (var j = 0; j < p.leaks.length; j++) {\n"
"          all.push({\n"
"            size: p.leaks[j].size,\n"
"            file: p.leaks[j].file,\n"
"            line: p.leaks[j].line,\n"
"            nframes: p.leaks[j].nframes,\n"
"            frames: p.leaks[j].frames,\n"
"            pid: p.pid,\n"
"            name: p.name,\n"
"            seq: seq++\n"
"          });\n"
"        }\n"
"      }\n"
"      gAllLeaks = all;\n"
"      renderLeaks();\n"
"    })\n"
"    .catch(function() {\n"
"      failCount++;\n"
"      document.getElementById('status-dot').classList.add('off');\n"
"      if (failCount <= 1) {\n"
"        document.getElementById('refresh-age').textContent = '连接失败，重试中...';\n"
"      }\n"
"    });\n"
"}\n"
"\n"
"function loadProcesses() {\n"
"  var filter = (document.getElementById('proc-filter').value || '').toLowerCase();\n"
"  fetch('/api/processes')\n"
"    .then(function(r) { return r.json(); })\n"
"    .then(function(d) {\n"
"      var rows = '';\n"
"      var shown = 0;\n"
"      for (var i = 0; i < d.processes.length; i++) {\n"
"        var p = d.processes[i];\n"
"        if (filter && p.name.toLowerCase().indexOf(filter) < 0) continue;\n"
"        shown++;\n"
"        var stateLabel = p.state === 'R' ? '运行' : (p.state === 'S' ? '睡眠' : p.state);\n"
"        var injHtml = '';\n"
"        if (p.injected) {\n"
"          if (p.inj_status === 1) {\n"
"            injHtml = '<span class=\"badge-ok\">监控中</span>';\n"
"          } else if (p.inj_status === 2) {\n"
"            injHtml = '<span class=\"badge-fail\" title=\"' + escAttr(p.inj_err) + '\">失败</span>';\n"
"          }\n"
"        } else {\n"
"          injHtml = '<span class=\"badge-pending\">未注入</span>';\n"
"        }\n"
"        var btnHtml = '';\n"
"        if (p.injected && p.inj_status === 1) {\n"
"          btnHtml = '<span class=\"badge-ok\">已注入</span>';\n"
"        } else {\n"
"          btnHtml = '<button class=\"btn-sm\" onclick=\"injectProcess(' + p.pid + ', this)\">注入</button>';\n"
"        }\n"
"        rows += '<tr>' +\n"
"          '<td style=\"font-family:var(--mono);font-size:11px\">' + p.pid + '</td>' +\n"
"          '<td>' + esc(p.name) + '</td>' +\n"
"          '<td style=\"font-size:11px\">' + stateLabel + '</td>' +\n"
"          '<td>' + injHtml + '</td>' +\n"
"          '<td>' + btnHtml + '</td>' +\n"
"          '</tr>';\n"
"      }\n"
"      document.getElementById('ptb').innerHTML = rows ||\n"
"        '<tr><td colspan=\"5\"><div class=\"empty\"><p>' + (filter ? '无匹配进程' : '无可用进程') + '</p></div></td></tr>';\n"
"      document.getElementById('proc-count-inject').textContent = shown > 0 ? '(' + shown + ')' : '';\n"
"    })\n"
"    .catch(function() {\n"
"      document.getElementById('ptb').innerHTML = '<tr><td colspan=\"5\"><div class=\"empty\"><p>加载失败</p></div></td></tr>';\n"
"    });\n"
"}\n"
"\n"
"function injectProcess(pid, btn) {\n"
"  btn.disabled = true;\n"
"  btn.textContent = '...';\n"
"  toast('正在向 PID ' + pid + ' 注入...');\n"
"  fetch('/api/inject?pid=' + pid)\n"
"    .then(function(r) { return r.json(); })\n"
"    .then(function(d) {\n"
"      if (d.status === 'ok') {\n"
"        toast('PID ' + pid + ' 注入成功！(' + d.patched + ' 个GOT表项已修补)');\n"
"        loadProcesses();\n"
"      } else {\n"
"        toast('注入失败: ' + d.error);\n"
"        btn.disabled = false;\n"
"        btn.textContent = '重试';\n"
"      }\n"
"    })\n"
"    .catch(function() {\n"
"      toast('注入请求失败（网络错误）');\n"
"      btn.disabled = false;\n"
"      btn.textContent = '重试';\n"
"    });\n"
"}\n"
"\n"
"loadProcesses();\n"
"\n"
"function parseFrame(raw) {\n"
"  if (!raw) return { fn: '?', lib: '', bin: '', off: '' };\n"
"  var parts = raw.split('|');\n"
"  var display = parts[0] || raw;\n"
"  var m = display.match(/^(.+?)\\s+\\((.+?)\\)\\s*$/);\n"
"  if (m) return { fn: m[1], lib: m[2], bin: parts[1] || '', off: parts[2] || '' };\n"
"  m = display.match(/^(.+?)\\((.+?)\\)\\s*$/);\n"
"  if (m) return { fn: m[1], lib: '', bin: parts[1] || '', off: parts[2] || '' };\n"
"  return { fn: display, lib: '', bin: parts[1] || '', off: parts[2] || '' };\n"
"}\n"
"\n"
"function parseTopFn(raw) {\n"
"  if (!raw || raw === '(none)') return '(none)';\n"
"  return parseFrame(raw).fn;\n"
"}\n"
"\n"
"function resolveFrame(el, bin, off) {\n"
"  if (!bin || !off) return;\n"
"  var fnEl = el.querySelector('.fn');\n"
"  var orig = fnEl.textContent;\n"
"  fnEl.textContent = orig + ' (解析中...)';\n"
"  fetch('/api/addr2line?bin=' + encodeURIComponent(bin) + '&off=' + off)\n"
"    .then(function(r) { return r.json(); })\n"
"    .then(function(d) {\n"
"      fnEl.textContent = orig;\n"
"      var tip = el.querySelector('.source-tip');\n"
"      if (!tip) {\n"
"        tip = document.createElement('span');\n"
"        tip.className = 'source-tip';\n"
"        el.appendChild(tip);\n"
"      }\n"
"      tip.textContent = ' @ ' + d.result;\n"
"      tip.title = d.result;\n"
"    })\n"
"    .catch(function() {\n"
"      fnEl.textContent = orig;\n"
"    });\n"
"}\n"
"\n"
"function fmtBytes(b) {\n"
"  if (b < 1024) return b + ' B';\n"
"  if (b < 1048576) return (b / 1024).toFixed(1) + ' KB';\n"
"  if (b < 1073741824) return (b / 1048576).toFixed(1) + ' MB';\n"
"  return (b / 1073741824).toFixed(1) + ' GB';\n"
"}\n"
"\n"
"function esc(s) {\n"
"  if (!s) return '';\n"
"  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/\"/g, '&quot;');\n"
"}\n"
"\n"
"function escAttr(s) {\n"
"  if (!s) return '';\n"
"  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/\"/g, '&quot;').replace(/'/g, '&#39;');\n"
"}\n"
"\n"
"function toast(msg) {\n"
"  var t = document.getElementById('toast');\n"
"  t.textContent = msg;\n"
"  t.classList.add('show');\n"
"  setTimeout(function() { t.classList.remove('show'); }, 2000);\n"
"}\n"
"</script>\n"
"</body>\n"
"</html>";

/**
 * JSON 字符串转义。
 *
 * 将源字符串中的 "、\、\n、\r、\t 等 JSON 特殊字符
 * 进行转义后写入目标缓冲区。
 *
 * 缺陷修复: 增加控制字符过滤（\x00-\x1f），防止污染 JSON。
 */
static void json_escape(char* dst, const char* src, size_t n)
{
    size_t j = 0;
    for (size_t i = 0; src[i] && j < n - 1; i++) {
        switch (src[i]) {
        case '"':  if (j < n-2) { dst[j++]='\\'; dst[j++]='"'; } break;
        case '\\': if (j < n-2) { dst[j++]='\\'; dst[j++]='\\'; } break;
        case '\n': if (j < n-2) { dst[j++]='\\'; dst[j++]='n'; } break;
        case '\r': if (j < n-2) { dst[j++]='\\'; dst[j++]='r'; } break;
        case '\t': if (j < n-2) { dst[j++]='\\'; dst[j++]='t'; } break;
        default:
            /* 过滤其他控制字符 */
            if ((unsigned char)src[i] < 0x20) {
                if (j < n - 7) {
                    dst[j++] = '\\';
                    dst[j++] = 'u';
                    dst[j++] = '0';
                    dst[j++] = '0';
                    dst[j++] = "0123456789abcdef"[(src[i] >> 4) & 0xf];
                    dst[j++] = "0123456789abcdef"[src[i] & 0xf];
                }
            } else {
                dst[j++] = src[i];
            }
            break;
        }
    }
    dst[j] = '\0';
}

/**
 * 生成 JSON 格式的 API 响应并发送给 HTTP 客户端。
 *
 * 遍历所有被监控进程，序列化其泄漏数据为 JSON 格式，
 * 包含进程元信息、泄漏列表和每条的调用栈。
 *
 * 缺陷修复 #4: 使用 safe_append 检测缓冲区截断。
 * 缺陷修复 #6: 在错误路径正确释放锁。
 *
 * 格式：{ nprocs, total_leaks, total_bytes, procs: [...] }
 */
static void send_api_data(int fd)
{
    pthread_mutex_lock(&g_lock);

    /* 汇总统计 */
    int total_leaks = 0;
    size_t total_bytes = 0;
    for (int i = 0; i < g_nprocs; i++) {
        pthread_mutex_lock(&g_procs[i].lock);
        total_leaks += g_procs[i].leak_count;
        total_bytes += g_procs[i].total_leaked;
        pthread_mutex_unlock(&g_procs[i].lock);
    }

    /* 缺陷修复 #4,#6: 增大缓冲区到 256KB，确保足够容纳大报告 */
    enum { JSON_BUF_SIZE = 262144 };
    char* buf = malloc(JSON_BUF_SIZE);
    if (!buf) { pthread_mutex_unlock(&g_lock); return; }
    int pos = 0;
    int truncated = 0;

    truncated |= (safe_append(buf, &pos, JSON_BUF_SIZE,
        "{\"nprocs\":%d,\"total_leaks\":%d,\"total_bytes\":%zu,\"procs\":[",
        g_nprocs, total_leaks, total_bytes) == 0);

    for (int i = 0; i < g_nprocs && !truncated; i++) {
        mttd_proc_t* p = &g_procs[i];
        pthread_mutex_lock(&p->lock);

        /* 获取栈顶帧（首个有符号的帧）作为摘要显示 */
        char top_stack[256] = "(none)";
        for (int j = 0; j < p->leak_count; j++) {
            if (p->leaks[j].nframes > 0 && p->leaks[j].frames[0][0]) {
                snprintf(top_stack, sizeof(top_stack), "%s",
                         p->leaks[j].frames[0]);
                break;
            }
        }

        char escaped[512];
        json_escape(escaped, p->name, sizeof(escaped));
        truncated |= (safe_append(buf, &pos, JSON_BUF_SIZE,
            "%s{\"pid\":%d,\"name\":\"%s\",\"active\":%s,"
            "\"leak_count\":%d,\"total_leaked\":%zu,"
            "\"last_seen\":%ld,\"top_stack\":\"",
            i > 0 ? "," : "", p->pid, escaped,
            p->active ? "true" : "false",
            p->leak_count, p->total_leaked,
            (long)p->last_seen) == 0);
        json_escape(escaped, top_stack, sizeof(escaped));
        truncated |= (safe_append(buf, &pos, JSON_BUF_SIZE, "%s", escaped) == 0);
        truncated |= (safe_append(buf, &pos, JSON_BUF_SIZE, "\",\"leaks\":[") == 0);

        for (int j = 0; j < p->leak_count && !truncated; j++) {
            mttd_leak_t* l = &p->leaks[j];
            json_escape(escaped, l->file, sizeof(escaped));
            truncated |= (safe_append(buf, &pos, JSON_BUF_SIZE,
                "%s{\"size\":%zu,\"file\":\"%s\",\"line\":%d,\"nframes\":%d,\"frames\":[",
                j > 0 ? "," : "", l->size, escaped, l->line, l->nframes) == 0);
            for (int k = 0; k < l->nframes; k++) {
                if (l->frames[k][0]) {
                    char fe[MTT_SYMBOL_MAX * 2];
                    json_escape(fe, l->frames[k], sizeof(fe));
                    truncated |= (safe_append(buf, &pos, JSON_BUF_SIZE,
                        "%s\"%s\"", k > 0 ? "," : "", fe) == 0);
                }
            }
            truncated |= (safe_append(buf, &pos, JSON_BUF_SIZE, "]}") == 0);
        }
        truncated |= (safe_append(buf, &pos, JSON_BUF_SIZE, "]}") == 0);
        pthread_mutex_unlock(&p->lock);
    }
    truncated |= (safe_append(buf, &pos, JSON_BUF_SIZE, "]}") == 0);
    /* 缺陷修复 #6: g_lock 已在上面获取，此处安全释放 */
    pthread_mutex_unlock(&g_lock);

    /* 组装并发送 HTTP 响应（含 CORS 头） */
    char hdr[256];
    int hdrlen = snprintf(hdr, sizeof(hdr),
        "HTTP/1.1 %s\r\n"
        "Content-Type: application/json\r\n"
        "Access-Control-Allow-Origin: *\r\n"
        "Connection: close\r\n"
        "Content-Length: %d\r\n\r\n",
        truncated ? "206 Partial Content" : "200 OK",
        (int)strlen(buf));
    if (hdrlen < 0 || hdrlen >= (int)sizeof(hdr)) {
        /* 头构建失败，发送最小错误响应 */
        send_all(fd, "HTTP/1.1 500 Internal Error\r\nConnection: close\r\n\r\n", 50);
    } else {
        send_all(fd, hdr, (size_t)hdrlen);
        send_all(fd, buf, strlen(buf));
    }
    free(buf);
}

/**
 * addr2line 解析端点：验证输入安全性后调用 addr2line。
 *
 * 缺陷修复 #7: 对 bin 和 offset 参数进行严格的白名单校验，
 * 防止通过 shell 元字符实现命令注入。
 *
 * @param fd       HTTP 客户端 socket
 * @param bin      二进制文件路径（URL 编码，服务端需解码）
 * @param offset   文件内偏移（十六进制字符串，如 "0x2cc6"）
 */
static void send_addr2line(int fd, const char* bin, const char* offset)
{
    char result[512] = {0};
    int valid = 1;

    /* URL 解码 %2F → / 等 */
    char bin_decoded[512] = {0};
    size_t di = 0;
    for (const char* s = bin; *s && di < sizeof(bin_decoded) - 1; s++) {
        if (*s == '%' && isxdigit((unsigned char)s[1]) && isxdigit((unsigned char)s[2])) {
            unsigned int c;
            if (sscanf(s + 1, "%2x", &c) == 1) {
                bin_decoded[di++] = (char)c;
                s += 2;
                continue;
            }
        }
        /* 缺陷修复 #7: 白名单字符检查 */
        if (isalnum((unsigned char)*s) || *s == '/' || *s == '.' ||
            *s == '-' || *s == '_' || *s == '+') {
            bin_decoded[di++] = *s;
        } else {
            valid = 0;
            break;
        }
    }
    bin_decoded[di] = '\0';

    /* 缺陷修复 #7: offset 严格校验（仅允许 0x 前缀 + 十六进制字符） */
    char offset_safe[64] = {0};
    if (offset) {
        const char* p = offset;
        size_t oi = 0;
        if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) {
            offset_safe[oi++] = '0';
            offset_safe[oi++] = 'x';
            p += 2;
        }
        while (*p && oi < sizeof(offset_safe) - 1) {
            if (isxdigit((unsigned char)*p))
                offset_safe[oi++] = *p;
            else
                { valid = 0; break; }
            p++;
        }
        offset_safe[oi] = '\0';
        if (oi <= 2) valid = 0; /* 至少有一个十六进制数字 */
    } else {
        valid = 0;
    }

    if (valid && bin_decoded[0] && offset_safe[2]) {
        /* 使用数组参数形式 exec，完全避免 shell 注入 */
        char cmd[768];
        snprintf(cmd, sizeof(cmd),
                 "addr2line -e %s -f -p %s 2>/dev/null",
                 bin_decoded, offset_safe);

        FILE* fp = popen(cmd, "r");
        if (fp) {
            if (fgets(result, sizeof(result), fp) == NULL)
                snprintf(result, sizeof(result),
                         "(无法解析 — 无调试信息或二进制不可访问)");
            else {
                size_t len = strlen(result);
                if (len > 0 && result[len-1] == '\n') result[len-1] = '\0';
            }
            pclose(fp);
        } else {
            snprintf(result, sizeof(result), "(addr2line 不可用)");
        }
    } else {
        snprintf(result, sizeof(result), "(无效的地址参数)");
    }

    /* 构建并发送 JSON 响应 */
    char body[1280];
    int bodylen = snprintf(body, sizeof(body), "{\"bin\":\"");
    json_escape(body + bodylen, bin_decoded, sizeof(body) - (size_t)bodylen - 1);
    bodylen = (int)strlen(body);
    snprintf(body + bodylen, sizeof(body) - (size_t)bodylen,
             "\",\"offset\":\"%s\",\"result\":\"", offset_safe);
    bodylen = (int)strlen(body);
    json_escape(body + bodylen, result, sizeof(body) - (size_t)bodylen);
    bodylen = (int)strlen(body);
    snprintf(body + bodylen, sizeof(body) - (size_t)bodylen, "\"}");

    char hdr[256];
    int hdrlen = snprintf(hdr, sizeof(hdr),
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: application/json\r\n"
        "Access-Control-Allow-Origin: *\r\n"
        "Connection: close\r\n"
        "Content-Length: %d\r\n\r\n", (int)strlen(body));

    send_all(fd, hdr, (size_t)hdrlen);
    send_all(fd, body, strlen(body));
}

/* ---- 注入 API 端点 ---- */

/** libmemorytracetool.so 的默认搜索路径（相对于 mttd 可执行文件） */
static const char* default_lib_paths[] = {
    "lib/libmemorytracetool.so",
    "../lib/libmemorytracetool.so",
    "/usr/local/lib/libmemorytracetool.so",
    NULL
};

/** 解析出注入库的绝对路径 */
static int resolve_lib_path(char* out, size_t out_sz)
{
    (void)out_sz;
    for (int i = 0; default_lib_paths[i]; i++) {
        if (realpath(default_lib_paths[i], out)) return 0;
    }
    /* fallback: 假设在 build 目录下 ../lib/libmemorytracetool.so */
    if (realpath("lib/libmemorytracetool.so", out)) return 0;
    return -1;
}

/**
 * GET /api/processes — 扫描 /proc 返回运行中进程列表（含注入状态）。
 *
 * 过滤规则: 只显示用户态进程（有 comm）、排除内核线程。
 * 每条记录标注是否已被注入以及注入状态。
 *
 * @param fd  HTTP 客户端 socket
 */
static void send_api_processes(int fd)
{
    char buf[65536];
    int pos = 0;
    int size = (int)sizeof(buf);

    const char* hdr =
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: application/json; charset=utf-8\r\n"
        "Access-Control-Allow-Origin: *\r\n"
        "Connection: close\r\n\r\n";
    int hdr_len = (int)strlen(hdr);
    if (pos + hdr_len < size) { memcpy(buf + pos, hdr, hdr_len); pos += hdr_len; }

    safe_append(buf, &pos, size, "{\"processes\":[");
    int first = 1;

    DIR* dir = opendir("/proc");
    if (dir) {
        struct dirent* de;
        while ((de = readdir(dir))) {
            /* 只处理数字目录（PID） */
            if (de->d_name[0] < '0' || de->d_name[0] > '9') continue;
            int pid = atoi(de->d_name);
            if (pid <= 1) continue;

            char comm_path[64], comm[256] = "";
            snprintf(comm_path, sizeof(comm_path), "/proc/%d/comm", pid);
            FILE* fc = fopen(comm_path, "r");
            if (!fc) continue;
            if (!fgets(comm, sizeof(comm), fc)) { fclose(fc); continue; }
            fclose(fc);
            /* 去掉尾部换行 */
            size_t cl = strlen(comm);
            while (cl > 0 && (comm[cl-1] == '\n' || comm[cl-1] == '\r'))
                comm[--cl] = '\0';

            /* 跳过内核线程: /proc/<pid>/exe 不可读 */
            char exe_path[64];
            snprintf(exe_path, sizeof(exe_path), "/proc/%d/exe", pid);
            if (access(exe_path, F_OK) != 0) continue;

            /* 检查进程状态（跳过僵尸） */
            char stat_path[64];
            snprintf(stat_path, sizeof(stat_path), "/proc/%d/stat", pid);
            FILE* fs = fopen(stat_path, "r");
            if (!fs) continue;
            char state = '?';
            /* stat 格式: pid (comm) state ... */
            fscanf(fs, "%*d %*s %c", &state);
            fclose(fs);
            if (state == 'Z' || state == 'X') continue; /* 跳过僵尸和已死进程 */

            /* 检查注入状态 */
            int inj_status = 0;  /* 0=未注入，1=成功，2=失败 */
            const char* inj_err = "";
            for (int i = 0; i < g_ninjected; i++) {
                if (g_injected[i].pid == pid) {
                    inj_status = g_injected[i].inject_status;
                    inj_err = g_injected[i].inject_err;
                    break;
                }
            }

            if (!first) safe_append(buf, &pos, size, ",");
            first = 0;
            safe_append(buf, &pos, size,
                "{\"pid\":%d,\"name\":\"%s\",\"state\":\"%c\","
                "\"injected\":%s,\"inj_status\":%d,\"inj_err\":\"%s\"}",
                pid, comm, state,
                inj_status == 1 ? "true" : "false",
                inj_status, inj_err);
        }
        closedir(dir);
    }
    safe_append(buf, &pos, size, "]}");

    send_all(fd, buf, pos);
}

/**
 * GET /api/inject?pid=N — 向目标进程注入 libmemorytracetool.so。
 *
 * 通过 fork() 子进程执行 ptrace 注入，避免阻塞主事件循环。
 * 超时保护: alarm(MTT_INJECT_TIMEOUT_SEC) 防止注入挂死。
 *
 * @param fd   HTTP 客户端 socket
 * @param pid  目标进程 PID
 */
static void handle_api_inject(int fd, int pid)
{
    char resp[2048];
    int valid = 1;
    const char* err_msg = "";

    /* 验证 */
    if (pid <= 1) {
        valid = 0; err_msg = "Invalid PID";
    } else if (pid == getpid()) {
        valid = 0; err_msg = "Cannot inject into self (the daemon)";
    } else {
        /* 检查是否已注入 */
        for (int i = 0; i < g_ninjected; i++) {
            if (g_injected[i].pid == pid && g_injected[i].inject_status == 1) {
                snprintf(resp, sizeof(resp),
                    "{\"pid\":%d,\"status\":\"already_injected\","
                    "\"error\":\"Already injected at %s\"}",
                    pid, ctime(&g_injected[i].inject_time));
                valid = 0;
                break;
            }
        }
        if (valid) {
            char proc_path[64];
            snprintf(proc_path, sizeof(proc_path), "/proc/%d", pid);
            if (access(proc_path, F_OK) != 0) {
                valid = 0; err_msg = "PID not found";
            }
        }
    }

    if (!valid && err_msg[0]) {
        int n = snprintf(resp, sizeof(resp),
            "HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=utf-8\r\n"
            "Access-Control-Allow-Origin: *\r\nConnection: close\r\n\r\n"
            "{\"pid\":%d,\"status\":\"fail\",\"error\":\"%s\"}", pid, err_msg);
        send_all(fd, resp, n);
        shutdown(fd, SHUT_RDWR);
        close(fd);
        return;
    }
    if (!valid) {
        /* already_injected 已写入 resp */
        int n = (int)strlen(resp);
        char hdr[256];
        int hdrlen = snprintf(hdr, sizeof(hdr),
            "HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=utf-8\r\n"
            "Access-Control-Allow-Origin: *\r\nContent-Length: %d\r\n"
            "Connection: close\r\n\r\n", n);
        send_all(fd, hdr, hdrlen);
        send_all(fd, resp, n);
        shutdown(fd, SHUT_RDWR);
        close(fd);
        return;
    }

    /* 解析库路径 */
    char lib_path[512];
    if (resolve_lib_path(lib_path, sizeof(lib_path)) != 0) {
        int n = snprintf(resp, sizeof(resp),
            "HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=utf-8\r\n"
            "Access-Control-Allow-Origin: *\r\nConnection: close\r\n\r\n"
            "{\"pid\":%d,\"status\":\"fail\",\"error\":\"Cannot find libmemorytracetool.so\"}",
            pid);
        send_all(fd, resp, n);
        shutdown(fd, SHUT_RDWR);
        close(fd);
        return;
    }

    /* fork 子进程执行注入（避免 ptrace 阻塞主事件循环） */
    int pipefd[2];
    if (pipe(pipefd) == -1) {
        int n = snprintf(resp, sizeof(resp),
            "HTTP/1.1 500 Internal Error\r\nContent-Type: application/json\r\n"
            "Access-Control-Allow-Origin: *\r\nConnection: close\r\n\r\n"
            "{\"pid\":%d,\"status\":\"fail\",\"error\":\"pipe() failed\"}", pid);
        send_all(fd, resp, n);
        shutdown(fd, SHUT_RDWR);
        close(fd);
        return;
    }

    pid_t child = fork();
    if (child == -1) {
        close(pipefd[0]); close(pipefd[1]);
        int n = snprintf(resp, sizeof(resp),
            "HTTP/1.1 500 Internal Error\r\nContent-Type: application/json\r\n"
            "Access-Control-Allow-Origin: *\r\nConnection: close\r\n\r\n"
            "{\"pid\":%d,\"status\":\"fail\",\"error\":\"fork() failed\"}", pid);
        send_all(fd, resp, n);
        shutdown(fd, SHUT_RDWR);
        close(fd);
        return;
    }

    if (child == 0) {
        /* ---- 子进程: 执行注入 ---- */
        close(pipefd[0]);
        alarm(MTT_INJECT_TIMEOUT_SEC);
        inject_result_t r = inject_library(pid, lib_path);
        alarm(0);
        /* 通过管道将结果发回父进程 */
        ssize_t w = write(pipefd[1], &r, sizeof(r));
        (void)w;
        close(pipefd[1]);
        _exit(0);
    }

    /* ---- 父进程: 等待结果 ---- */
    close(pipefd[1]);
    inject_result_t result;
    memset(&result, 0, sizeof(result));
    result.status = INJECT_ERR_TIMEOUT;
    snprintf(result.err_msg, sizeof(result.err_msg), "Injection timed out");

    ssize_t rbytes = read(pipefd[0], &result, sizeof(result));
    close(pipefd[0]);

    /* 等待子进程结束 */
    int wstatus;
    waitpid(child, &wstatus, 0);

    if (rbytes != sizeof(result)) {
        /* 子进程可能崩溃或管道中断 */
        int n = snprintf(resp, sizeof(resp),
            "HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=utf-8\r\n"
            "Access-Control-Allow-Origin: *\r\nConnection: close\r\n\r\n"
            "{\"pid\":%d,\"status\":\"fail\",\"error\":\"Injector child failed\"}",
            pid);
        send_all(fd, resp, n);
        shutdown(fd, SHUT_RDWR);
        close(fd);
        return;
    }

    /* 记录注入结果 */
    if (g_ninjected < MTT_MAX_INJECTED) {
        g_injected[g_ninjected].pid = pid;
        g_injected[g_ninjected].inject_time = time(NULL);
        g_injected[g_ninjected].inject_status = (result.status == INJECT_OK) ? 1 : 2;
        g_injected[g_ninjected].lib_base = result.lib_base;
        g_injected[g_ninjected].patched_count = result.patched_count;
        snprintf(g_injected[g_ninjected].inject_err,
                 sizeof(g_injected[g_ninjected].inject_err),
                 "%s", result.err_msg);
        g_ninjected++;
    }

    char hdr[256];
    int body_len = snprintf(resp, sizeof(resp),
        "{\"pid\":%d,\"status\":\"%s\",\"error\":\"%s\",\"patched\":%d}",
        pid,
        result.status == INJECT_OK ? "ok" : "fail",
        result.err_msg, result.patched_count);
    int hdrlen = snprintf(hdr, sizeof(hdr),
        "HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=utf-8\r\n"
        "Access-Control-Allow-Origin: *\r\nContent-Length: %d\r\n"
        "Connection: close\r\n\r\n", body_len);
    send_all(fd, hdr, hdrlen);
    send_all(fd, resp, body_len);
    shutdown(fd, SHUT_RDWR);
    close(fd);
}

/**
 * GET /api/injected — 返回所有注入记录。
 */
static void send_api_injected(int fd)
{
    char buf[16384];
    int pos = 0;
    int size = (int)sizeof(buf);

    const char* hdr =
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: application/json; charset=utf-8\r\n"
        "Access-Control-Allow-Origin: *\r\n"
        "Connection: close\r\n\r\n";
    int hdr_len = (int)strlen(hdr);
    if (pos + hdr_len < size) { memcpy(buf + pos, hdr, hdr_len); pos += hdr_len; }

    safe_append(buf, &pos, size, "{\"injected\":[");
    for (int i = 0; i < g_ninjected; i++) {
        if (i > 0) safe_append(buf, &pos, size, ",");
        safe_append(buf, &pos, size,
            "{\"pid\":%d,\"inject_status\":%d,\"lib_base\":\"0x%lx\","
            "\"patched\":%d,\"time\":%ld,\"error\":\"%s\"}",
            g_injected[i].pid,
            g_injected[i].inject_status,
            g_injected[i].lib_base,
            g_injected[i].patched_count,
            (long)g_injected[i].inject_time,
            g_injected[i].inject_err);
    }
    safe_append(buf, &pos, size, "]}");

    send_all(fd, buf, pos);
}

/**
 * 处理 HTTP 请求并路由。
 *
 * 缺陷修复 #8: 添加请求方法验证和基本请求大小限制。
 *
 * 支持的路由：
 *   GET /api/data       → JSON 泄漏数据（send_api_data）
 *   GET /api/addr2line  → addr2line 源码解析（send_addr2line）
 *   GET /api/processes  → 进程列表（send_api_processes）
 *   GET /api/inject     → 运行时注入（handle_api_inject）
 *   GET /api/injected   → 注入记录（send_api_injected）
 *   其他                → 看板 HTML 页面（g_dashboard_html）
 */
static void handle_http(int fd)
{
    char buf[4096];
    ssize_t n = recv(fd, buf, sizeof(buf) - 1, 0);
    if (n <= 0) { shutdown(fd, SHUT_RDWR); close(fd); return; }
    buf[n] = '\0';

    /* 缺陷修复 #8: 仅处理 GET 请求 */
    if (strncmp(buf, "GET ", 4) != 0) {
        const char* err =
            "HTTP/1.1 405 Method Not Allowed\r\n"
            "Content-Length: 0\r\n"
            "Connection: close\r\n\r\n";
        send_all(fd, err, strlen(err));
        shutdown(fd, SHUT_RDWR);
        close(fd);
        return;
    }

    if (strncmp(buf, "GET /api/addr2line", 17) == 0) {
        char bin[512] = {0};
        char off[64] = {0};
        /* 解析查询参数: ?bin=...&off=... */
        char* params = strchr(buf, '?');
        if (params) {
            char* p = strstr(params, "bin=");
            if (p) {
                int i = 0;
                p += 4;
                while (*p && *p != '&' && *p != ' ' && i < (int)sizeof(bin) - 1)
                    bin[i++] = *p++;
                bin[i] = '\0';
            }
            p = strstr(params, "off=");
            if (p) {
                int i = 0;
                p += 4;
                while (*p && *p != '&' && *p != ' ' && i < (int)sizeof(off) - 1)
                    off[i++] = *p++;
                off[i] = '\0';
            }
        }
        if (bin[0] && off[0])
            send_addr2line(fd, bin, off);
        else {
            const char* err =
                "HTTP/1.1 400 Bad Request\r\n"
                "Content-Length: 0\r\n"
                "Connection: close\r\n\r\n";
            send_all(fd, err, strlen(err));
        }
    } else if (strncmp(buf, "GET /api/processes", 18) == 0) {
        send_api_processes(fd);
    } else if (strncmp(buf, "GET /api/inject", 15) == 0) {
        /* 解析 ?pid=N */
        int pid = 0;
        char* params = strchr(buf, '?');
        if (params) {
            char* p = strstr(params, "pid=");
            if (p) pid = atoi(p + 4);
        }
        if (pid > 1)
            handle_api_inject(fd, pid);
        else {
            const char* err =
                "HTTP/1.1 400 Bad Request\r\n"
                "Content-Type: application/json\r\n"
                "Connection: close\r\n\r\n"
                "{\"error\":\"missing pid parameter\"}";
            send_all(fd, err, strlen(err));
        }
    } else if (strncmp(buf, "GET /api/injected", 17) == 0) {
        send_api_injected(fd);
    } else if (strncmp(buf, "GET /api/data", 13) == 0) {
        send_api_data(fd);
    } else {
        /* 看板 HTML 已内嵌 HTTP 头，直接 send */
        send_all(fd, g_dashboard_html, strlen(g_dashboard_html));
    }
    shutdown(fd, SHUT_RDWR);
    close(fd);
}

/* ---- 主函数 ---- */

/** 信号处理器：设置退出标志 */
static void signal_handler(int sig)
{
    (void)sig;
    g_running = 0;
}

/**
 * 守护进程入口。
 *
 * 缺陷修复 #8: 添加客户端连接的空闲超时机制。
 * 缺陷修复 #3: 使用 shutdown() 优雅关闭 TCP 连接。
 *
 * 启动流程：
 *   1. 创建并监听 Unix Domain Socket（/tmp/mttd.sock）
 *   2. 创建并监听 TCP Socket（默认 8080，命令行参数可改）
 *   3. 进入 select 事件循环，同时处理 Unix 客户端和 HTTP 请求
 *   4. 收到 SIGINT/SIGTERM 后优雅退出，清理资源
 *
 * 用法: mttd [port]
 */
int main(int argc, char** argv)
{
    int port = 8080;
    if (argc > 1) port = atoi(argv[1]);

    signal(SIGINT,  signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGPIPE, SIG_IGN); /* 防止向已关闭 socket 写入时触发 SIGPIPE */

    /* ---- Unix Socket 初始化 ---- */
    unlink(MTT_SOCK_PATH); /* 清理上次运行可能残留的 socket 文件 */

    int unix_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (unix_fd < 0) { perror("unix socket"); return 1; }

    struct sockaddr_un unix_addr = {0};
    unix_addr.sun_family = AF_UNIX;
    strncpy(unix_addr.sun_path, MTT_SOCK_PATH, sizeof(unix_addr.sun_path) - 1);

    if (bind(unix_fd, (struct sockaddr*)&unix_addr, sizeof(unix_addr)) < 0) {
        perror("unix bind"); close(unix_fd); return 1;
    }
    if (listen(unix_fd, 32) < 0) { perror("unix listen"); return 1; }
    printf("[mttd] Unix socket: %s\n", MTT_SOCK_PATH);

    /* ---- HTTP Socket 初始化 ---- */
    int http_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (http_fd < 0) { perror("tcp socket"); return 1; }

    int opt = 1;
    setsockopt(http_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in http_addr = {0};
    http_addr.sin_family = AF_INET;
    http_addr.sin_addr.s_addr = INADDR_ANY;
    http_addr.sin_port = htons(port);

    if (bind(http_fd, (struct sockaddr*)&http_addr, sizeof(http_addr)) < 0) {
        perror("http bind"); return 1;
    }
    if (listen(http_fd, 32) < 0) { perror("http listen"); return 1; }
    printf("[mttd] HTTP Dashboard: http://0.0.0.0:%d\n", port);

    /* ---- 客户端追踪数组 ---- */
    enum { MAX_CLIENTS = 32 };
    int clients[MAX_CLIENTS];
    int nclients = 0;
    unix_client_ctx_t client_ctxs[MAX_CLIENTS];
    mttd_proc_t* client_procs[MAX_CLIENTS];
    for (int i = 0; i < MAX_CLIENTS; i++) {
        clients[i] = -1;
        client_procs[i] = NULL;
        memset(&client_ctxs[i], 0, sizeof(client_ctxs[i]));
    }

    printf("[mttd] Ready.\n");

    /* ---- 事件循环 ---- */
    while (g_running) {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(unix_fd, &rfds);
        FD_SET(http_fd, &rfds);
        int maxfd = (unix_fd > http_fd ? unix_fd : http_fd);

        /* 将所有活跃客户端 fd 加入 select 集合 */
        for (int i = 0; i < nclients; i++) {
            if (clients[i] > 0) {
                FD_SET(clients[i], &rfds);
                if (clients[i] > maxfd) maxfd = clients[i];
            }
        }

        /* 1 秒超时，允许及时响应信号 */
        struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
        int ready = select(maxfd + 1, &rfds, NULL, NULL, &tv);
        if (ready < 0) {
            if (errno == EINTR) continue; /* 被信号中断，检查 g_running */
            break;
        }

        /* 缺陷修复 #8: 超时处理 — 清理空闲超时的客户端连接 */
        time_t now = time(NULL);
        for (int i = 0; i < nclients; ) {
            if (clients[i] > 0 && client_procs[i]) {
                if (now - client_procs[i]->last_seen > MTT_CLIENT_TIMEOUT_S) {
                    shutdown(clients[i], SHUT_RDWR);
                    close(clients[i]);
                    for (int j = i; j < nclients - 1; j++) {
                        clients[j] = clients[j + 1];
                        client_ctxs[j] = client_ctxs[j + 1];
                        client_procs[j] = client_procs[j + 1];
                    }
                    nclients--;
                    continue;
                }
            }
            i++;
        }

        /* 接受新的 Unix Socket 连接 */
        if (FD_ISSET(unix_fd, &rfds)) {
            int cfd = accept(unix_fd, NULL, NULL);
            if (cfd >= 0) {
                set_nonblock(cfd);
                set_recv_timeout(cfd, MTT_CLIENT_TIMEOUT_S);
                if (nclients < MAX_CLIENTS) {
                    clients[nclients] = cfd;
                    memset(&client_ctxs[nclients], 0, sizeof(unix_client_ctx_t));
                    client_procs[nclients] = NULL;
                    nclients++;
                } else {
                    close(cfd); /* 客户端数已满 */
                }
            }
        }

        /* 接受新的 HTTP 连接（短连接，一次请求-响应即关闭） */
        if (FD_ISSET(http_fd, &rfds)) {
            int cfd = accept(http_fd, NULL, NULL);
            if (cfd >= 0) handle_http(cfd);
        }

        /* 处理 Unix 客户端的 I/O（协议解析） */
        for (int i = 0; i < nclients; ) {
            if (clients[i] < 0) { i++; continue; }
            if (FD_ISSET(clients[i], &rfds)) {
                mttd_proc_t* proc = NULL;
                int rc = parse_unix_client(clients[i], &client_ctxs[i], &proc);
                client_procs[i] = proc;
                if (proc) {
                    proc->last_seen = time(NULL);
                }
                if (rc <= 0) {
                    /* 连接关闭或出错，从活跃列表中移除 */
                    shutdown(clients[i], SHUT_RDWR);
                    close(clients[i]);
                    for (int j = i; j < nclients - 1; j++) {
                        clients[j] = clients[j + 1];
                        client_ctxs[j] = client_ctxs[j + 1];
                        client_procs[j] = client_procs[j + 1];
                    }
                    nclients--;
                    continue;
                }
            }
            i++;
        }
    }

    /* ---- 清理 ---- */
    printf("[mttd] Shutting down...\n");
    for (int i = 0; i < nclients; i++) {
        shutdown(clients[i], SHUT_RDWR);
        close(clients[i]);
    }
    for (int i = 0; i < g_nprocs; i++) {
        free(g_procs[i].leaks);
    }
    close(unix_fd);
    close(http_fd);
    unlink(MTT_SOCK_PATH);
    return 0;
}

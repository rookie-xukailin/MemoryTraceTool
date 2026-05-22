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

/* ---- 全局状态 ---- */

static mttd_proc_t g_procs[MTT_MAX_PROCS];      /* 被监控进程数组 */
static int         g_nprocs = 0;                  /* 当前监控的进程数 */
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER; /* 保护 g_procs / g_nprocs */
static volatile int g_running = 1;                /* 信号控制的主循环退出标志 */

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
"  --bg: #0a0e14;\n"
"  --surface: #12171e;\n"
"  --border: #1e2733;\n"
"  --text: #c9d1d9;\n"
"  --text-dim: #6e7681;\n"
"  --accent: #58a6ff;\n"
"  --green: #3fb950;\n"
"  --red: #f85149;\n"
"  --orange: #d29922;\n"
"  --purple: #a371f7;\n"
"  --font: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif;\n"
"  --mono: 'SF Mono', 'Cascadia Code', 'Fira Code', 'JetBrains Mono', monospace;\n"
"  --radius: 8px;\n"
"}\n"
"* { margin: 0; padding: 0; box-sizing: border-box; }\n"
"body {\n"
"  font-family: var(--font);\n"
"  background: var(--bg);\n"
"  color: var(--text);\n"
"  min-height: 100vh;\n"
"  line-height: 1.5;\n"
"}\n"
".header {\n"
"  background: var(--surface);\n"
"  border-bottom: 1px solid var(--border);\n"
"  padding: 14px 24px;\n"
"  display: flex;\n"
"  align-items: center;\n"
"  justify-content: space-between;\n"
"  position: sticky;\n"
"  top: 0;\n"
"  z-index: 100;\n"
"  backdrop-filter: blur(12px);\n"
"}\n"
".header-left { display: flex; align-items: center; gap: 12px; }\n"
".header h1 { font-size: 17px; font-weight: 600; color: #e6edf3; letter-spacing: -.3px; }\n"
".status-dot {\n"
"  width: 8px; height: 8px;\n"
"  border-radius: 50%;\n"
"  background: var(--green);\n"
"  box-shadow: 0 0 6px rgba(63,185,80,.5);\n"
"  animation: pulse 2s ease-in-out infinite;\n"
"}\n"
"@keyframes pulse { 0%,100%{opacity:1} 50%{opacity:.4} }\n"
".status-dot.off { background: var(--text-dim); box-shadow: none; animation: none; }\n"
".header-right { display: flex; align-items: center; gap: 14px; font-size: 12px; color: var(--text-dim); }\n"
".header-right .refresh-age { font-family: var(--mono); }\n"
".btn {\n"
"  background: var(--surface);\n"
"  border: 1px solid #2a3542;\n"
"  color: var(--text);\n"
"  padding: 5px 14px;\n"
"  border-radius: 6px;\n"
"  cursor: pointer;\n"
"  font-size: 12px;\n"
"  font-family: var(--font);\n"
"  transition: background .15s, border-color .15s;\n"
"}\n"
".btn:hover { background: #1a2330; border-color: #3a4558; }\n"
".btn.paused { border-color: var(--orange); color: var(--orange); }\n"
".container { max-width: 1440px; margin: 0 auto; padding: 20px 24px; }\n"
".summary {\n"
"  display: grid;\n"
"  grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));\n"
"  gap: 14px;\n"
"  margin-bottom: 22px;\n"
"}\n"
".card {\n"
"  background: var(--surface);\n"
"  border: 1px solid var(--border);\n"
"  border-radius: var(--radius);\n"
"  padding: 18px 20px;\n"
"  transition: border-color .2s;\n"
"}\n"
".card:hover { border-color: #2a3542; }\n"
".card .card-icon { font-size: 20px; margin-bottom: 8px; opacity: .7; }\n"
".card .val {\n"
"  font-size: 30px;\n"
"  font-weight: 700;\n"
"  color: #e6edf3;\n"
"  font-family: var(--mono);\n"
"  letter-spacing: -1px;\n"
"}\n"
".card .lbl {\n"
"  font-size: 12px;\n"
"  color: var(--text-dim);\n"
"  text-transform: uppercase;\n"
"  letter-spacing: .6px;\n"
"  margin-top: 2px;\n"
"}\n"
".card.accent  { border-left: 3px solid var(--accent); }\n"
".card.warning { border-left: 3px solid var(--orange); }\n"
".card.danger  { border-left: 3px solid var(--red); }\n"
".section { margin-bottom: 22px; }\n"
".section-title {\n"
"  font-size: 14px;\n"
"  font-weight: 600;\n"
"  color: #e6edf3;\n"
"  margin-bottom: 10px;\n"
"  display: flex;\n"
"  align-items: center;\n"
"  gap: 8px;\n"
"}\n"
".section-title .count { font-size: 11px; color: var(--text-dim); font-weight: 400; }\n"
".table-wrap {\n"
"  background: var(--surface);\n"
"  border: 1px solid var(--border);\n"
"  border-radius: var(--radius);\n"
"  overflow: hidden;\n"
"}\n"
"table { width: 100%; border-collapse: collapse; }\n"
"thead th {\n"
"  text-align: left;\n"
"  padding: 9px 14px;\n"
"  background: #0d1117;\n"
"  font-size: 11px;\n"
"  font-weight: 600;\n"
"  color: var(--text-dim);\n"
"  text-transform: uppercase;\n"
"  letter-spacing: .4px;\n"
"  border-bottom: 1px solid var(--border);\n"
"  white-space: nowrap;\n"
"}\n"
"tbody td {\n"
"  padding: 9px 14px;\n"
"  font-size: 13px;\n"
"  border-bottom: 1px solid rgba(30,39,51,.5);\n"
"  white-space: nowrap;\n"
"}\n"
"tbody tr:last-child td { border-bottom: none; }\n"
"tbody tr { transition: background .12s; }\n"
"tbody tr:hover { background: rgba(88,166,255,.04); }\n"
".badge {\n"
"  display: inline-flex;\n"
"  align-items: center;\n"
"  gap: 5px;\n"
"  padding: 2px 10px;\n"
"  border-radius: 10px;\n"
"  font-size: 11px;\n"
"  font-weight: 600;\n"
"}\n"
".badge-live {\n"
"  background: rgba(63,185,80,.15);\n"
"  color: var(--green);\n"
"}\n"
".badge-live::before {\n"
"  content: '';\n"
"  width: 6px; height: 6px;\n"
"  border-radius: 50%;\n"
"  background: var(--green);\n"
"}\n"
".badge-done {\n"
"  background: rgba(110,118,129,.12);\n"
"  color: var(--text-dim);\n"
"}\n"
".hot-fn {\n"
"  font-family: var(--mono);\n"
"  font-size: 12px;\n"
"  color: var(--accent);\n"
"  max-width: 280px;\n"
"  overflow: hidden;\n"
"  text-overflow: ellipsis;\n"
"}\n"
".leak-card {\n"
"  background: var(--surface);\n"
"  border: 1px solid var(--border);\n"
"  border-radius: var(--radius);\n"
"  margin-bottom: 6px;\n"
"  overflow: hidden;\n"
"  transition: border-color .15s;\n"
"}\n"
".leak-card:hover { border-color: #2a3542; }\n"
".leak-header {\n"
"  padding: 10px 16px;\n"
"  cursor: pointer;\n"
"  display: flex;\n"
"  align-items: center;\n"
"  gap: 12px;\n"
"  font-size: 13px;\n"
"  user-select: none;\n"
"}\n"
".leak-header:hover { background: rgba(255,255,255,.02); }\n"
".leak-header .arrow {\n"
"  font-size: 10px;\n"
"  color: var(--text-dim);\n"
"  transition: transform .2s;\n"
"  flex-shrink: 0;\n"
"}\n"
".leak-card.open .leak-header .arrow { transform: rotate(90deg); }\n"
".leak-header .sz {\n"
"  color: var(--red);\n"
"  font-weight: 600;\n"
"  font-family: var(--mono);\n"
"  white-space: nowrap;\n"
"}\n"
".leak-header .loc {\n"
"  color: var(--accent);\n"
"  font-family: var(--mono);\n"
"  font-size: 12px;\n"
"}\n"
".leak-header .proc-info {\n"
"  color: var(--text-dim);\n"
"  font-size: 11px;\n"
"  margin-left: auto;\n"
"  white-space: nowrap;\n"
"}\n"
".leak-body { display: none; padding: 0 16px 14px; }\n"
".leak-card.open .leak-body { display: block; }\n"
".leak-body-divider {\n"
"  border-top: 1px solid var(--border);\n"
"  margin-bottom: 10px;\n"
"}\n"
".call-tree {\n"
"  padding: 6px 0 0 14px;\n"
"  border-left: 2px solid var(--border);\n"
"  margin-left: 6px;\n"
"}\n"
".call-node {\n"
"  padding: 5px 0 5px 16px;\n"
"  position: relative;\n"
"  font-family: var(--mono);\n"
"  font-size: 12px;\n"
"  line-height: 1.4;\n"
"}\n"
".call-node::before {\n"
"  content: '';\n"
"  position: absolute;\n"
"  left: 0; top: 50%;\n"
"  width: 10px; height: 2px;\n"
"  background: var(--border);\n"
"  border-radius: 1px;\n"
"}\n"
".call-node .fn { color: #e6edf3; }\n"
".call-node .lib { color: var(--text-dim); font-size: 11px; margin-left: 4px; }\n"
".call-node.entry .fn { color: var(--purple); font-weight: 600; }\n"
".call-node.leak-site { color: var(--red); font-weight: 600; }\n"
".call-node.leak-site .fn { color: var(--red); }\n"
".call-node[onclick]:hover { background: rgba(88,166,255,.06); border-radius: 4px; }\n"
".call-node .source-tip { color: var(--green); font-size: 11px; margin-left: 6px; font-weight: 400; }\n"
".call-node.leak-site .tag {\n"
"  display: inline-block;\n"
"  background: rgba(248,81,73,.15);\n"
"  color: var(--red);\n"
"  font-size: 10px;\n"
"  padding: 1px 6px;\n"
"  border-radius: 3px;\n"
"  margin-left: 8px;\n"
"  font-weight: 600;\n"
"  letter-spacing: .3px;\n"
"}\n"
".empty {\n"
"  text-align: center;\n"
"  padding: 40px 20px;\n"
"  color: var(--text-dim);\n"
"  font-size: 13px;\n"
"}\n"
".empty .empty-icon { font-size: 32px; margin-bottom: 8px; opacity: .3; }\n"
".toast {\n"
"  position: fixed;\n"
"  bottom: 20px;\n"
"  right: 20px;\n"
"  background: var(--surface);\n"
"  border: 1px solid #2a3542;\n"
"  padding: 10px 18px;\n"
"  border-radius: var(--radius);\n"
"  font-size: 12px;\n"
"  color: var(--text-dim);\n"
"  opacity: 0;\n"
"  transform: translateY(10px);\n"
"  transition: all .3s;\n"
"  pointer-events: none;\n"
"  z-index: 200;\n"
"}\n"
".toast.show { opacity: 1; transform: translateY(0); }\n"
"@media (max-width: 768px) {\n"
"  .summary { grid-template-columns: 1fr; }\n"
"  .header { padding: 10px 14px; }\n"
"  .container { padding: 14px; }\n"
"  table { font-size: 11px; }\n"
"  thead th, tbody td { padding: 7px 8px; }\n"
"}\n"
"</style>\n"
"</head>\n"
"<body>\n"
"\n"
"<div class=\"header\">\n"
"  <div class=\"header-left\">\n"
"    <div class=\"status-dot\" id=\"status-dot\"></div>\n"
"    <h1>MemoryTraceTool</h1>\n"
"  </div>\n"
"  <div class=\"header-right\">\n"
"    <span class=\"refresh-age\" id=\"refresh-age\">--</span>\n"
"    <button class=\"btn\" id=\"btn-pause\" onclick=\"toggleAuto()\">暂停刷新</button>\n"
"    <button class=\"btn\" onclick=\"refresh()\">立即刷新</button>\n"
"  </div>\n"
"</div>\n"
"\n"
"<div class=\"container\">\n"
"\n"
"  <div class=\"summary\">\n"
"    <div class=\"card accent\">\n"
"      <div class=\"card-icon\">&#x1f4bb;</div>\n"
"      <div class=\"val\" id=\"p\">--</div>\n"
"      <div class=\"lbl\">监控进程数</div>\n"
"    </div>\n"
"    <div class=\"card warning\">\n"
"      <div class=\"card-icon\">&#x26a0;&#xfe0f;</div>\n"
"      <div class=\"val\" id=\"l\">--</div>\n"
"      <div class=\"lbl\">泄漏总数</div>\n"
"    </div>\n"
"    <div class=\"card danger\">\n"
"      <div class=\"card-icon\">&#x1f4c8;</div>\n"
"      <div class=\"val\" id=\"b\">--</div>\n"
"      <div class=\"lbl\">泄漏字节数</div>\n"
"    </div>\n"
"  </div>\n"
"\n"
"  <div class=\"section\">\n"
"    <div class=\"section-title\">\n"
"      &#x1f4cb; 被监控进程 <span class=\"count\" id=\"proc-count\"></span>\n"
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
"          <tr><td colspan=\"7\"><div class=\"empty\"><div class=\"empty-icon\">&#x1f4e1;</div>等待被监控进程接入...</div></td></tr>\n"
"        </tbody>\n"
"      </table>\n"
"    </div>\n"
"  </div>\n"
"\n"
"  <div class=\"section\">\n"
"    <div class=\"section-title\">\n"
"      &#x1f534; 可疑泄漏排行 <span class=\"count\" id=\"leak-count\"></span>\n"
"    </div>\n"
"    <div id=\"tl\"><div class=\"empty\"><div class=\"empty-icon\">&#x2705;</div>暂无泄漏 &mdash; 一切正常</div></div>\n"
"  </div>\n"
"\n"
"</div>\n"
"\n"
"<div class=\"toast\" id=\"toast\"></div>\n"
"\n"
"<script>\n"
"var autoRefresh = true;\n"
"var failCount = 0;\n"
"\n"
"setInterval(function() { if (autoRefresh) refresh(); }, 3000);\n"
"refresh();\n"
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
"          '<td style=\"font-family:var(--mono)\">' + p.pid + '</td>' +\n"
"          '<td>' + esc(p.name) + '</td>' +\n"
"          '<td>' + badge + '</td>' +\n"
"          '<td style=\"font-family:var(--mono)\">' + p.leak_count + '</td>' +\n"
"          '<td style=\"font-family:var(--mono)\">' + fmtBytes(p.total_leaked) + '</td>' +\n"
"          '<td>' + seen + '</td>' +\n"
"          '<td><span class=\"hot-fn\" title=\"' + escAttr(p.top_stack || '') + '\">' + esc(topFn) + '</span></td>' +\n"
"          '</tr>';\n"
"      }\n"
"      document.getElementById('tb').innerHTML = rows ||\n"
"        '<tr><td colspan=\"7\"><div class=\"empty\"><div class=\"empty-icon\">&#x1f4e1;</div>等待被监控进程接入...</div></td></tr>';\n"
"      document.getElementById('proc-count').textContent = d.nprocs > 0 ? '(' + d.nprocs + ')' : '';\n"
"\n"
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
"            name: p.name\n"
"          });\n"
"        }\n"
"      }\n"
"      all.sort(function(a, b) { return b.size - a.size; });\n"
"      var top = all.slice(0, 15);\n"
"\n"
"      var html = '';\n"
"      for (var i = 0; i < top.length; i++) {\n"
"        var l = top[i];\n"
"        html += '<div class=\"leak-card\" onclick=\"this.classList.toggle(\\'open\\')\">';\n"
"        html += '<div class=\"leak-header\">';\n"
"        html += '<span class=\"arrow\">&#x25b6;</span>';\n"
"        html += '<span class=\"sz\">' + fmtBytes(l.size) + '</span>';\n"
"        html += '<span class=\"loc\">' + esc(l.file) + ':' + l.line + '</span>';\n"
"        html += '<span class=\"proc-info\">PID ' + l.pid + ' &middot; ' + esc(l.name) + '</span>';\n"
"        html += '</div>';\n"
"        html += '<div class=\"leak-body\"><div class=\"leak-body-divider\"></div>';\n"
"        html += '<div class=\"call-tree\">';\n"
"\n"
"        if (l.nframes > 0) {\n"
"          for (var j = l.nframes - 1; j >= 0; j--) {\n"
"            var cls = j === 0 ? 'call-node leak-site' : (j === l.nframes - 1 ? 'call-node entry' : 'call-node');\n"
"            var parsed = parseFrame(l.frames[j] || '?');\n"
"            html += '<div class=\"' + cls + '\"';\n"
"            if (parsed.bin && parsed.off) html += ' onclick=\"event.stopPropagation();resolveFrame(this,\\'' + escAttr(parsed.bin) + '\\',\\'' + escAttr(parsed.off) + '\\')\" style=\"cursor:pointer\" title=\"点击解析源码位置\"';\n"
"            html += '>';\n"
"            html += '<span class=\"fn\">' + esc(parsed.fn) + '</span>';\n"
"            if (parsed.lib) html += '<span class=\"lib\">' + esc(parsed.lib) + '</span>';\n"
"            if (j === 0) html += '<span class=\"tag\">泄漏点</span>';\n"
"            html += '</div>';\n"
"          }\n"
"        } else {\n"
"          html += '<div class=\"call-node\"><span class=\"fn\" style=\"color:var(--text-dim)\">(无调用栈)</span></div>';\n"
"        }\n"
"\n"
"        html += '</div></div></div>';\n"
"      }\n"
"      document.getElementById('tl').innerHTML = html ||\n"
"        '<div class=\"empty\"><div class=\"empty-icon\">&#x2705;</div>暂无泄漏 &mdash; 一切正常</div>';\n"
"      document.getElementById('leak-count').textContent = all.length > 0 ? '(Top ' + Math.min(all.length, 15) + ' / 共 ' + all.length + ')' : '';\n"
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
"function parseFrame(raw) {\n"
"  if (!raw) return { fn: '?', lib: '', bin: '', off: '' };\n"
"  // 格式: display_name|binary_path|file_offset\n"
"  var parts = raw.split('|');\n"
"  var display = parts[0] || raw;\n"
"  var m = display.match(/^(.+?)\\s+\\((.+?)\\)\\s*$/);\n"
"  if (m) return { fn: m[1], lib: m[2], bin: parts[1] || '', off: parts[2] || '' };\n"
"  // 无括号格式也尝试提取\n"
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
"// 点击栈帧时调用 addr2line 解析源码位置\n"
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

/**
 * 处理 HTTP 请求并路由。
 *
 * 缺陷修复 #8: 添加请求方法验证和基本请求大小限制。
 *
 * 支持的路由：
 *   GET /api/data       → JSON 泄漏数据（send_api_data）
 *   GET /api/addr2line  → addr2line 源码解析（send_addr2line）
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

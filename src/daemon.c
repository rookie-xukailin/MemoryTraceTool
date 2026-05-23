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
#include <sys/stat.h>
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

static void persist_proc(mttd_proc_t* p);

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
    persist_proc(p);
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

/* ---- 持久化与存活检测 ---- */

/** 获取持久化日志目录（优先 /var/log/mtt，fallback /tmp/mtt-logs） */
static const char* get_log_dir(void)
{
    static char dir[256] = {0};
    if (dir[0]) return dir;

    const char* primary = MTT_LOG_DIR;
    if (mkdir(primary, 0755) == 0 || access(primary, W_OK) == 0) {
        snprintf(dir, sizeof(dir), "%s", primary);
        return dir;
    }
    /* fallback */
    const char* fb = "/tmp/mtt-logs";
    mkdir(fb, 0755);
    snprintf(dir, sizeof(dir), "%s", fb);
    return dir;
}

/** 将进程泄漏数据序列化为 JSON 并写入持久化文件 */
static void persist_proc(mttd_proc_t* p)
{
    const char* logdir = get_log_dir();
    char path[512];
    snprintf(path, sizeof(path), "%s/%d.json", logdir, p->pid);

    FILE* f = fopen(path, "w");
    if (!f) return;

    fprintf(f, "{\"pid\":%d,\"name\":\"%s\",\"active\":%d,\"total_leaked\":%zu,"
            "\"last_seen\":%ld,\"leaks\":[",
            p->pid, p->name, p->active, p->total_leaked, (long)p->last_seen);

    for (int i = 0; i < p->leak_count; i++) {
        mttd_leak_t* l = &p->leaks[i];
        fprintf(f, "%s{\"size\":%zu,\"file\":\"%s\",\"line\":%d,\"nframes\":%d,\"frames\":[",
                i > 0 ? "," : "", l->size, l->file, l->line, l->nframes);
        for (int j = 0; j < l->nframes; j++) {
            fprintf(f, "%s\"", j > 0 ? "," : "");
            /* 转义 JSON 特殊字符 */
            for (char* s = l->frames[j]; *s; s++) {
                if (*s == '"' || *s == '\\') fputc('\\', f);
                fputc(*s, f);
            }
            fputc('"', f);
        }
        fprintf(f, "]}");
    }
    fprintf(f, "]}\n");
    fclose(f);
}

/** 启动时从持久化目录加载历史记录 */
static void load_persisted(void)
{
    const char* logdir = get_log_dir();
    DIR* d = opendir(logdir);
    if (!d) return;

    struct dirent* de;
    while ((de = readdir(d))) {
        if (de->d_name[0] == '.') continue;
        char path[512];
        snprintf(path, sizeof(path), "%s/%s", logdir, de->d_name);
        FILE* f = fopen(path, "r");
        if (!f) continue;

        fseek(f, 0, SEEK_END);
        long sz = ftell(f);
        fseek(f, 0, SEEK_SET);
        if (sz <= 0 || sz > 1048576) { fclose(f); continue; } /* 跳过空文件或 >1MB */

        char* json = malloc((size_t)sz + 1);
        if (!json) { fclose(f); continue; }
        size_t nread = fread(json, 1, (size_t)sz, f);
        fclose(f);
        if (nread <= 0) { free(json); continue; }
        json[nread] = '\0';

        /* 简易 JSON 解析：提取 pid/name/active */
        int pid = 0;
        char name[256] = {0};
        char* pp = json;
        char* pidp = strstr(pp, "\"pid\":");
        if (pidp) pid = atoi(pidp + 6);
        char* namep = strstr(pp, "\"name\":\"");
        if (namep) {
            namep += 8;
            int ni = 0;
            while (*namep && *namep != '"' && ni < 254) name[ni++] = *namep++;
            name[ni] = '\0';
        }
        char* actp = strstr(pp, "\"active\":");
        int persisted_active = actp ? atoi(actp + 9) : 1;

        free(json);

        if (pid <= 1) continue;

        /* 检查是否已有此 PID 的记录 */
        int exists = 0;
        for (int i = 0; i < g_nprocs; i++) {
            if (g_procs[i].pid == pid) { exists = 1; break; }
        }
        if (exists) continue;

        /* 创建记录（标记为非活跃，等待 HELLO 恢复） */
        if (g_nprocs < MTT_MAX_PROCS) {
            mttd_proc_t* p = &g_procs[g_nprocs++];
            memset(p, 0, sizeof(*p));
            p->pid = pid;
            snprintf(p->name, sizeof(p->name), "%s", name[0] ? name : "?");
            p->active = persisted_active; /* 使用持久化的状态 */
            p->last_seen = time(NULL);
            p->leak_cap = 32;
            p->leaks = malloc(p->leak_cap * sizeof(mttd_leak_t));
            pthread_mutex_init(&p->lock, NULL);
            printf("[mttd] 已加载历史记录: PID %d (%s)\n", pid, name);
        }
    }
    closedir(d);
}

/** 检查已监控进程是否仍然存活 */
static void check_liveness(void)
{
    for (int i = 0; i < g_nprocs; i++) {
        if (!g_procs[i].active) continue;
        char proc_path[64];
        snprintf(proc_path, sizeof(proc_path), "/proc/%d", g_procs[i].pid);
        if (access(proc_path, F_OK) != 0) {
            pthread_mutex_lock(&g_procs[i].lock);
            g_procs[i].active = 0;
            pthread_mutex_unlock(&g_procs[i].lock);
            persist_proc(&g_procs[i]);
        }
    }
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
"<title>MemoryTraceTool</title>\n"
"<style>\n"
":root {\n"
"  --bg: #0b0c0e;\n"
"  --bg-panel: #1e1f25;\n"
"  --bg-input: #18191d;\n"
"  --bg-hover: rgba(255,255,255,0.03);\n"
"  --border: rgba(255,255,255,0.06);\n"
"  --text: #d8d9da;\n"
"  --text-secondary: #8e8e8e;\n"
"  --accent: #3274d9;\n"
"  --green: #3eb579;\n"
"  --green-bg: rgba(62,181,121,0.12);\n"
"  --red: #e02f44;\n"
"  --red-bg: rgba(224,47,68,0.1);\n"
"  --orange: #e0b400;\n"
"  --orange-bg: rgba(224,180,0,0.12);\n"
"  --purple: #9f6bff;\n"
"  --radius: 6px;\n"
"  --font: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Noto Sans', 'Helvetica Neue', Arial, sans-serif;\n"
"  --mono: 'JetBrains Mono', 'Cascadia Code', 'Fira Code', 'SF Mono', ui-monospace, monospace;\n"
"}\n"
"*{margin:0;padding:0;box-sizing:border-box}\n"
"body{\n"
"  font-family:var(--font);\n"
"  font-size:13px;\n"
"  background:var(--bg);\n"
"  color:var(--text);\n"
"  min-height:100vh;\n"
"  display:flex;\n"
"  -webkit-font-smoothing:antialiased;\n"
"}\n"
"a{color:var(--accent);text-decoration:none}\n"
"\n"
"/* ======== SIDEBAR ======== */\n"
".sidebar{\n"
"  width:220px; min-width:220px;\n"
"  background:var(--bg-panel);\n"
"  border-right:1px solid var(--border);\n"
"  display:flex; flex-direction:column;\n"
"  position:sticky; top:0; height:100vh;\n"
"  z-index:100;\n"
"  transition:width .2s, min-width .2s;\n"
"}\n"
".sidebar.collapsed{width:56px;min-width:56px}\n"
".sidebar-brand{\n"
"  padding:16px 18px;\n"
"  display:flex; align-items:center; gap:10px;\n"
"  font-size:14px; font-weight:700;\n"
"  border-bottom:1px solid var(--border);\n"
"  letter-spacing:-.3px;\n"
"}\n"
".sidebar-brand .dot{\n"
"  width:10px; height:10px; border-radius:50%;\n"
"  background:var(--green);\n"
"  box-shadow:0 0 8px rgba(62,181,121,0.5);\n"
"  flex-shrink:0;\n"
"}\n"
".sidebar-brand .dot.off{background:#555;box-shadow:none}\n"
".sidebar.collapsed .brand-text{display:none}\n"
".sidebar.collapsed .sidebar-brand{gap:0;padding:16px 14px;justify-content:center}\n"
"\n"
".sidebar-nav{flex:1;padding:10px 0;display:flex;flex-direction:column;gap:2px}\n"
".nav-item{\n"
"  display:flex;align-items:center;gap:10px;\n"
"  padding:8px 18px;font-size:13px;color:var(--text-secondary);\n"
"  cursor:pointer;transition:all .15s;\n"
"  border-left:2px solid transparent;\n"
"  user-select:none;white-space:nowrap;\n"
"}\n"
".nav-item:hover{color:var(--text);background:var(--bg-hover)}\n"
".nav-item.active{color:var(--text);background:var(--bg-hover);border-left-color:var(--accent)}\n"
".nav-item svg{flex-shrink:0;opacity:.6}\n"
".nav-item.active svg,.nav-item:hover svg{opacity:1}\n"
".sidebar.collapsed .nav-item{padding:8px 14px;justify-content:center;gap:0}\n"
".sidebar.collapsed .nav-label{display:none}\n"
"\n"
".sidebar-toggle{\n"
"  padding:12px 18px;border-top:1px solid var(--border);\n"
"  font-size:12px;color:var(--text-secondary);cursor:pointer;\n"
"  transition:color .15s;user-select:none;text-align:center;\n"
"}\n"
".sidebar-toggle:hover{color:var(--text)}\n"
".sidebar.collapsed .sidebar-toggle{padding:12px 10px}\n"
"\n"
"/* ======== MAIN ======== */\n"
".main{flex:1;display:flex;flex-direction:column;min-width:0}\n"
".topbar{\n"
"  padding:12px 24px;\n"
"  background:var(--bg-panel);\n"
"  border-bottom:1px solid var(--border);\n"
"  display:flex;align-items:center;justify-content:space-between;\n"
"  position:sticky;top:0;z-index:50;\n"
"  gap:12px;\n"
"}\n"
".topbar-left{display:flex;align-items:center;gap:12px}\n"
".topbar-age{font-family:var(--mono);font-size:12px;color:var(--text-secondary)}\n"
".btn{\n"
"  background:var(--bg-input);border:1px solid var(--border);\n"
"  color:var(--text);padding:5px 12px;border-radius:4px;\n"
"  cursor:pointer;font-size:12px;font-family:var(--font);\n"
"  transition:all .15s;white-space:nowrap;\n"
"  position:relative;overflow:hidden;\n"
"}\n"
".btn:hover{background:var(--bg-hover);border-color:rgba(255,255,255,0.12)}\n"
".btn:active{transform:scale(.97)}\n"
".btn.paused{border-color:var(--orange);color:var(--orange)}\n"
"\n"
"/* ripple */\n"
".ripple{\n"
"  position:absolute;border-radius:50%;\n"
"  background:rgba(255,255,255,0.12);\n"
"  transform:scale(0);\n"
"  animation:ripple-anim .5s ease-out;\n"
"  pointer-events:none;\n"
"}\n"
"@keyframes ripple-anim{to{transform:scale(4);opacity:0}}\n"
"\n"
".content{padding:20px 24px;flex:1}\n"
"\n"
"/* ======== KPI CARDS ======== */\n"
".kpi-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:18px}\n"
".kpi{\n"
"  background:var(--bg-panel);border:1px solid var(--border);\n"
"  border-radius:var(--radius);padding:16px 20px;\n"
"  transition:border-color .15s;\n"
"}\n"
".kpi:hover{border-color:rgba(255,255,255,0.1)}\n"
".kpi-label{font-size:11px;color:var(--text-secondary);text-transform:uppercase;letter-spacing:.5px;font-weight:600;margin-bottom:6px}\n"
".kpi-value{font-size:26px;font-weight:700;font-family:var(--mono);letter-spacing:-1px;line-height:1.1;font-variant-numeric:tabular-nums}\n"
".kpi-sub{font-size:11px;color:var(--text-secondary);margin-top:3px}\n"
".kpi-procs{border-left:3px solid var(--accent)}.kpi-procs .kpi-value{color:var(--accent)}\n"
".kpi-leaks{border-left:3px solid var(--orange)}.kpi-leaks .kpi-value{color:var(--orange)}\n"
".kpi-bytes{border-left:3px solid var(--red)}.kpi-bytes .kpi-value{color:var(--red)}\n"
".kpi-persist{border-left:3px solid var(--purple)}.kpi-persist .kpi-value{color:var(--purple)}\n"
"\n"
"/* ======== SECTION PANELS ======== */\n"
".section{margin-bottom:18px}\n"
".section-head{\n"
"  display:flex;align-items:center;gap:8px;\n"
"  margin-bottom:8px;\n"
"}\n"
".section-head h2{font-size:13px;font-weight:600}\n"
".section-head .count{font-size:11px;color:var(--text-secondary);font-weight:400}\n"
"\n"
".panel{\n"
"  background:var(--bg-panel);border:1px solid var(--border);\n"
"  border-radius:var(--radius);overflow:hidden;\n"
"}\n"
"\n"
"/* ======== TWO-COLUMN ROW ======== */\n"
".panel-row{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:18px}\n"
"\n"
"/* ======== TABLE ======== */\n"
"table{width:100%;border-collapse:collapse;font-variant-numeric:tabular-nums}\n"
"thead th{\n"
"  text-align:left;padding:8px 12px;\n"
"  background:var(--bg-input);\n"
"  font-size:11px;font-weight:600;\n"
"  color:var(--text-secondary);\n"
"  text-transform:uppercase;letter-spacing:.4px;\n"
"  border-bottom:1px solid var(--border);\n"
"  white-space:nowrap;\n"
"  position:sticky;top:0;z-index:1;\n"
"}\n"
"tbody td{\n"
"  padding:7px 12px;font-size:12.5px;\n"
"  border-bottom:1px solid var(--border);\n"
"  white-space:nowrap;\n"
"  font-variant-numeric:tabular-nums;\n"
"}\n"
"tbody tr:last-child td{border-bottom:none}\n"
"tbody tr:hover{background:var(--bg-hover)}\n"
"\n"
".badge{\n"
"  display:inline-flex;align-items:center;gap:4px;\n"
"  padding:1px 8px;border-radius:4px;font-size:11px;font-weight:600;\n"
"}\n"
".badge-live{background:var(--green-bg);color:var(--green);border:1px solid rgba(62,181,121,0.25)}\n"
".badge-live::before{content:'';width:6px;height:6px;border-radius:50%;background:var(--green);animation:pulse 2s ease-in-out infinite}\n"
".badge-done{background:var(--bg-input);color:var(--text-secondary)}\n"
"@keyframes pulse{0%,100%{opacity:1}50%{opacity:.4}}\n"
".badge-ok{display:inline-flex;padding:1px 8px;border-radius:4px;font-size:11px;font-weight:500;background:var(--green-bg);color:var(--green)}\n"
".badge-fail{display:inline-flex;padding:1px 8px;border-radius:4px;font-size:11px;font-weight:500;background:var(--red-bg);color:var(--red)}\n"
".badge-pending{display:inline-flex;padding:1px 8px;border-radius:4px;font-size:11px;font-weight:500;background:var(--orange-bg);color:var(--orange)}\n"
"\n"
".btn-sm{\n"
"  padding:3px 10px;font-size:11px;border-radius:4px;\n"
"  border:1px solid var(--border);background:var(--bg-input);\n"
"  color:var(--text);cursor:pointer;transition:all .15s;\n"
"  position:relative;overflow:hidden;\n"
"  font-family:var(--font);\n"
"}\n"
".btn-sm:hover{background:var(--accent);color:#fff;border-color:var(--accent)}\n"
".btn-sm:disabled{opacity:.4;cursor:not-allowed}\n"
"\n"
".hot-fn{\n"
"  font-family:var(--mono);font-size:11.5px;color:var(--accent);\n"
"  max-width:260px;overflow:hidden;text-overflow:ellipsis;display:inline-block;\n"
"}\n"
"\n"
"/* ======== CONTROLS ======== */\n"
".controls{\n"
"  display:flex;gap:8px;align-items:center;margin-bottom:8px;flex-wrap:wrap;\n"
"}\n"
".controls input[type=\"text\"]{\n"
"  width:220px;padding:5px 10px;border:1px solid var(--border);\n"
"  border-radius:4px;font-size:12px;background:var(--bg-input);color:var(--text);\n"
"  font-family:var(--font);transition:border-color .15s;\n"
"}\n"
".controls input[type=\"text\"]:focus{outline:none;border-color:var(--accent)}\n"
".controls input[type=\"text\"]::placeholder{color:var(--text-secondary)}\n"
".sort-btn{font-size:11px;padding:3px 10px;font-family:var(--font)}\n"
".sort-btn.active{background:var(--accent);color:#fff;border-color:var(--accent)}\n"
".sort-btn.active:hover{background:var(--accent)}\n"
"\n"
"/* ======== LEAK CARDS ======== */\n"
".leak-card{\n"
"  background:var(--bg-panel);border:1px solid var(--border);\n"
"  border-radius:var(--radius);margin-bottom:8px;overflow:hidden;\n"
"  transition:border-color .15s;\n"
"}\n"
".leak-card:hover{border-color:rgba(255,255,255,0.1)}\n"
".leak-header{\n"
"  padding:10px 16px;display:flex;align-items:center;gap:12px;\n"
"  font-size:12.5px;border-bottom:1px solid var(--border);\n"
"}\n"
".leak-header .sz{color:var(--red);font-weight:600;font-family:var(--mono);font-size:13px;white-space:nowrap;min-width:76px;font-variant-numeric:tabular-nums}\n"
".leak-header .loc{color:var(--accent);font-family:var(--mono);font-size:12px}\n"
".leak-header .proc-info{color:var(--text-secondary);font-size:11px;margin-left:auto;white-space:nowrap}\n"
"\n"
"/* Call tree */\n"
".leak-body{padding:0}\n"
".call-tree{padding:2px 0;position:relative}\n"
".call-tree::before{\n"
"  content:'';position:absolute;left:28px;top:10px;bottom:10px;width:2px;\n"
"  background:linear-gradient(to bottom,#333 0%,#9f6bff 20%,#3274d9 60%,#e02f44 100%);\n"
"  border-radius:1px;\n"
"}\n"
".call-node{\n"
"  padding:7px 10px 7px 52px;position:relative;\n"
"  font-family:var(--mono);font-size:12px;line-height:1.4;\n"
"  transition:background .1s;\n"
"}\n"
".call-node::before{\n"
"  content:'';position:absolute;left:28px;top:50%;\n"
"  width:12px;height:1.5px;background:var(--border);border-radius:1px;\n"
"}\n"
".call-node .fn{color:var(--text);font-weight:500}\n"
".call-node .lib{color:var(--text-secondary);font-size:11px;margin-left:4px}\n"
".call-node.entry .fn{color:var(--purple);font-weight:600}\n"
".call-node.leak-site{\n"
"  background:var(--red-bg);\n"
"  border-left:2px solid var(--red);\n"
"}\n"
".call-node.leak-site .fn{color:var(--red);font-weight:700}\n"
".call-node .tag{\n"
"  display:inline-block;background:var(--red-bg);color:var(--red);\n"
"  font-size:10px;padding:0 6px;border-radius:3px;margin-left:6px;\n"
"  font-weight:600;letter-spacing:.3px;\n"
"  border:1px solid rgba(224,47,68,0.25);\n"
"}\n"
".call-node[onclick]:hover{background:rgba(50,116,217,0.08);border-radius:4px;cursor:pointer}\n"
".call-node .source-tip{color:var(--green);font-size:11px;margin-left:4px;font-weight:500}\n"
"\n"
"/* ======== PAGINATION ======== */\n"
".pager{\n"
"  display:flex;align-items:center;justify-content:center;gap:3px;margin-top:8px;\n"
"}\n"
".pg-btn{\n"
"  background:var(--bg-input);border:1px solid var(--border);\n"
"  color:var(--text-secondary);padding:3px 8px;border-radius:4px;\n"
"  cursor:pointer;font-size:11px;font-family:var(--font);font-variant-numeric:tabular-nums;\n"
"  transition:all .15s;min-width:28px;text-align:center;\n"
"}\n"
".pg-btn:hover{background:var(--bg-hover);color:var(--text)}\n"
".pg-btn.active{background:var(--accent);color:#fff;border-color:var(--accent)}\n"
".pg-btn:disabled{opacity:.3;cursor:not-allowed}\n"
"\n"
"/* ======== EMPTY STATE ======== */\n"
".empty{text-align:center;padding:36px 16px;color:var(--text-secondary);font-size:12.5px}\n"
"\n"
"/* ======== TOAST ======== */\n"
".toast{\n"
"  position:fixed;bottom:24px;right:24px;\n"
"  background:var(--bg-panel);color:var(--text);\n"
"  padding:8px 18px;border-radius:4px;font-size:12px;font-weight:500;\n"
"  opacity:0;transform:translateY(6px);transition:all .2s;\n"
"  pointer-events:none;z-index:200;\n"
"  border:1px solid var(--border);\n"
"}\n"
".toast.show{opacity:1;transform:translateY(0)}\n"
"\n"
"/* ======== CURSOR ART TEXT ======== */\n"
".cursor-art{\n"
"  position:fixed;pointer-events:none;z-index:9999;\n"
"  font-family:'Brush Script MT','Comic Sans MS','Segoe Script','STKaiti',cursive,serif;\n"
"  font-size:15px;color:rgba(200,200,210,0.28);\n"
"  letter-spacing:2px;\n"
"  white-space:nowrap;\n"
"  transition:opacity .3s;\n"
"  text-shadow:0 0 8px rgba(160,120,255,0.25);\n"
"  user-select:none;\n"
"}\n"
".cursor-art.hidden{opacity:0}\n"
"\n"
"/* ======== RESPONSIVE ======== */\n"
"@media(max-width:1100px){.panel-row{grid-template-columns:1fr}.kpi-grid{grid-template-columns:repeat(2,1fr)}}\n"
"@media(max-width:768px){.sidebar{width:56px;min-width:56px}.sidebar .brand-text,.sidebar .nav-label{display:none}.kpi-grid{grid-template-columns:1fr}}\n"
"</style>\n"
"</head>\n"
"<body>\n"
"\n"
"<!-- ======== SIDEBAR ======== -->\n"
"<aside class=\"sidebar\" id=\"sidebar\">\n"
"  <div class=\"sidebar-brand\">\n"
"    <div class=\"dot\" id=\"status-dot\" title=\"连接状态\"></div>\n"
"    <span class=\"brand-text\">MemoryTraceTool</span>\n"
"  </div>\n"
"  <nav class=\"sidebar-nav\">\n"
"    <div class=\"nav-item active\" data-panel=\"dashboard\">\n"
"      <svg width=\"16\" height=\"16\" viewBox=\"0 0 16 16\" fill=\"none\"><rect x=\"1.5\" y=\"1.5\" width=\"13\" height=\"13\" rx=\"2\" stroke=\"currentColor\" stroke-width=\"1.3\"/><line x1=\"2\" y1=\"5.5\" x2=\"14\" y2=\"5.5\" stroke=\"currentColor\" stroke-width=\"1\"/><line x1=\"6\" y1=\"5.5\" x2=\"6\" y2=\"14.5\" stroke=\"currentColor\" stroke-width=\"1\"/></svg>\n"
"      <span class=\"nav-label\">概览仪表盘</span>\n"
"    </div>\n"
"  </nav>\n"
"  <div class=\"sidebar-toggle\" onclick=\"toggleSidebar()\" title=\"折叠侧边栏\">&laquo;</div>\n"
"</aside>\n"
"\n"
"<!-- ======== MAIN CONTENT ======== -->\n"
"<div class=\"main\">\n"
"<div class=\"topbar\">\n"
"  <div class=\"topbar-left\">\n"
"    <span class=\"topbar-age\" id=\"refresh-age\">--</span>\n"
"  </div>\n"
"  <div>\n"
"    <button class=\"btn\" id=\"btn-pause\" onclick=\"toggleAuto()\">暂停刷新</button>\n"
"    <button class=\"btn\" onclick=\"refresh();loadProcesses()\">立即刷新</button>\n"
"  </div>\n"
"</div>\n"
"\n"
"<div class=\"content\">\n"
"\n"
"  <!-- KPI Row -->\n"
"  <div class=\"kpi-grid\">\n"
"    <div class=\"kpi kpi-procs\"><div class=\"kpi-label\">监控进程</div><div class=\"kpi-value\" id=\"p\">--</div><div class=\"kpi-sub\">当前活跃连接</div></div>\n"
"    <div class=\"kpi kpi-leaks\"><div class=\"kpi-label\">泄漏总数</div><div class=\"kpi-value\" id=\"l\">--</div><div class=\"kpi-sub\">可疑内存泄漏点</div></div>\n"
"    <div class=\"kpi kpi-bytes\"><div class=\"kpi-label\">泄漏字节</div><div class=\"kpi-value\" id=\"b\">--</div><div class=\"kpi-sub\">累计未释放内存</div></div>\n"
"    <div class=\"kpi kpi-persist\"><div class=\"kpi-label\">持久化记录</div><div class=\"kpi-value\" id=\"h\">--</div><div class=\"kpi-sub\">已保存的历史进程</div></div>\n"
"  </div>\n"
"\n"
"  <!-- Row 2: Two panels -->\n"
"  <div class=\"panel-row\">\n"
"    <!-- Monitored Processes -->\n"
"    <div>\n"
"      <div class=\"section-head\"><h2>被监控进程</h2><span class=\"count\" id=\"proc-count\"></span></div>\n"
"      <div class=\"panel\">\n"
"        <table>\n"
"          <thead><tr><th>PID</th><th>进程名</th><th>状态</th><th>泄漏数</th><th>字节数</th><th>最后活跃</th><th>热点函数</th></tr></thead>\n"
"          <tbody id=\"tb\"><tr><td colspan=\"7\"><div class=\"empty\"><p>等待被监控进程接入...</p></div></td></tr></tbody>\n"
"        </table>\n"
"      </div>\n"
"    </div>\n"
"    <!-- Injectable Processes -->\n"
"    <div>\n"
"      <div class=\"section-head\"><h2>可注入进程</h2><span class=\"count\" id=\"proc-count-inject\"></span></div>\n"
"      <div class=\"controls\">\n"
"        <input type=\"text\" id=\"proc-filter\" placeholder=\"搜索进程名...\" oninput=\"loadProcesses()\">\n"
"      </div>\n"
"      <div class=\"panel\">\n"
"        <table>\n"
"          <thead><tr><th style=\"width:56px\">PID</th><th>进程名</th><th style=\"width:72px\">堆内存</th><th style=\"width:72px\">注入状态</th><th style=\"width:56px\">操作</th></tr></thead>\n"
"          <tbody id=\"ptb\"><tr><td colspan=\"5\"><div class=\"empty\"><p>加载中...</p></div></td></tr></tbody>\n"
"        </table>\n"
"      </div>\n"
"      <div class=\"pager\" id=\"proc-pager\"></div>\n"
"    </div>\n"
"  </div>\n"
"\n"
"  <!-- Row 3: Leak Ranking -->\n"
"  <div>\n"
"    <div class=\"section-head\"><h2>可疑泄漏排行</h2><span class=\"count\" id=\"leak-count\"></span></div>\n"
"    <div class=\"controls\">\n"
"      <input type=\"text\" id=\"leak-filter\" placeholder=\"搜索泄漏 — 进程名 / PID / 文件名...\" oninput=\"renderLeaks()\">\n"
"      <span style=\"font-size:11px;color:var(--text-secondary)\">排序:</span>\n"
"      <button class=\"btn sort-btn active\" id=\"sort-size\" onclick=\"setSort('size')\">大小</button>\n"
"      <button class=\"btn sort-btn\" id=\"sort-time\" onclick=\"setSort('time')\">最近</button>\n"
"      <button class=\"btn sort-btn\" id=\"sort-proc\" onclick=\"setSort('proc')\">进程</button>\n"
"    </div>\n"
"    <div id=\"tl\"><div class=\"empty\"><p>暂无泄漏 - 一切正常</p></div></div>\n"
"  </div>\n"
"\n"
"</div>\n"
"</div>\n"
"\n"
"<div class=\"toast\" id=\"toast\"></div>\n"
"<div class=\"cursor-art hidden\" id=\"cursor-art\">王华是cos0</div>\n"
"\n"
"<script>\n"
"var autoRefresh = true;\n"
"var failCount = 0;\n"
"var gAllLeaks = [];\n"
"var gSortMode = 'size';\n"
"var gProcPage = 1;\n"
"var gProcPageSize = 15;\n"
"var gAllProcs = [];\n"
"\n"
"/* ---- sidebar toggle ---- */\n"
"function toggleSidebar(){\n"
"  var sb = document.getElementById('sidebar');\n"
"  sb.classList.toggle('collapsed');\n"
"}\n"
"\n"
"/* ---- ripple ---- */\n"
"document.addEventListener('click',function(e){\n"
"  var el = e.target.closest('.btn,.btn-sm,.pg-btn');\n"
"  if(!el)return;\n"
"  var r = document.createElement('span');\n"
"  r.className='ripple';\n"
"  var rect=el.getBoundingClientRect();\n"
"  var s=Math.max(rect.width,rect.height);\n"
"  r.style.width=r.style.height=s+'px';\n"
"  r.style.left=(e.clientX-rect.left-s/2)+'px';\n"
"  r.style.top=(e.clientY-rect.top-s/2)+'px';\n"
"  el.appendChild(r);\n"
"  setTimeout(function(){r.remove()},500);\n"
"});\n"
"\n"
"/* ---- cursor art text: follows mouse ---- */\n"
"var cursorArt = document.getElementById('cursor-art');\n"
"var artTimer = null;\n"
"document.addEventListener('mousemove',function(e){\n"
"  cursorArt.classList.remove('hidden');\n"
"  cursorArt.style.left = (e.clientX + 16) + 'px';\n"
"  cursorArt.style.top = (e.clientY + 18) + 'px';\n"
"  clearTimeout(artTimer);\n"
"  artTimer = setTimeout(function(){ cursorArt.classList.add('hidden'); }, 2000);\n"
"});\n"
"\n"
"/* ---- auto refresh ---- */\n"
"setInterval(function(){if(autoRefresh){refresh();loadProcesses();}},3000);\n"
"refresh();\n"
"\n"
"function toggleAuto(){\n"
"  autoRefresh=!autoRefresh;\n"
"  var btn=document.getElementById('btn-pause');\n"
"  var dot=document.getElementById('status-dot');\n"
"  if(autoRefresh){btn.textContent='暂停刷新';btn.classList.remove('paused');dot.classList.remove('off');refresh()}\n"
"  else{btn.textContent='恢复刷新';btn.classList.add('paused');dot.classList.add('off');document.getElementById('refresh-age').textContent='已暂停'}\n"
"  toast(autoRefresh?'自动刷新已恢复':'自动刷新已暂停');\n"
"}\n"
"\n"
"function refresh(){\n"
"  fetch('/api/data')\n"
"    .then(function(r){return r.json()})\n"
"    .then(function(d){\n"
"      failCount=0;\n"
"      document.getElementById('status-dot').classList.remove('off');\n"
"      document.getElementById('refresh-age').textContent=new Date().toLocaleTimeString();\n"
"      document.getElementById('p').textContent=d.nprocs;\n"
"      document.getElementById('l').textContent=d.total_leaks;\n"
"      document.getElementById('b').textContent=fmtBytes(d.total_bytes);\n"
"      document.getElementById('h').textContent=d.nprocs;\n"
"\n"
"      var rows='';\n"
"      for(var i=0;i<d.procs.length;i++){\n"
"        var p=d.procs[i];\n"
"        var badge=p.active\n"
"          ?'<span class=\"badge badge-live\">运行中</span>'\n"
"          :'<span class=\"badge badge-done\">已退出</span>';\n"
"        var seen=p.last_seen?new Date(p.last_seen*1000).toLocaleTimeString():'--';\n"
"        var topFn=parseTopFn(p.top_stack);\n"
"        rows+='<tr>'+\n"
"          '<td style=\"font-family:var(--mono)\">'+p.pid+'</td>'+\n"
"          '<td>'+esc(p.name)+'</td>'+\n"
"          '<td>'+badge+'</td>'+\n"
"          '<td style=\"font-family:var(--mono)\">'+p.leak_count+'</td>'+\n"
"          '<td style=\"font-family:var(--mono)\">'+fmtBytes(p.total_leaked)+'</td>'+\n"
"          '<td style=\"font-size:11px;color:var(--text-secondary)\">'+seen+'</td>'+\n"
"          '<td><span class=\"hot-fn\" title=\"'+escAttr(p.top_stack||'')+'\">'+esc(topFn)+'</span></td>'+\n"
"          '</tr>';\n"
"      }\n"
"      document.getElementById('tb').innerHTML=rows||'<tr><td colspan=\"7\"><div class=\"empty\"><p>等待被监控进程接入...</p></div></td></tr>';\n"
"      document.getElementById('proc-count').textContent=d.nprocs>0?'('+d.nprocs+')':'';\n"
"\n"
"      var seq=0;var all=[];\n"
"      for(var i=0;i<d.procs.length;i++){\n"
"        var pp=d.procs[i];\n"
"        for(var j=0;j<pp.leaks.length;j++){\n"
"          all.push({\n"
"            size:pp.leaks[j].size,file:pp.leaks[j].file,line:pp.leaks[j].line,\n"
"            nframes:pp.leaks[j].nframes,frames:pp.leaks[j].frames,\n"
"            pid:pp.pid,name:pp.name,seq:seq++\n"
"          });\n"
"        }\n"
"      }\n"
"      gAllLeaks=all;\n"
"      renderLeaks();\n"
"    })\n"
"    .catch(function(){\n"
"      failCount++;\n"
"      document.getElementById('status-dot').classList.add('off');\n"
"      if(failCount<=1)document.getElementById('refresh-age').textContent='连接失败，重试中...';\n"
"    });\n"
"}\n"
"\n"
"function setSort(mode){\n"
"  gSortMode=mode;\n"
"  document.getElementById('sort-size').classList.toggle('active',mode==='size');\n"
"  document.getElementById('sort-time').classList.toggle('active',mode==='time');\n"
"  document.getElementById('sort-proc').classList.toggle('active',mode==='proc');\n"
"  renderLeaks();\n"
"}\n"
"\n"
"function renderLeaks(){\n"
"  var filter=(document.getElementById('leak-filter').value||'').toLowerCase();\n"
"  var filtered=gAllLeaks;\n"
"  if(filter){\n"
"    filtered=gAllLeaks.filter(function(l){\n"
"      return (l.name&&l.name.toLowerCase().indexOf(filter)>=0)||\n"
"             (l.file&&l.file.toLowerCase().indexOf(filter)>=0)||\n"
"             String(l.pid).indexOf(filter)>=0;\n"
"    });\n"
"  }\n"
"\n"
"  if(gSortMode==='size'){filtered.sort(function(a,b){return b.size-a.size})}\n"
"  else if(gSortMode==='time'){filtered.sort(function(a,b){return b.seq-a.seq})}\n"
"  else if(gSortMode==='proc'){filtered.sort(function(a,b){var c=(a.name||'').localeCompare(b.name||'');return c!==0?c:a.pid-b.pid})}\n"
"\n"
"  var top=filtered.slice(0,15);\n"
"  var html='';\n"
"  for(var i=0;i<top.length;i++){\n"
"    var l=top[i];\n"
"    var leakFrameIdx=0;\n"
"    if(l.nframes>0){\n"
"      for(var j=0;j<l.nframes;j++){\n"
"        var pf=parseFrame(l.frames[j]||'?');\n"
"        var isInternal=(pf.bin&&pf.bin.indexOf('libmemorytracetool')>=0)||\n"
"                       (pf.lib&&pf.lib.indexOf('libmemorytracetool')>=0)||\n"
"                       (pf.fn&&(pf.fn.indexOf('mtt_')===0||pf.fn==='capture_stack'||pf.fn==='backtrace'));\n"
"        if(!isInternal){leakFrameIdx=j;break}\n"
"      }\n"
"    }\n"
"    var maxFrames=Math.min(l.nframes,10);\n"
"    html+='<div class=\"leak-card\">';\n"
"    html+='<div class=\"leak-header\">';\n"
"    html+='<span class=\"sz\">'+fmtBytes(l.size)+'</span>';\n"
"    html+='<span class=\"loc\">'+esc(l.file)+':'+l.line+'</span>';\n"
"    html+='<span class=\"proc-info\">PID '+l.pid+' · '+esc(l.name)+'</span>';\n"
"    html+='</div><div class=\"leak-body\"><div class=\"call-tree\">';\n"
"    if(l.nframes>0){\n"
"      for(var j=maxFrames-1;j>=0;j--){\n"
"        var cls=j===leakFrameIdx?'call-node leak-site':(j===maxFrames-1?'call-node entry':'call-node');\n"
"        var parsed=parseFrame(l.frames[j]||'?');\n"
"        html+='<div class=\"'+cls+'\"';\n"
"        if(parsed.bin&&parsed.off)html+=' onclick=\"event.stopPropagation();resolveFrame(this,\\''+escAttr(parsed.bin)+'\\',\\''+escAttr(parsed.off)+'\\')\" style=\"cursor:pointer\" title=\"点击解析源码位置\"';\n"
"        html+='><span class=\"fn\">'+esc(parsed.fn)+'</span>';\n"
"        if(parsed.lib)html+='<span class=\"lib\">'+esc(parsed.lib)+'</span>';\n"
"        if(j===leakFrameIdx)html+='<span class=\"tag\">泄漏点</span>';\n"
"        html+='</div>';\n"
"      }\n"
"    }else{html+='<div class=\"call-node\"><span class=\"fn\" style=\"color:var(--text-secondary)\">(无调用栈)</span></div>'}\n"
"    html+='</div></div></div>';\n"
"  }\n"
"\n"
"  var totalAll=gAllLeaks.length;\n"
"  var label='';\n"
"  if(totalAll>0){\n"
"    if(filter){label='(匹配 '+Math.min(filtered.length,15)+' / 共 '+totalAll+')'}\n"
"    else{label='(Top '+Math.min(totalAll,15)+' / 共 '+totalAll+')'}\n"
"  }\n"
"  document.getElementById('tl').innerHTML=html||'<div class=\"empty\"><p>'+(filter?'无匹配泄漏':'暂无泄漏 - 一切正常')+'</p></div>';\n"
"  document.getElementById('leak-count').textContent=label;\n"
"}\n"
"\n"
"/* ---- process list ---- */\n"
"function loadProcesses(){\n"
"  var filter=(document.getElementById('proc-filter').value||'').toLowerCase();\n"
"  fetch('/api/processes')\n"
"    .then(function(r){return r.json()})\n"
"    .then(function(d){\n"
"      gAllProcs=d.processes;\n"
"      if(filter){gAllProcs=gAllProcs.filter(function(p){return p.name.toLowerCase().indexOf(filter)>=0})}\n"
"      gProcPage=Math.min(gProcPage,Math.max(1,Math.ceil(gAllProcs.length/gProcPageSize)));\n"
"      renderProcPage();renderPager();\n"
"    })\n"
"    .catch(function(){document.getElementById('ptb').innerHTML='<tr><td colspan=\"5\"><div class=\"empty\"><p>加载失败</p></div></td></tr>'});\n"
"}\n"
"\n"
"function renderProcPage(){\n"
"  var start=(gProcPage-1)*gProcPageSize;\n"
"  var page=gAllProcs.slice(start,start+gProcPageSize);\n"
"  var rows='';\n"
"  for(var i=0;i<page.length;i++){\n"
"    var p=page[i];\n"
"    var injHtml=p.injected\n"
"      ?(p.inj_status===1?'<span class=\"badge-ok\">监控中</span>':'<span class=\"badge-fail\" title=\"'+escAttr(p.inj_err||'')+'\">失败</span>')\n"
"      :'<span class=\"badge-pending\">未注入</span>';\n"
"    var btnHtml=(p.injected&&p.inj_status===1)\n"
"      ?'<span class=\"badge-ok\">已注入</span>'\n"
"      :'<button class=\"btn-sm\" onclick=\"injectProcess('+p.pid+',this)\">注入</button>';\n"
"    var heapStr=p.heap_kb>=1024?(p.heap_kb/1024).toFixed(1)+' MB':p.heap_kb+' KB';\n"
"    rows+='<tr>'+\n"
"      '<td style=\"font-family:var(--mono)\">'+p.pid+'</td>'+\n"
"      '<td>'+esc(p.name)+'</td>'+\n"
"      '<td style=\"font-family:var(--mono);color:var(--text-secondary)\">'+heapStr+'</td>'+\n"
"      '<td>'+injHtml+'</td>'+\n"
"      '<td>'+btnHtml+'</td>'+\n"
"      '</tr>';\n"
"  }\n"
"  document.getElementById('ptb').innerHTML=rows||'<tr><td colspan=\"5\"><div class=\"empty\"><p>'+(gAllProcs.length===0?'无可用进程':'无匹配进程')+'</p></div></td></tr>';\n"
"  document.getElementById('proc-count-inject').textContent=gAllProcs.length>0?'('+gAllProcs.length+')':'';\n"
"}\n"
"\n"
"function renderPager(){\n"
"  var total=Math.max(1,Math.ceil(gAllProcs.length/gProcPageSize));\n"
"  var h='';\n"
"  h+='<button class=\"pg-btn\" '+(gProcPage<=1?'disabled':'')+' onclick=\"goPage('+(gProcPage-1)+')\">&laquo;</button>';\n"
"  for(var i=1;i<=total&&i<=8;i++){\n"
"    h+='<button class=\"pg-btn'+(i===gProcPage?' active':'')+'\" onclick=\"goPage('+i+')\">'+i+'</button>';\n"
"  }\n"
"  if(total>8)h+='<span style=\"font-size:11px;color:var(--text-secondary);margin:0 4px\">...'+total+'</span>';\n"
"  h+='<button class=\"pg-btn\" '+(gProcPage>=total?'disabled':'')+' onclick=\"goPage('+(gProcPage+1)+')\">&raquo;</button>';\n"
"  document.getElementById('proc-pager').innerHTML=h;\n"
"}\n"
"\n"
"function goPage(n){gProcPage=n;renderProcPage();renderPager()}\n"
"\n"
"function injectProcess(pid,btn){\n"
"  btn.disabled=true;btn.textContent='...';\n"
"  toast('正在向 PID '+pid+' 注入...');\n"
"  fetch('/api/inject?pid='+pid)\n"
"    .then(function(r){return r.json()})\n"
"    .then(function(d){\n"
"      if(d.status==='ok'){toast('PID '+pid+' 注入成功！('+d.patched+' GOT)');loadProcesses()}\n"
"      else{toast('注入失败: '+d.error);btn.disabled=false;btn.textContent='重试'}\n"
"    })\n"
"    .catch(function(){toast('注入请求失败');btn.disabled=false;btn.textContent='重试'});\n"
"}\n"
"\n"
"loadProcesses();\n"
"\n"
"function parseFrame(raw){\n"
"  if(!raw)return{fn:'?',lib:'',bin:'',off:''};\n"
"  var parts=raw.split('|');\n"
"  var display=parts[0]||raw;\n"
"  var m=display.match(/^(.+?)\\s+\\((.+?)\\)\\s*$/);\n"
"  if(m)return{fn:m[1],lib:m[2],bin:parts[1]||'',off:parts[2]||''};\n"
"  m=display.match(/^(.+?)\\((.+?)\\)\\s*$/);\n"
"  if(m)return{fn:m[1],lib:'',bin:parts[1]||'',off:parts[2]||''};\n"
"  return{fn:display,lib:'',bin:parts[1]||'',off:parts[2]||''};\n"
"}\n"
"\n"
"function parseTopFn(raw){\n"
"  if(!raw||raw==='(none)')return'(none)';\n"
"  return parseFrame(raw).fn;\n"
"}\n"
"\n"
"function resolveFrame(el,bin,off){\n"
"  if(!bin||!off)return;\n"
"  var fnEl=el.querySelector('.fn');\n"
"  var orig=fnEl.textContent;\n"
"  fnEl.textContent=orig+' (解析中...)';\n"
"  fetch('/api/addr2line?bin='+encodeURIComponent(bin)+'&off='+off)\n"
"    .then(function(r){return r.json()})\n"
"    .then(function(d){\n"
"      fnEl.textContent=orig;\n"
"      var tip=el.querySelector('.source-tip');\n"
"      if(!tip){tip=document.createElement('span');tip.className='source-tip';el.appendChild(tip)}\n"
"      tip.textContent=' @ '+d.result;tip.title=d.result;\n"
"    })\n"
"    .catch(function(){fnEl.textContent=orig});\n"
"}\n"
"\n"
"function fmtBytes(b){\n"
"  if(b<1024)return b+' B';\n"
"  if(b<1048576)return(b/1024).toFixed(1)+' KB';\n"
"  if(b<1073741824)return(b/1048576).toFixed(1)+' MB';\n"
"  return(b/1073741824).toFixed(2)+' GB';\n"
"}\n"
"\n"
"function esc(s){if(!s)return'';return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/\"/g,'&quot;')}\n"
"function escAttr(s){if(!s)return'';return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/\"/g,'&quot;').replace(/'/g,'&#39;')}\n"
"\n"
"function toast(msg){\n"
"  var t=document.getElementById('toast');\n"
"  t.textContent=msg;t.classList.add('show');\n"
"  setTimeout(function(){t.classList.remove('show')},2000);\n"
"}\n"
"</script>\n"
"</body>\n"
"</html>\n"
;

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

/** libmemorytracetool.so 的备选搜索路径（绝对路径兜底） */
static const char* default_lib_paths[] = {
    "/usr/local/lib/libmemorytracetool.so",
    NULL
};

/** 解析出注入库的绝对路径（基于 /proc/self/exe 定位项目树中的 .so） */
static int resolve_lib_path(char* out, size_t out_sz)
{
    (void)out_sz;
    /* 通过 /proc/self/exe 获取 mttd 自身路径，推导 ../lib/libmemorytracetool.so */
    char self_exe[512];
    ssize_t n = readlink("/proc/self/exe", self_exe, sizeof(self_exe) - 1);
    if (n > 0) {
        self_exe[n] = '\0';
        char* slash = strrchr(self_exe, '/');
        if (slash) {
            *slash = '\0';                              /* self_exe 现在是 build/ 目录 */
            char rel[640];
            snprintf(rel, sizeof(rel), "%s/../lib/libmemorytracetool.so", self_exe);
            if (realpath(rel, out)) return 0;
        }
    }

    /* 兜底：绝对路径安装 */
    for (int i = 0; default_lib_paths[i]; i++) {
        if (realpath(default_lib_paths[i], out)) return 0;
    }
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
/* 用于排序的临时进程信息 */
typedef struct {
    int pid;
    char name[256];
    char state;
    int inj_status;
    char inj_err[256];
    unsigned long heap_kb;
} proc_info_t;

static int proc_cmp_heapsz(const void* a, const void* b)
{
    const proc_info_t* pa = (const proc_info_t*)a;
    const proc_info_t* pb = (const proc_info_t*)b;
    if (pb->heap_kb > pa->heap_kb) return 1;
    if (pb->heap_kb < pa->heap_kb) return -1;
    return 0;
}

static void send_api_processes(int fd)
{
    char buf[131072];
    int pos = 0;
    int size = (int)sizeof(buf);

    const char* hdr =
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: application/json; charset=utf-8\r\n"
        "Access-Control-Allow-Origin: *\r\n"
        "Connection: close\r\n\r\n";
    int hdr_len = (int)strlen(hdr);
    if (pos + hdr_len < size) { memcpy(buf + pos, hdr, hdr_len); pos += hdr_len; }

    /* 第一步：收集所有进程信息 */
    enum { MAX_COLLECT = 4096 };
    proc_info_t* procs = malloc(MAX_COLLECT * sizeof(proc_info_t));
    int n = 0;
    if (!procs) { send_all(fd, buf, pos); return; }

    DIR* dir = opendir("/proc");
    if (dir) {
        struct dirent* de;
        while ((de = readdir(dir)) && n < MAX_COLLECT) {
            if (de->d_name[0] < '0' || de->d_name[0] > '9') continue;
            int pid = atoi(de->d_name);
            if (pid <= 1) continue;

            char comm_path[64], comm[256] = "";
            snprintf(comm_path, sizeof(comm_path), "/proc/%d/comm", pid);
            FILE* fc = fopen(comm_path, "r");
            if (!fc) continue;
            if (!fgets(comm, sizeof(comm), fc)) { fclose(fc); continue; }
            fclose(fc);
            size_t cl = strlen(comm);
            while (cl > 0 && (comm[cl-1] == '\n' || comm[cl-1] == '\r'))
                comm[--cl] = '\0';

            char exe_path[64];
            snprintf(exe_path, sizeof(exe_path), "/proc/%d/exe", pid);
            if (access(exe_path, F_OK) != 0) continue;

            char stat_path[64];
            snprintf(stat_path, sizeof(stat_path), "/proc/%d/stat", pid);
            FILE* fs = fopen(stat_path, "r");
            if (!fs) continue;
            char state = '?';
            fscanf(fs, "%*d %*s %c", &state);
            fclose(fs);
            if (state == 'Z' || state == 'X' || state == 'T' || state == 'D') continue;

            /* 读取堆内存使用量 (VmData from /proc/<pid>/status) */
            unsigned long heap_kb = 0;
            char status_path[64];
            snprintf(status_path, sizeof(status_path), "/proc/%d/status", pid);
            FILE* fst = fopen(status_path, "r");
            if (fst) {
                char sline[256];
                while (fgets(sline, sizeof(sline), fst)) {
                    if (strncmp(sline, "VmData:", 7) == 0) {
                        /* VmData: <N> kB */
                        char* vp = sline + 7;
                        while (*vp == ' ' || *vp == '\t') vp++;
                        heap_kb = strtoul(vp, NULL, 10);
                        break;
                    }
                }
                fclose(fst);
            }

            proc_info_t* pi = &procs[n++];
            memset(pi, 0, sizeof(*pi));
            pi->pid = pid;
            pi->state = state;
            pi->heap_kb = heap_kb;
            snprintf(pi->name, sizeof(pi->name), "%s", comm);
            for (int i = 0; i < g_ninjected; i++) {
                if (g_injected[i].pid == pid) {
                    pi->inj_status = g_injected[i].inject_status;
                    snprintf(pi->inj_err, sizeof(pi->inj_err), "%s", g_injected[i].inject_err);
                    break;
                }
            }
        }
        closedir(dir);
    }

    /* 第二步：按堆内存降序排序 */
    qsort(procs, (size_t)n, sizeof(proc_info_t), proc_cmp_heapsz);

    /* 第三步：序列化为 JSON */
    safe_append(buf, &pos, size, "{\"processes\":[");
    for (int i = 0; i < n; i++) {
        proc_info_t* pi = &procs[i];
        if (i > 0) safe_append(buf, &pos, size, ",");
        safe_append(buf, &pos, size,
            "{\"pid\":%d,\"name\":\"%s\",\"state\":\"%c\","
            "\"injected\":%s,\"inj_status\":%d,\"inj_err\":\"%s\",\"heap_kb\":%lu}",
            pi->pid, pi->name, pi->state,
            pi->inj_status == 1 ? "true" : "false",
            pi->inj_status, pi->inj_err, pi->heap_kb);
    }
    safe_append(buf, &pos, size, "]}");
    free(procs);

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

    /* 加载持久化历史记录 */
    pthread_mutex_lock(&g_lock);
    load_persisted();
    pthread_mutex_unlock(&g_lock);

    printf("[mttd] Ready.\n");

    /* ---- 事件循环 ---- */
    unsigned loop_ticks = 0;
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

        /* 每 5 次循环（约 5 秒）检查进程存活状态 */
        if (++loop_ticks % 5 == 0) {
            pthread_mutex_lock(&g_lock);
            check_liveness();
            pthread_mutex_unlock(&g_lock);
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

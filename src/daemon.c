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

/* ---- 全局状态 ---- */

static mttd_proc_t g_procs[MTT_MAX_PROCS];      /* 被监控进程数组 */
static int         g_nprocs = 0;                  /* 当前监控的进程数 */
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER; /* 保护 g_procs / g_nprocs */
static volatile int g_running = 1;                /* 信号控制的主循环退出标志 */

/* ---- 辅助函数 ---- */

/**
 * 查找或创建进程记录。
 *
 * 如果 pid 已存在（常驻进程重复报告），清空旧泄漏数据并重新初始化，
 * 以实现"同一 PID 重新连接 = 刷新报告"的语义。
 * 如果是新 PID，在 g_procs 数组末尾追加一条记录。
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
            pthread_mutex_lock(&p->lock);
            free(p->leaks);
            p->leak_cap = 32;
            p->leaks = malloc(p->leak_cap * sizeof(mttd_leak_t));
            p->leak_count = 0;
            p->total_leaked = 0;
            p->active = 1;
            p->last_seen = time(NULL);
            snprintf(p->name, sizeof(p->name), "%s", name);
            pthread_mutex_unlock(&p->lock);
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
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

/* ---- Unix Socket 客户端处理 ---- */

/**
 * 解析来自 Unix Socket 客户端的文本行协议。
 *
 * 使用静态缓冲区累积收到的数据，逐行解析命令：
 * - HELLO: 注册/刷新进程
 * - LEAK:  添加泄漏记录（追加到当前进程的最后一条）
 * - FRAME: 填充当前泄漏记录的栈帧符号
 * - BYE:   标记进程退出，关闭连接
 *
 * 未完整接收的行会保留在静态缓冲区中等待下次调用。
 *
 * @param fd         客户端 socket fd
 * @param out_proc   输出当前客户端关联的进程记录指针
 * @return           >0 继续读取，0 连接关闭，<0 错误
 */
static int parse_unix_client(int fd, mttd_proc_t** out_proc)
{
    static char buf[16384];
    static int  bufpos = 0;
    static mttd_proc_t* proc = NULL;
    *out_proc = proc;

    ssize_t n = read(fd, buf + bufpos, sizeof(buf) - bufpos - 1);
    if (n <= 0) { *out_proc = proc; return n; }

    bufpos += n;
    buf[bufpos] = '\0';

    char* line = buf;
    char* nl;

    /* 逐行解析：找到换行符就处理一行 */
    while ((nl = strchr(line, '\n')) != NULL) {
        *nl = '\0';

        if (strncmp(line, "HELLO ", 6) == 0) {
            int pid;
            char name[256] = {0};
            sscanf(line, "HELLO %d %255[^\n]", &pid, name);
            pthread_mutex_lock(&g_lock);
            proc = find_or_create_proc(pid, name);
            if (proc) proc->active = 1;
            pthread_mutex_unlock(&g_lock);
        }
        else if (strncmp(line, "LEAK ", 5) == 0 && proc) {
            mttd_leak_t leak;
            memset(&leak, 0, sizeof(leak));
            sscanf(line, "LEAK %zu %127s %d %d",
                   &leak.size, leak.file, &leak.line, &leak.nframes);
            if (leak.nframes > MTT_MAX_STACK) leak.nframes = MTT_MAX_STACK;
            pthread_mutex_lock(&proc->lock);
            add_leak(proc, &leak);
            pthread_mutex_unlock(&proc->lock);
        }
        else if (strncmp(line, "FRAME ", 6) == 0 && proc) {
            int idx;
            char sym[MTT_SYMBOL_MAX];
            sym[0] = '\0';
            sscanf(line, "FRAME %d %255[^\n]", &idx, sym);
            pthread_mutex_lock(&proc->lock);
            /* FRAME 索引总是在当前进程中最后一条 LEAK 的上下文中 */
            if (proc->leak_count > 0 && idx >= 0 && idx < MTT_MAX_STACK) {
                mttd_leak_t* last = &proc->leaks[proc->leak_count - 1];
                snprintf(last->frames[idx], MTT_SYMBOL_MAX, "%s", sym);
            }
            pthread_mutex_unlock(&proc->lock);
        }
        else if (strncmp(line, "BYE", 3) == 0) {
            if (proc) {
                pthread_mutex_lock(&proc->lock);
                proc->active = 0; /* 标记进程已退出 */
                pthread_mutex_unlock(&proc->lock);
            }
            *out_proc = proc;
            close(fd);
            return 0;
        }

        line = nl + 1;
    }

    /* 将未处理完的残留数据移到缓冲区开头 */
    if (line > buf) {
        int remaining = bufpos - (line - buf);
        memmove(buf, line, remaining);
        bufpos = remaining;
    }
    *out_proc = proc;
    return 1;
}

/* ---- HTTP 处理 ---- */

/* 看板 HTML 模板（内嵌 CSS/JS，零外部依赖）。
 * meta refresh 实现 3 秒自动刷新。
 * JS 通过 fetch /api/data 获取 JSON 数据并动态渲染 DOM。 */
static const char* g_dashboard_html =
"HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nConnection: close\r\n\r\n"
"<!DOCTYPE html>\n"
"<html lang=\"en\">\n"
"<head>\n"
"<meta charset=\"UTF-8\">\n"
"<meta http-equiv=\"refresh\" content=\"3\">\n"
"<title>MemoryTraceTool Dashboard</title>\n"
"<style>\n"
"*{margin:0;padding:0;box-sizing:border-box}"
"body{font-family:monospace;background:#0d1117;color:#c9d1d9;padding:20px}"
"h1{color:#58a6ff;margin-bottom:10px;font-size:20px}"
".summary{display:flex;gap:16px;margin:16px 0;flex-wrap:wrap}"
".card{background:#161b22;border:1px solid #30363d;border-radius:6px;padding:16px;min-width:150px}"
".card .val{font-size:28px;color:#58a6ff;font-weight:bold}"
".card .lbl{font-size:12px;color:#8b949e;margin-top:4px}"
"table{width:100%;border-collapse:collapse;margin-top:12px}"
"th{text-align:left;padding:8px 12px;background:#161b22;border-bottom:2px solid #30363d;font-size:12px;color:#8b949e}"
"td{padding:8px 12px;border-bottom:1px solid #21262d;font-size:12px}"
"tr:hover{background:#161b22}"
".bad-red{background:#da3633;color:#fff;padding:1px 6px;border-radius:8px;font-size:11px}"
".bad-grn{background:#238636;color:#fff;padding:1px 6px;border-radius:8px;font-size:11px}"
".stack{background:#161b22;border:1px solid #30363d;border-radius:4px;padding:10px;margin:6px 0;font-size:11px;line-height:1.5}"
".stack .f{color:#8b949e}"
".stack .f:nth-child(-n+2){color:#58a6ff}"
".sec{margin-top:20px}"
".sec h2{font-size:15px;color:#c9d1d9;margin-bottom:8px;border-bottom:1px solid #21262d;padding-bottom:6px}"
"</style>\n"
"</head>\n"
"<body>\n"
"<h1>MemoryTraceTool</h1>\n"
"<div class=\"summary\">\n"
"<div class=\"card\"><div class=\"val\" id=\"p\">0</div><div class=\"lbl\">Processes</div></div>\n"
"<div class=\"card\"><div class=\"val\" id=\"l\">0</div><div class=\"lbl\">Leaks</div></div>\n"
"<div class=\"card\"><div class=\"val\" id=\"b\">0</div><div class=\"lbl\">Bytes Leaked</div></div>\n"
"</div>\n"
"<div class=\"sec\">\n"
"<h2>Monitored Processes</h2>\n"
"<table>\n"
"<thead><tr><th>PID</th><th>Name</th><th>Status</th><th>Leaks</th><th>Bytes</th><th>Last Seen</th><th>Top Frame</th></tr></thead>\n"
"<tbody id=\"tb\"><tr><td colspan=7 style=color:#8b949e>No processes monitored yet.</td></tr></tbody>\n"
"</table>\n"
"</div>\n"
"<div class=\"sec\">\n"
"<h2>Top Suspect Leaks</h2>\n"
"<div id=\"tl\"></div>\n"
"</div>\n"
"<script>\n"
"fetch('/api/data').then(r=>r.json()).then(d=>{\n"
"document.getElementById('p').textContent=d.nprocs;\n"
"document.getElementById('l').textContent=d.total_leaks;\n"
"document.getElementById('b').textContent=(d.total_bytes<1024?d.total_bytes+' B':d.total_bytes<1048576?(d.total_bytes/1024).toFixed(1)+' KB':(d.total_bytes/1048576).toFixed(1)+' MB');\n"
"let rows='';\n"
"for(const p of d.procs){\n"
"let bad=p.active?'<span class=bad-red>ACTIVE</span>':'<span class=bad-grn>DONE</span>';\n"
"let seen=p.last_seen?new Date(p.last_seen*1000).toLocaleTimeString():'—';\n"
"rows+='<tr><td>'+p.pid+'</td><td>'+esc(p.name)+'</td><td>'+bad+'</td><td>'+p.leak_count+'</td><td>'+fmt(p.total_leaked)+'</td><td>'+seen+'</td><td style=font-size:11px;max-width:280px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap>'+esc(p.top_stack||'(none)')+'</td></tr>';\n"
"}\n"
"document.getElementById('tb').innerHTML=rows||'<tr><td colspan=6 style=color:#8b949e>No processes monitored yet.</td></tr>';\n"
"let all=[];\n"
"for(const p of d.procs){for(const l of p.leaks){all.push({...l,pid:p.pid,name:p.name});}}\n"
"all.sort((a,b)=>b.size-a.size);\n"
"let top=all.slice(0,15);\n"
"let h='';\n"
"for(const l of top){\n"
"h+='<div class=stack><strong>'+l.size+' bytes</strong> &mdash; '+esc(l.file)+':'+l.line+' &mdash; PID '+l.pid+' ('+esc(l.name)+')';\n"
"for(let i=0;i<l.nframes;i++){\n"
"h+='<div class=f>  #'+i+' '+esc(l.frames[i]||'?')+'</div>';\n"
"}\n"
"h+='</div>';\n"
"}\n"
"document.getElementById('tl').innerHTML=h||'<div style=color:#8b949e>No leaks detected.</div>';\n"
"});\n"
"function fmt(b){return b<1024?b+' B':b<1048576?(b/1024).toFixed(1)+' KB':(b/1048576).toFixed(1)+' MB';}\n"
"function esc(s){return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/\"/g,'&quot;');}\n"
"</script>\n"
"</body>\n"
"</html>";

/**
 * JSON 字符串转义。
 *
 * 将源字符串中的 "、\、\n、\r、\t 等 JSON 特殊字符
 * 进行转义后写入目标缓冲区。
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
        default: dst[j++] = src[i]; break;
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

    char* buf = malloc(131072); /* 128 KB 缓冲区 */
    if (!buf) { pthread_mutex_unlock(&g_lock); return; }
    int pos = 0;
    int bsz = 131072;

    pos += snprintf(buf + pos, bsz - pos,
        "{\"nprocs\":%d,\"total_leaks\":%d,\"total_bytes\":%zu,\"procs\":[",
        g_nprocs, total_leaks, total_bytes);

    for (int i = 0; i < g_nprocs; i++) {
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
        pos += snprintf(buf + pos, bsz - pos,
            "%s{\"pid\":%d,\"name\":\"%s\",\"active\":%s,"
            "\"leak_count\":%d,\"total_leaked\":%zu,"
            "\"last_seen\":%ld,\"top_stack\":\"",
            i > 0 ? "," : "", p->pid, escaped,
            p->active ? "true" : "false",
            p->leak_count, p->total_leaked,
            (long)p->last_seen);
        json_escape(escaped, top_stack, sizeof(escaped));
        pos += snprintf(buf + pos, bsz - pos, "%s", escaped);
        pos += snprintf(buf + pos, bsz - pos, "\",\"leaks\":[");

        for (int j = 0; j < p->leak_count; j++) {
            mttd_leak_t* l = &p->leaks[j];
            json_escape(escaped, l->file, sizeof(escaped));
            pos += snprintf(buf + pos, bsz - pos,
                "%s{\"size\":%zu,\"file\":\"%s\",\"line\":%d,\"nframes\":%d,\"frames\":[",
                j > 0 ? "," : "", l->size, escaped, l->line, l->nframes);
            for (int k = 0; k < l->nframes; k++) {
                if (l->frames[k][0]) {
                    char fe[MTT_SYMBOL_MAX * 2];
                    json_escape(fe, l->frames[k], sizeof(fe));
                    pos += snprintf(buf + pos, bsz - pos,
                        "%s\"%s\"", k > 0 ? "," : "", fe);
                }
            }
            pos += snprintf(buf + pos, bsz - pos, "]}");
        }
        pos += snprintf(buf + pos, bsz - pos, "]}");
        pthread_mutex_unlock(&p->lock);
    }
    pos += snprintf(buf + pos, bsz - pos, "]}");
    pthread_mutex_unlock(&g_lock);

    /* 组装并发送 HTTP 响应（含 CORS 头） */
    char hdr[256];
    int hdrlen = snprintf(hdr, sizeof(hdr),
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: application/json\r\n"
        "Access-Control-Allow-Origin: *\r\n"
        "Connection: close\r\n"
        "Content-Length: %d\r\n\r\n", (int)strlen(buf));

    send(fd, hdr, hdrlen, MSG_NOSIGNAL);
    send(fd, buf, strlen(buf), MSG_NOSIGNAL);
    free(buf);
}

/**
 * 处理 HTTP 请求并路由。
 *
 * 当前支持两个路由：
 *   GET /api/data → JSON 数据（send_api_data）
 *   其他          → 看板 HTML 页面（g_dashboard_html）
 */
static void handle_http(int fd)
{
    char buf[4096];
    ssize_t n = recv(fd, buf, sizeof(buf) - 1, 0);
    if (n <= 0) { close(fd); return; }
    buf[n] = '\0';

    if (strncmp(buf, "GET /api/data", 13) == 0) {
        send_api_data(fd);
    } else {
        /* 看板 HTML 已内嵌 HTTP 头，直接 send */
        send(fd, g_dashboard_html, strlen(g_dashboard_html), MSG_NOSIGNAL);
    }
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
    mttd_proc_t* client_procs[MAX_CLIENTS]; /* 每个 fd 对应的进程上下文 */
    for (int i = 0; i < MAX_CLIENTS; i++) {
        clients[i] = -1;
        client_procs[i] = NULL;
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

        /* 接受新的 Unix Socket 连接 */
        if (FD_ISSET(unix_fd, &rfds)) {
            int cfd = accept(unix_fd, NULL, NULL);
            if (cfd >= 0) {
                set_nonblock(cfd);
                if (nclients < MAX_CLIENTS) {
                    clients[nclients] = cfd;
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
                int rc = parse_unix_client(clients[i], &proc);
                client_procs[i] = proc;
                if (rc <= 0) {
                    /* 连接关闭或出错，从活跃列表中移除 */
                    close(clients[i]);
                    for (int j = i; j < nclients - 1; j++) {
                        clients[j] = clients[j + 1];
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
    for (int i = 0; i < nclients; i++) close(clients[i]);
    for (int i = 0; i < g_nprocs; i++) {
        free(g_procs[i].leaks);
    }
    close(unix_fd);
    close(http_fd);
    unlink(MTT_SOCK_PATH);
    return 0;
}

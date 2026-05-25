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
#ifndef WITHOUT_INJECTOR
#include "injector.h"
#endif
#include "internal.h"

/* ---- 全局状态 ---- */

static mttd_proc_t g_procs[MTT_MAX_PROCS];      /* 被监控进程数组 */
static int         g_nprocs = 0;                  /* 当前监控的进程数 */
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER; /* 保护 g_procs / g_nprocs */
static volatile sig_atomic_t g_running = 1;        /* 信号控制的主循环退出标志 */

/* 运行时注入追踪 */
#ifndef WITHOUT_INJECTOR
static mttd_injected_t g_injected[MTT_MAX_INJECTED]; /* 注入记录数组 */
static int             g_ninjected = 0;               /* 当前注入数 */
#endif

/* 长期监控安全: 全局泄漏记录计数器 */
static _Atomic size_t g_total_leaks_global = 0;

/* 被清除的 PID 黑名单：/api/clear 或 /api/reset 移除的进程不可通过 HELLO 重连 */
#define MTT_BLOCKED_MAX 256
static int g_blocked_pids[MTT_BLOCKED_MAX];
static int g_nblocked = 0;

/** 检查 PID 是否在黑名单中 */
static int is_pid_blocked(int pid)
{
    for (int i = 0; i < g_nblocked; i++)
        if (g_blocked_pids[i] == pid) return 1;
    return 0;
}

/** 将 PID 加入黑名单（去重） */
static void block_pid(int pid)
{
    if (g_nblocked >= MTT_BLOCKED_MAX) return;
    if (is_pid_blocked(pid)) return;
    g_blocked_pids[g_nblocked++] = pid;
}

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
            /* 递减全局计数器：旧泄漏记录即将被释放，需减去计数防止溢出 */
            atomic_fetch_sub(&g_total_leaks_global,
                             (size_t)p->leak_count);
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
static void json_escape(char* dst, const char* src, size_t n);

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
        int newcap = p->leak_cap > 0 ? p->leak_cap * 2 : 32;
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
    /* 标记需持久化，由调用者释放锁后写入磁盘，避免持锁 I/O */
    p->dirty = 1;
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

    char escaped[512];
    json_escape(escaped, p->name, sizeof(escaped));
    fprintf(f, "{\"pid\":%d,\"name\":\"%s\",\"active\":%d,\"total_leaked\":%zu,"
            "\"last_seen\":%ld,\"leaks\":[",
            p->pid, escaped, p->active, p->total_leaked, (long)p->last_seen);

    for (int i = 0; i < p->leak_count; i++) {
        mttd_leak_t* l = &p->leaks[i];
        json_escape(escaped, l->file, sizeof(escaped));
        fprintf(f, "%s{\"size\":%zu,\"file\":\"%s\",\"line\":%d,\"nframes\":%d,\"frames\":[",
                i > 0 ? "," : "", l->size, escaped, l->line, l->nframes);
        for (int j = 0; j < l->nframes; j++) {
            char escaped_frame[MTT_SYMBOL_MAX * 2];
            json_escape(escaped_frame, l->frames[j], sizeof(escaped_frame));
            fprintf(f, "%s\"%s\"", j > 0 ? "," : "", escaped_frame);
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

        /* 简易 JSON 解析：提取 pid/name/active/total_leaked/leak_count */
        int pid = 0;
        size_t total_leaked = 0;
        int leak_count = 0;
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
        char* tlp = strstr(pp, "\"total_leaked\":");
        if (tlp) total_leaked = (size_t)atoll(tlp + 15);
        /* 统计泄漏记录条数: 每个 "size": 字段对应一条记录 */
        {
            char* sp = pp;
            while ((sp = strstr(sp, "\"size\":")) != NULL) {
                leak_count++;
                sp++;
            }
        }

        if (pid <= 1) { free(json); continue; }

        /* 跳过黑名单中的 PID */
        if (is_pid_blocked(pid)) { free(json); continue; }

        /* 检查是否已有此 PID 的记录 */
        int exists = 0;
        for (int i = 0; i < g_nprocs; i++) {
            if (g_procs[i].pid == pid) { exists = 1; break; }
        }
        if (exists) { free(json); continue; }

        /* 创建记录（标记为非活跃，等待 HELLO 恢复） */
        if (g_nprocs < MTT_MAX_PROCS) {
            mttd_proc_t* p = &g_procs[g_nprocs++];
            memset(p, 0, sizeof(*p));
            p->pid = pid;
            snprintf(p->name, sizeof(p->name), "%s", name[0] ? name : "?");
            p->active = persisted_active;
            p->total_leaked = total_leaked;
            p->leak_count = 0; /* 由实际解析决定 */
            p->last_seen = time(NULL);
            p->leak_cap = leak_count > 32 ? leak_count : 32;
            if (p->leak_cap > MTT_MAX_LEAKS) p->leak_cap = MTT_MAX_LEAKS;
            p->leaks = calloc((size_t)p->leak_cap, sizeof(mttd_leak_t));
            pthread_mutex_init(&p->lock, NULL);

            /* 解析每条泄漏记录 */
            {
                char* leakp = strstr(json, "\"leaks\":[");
                if (leakp) {
                    leakp += 8; /* 跳过 "leaks":[ */
                    char* start = leakp;
                    while (*start && p->leak_count < p->leak_cap) {
                        char* lb = strstr(start, "{\"size\":");
                        if (!lb) break;
                        mttd_leak_t* lk = &p->leaks[p->leak_count];

                        /* size */
                        char* szp = strstr(lb, "\"size\":");
                        if (szp) lk->size = (size_t)atoll(szp + 7);

                        /* file */
                        char* fp_str = strstr(lb, "\"file\":\"");
                        if (fp_str) {
                            fp_str += 8;
                            int fi = 0;
                            while (*fp_str && *fp_str != '"' && fi < 127)
                                lk->file[fi++] = *fp_str++;
                            lk->file[fi] = '\0';
                        }

                        /* line */
                        char* lnp = strstr(lb, "\"line\":");
                        if (lnp) lk->line = atoi(lnp + 7);

                        /* nframes */
                        char* nfp = strstr(lb, "\"nframes\":");
                        if (nfp) {
                            lk->nframes = atoi(nfp + 10);
                            if (lk->nframes > MTT_MAX_STACK) lk->nframes = MTT_MAX_STACK;
                            if (lk->nframes < 0) lk->nframes = 0;
                        }

                        /* frames 数组 */
                        char* frames_start = strstr(lb, "\"frames\":[");
                        if (frames_start) {
                            frames_start += 10; /* 跳过 "frames":[ */
                            char* fc = frames_start;
                            for (int fj = 0; fj < lk->nframes; ) {
                                char* fq = strchr(fc, '"');
                                if (!fq) break;
                                char* fe = strchr(fq + 1, '"');
                                if (!fe) break;
                                size_t flen = (size_t)(fe - fq - 1);
                                if (flen > MTT_SYMBOL_MAX - 1) flen = MTT_SYMBOL_MAX - 1;
                                memcpy(lk->frames[fj], fq + 1, flen);
                                lk->frames[fj][flen] = '\0';
                                fj++;
                                fc = fe + 1;
                            }
                        }

                        p->leak_count++;
                        p->total_leaked += lk->size;
                        /* 更新全局计数器 */
                        atomic_fetch_add(&g_total_leaks_global, 1);

                        /* 找下一个 leak 起始 or 数组结束 */
                        char* next = strstr(lb + 1, "{\"size\":");
                        start = next;
                    }
                }
            }

            printf("[mttd] 已加载历史记录: PID %d (%s), 总计=%zu, 泄漏=%d 条\n",
                   pid, name, p->total_leaked, p->leak_count);
        }
        free(json);
    }
    closedir(d);
}

/**
 * 检查已监控进程是否仍然存活。
 *
 * 仅在同时满足以下两个条件时才标记进程为"已退出"：
 *   1. /proc/<pid> 目录不存在（内核确认进程已消失）
 *   2. 最后一次通信距今超过宽限期（避免 /proc 暂时不可访问导致误判）
 *
 * 宽限期设为 10 秒，远大于 HELLO 的 3 秒报告间隔，
 * 确保活跃进程不会因 /proc 访问问题被误标记为退出。
 */
static void check_liveness(void)
{
    for (int i = 0; i < g_nprocs; i++) {
        if (!g_procs[i].active) continue;
        char proc_path[64];
        snprintf(proc_path, sizeof(proc_path), "/proc/%d", g_procs[i].pid);
        if (access(proc_path, F_OK) != 0) {
            /* 宽限期：最后一次通信距今不足 10 秒则暂不标记退出 */
            time_t now = time(NULL);
            if (now - g_procs[i].last_seen < 10) continue;
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
    int  skip_frames; /* LEAK sscanf 失败时置 1，跳过后续 FRAME 防止串帧 */
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
    if (n <= 0) {
        if (ctx->proc)
            fprintf(stderr, "[mttd] client fd=%d disconnected (pid=%d name=%s n=%zd errno=%d)\n",
                    fd, ctx->proc->pid, ctx->proc->name, n, errno);
        else
            fprintf(stderr, "[mttd] client fd=%d disconnected (no proc n=%zd errno=%d)\n",
                    fd, n, errno);
        *out_proc = ctx->proc;
        return (int)n;
    }

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
                fprintf(stderr, "[mttd] HELLO pid=%d name=%s\n", pid, name);
                pthread_mutex_lock(&g_lock);
                if (is_pid_blocked(pid)) {
                    fprintf(stderr, "[mttd] HELLO pid=%d ignored (blocked)\n", pid);
                    pthread_mutex_unlock(&g_lock);
                } else {
                    ctx->proc = find_or_create_proc(pid, name);
                    if (ctx->proc) ctx->proc->active = 1;
                    pthread_mutex_unlock(&g_lock);
                }
            }
        }
        else if (strncmp(line, "STAT ", 5) == 0 && ctx->proc) {
            size_t cur_bytes = 0, allocs = 0, frees = 0, vm_rss = 0;
            if (sscanf(line, "STAT %zu %zu %zu %zu",
                       &cur_bytes, &allocs, &frees, &vm_rss) >= 4) {
                pthread_mutex_lock(&ctx->proc->lock);
                ctx->proc->current_bytes = cur_bytes;
                ctx->proc->alloc_count   = allocs;
                ctx->proc->free_count    = frees;
                ctx->proc->heap_rss_kb   = vm_rss;
                pthread_mutex_unlock(&ctx->proc->lock);
                fprintf(stderr, "[mttd] STAT pid=%d cur=%zuKB allocs=%zu frees=%zu rss=%zuKB\n",
                    ctx->proc->pid, cur_bytes / 1024, allocs, frees, vm_rss);
            }
        }
        else if (strncmp(line, "LEAK ", 5) == 0 && ctx->proc) {
            mttd_leak_t leak;
            memset(&leak, 0, sizeof(leak));
            ctx->skip_frames = 1; /* 预设跳过 FRAME，sscanf 成功后清除 */
            if (sscanf(line, "LEAK %zu %127s %d %d",
                       &leak.size, leak.file, &leak.line, &leak.nframes) >= 4) {
                fprintf(stderr, "[mttd] LEAK pid=%d name=%s size=%zu file=%s:%d frames=%d\n",
                        ctx->proc->pid, ctx->proc->name,
                        leak.size, leak.file, leak.line, leak.nframes);
                if (leak.nframes > MTT_MAX_STACK) leak.nframes = MTT_MAX_STACK;
                if (leak.nframes < 0) leak.nframes = 0;
                pthread_mutex_lock(&ctx->proc->lock);
                int added = add_leak(ctx->proc, &leak);
                int should_persist = (ctx->proc->leak_count % 5 == 0);
                pthread_mutex_unlock(&ctx->proc->lock);
                ctx->skip_frames = (added != 0); /* add_leak 失败则跳过后续 FRAME */
                if (should_persist) persist_proc(ctx->proc);
            }
        }
        else if (strncmp(line, "FRAME ", 6) == 0 && ctx->proc
                 && !ctx->skip_frames) {
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
        else if (strcmp(line, "BYE") == 0) {
            if (ctx->proc) {
                fprintf(stderr, "[mttd] BYE pid=%d name=%s leak_count=%d\n",
                        ctx->proc->pid, ctx->proc->name, ctx->proc->leak_count);
                pthread_mutex_lock(&ctx->proc->lock);
                ctx->proc->active = 0; /* 标记进程已退出 */
                pthread_mutex_unlock(&ctx->proc->lock);
                persist_proc(ctx->proc); /* 退出时确保持久化 */
            }
            *out_proc = ctx->proc;
            ctx->bufpos = 0;
            ctx->proc = NULL;
            return -1; /* 通知调用者关闭 fd（由事件循环统一清理） */
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
"HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nCache-Control: no-store, max-age=0\r\nConnection: close\r\n\r\n"
"<!DOCTYPE html>\n"
"<html lang=\"zh-CN\">\n"
"<head>\n"
"<meta charset=\"UTF-8\">\n"
"<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n"
"<title>MemoryTraceTool</title>\n"
"<style>\n"
":root{\n"
"  --bg:#080b12;\n"
"  --surface:#111622;\n"
"  --surface-hover:#181d2a;\n"
"  --border:rgba(0,212,255,.07);\n"
"  --border-strong:rgba(0,212,255,.13);\n"
"  --text:#e4e7ec;\n"
"  --text2:#8892a4;\n"
"  --text3:#5e6676;\n"
"  --accent:#00d4ff;\n"
"  --green:#00e676;\n"
"  --red:#ff3b3b;\n"
"  --orange:#ffb800;\n"
"  --purple:#b388ff;\n"
"  --font:-apple-system,BlinkMacSystemFont,'Segoe UI','Noto Sans',system-ui,sans-serif;\n"
"  --mono:'Courier New','Liberation Mono','Consolas',monospace;\n"
"  --radius:4px;\n"
"}\n"
"*{margin:0;padding:0;box-sizing:border-box}\n"
"body{\n"
"  font-family:var(--font);font-size:14px;\n"
"  background:var(--bg);color:var(--text);\n"
"  min-height:100vh;display:flex;\n"
"  -webkit-font-smoothing:antialiased;\n"
"}\n"
"\n"
"/* ===== SIDEBAR ===== */\n"
".sidebar{\n"
"  width:220px;min-width:220px;\n"
"  background:var(--surface);border-right:1px solid var(--border);\n"
"  display:flex;flex-direction:column;position:sticky;top:0;height:100vh;z-index:100;\n"
"  transition:width .2s,min-width .2s;\n"
"}\n"
".sidebar.folded{width:50px;min-width:50px}\n"
".sb-brand{\n"
"  padding:14px 16px;display:flex;align-items:center;gap:9px;\n"
"  font-size:15px;font-weight:700;letter-spacing:-.2px;\n"
"  border-bottom:1px solid var(--border);\n"
"}\n"
".sb-dot{width:8px;height:8px;border-radius:50%;background:var(--green);box-shadow:0 0 6px var(--green);flex-shrink:0;transition:all .3s}\n"
".sb-dot.off{background:#444;box-shadow:none}\n"
".sidebar.folded .sb-text{display:none}\n"
".sidebar.folded .sb-brand{justify-content:center;padding:14px 8px}\n"
".sb-nav{flex:1;padding:8px 0;display:flex;flex-direction:column;gap:1px}\n"
".sb-item{\n"
"  display:flex;align-items:center;gap:9px;padding:7px 16px;\n"
"  font-size:14px;color:var(--text2);cursor:pointer;transition:all .12s;\n"
"  border-left:2px solid transparent;user-select:none;white-space:nowrap;\n"
"}\n"
".sb-item:hover{color:var(--text);background:var(--surface-hover)}\n"
".sb-item.on{color:var(--accent);border-left-color:var(--accent)}\n"
".sb-item svg{flex-shrink:0;opacity:.55}\n"
".sb-item.on svg,.sb-item:hover svg{opacity:1}\n"
".sidebar.folded .sb-item{padding:7px 10px;justify-content:center}\n"
".sidebar.folded .sb-label{display:none}\n"
".sb-toggle{\n"
"  padding:10px 16px;border-top:1px solid var(--border);\n"
"  font-size:12px;color:var(--text3);cursor:pointer;user-select:none;text-align:center;transition:color .15s;\n"
"}\n"
".sb-toggle:hover{color:var(--text)}\n"
".sidebar.folded .sb-toggle{padding:10px 6px}\n"
"\n"
"/* ===== MAIN ===== */\n"
".main{flex:1;display:flex;flex-direction:column;min-width:0}\n"
".topbar{\n"
"  padding:10px 22px;background:var(--surface);border-bottom:1px solid var(--border);\n"
"  display:flex;align-items:center;justify-content:space-between;position:sticky;top:0;z-index:50;\n"
"}\n"
".topbar-left{display:flex;align-items:center;gap:10px}\n"
".topbar-time{font-family:var(--mono);font-size:12px;color:var(--accent);font-variant-numeric:tabular-nums}\n"
".topbar-status{font-size:12px;color:var(--text2);letter-spacing:.3px}\n"
"\n"
".btn{\n"
"  background:transparent;border:1px solid var(--border-strong);color:var(--text);\n"
"  padding:5px 13px;border-radius:var(--radius);cursor:pointer;font-size:12px;\n"
"  font-family:var(--font);transition:all .12s;white-space:nowrap;\n"
"  position:relative;overflow:hidden;letter-spacing:.2px;\n"
"}\n"
".btn:hover{background:var(--surface-hover);border-color:var(--accent);color:var(--accent)}\n"
".btn:active{transform:scale(.97)}\n"
".btn.warn{border-color:var(--orange);color:var(--orange)}\n"
".btn.warn:hover{background:rgba(255,184,0,.08)}\n"
"\n"
"/* ripple */\n"
".ripple{\n"
"  position:absolute;border-radius:50%;background:rgba(0,212,255,.2);\n"
"  transform:scale(0);animation:ripple .45s ease-out;pointer-events:none;\n"
"}\n"
"@keyframes ripple{to{transform:scale(4);opacity:0}}\n"
"\n"
".content{padding:18px 22px;flex:1}\n"
"/* ===== TAB PANELS ===== */\n"
".tab-panel{animation:fadeIn .2s ease}\n"
"@keyframes fadeIn{from{opacity:.6;transform:translateY(4px)}to{opacity:1;transform:translateY(0)}}\n"
"\n"
"\n"
"/* ===== KPI ===== */\n"
".kpi-row{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin-bottom:16px}\n"
".kpi{\n"
"  background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);\n"
"  padding:14px 18px;transition:border-color .15s;position:relative;overflow:hidden;\n"
"}\n"
".kpi::after{\n"
"  content:'';position:absolute;top:0;left:0;right:0;height:1px;\n"
"  background:linear-gradient(90deg,transparent,rgba(0,212,255,.06),transparent);\n"
"}\n"
".kpi:hover{border-color:var(--border-strong)}\n"
".kpi-label{font-size:11px;color:var(--text2);text-transform:uppercase;letter-spacing:.6px;font-weight:600;margin-bottom:4px}\n"
".kpi-val{font-size:28px;font-weight:700;font-family:var(--mono);letter-spacing:-.5px;line-height:1.1;font-variant-numeric:tabular-nums}\n"
".kpi-sub{font-size:11px;color:var(--text3);margin-top:4px}\n"
".kpi:nth-child(1){border-left:2px solid var(--accent)}.kpi:nth-child(1) .kpi-val{color:var(--accent)}\n"
".kpi:nth-child(2){border-left:2px solid var(--orange)}.kpi:nth-child(2) .kpi-val{color:var(--orange)}\n"
".kpi:nth-child(3){border-left:2px solid var(--red)}.kpi:nth-child(3) .kpi-val{color:var(--red)}\n"
".kpi:nth-child(4){border-left:2px solid var(--purple)}.kpi:nth-child(4) .kpi-val{color:var(--purple)}\n"
"\n"
"/* ===== PANELS ===== */\n"
".sec{margin-bottom:14px}\n"
".sec-head{display:flex;align-items:center;gap:8px;margin-bottom:6px}\n"
".sec-head h2{font-size:14px;font-weight:600;letter-spacing:.2px}\n"
".sec-head .cnt{font-size:11px;color:var(--text3)}\n"
"\n"
".panel{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);overflow:hidden}\n"
".panel-row{display:grid;grid-template-columns:1fr;gap:14px;margin-bottom:14px}\n"
"\n"
"/* ===== TABLE ===== */\n"
"table{width:100%;border-collapse:collapse;font-variant-numeric:tabular-nums}\n"
"thead th{\n"
"  text-align:left;padding:8px 12px;background:rgba(0,0,0,.25);\n"
"  font-size:11px;font-weight:600;color:var(--text2);text-transform:uppercase;\n"
"  letter-spacing:.4px;border-bottom:1px solid var(--border);white-space:nowrap;\n"
"  font-family:var(--font);\n"
"}\n"
"tbody td{\n"
"  padding:8px 12px;font-size:13px;border-bottom:1px solid var(--border);\n"
"  white-space:nowrap;font-family:var(--mono);font-variant-numeric:tabular-nums;\n"
"}\n"
"tbody tr:last-child td{border-bottom:none}\n"
"tbody tr{transition:background .08s;cursor:default}\n"
"tbody tr:nth-child(even){background:rgba(255,255,255,.012)}\n"
"tbody tr:hover{background:var(--surface-hover)}\n"
"tbody tr.clickable{cursor:pointer}\n"
"tbody tr.clickable:hover td{color:var(--accent)}\n"
"\n"
"/* 可注入进程表保持紧凑字体 */\n"
".inj-table thead th{font-size:10px;padding:6px 8px}\n"
".inj-table tbody td{font-size:12px;padding:5px 8px}\n"
"\n"
"\n"
".badge{\n"
"  display:inline-flex;align-items:center;gap:4px;padding:1px 7px;\n"
"  border-radius:3px;font-size:11px;font-weight:600;font-family:var(--font);\n"
"}\n"
".badge-live{background:rgba(0,230,118,.08);color:var(--green);border:1px solid rgba(0,230,118,.18)}\n"
".badge-live::before{content:'';width:5px;height:5px;border-radius:50%;background:var(--green);animation:pulse 2s infinite}\n"
".badge-gone{background:rgba(255,255,255,.03);color:var(--text3)}\n"
"@keyframes pulse{0%,100%{opacity:1}50%{opacity:.35}}\n"
".badge-ok{background:rgba(0,230,118,.06);color:var(--green);font-size:11px;padding:1px 7px;border-radius:3px;font-family:var(--font)}\n"
".badge-fail{background:rgba(255,59,59,.06);color:var(--red);font-size:11px;padding:1px 7px;border-radius:3px;font-family:var(--font)}\n"
".badge-pend{background:rgba(255,184,0,.06);color:var(--orange);font-size:11px;padding:1px 7px;border-radius:3px;font-family:var(--font)}\n"
"\n"
".btn-sm{\n"
"  padding:2px 8px;font-size:11px;border-radius:3px;font-family:var(--font);\n"
"  border:1px solid var(--border-strong);background:transparent;color:var(--text);cursor:pointer;\n"
"  cursor:pointer;transition:all .12s;position:relative;overflow:hidden;\n"
"}\n"
".btn-sm:hover{background:var(--accent);color:#000;border-color:var(--accent);font-weight:600}\n"
".btn-sm:disabled{opacity:.35;cursor:not-allowed}\n"
".btn-sm:disabled:hover{background:transparent;color:var(--text);border-color:var(--border-strong)}\n"
"\n"
".cmdline{font-family:var(--mono);font-size:12px;color:var(--text3);max-width:220px;overflow:hidden;text-overflow:ellipsis;display:inline-block}\n"
"\n"
"/* ===== CONTROLS ===== */\n"
".ctrls{display:flex;gap:6px;align-items:center;margin-bottom:6px;flex-wrap:wrap}\n"
".ctrls input{\n"
"  width:200px;padding:4px 9px;border:1px solid var(--border);border-radius:3px;\n"
"  font-size:12px;background:var(--bg);color:var(--text);font-family:var(--font);\n"
"  transition:border-color .15s;\n"
"}\n"
".ctrls input:focus{outline:none;border-color:var(--accent);box-shadow:0 0 0 2px rgba(0,212,255,.3)}\n"
"button:focus-visible,.btn:focus-visible,.btn-sm:focus-visible,.pg:focus-visible,.sort:focus-visible,.sb-item:focus-visible{outline:none;box-shadow:0 0 0 2px var(--accent)}\n"
".ctrls input::placeholder{color:var(--text3)}\n"
".sort{font-size:11px;padding:2px 9px;cursor:pointer}\n"
".sort.on{background:var(--accent);color:#000;border-color:var(--accent);font-weight:600}\n"
"\n"
"/* ===== LEAK LIST ===== */\n"
".leak-card{\n"
"  background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);\n"
"  margin-bottom:6px;overflow:hidden;transition:border-color .15s;\n"
"}\n"
".leak-card:hover{border-color:var(--border-strong)}\n"
".leak-hdr{\n"
"  padding:8px 14px;display:flex;align-items:center;gap:10px;font-size:13px;\n"
"  border-bottom:1px solid var(--border);cursor:pointer;user-select:none;\n"
"  transition:background .1s;\n"
"}\n"
".leak-hdr:hover{background:var(--surface-hover)}\n"
".leak-card:not(.expanded) .leak-hdr{border-bottom-color:transparent}\n"
".leak-card .call-tree{display:none}\n"
".leak-card.expanded .call-tree{display:block}\n"
".leak-hdr::after{\n"
"  content:'\\25b6';margin-left:auto;font-size:8px;color:var(--text3);transition:transform .2s;\n"
"}\n"
".leak-card.expanded>.leak-hdr::after{transform:rotate(90deg)}\n"
".leak-hdr .sz{color:var(--red);font-weight:600;font-family:var(--mono);font-size:14px;min-width:64px;font-variant-numeric:tabular-nums}\n"
".leak-hdr .loc{color:var(--accent);font-family:var(--mono);font-size:13px}\n"
".leak-hdr .n{color:var(--orange);font-size:11px;margin-left:auto;font-weight:600}\n"
".leak-hdr .info{color:var(--text3);font-size:11px;margin-left:8px}\n"
"\n"
".call-tree{padding:2px 0;position:relative}\n"
".call-tree::before{\n"
"  content:'';position:absolute;left:26px;top:8px;bottom:8px;width:1.5px;\n"
"  background:linear-gradient(to bottom,#222 0%,var(--purple) 25%,var(--accent) 65%,var(--red) 100%);\n"
"  border-radius:1px;\n"
"}\n"
".cn{\n"
"  padding:6px 8px 6px 46px;position:relative;font-family:var(--mono);font-size:13px;\n"
"  line-height:1.35;transition:background .1s;\n"
"}\n"
".cn::before{content:'';position:absolute;left:26px;top:50%;width:10px;height:1.5px;background:var(--border-strong);border-radius:1px}\n"
".cn .fn{color:var(--text)}\n"
".cn .lib{color:var(--text3);font-size:11px;margin-left:4px}\n"
".cn.top .fn{color:var(--purple)}\n"
".cn.lk .fn{color:var(--red);font-weight:700}\n"
".cn.lk{background:rgba(255,59,59,.05);border-left:2px solid var(--red)}\n"
".cn .tag{display:inline-block;background:rgba(255,59,59,.1);color:var(--red);font-size:10px;padding:0 5px;border-radius:2px;margin-left:5px;font-weight:600}\n"
".cn[onclick]:hover{background:rgba(0,212,255,.05);border-radius:3px;cursor:pointer}\n"
".cn .src-tip{color:var(--green);font-size:12px;margin-left:6px;font-family:var(--mono)}\n"
".cn:not(.lk)::after{content:'\\25be';position:absolute;left:21px;bottom:0;font-size:7px;color:var(--accent);transform:translateY(55%);opacity:0.45;pointer-events:none}\n"
"\n"
"/* ===== PAGER ===== */\n"
".pager{display:flex;align-items:center;justify-content:center;gap:2px;margin-top:6px}\n"
".pg{\n"
"  background:transparent;border:1px solid var(--border);color:var(--text2);\n"
"  padding:2px 7px;border-radius:3px;cursor:pointer;font-size:11px;\n"
"  font-family:var(--mono);font-variant-numeric:tabular-nums;transition:all .12s;\n"
"}\n"
".pg:hover{background:var(--surface-hover);color:var(--text)}\n"
".pg.on{background:var(--accent);color:#000;border-color:var(--accent);font-weight:600}\n"
".pg:disabled{opacity:.25;cursor:not-allowed}\n"
"\n"
"/* ===== DETAIL PANEL ===== */\n"
".overlay{\n"
"  position:fixed;inset:0;background:rgba(0,0,0,.55);z-index:200;\n"
"  opacity:0;pointer-events:none;transition:opacity .25s;\n"
"}\n"
".overlay.show{opacity:1;pointer-events:auto}\n"
"\n"
".detail{\n"
"  position:fixed;top:50%;left:50%;width:700px;max-height:85vh;z-index:210;\n"
"  background:var(--surface);border:1px solid var(--border-strong);\n"
"  border-radius:8px;\n"
"  transform:translate(-50%,-50%) scale(.9);\n"
"  transition:transform .25s cubic-bezier(.4,0,.2,1),opacity .25s;\n"
"  display:flex;flex-direction:column;overflow:hidden;\n"
"  box-shadow:0 8px 48px rgba(0,0,0,.5);\n"
"  opacity:0;pointer-events:none;\n"
"}\n"
".detail.show{transform:translate(-50%,-50%) scale(1);opacity:1;pointer-events:auto}\n"
".detail-head{\n"
"  padding:16px 24px;border-bottom:1px solid var(--border);\n"
"  display:flex;align-items:center;justify-content:space-between;\n"
"  flex-shrink:0;\n"
"}\n"
".detail-head h3{font-size:16px;font-weight:600;font-family:var(--mono)}\n"
".detail-head .close{\n"
"  background:rgba(255,255,255,.05);border:1px solid var(--border-strong);\n"
"  color:var(--text2);cursor:pointer;\n"
"  font-size:16px;padding:4px 10px;border-radius:4px;transition:all .15s;\n"
"}\n"
".detail-head .close:hover{background:rgba(255,59,59,.1);color:var(--red);border-color:var(--red)}\n"
".detail-body{flex:1;overflow-y:auto;padding:16px 24px}\n"
".detail-body::-webkit-scrollbar{width:4px}\n"
".detail-body::-webkit-scrollbar-thumb{background:var(--border-strong);border-radius:2px}\n"
"\n"
".detail-stats{display:grid;grid-template-columns:repeat(4,1fr);gap:8px;margin-bottom:14px}\n"
".ds{background:rgba(0,0,0,.15);padding:10px 14px;border-radius:var(--radius);text-align:center}\n"
".ds-val{font-family:var(--mono);font-size:20px;font-weight:700;font-variant-numeric:tabular-nums}\n"
".ds-label{font-size:10px;color:var(--text3);text-transform:uppercase;letter-spacing:.4px;margin-top:2px}\n"
".ds:nth-child(1) .ds-val{color:var(--accent)}\n"
".ds:nth-child(2) .ds-val{color:var(--red)}\n"
".ds:nth-child(3) .ds-val{color:var(--orange)}\n"
".ds:nth-child(4) .ds-val{color:var(--green)}\n"
"\n"
".chart-wrap{\n"
"  background:rgba(0,0,0,.2);border:1px solid var(--border);\n"
"  border-radius:var(--radius);padding:8px;margin-bottom:14px;position:relative;user-select:none;\n"
"}\n"
".chart-wrap canvas{display:block;width:100%;height:auto;cursor:crosshair}\n"
".chart-tip{font-size:10px;color:var(--text3);text-align:center;margin-top:4px;letter-spacing:.2px;display:flex;align-items:center;justify-content:center;gap:6px}\n"
".chart-zoom-btn{font-size:11px;padding:1px 6px;border-radius:3px;border:1px solid var(--border);background:var(--surface);color:var(--text2);cursor:pointer;font-family:var(--mono);line-height:1.4}\n"
".chart-zoom-btn:hover{color:var(--accent);border-color:var(--accent)}\n"
"\n"
".leak-sec h4{font-size:12px;font-weight:600;color:var(--text2);text-transform:uppercase;letter-spacing:.4px;margin-bottom:6px}\n"
"\n"
"/* ===== TOAST ===== */\n"
".toast{\n"
"  position:fixed;bottom:20px;right:20px;\n"
"  background:var(--surface);color:var(--text);padding:7px 16px;border-radius:3px;\n"
"  font-size:12px;opacity:0;transform:translateY(4px);transition:all .2s;\n"
"  pointer-events:none;z-index:300;border:1px solid var(--border);\n"
"}\n"
".toast.show{opacity:1;transform:translateY(0)}\n"
"\n"
"/* ===== CURSOR TRAIL ===== */\n"
".trail{\n"
"  position:fixed;pointer-events:none;z-index:9999;\n"
"  font-family:'Segoe UI','Noto Sans',system-ui,sans-serif;\n"
"  font-size:18px;font-weight:700;\n"
"  color:rgba(0,212,255,.6);\n"
"  letter-spacing:3px;white-space:nowrap;\n"
"  text-shadow:0 0 14px rgba(0,212,255,.5),0 0 28px rgba(0,212,255,.2);\n"
"  transition:opacity .25s;\n"
"  will-change:transform,opacity;\n"
"}\n"
"\n"
"/* ===== EMPTY ===== */\n"
".empty{text-align:center;padding:32px 16px;color:var(--text3);font-size:13px}\n"
"\n"
"/* ===== MODAL ===== */\n"
".modal-overlay{\n"
"  position:fixed;inset:0;background:rgba(0,0,0,.6);z-index:400;\n"
"  opacity:0;pointer-events:none;transition:opacity .2s;\n"
"}\n"
".modal-overlay.show{opacity:1;pointer-events:auto}\n"
".modal-dialog{\n"
"  position:fixed;top:50%;left:50%;transform:translate(-50%,-50%) scale(.9);\n"
"  background:var(--surface);border:1px solid var(--border-strong);\n"
"  border-radius:8px;padding:32px 36px;z-index:410;\n"
"  max-width:540px;width:92%;\n"
"  opacity:0;pointer-events:none;transition:all .2s cubic-bezier(.4,0,.2,1);\n"
"}\n"
".modal-dialog.show{opacity:1;pointer-events:auto;transform:translate(-50%,-50%) scale(1)}\n"
".modal-icon{\n"
"  width:48px;height:48px;border-radius:50%;background:rgba(255,59,59,.12);\n"
"  color:var(--red);font-size:24px;font-weight:700;\n"
"  display:flex;align-items:center;justify-content:center;\n"
"  margin:0 auto 12px;font-family:var(--mono);\n"
"}\n"
".modal-title{font-size:17px;font-weight:600;text-align:center;margin-bottom:10px;color:var(--text)}\n"
".modal-body{font-size:13px;color:var(--text2);text-align:center;line-height:1.6;margin-bottom:18px}\n"
".modal-warn{color:var(--red);font-weight:600}\n"
".modal-actions{display:flex;gap:12px;justify-content:center;margin-top:4px}\n"
"\n"
"\n"
"/* ===== RESPONSIVE ===== */\n"
"\n"
".hamburger{display:none;position:fixed;top:10px;left:10px;z-index:150;background:var(--surface);border:1px solid var(--border);color:var(--text);padding:6px 10px;border-radius:var(--radius);cursor:pointer;font-size:18px}\n"
"@media(max-width:1024px){.kpi-row{grid-template-columns:1fr 1fr}.detail{width:80vw}}\n"
"@media(max-width:700px){.sidebar{display:none;position:fixed;z-index:200;top:0;left:0;height:100vh}.sidebar.open{display:flex}.hamburger{display:flex}.kpi-row{grid-template-columns:1fr}.detail{width:100vw}.panel{overflow-x:auto}}\n"
"</style>\n"
"</head>\n"
"<body>\n"
"<button class=\"hamburger\" onclick=\"var sb=document.getElementById('sidebar');sb.classList.toggle('open')\" title=\"菜单\">&#9776;</button>\n"
"\n"
"<!-- SIDEBAR -->\n"
"<aside class=\"sidebar\" id=\"sidebar\">\n"
"  <div class=\"sb-brand\"><div class=\"sb-dot\" id=\"status-dot\"></div><span class=\"sb-text\">MemoryTraceTool</span></div>\n"
"  <nav class=\"sb-nav\">\n"
"    <div class=\"sb-item on\" data-panel=\"overview\" onclick=\"switchPanel('overview')\" onkeydown=\"if(event.key==='Enter'||event.key===' ')switchPanel('overview')\" tabindex=\"0\" role=\"button\" aria-label=\"概览面板\">\n"
"      <svg width=\"14\" height=\"14\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.5\" aria-hidden=\"true\"><rect x=\"3\" y=\"3\" width=\"7\" height=\"7\" rx=\"1\"/><rect x=\"14\" y=\"3\" width=\"7\" height=\"7\" rx=\"1\"/><rect x=\"3\" y=\"14\" width=\"7\" height=\"7\" rx=\"1\"/><rect x=\"14\" y=\"14\" width=\"7\" height=\"7\" rx=\"1\"/></svg>\n"
"      <span class=\"sb-label\">概览</span>\n"
"    </div>\n"
"    <div class=\"sb-item\" data-panel=\"ranking\" onclick=\"switchPanel('ranking')\" onkeydown=\"if(event.key==='Enter'||event.key===' ')switchPanel('ranking')\" tabindex=\"0\" role=\"button\" aria-label=\"泄漏排行面板\">\n"
"      <svg width=\"14\" height=\"14\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.5\" aria-hidden=\"true\"><line x1=\"4\" y1=\"20\" x2=\"4\" y2=\"12\"/><line x1=\"10\" y1=\"20\" x2=\"10\" y2=\"7\"/><line x1=\"16\" y1=\"20\" x2=\"16\" y2=\"4\"/><line x1=\"2\" y1=\"20\" x2=\"22\" y2=\"20\"/></svg>\n"
"      <span class=\"sb-label\">泄漏排行</span>\n"
"    </div>\n"
"  </nav>\n"
"  <div class=\"sb-toggle\" onclick=\"toggleSidebar()\" onkeydown=\"if(event.key==='Enter'||event.key===' ')toggleSidebar()\" title=\"折叠/展开侧边栏\" role=\"button\" aria-label=\"折叠/展开侧边栏\" tabindex=\"0\">&laquo;</div>\n"
"</aside>\n"
"\n"
"<!-- MAIN -->\n"
"<div class=\"main\">\n"
"<div class=\"topbar\">\n"
"  <div class=\"topbar-left\">\n"
"    <span class=\"topbar-time\" id=\"clock\">--:--:--</span>\n"
"    <span class=\"topbar-stale\" id=\"stale\" style=\"font-size:11px;color:var(--text3);margin-left:4px\"></span>\n"
"    <span class=\"topbar-status\" id=\"conn-status\">在线</span>\n"
"  </div>\n"
"  <div>\n"
"    <button class=\"btn\" id=\"btn-pause\" onclick=\"toggleAuto()\">暂停刷新</button>\n"
"    <button class=\"btn\" onclick=\"refresh();loadProcs()\">立即刷新</button>\n"
"    <button class=\"btn warn\" onclick=\"openResetModal()\">重新监控</button>\n"
"    <button class=\"btn warn\" onclick=\"openClearModal()\">清除所有历史数据</button>\n"
"  </div>\n"
"</div>\n"
"\n"
"<div class=\"content\">\n"
"\n"
"<div id=\"panel-overview\" class=\"tab-panel\">\n"
"\n"
"<!-- KPI -->\n"
"<div class=\"kpi-row\">\n"
"  <div class=\"kpi\"><div class=\"kpi-label\">监控进程</div><div class=\"kpi-val\" id=\"kp-procs\">--</div><div class=\"kpi-sub\">活跃连接</div></div>\n"
"  <div class=\"kpi\"><div class=\"kpi-label\">泄漏总数</div><div class=\"kpi-val\" id=\"kp-leaks\">--</div><div class=\"kpi-sub\">可疑泄漏点</div></div>\n"
"  <div class=\"kpi\"><div class=\"kpi-label\">泄漏字节</div><div class=\"kpi-val\" id=\"kp-bytes\">--</div><div class=\"kpi-sub\">未释放内存</div></div>\n"
"  <div class=\"kpi\"><div class=\"kpi-label\">持久化</div><div class=\"kpi-val\" id=\"kp-hist\">--</div><div class=\"kpi-sub\">历史进程</div></div>\n"
"</div>\n"
"\n"
"<!-- TWO PANELS -->\n"
"<div class=\"panel-row\">\n"
"  <!-- MONITORED -->\n"
"  <div>\n"
"    <div class=\"sec-head\"><h2>被监控进程</h2><span class=\"cnt\" id=\"mc-cnt\"></span></div>\n"
"    <div class=\"panel\">\n"
"      <table>\n"
"        <thead><tr><th style=\"width:48px\">PID</th><th style=\"width:110px\">进程</th><th style=\"width:60px\">状态</th><th style=\"width:54px\">泄漏</th><th style=\"width:68px\">字节</th><th>热点函数</th><th style=\"width:56px\">活跃</th></tr></thead>\n"
"        <tbody id=\"mtb\"><tr><td colspan=\"7\"><div class=\"empty\">等待进程接入...</div></td></tr></tbody>\n"
"      </table>\n"
"    </div>\n"
"  </div>\n"
"  <!-- INJECTABLE -->\n"
"  <div>\n"
"    <div class=\"sec-head\"><h2>可注入进程</h2><span class=\"cnt\" id=\"ic-cnt\"></span></div>\n"
"    <div class=\"ctrls\"><input type=\"text\" id=\"proc-filter\" placeholder=\"搜索...\" oninput=\"debounceLoadProcs()\"></div>\n"
"    <div class=\"panel\">\n"
"      <table class=\"inj-table\">\n"
"        <thead><tr><th style=\"width:48px\">PID</th><th style=\"width:90px\">进程</th><th style=\"width:150px\">命令行</th><th style=\"width:62px\">堆</th><th style=\"width:60px\">运行</th><th style=\"width:56px\">注入</th><th style=\"width:50px\">操作</th></tr></thead>\n"
"        <tbody id=\"ptb\"><tr><td colspan=\"7\"><div class=\"empty\">加载中...</div></td></tr></tbody>\n"
"      </table>\n"
"    </div>\n"
"    <div class=\"pager\" id=\"pg\"></div>\n"
"  </div>\n"
"</div>\n"
"</div><!-- /#panel-overview -->\n"
"\n"
"<div id=\"panel-ranking\" class=\"tab-panel\" style=\"display:none\">\n"
"<div>\n"
"  <div class=\"sec-head\"><h2>泄漏排行榜</h2><span class=\"cnt\" id=\"lk-cnt\"></span></div>\n"
"  <div class=\"ctrls\">\n"
"    <input type=\"text\" id=\"leak-filter\" placeholder=\"搜索泄漏...\" oninput=\"debounceRenderLeaks()\">\n"
"    <span style=\"font-size:11px;color:var(--text3)\">排序:</span>\n"
"    <button class=\"btn sort on\" id=\"sort-bytes\" onclick=\"setSort('bytes')\">字节</button>\n"
"    <button class=\"btn sort\" id=\"sort-rate\" onclick=\"setSort('rate')\">速率</button>\n"
"    <button class=\"btn sort\" id=\"sort-count\" onclick=\"setSort('count')\">次数</button>\n"
"  </div>\n"
"  <div id=\"leak-list\"><div class=\"empty\">暂无泄漏</div></div>\n"
"</div>\n"
"\n"
"</div><!-- /#panel-ranking -->\n"
"\n"
"</div></div>\n"
"\n"
"<!-- DETAIL OVERLAY + PANEL -->\n"
"<div class=\"overlay\" id=\"overlay\" onclick=\"closeDetail()\"></div>\n"
"<div class=\"detail\" id=\"detail\">\n"
"  <div class=\"detail-head\">\n"
"    <h3 id=\"dtl-title\">进程详情</h3>\n"
"    <button class=\"close\" onclick=\"closeDetail()\">&times;</button>\n"
"  </div>\n"
"  <div class=\"detail-body\" id=\"dtl-body\"></div>\n"
"</div>\n"
"\n"
"<div class=\"toast\" id=\"toast\"></div>\n"
"<!-- Cursor trail elements -->\n"
"<div class=\"trail\" id=\"trail0\">王华是cos0</div>\n"
"<div class=\"trail\" id=\"trail1\">王华是cos0</div>\n"
"<div class=\"trail\" id=\"trail2\">王华是cos0</div>\n"
"\n"
"<script>\n"
"var autoRefresh=true,failCount=0,gLastUpdateTime=Date.now()/1000;\n"
"var gAllLeaks=[],gSortMode='bytes';\n"
"var gProcPage=1,gPageSize=15,gAllProcs=[];\n"
"var gPrevLeaked={}; /* pid -> prev total_leaked */\n"
"var gPrevTime=0;    /* timestamp of last snapshot */\n"
"var gPrevLeakMap={},gPrevLeakTime=0; /* 泄漏站点速率快照 */\n"
"var gHistory={};    /* pid -> [{t,bytes},...] */\n"
"var gDetailPid=0,gCachedProcs=null,gLastDetailSig='';\n"
"var gLoadSeq=0,toastTimer=0,gDebounceProc=0,gDebounceLeak=0,toastQueue=[],toastBusy=0;\n"
"function debounceLoadProcs(){clearTimeout(gDebounceProc);gDebounceProc=setTimeout(loadProcs,280)}\n"
"function debounceRenderLeaks(){clearTimeout(gDebounceLeak);gDebounceLeak=setTimeout(renderLeaks,280)}\n"
"\n"
"/* ===== SIDEBAR ===== */\n"
"function toggleSidebar(){var sb=document.getElementById('sidebar'),tog=sb.querySelector('.sb-toggle');sb.classList.toggle('folded');tog.innerHTML=sb.classList.contains('folded')?'&raquo;':'&laquo;'}\n"
"/* ===== TAB SWITCHING ===== */\n"
"function switchPanel(name){\n"
"  document.querySelectorAll('.sb-item').forEach(function(el){el.classList.toggle('on',el.getAttribute('data-panel')===name)});\n"
"  document.querySelectorAll('.tab-panel').forEach(function(el){el.style.display='none'});\n"
"  var panel=document.getElementById('panel-'+name);\n"
"  if(panel)panel.style.display='';\n"
"  if(name==='ranking')renderLeaks();\n"
"}\n"
"\n"
"\n"
"/* ===== RIPPLE ===== */\n"
"document.addEventListener('click',function(e){\n"
"  var el=e.target.closest('.btn,.btn-sm,.pg');\n"
"  if(!el)return;\n"
"  var r=document.createElement('span');r.className='ripple';\n"
"  var rect=el.getBoundingClientRect(),s=Math.max(rect.width,rect.height);\n"
"  r.style.width=r.style.height=s+'px';\n"
"  r.style.left=e.clientX-rect.left-s/2+'px';\n"
"  r.style.top=e.clientY-rect.top-s/2+'px';\n"
"  el.appendChild(r);setTimeout(function(){r.remove()},450);\n"
"});\n"
"\n"
"/* ===== CURSOR TRAIL: 3层lerp拖尾，20fps节流，移动渐显/静止渐消 ===== */\n"
"var trailEls=[],trailPositions=[],targetX=0,targetY=0,trailAlpha=0,trailActive=false;\n"
"var trailFadeTimer=null,trailFrameSkip=0,trailPaused=false;\n"
"var trailRunning=false,trailRafId=0,trailIdleTimer=null;\n"
"var stopTrailLoop,startTrailLoop;\n"
"(function initTrail(){\n"
"  for(var i=0;i<3;i++){\n"
"    trailEls.push(document.getElementById('trail'+i));\n"
"    trailPositions.push({x:0,y:0});\n"
"  }\n"
"  document.addEventListener('mousemove',function(e){\n"
"    targetX=e.clientX;targetY=e.clientY;trailActive=true;\n"
"    if(!trailRunning)startTrailLoop();\n"
"    trailFadeTimer&&clearTimeout(trailFadeTimer);trailIdleTimer&&clearTimeout(trailIdleTimer);\n"
"    trailFadeTimer=setTimeout(function(){trailActive=false},1200);\n"
"    trailIdleTimer=setTimeout(function(){stopTrailLoop()},30000); /* 30s闲置彻底停止 */\n"
"  });\n"
"  function tick(){\n"
"    if(!trailRunning)return;\n"
"    trailFrameSkip++;\n"
"    if(trailFrameSkip%3!==0){trailRafId=requestAnimationFrame(tick);return} /* 20fps */\n"
"    if(trailPaused){for(var i=0;i<3;i++){var el=trailEls[i];if(el)el.style.opacity='0'};trailRafId=requestAnimationFrame(tick);return}\n"
"    if(trailActive){trailAlpha=Math.min(1,trailAlpha+0.06)}\n"
"    else{trailAlpha=Math.max(0,trailAlpha-0.03)}\n"
"    if(trailAlpha<.005){for(var i=0;i<3;i++){var el=trailEls[i];if(el)el.style.opacity='0'};trailRafId=requestAnimationFrame(tick);return}\n"
"    var lag=0.08;\n"
"    for(var i=0;i<3;i++){\n"
"      var tp=trailPositions[i];\n"
"      var tx=(i===0)?targetX:trailPositions[i-1].x;\n"
"      var ty=(i===0)?targetY:trailPositions[i-1].y;\n"
"      tp.x+=(tx-tp.x)*lag;tp.y+=(ty-tp.y)*lag;\n"
"      var el=trailEls[i];if(!el)continue;\n"
"      el.style.left=tp.x+16+'px';el.style.top=tp.y+18+'px';\n"
"      el.style.opacity=trailAlpha*(0.85-i*0.2);\n"
"      el.style.transform='scale('+(1-i*0.05)+')';\n"
"      lag=Math.max(0.03,lag-0.025);\n"
"    }\n"
"    trailRafId=requestAnimationFrame(tick);\n"
"  }\n"
"  stopTrailLoop=function(){trailRunning=false;if(trailRafId){cancelAnimationFrame(trailRafId);trailRafId=0};for(var i=0;i<3;i++){var el=trailEls[i];if(el)el.style.opacity='0'}};\n"
"  startTrailLoop=function(){if(!trailRunning){trailRunning=true;trailRafId=requestAnimationFrame(tick)}};\n"
"  document.addEventListener('visibilitychange',function(){document.hidden?stopTrailLoop():startTrailLoop()});\n"
"  trailRafId=requestAnimationFrame(tick);\n"
"})();\n"
"\n"
"\n"
"/* ===== RESET MODAL ===== */\n"
"function openResetModal(){\n"
"  document.getElementById('reset-modal-overlay').classList.add('show');\n"
"  document.getElementById('reset-modal').classList.add('show');\n"
"}\n"
"function closeResetModal(){\n"
"  document.getElementById('reset-modal-overlay').classList.remove('show');\n"
"  document.getElementById('reset-modal').classList.remove('show');\n"
"}\n"
"function confirmReset(){\n"
"  var btn=document.getElementById('btn-confirm-reset');\n"
"  btn.disabled=true;btn.textContent='清除中...';\n"
"  fetch('/api/reset').then(function(r){return r.json()}).then(function(d){\n"
"    if(d.status==='ok'){\n"
"      gAllLeaks=[];gHistory={};gPrevLeaked={};gPrevTime=0;gDetailPid=0;gPrevLeakMap={};gPrevLeakTime=0;\n"
"      toast('已清除所有泄漏历史数据');\n"
"      closeResetModal();\n"
"      refresh();loadProcs();\n"
"      closeDetail();\n"
"    }else{toast('清除失败: '+(d.message||'未知错误'))}\n"
"    btn.disabled=false;btn.textContent='确认重新监控';\n"
"  }).catch(function(){\n"
"    toast('请求失败，请重试');\n"
"    btn.disabled=false;btn.textContent='确认重新监控';\n"
"  });\n"
"}\n"
"\n"
"/* ===== CLEAR MODAL ===== */\n"
"function openClearModal(){\n"
"  document.getElementById('clear-modal-overlay').classList.add('show');\n"
"  document.getElementById('clear-modal').classList.add('show');\n"
"}\n"
"function closeClearModal(){\n"
"  document.getElementById('clear-modal-overlay').classList.remove('show');\n"
"  document.getElementById('clear-modal').classList.remove('show');\n"
"}\n"
"function confirmClear(){\n"
"  var btn=document.getElementById('btn-confirm-clear');\n"
"  btn.disabled=true;btn.textContent='清除中...';\n"
"  fetch('/api/clear').then(function(r){return r.json()}).then(function(d){\n"
"    if(d.status==='ok'){\n"
"      gAllLeaks=[];gHistory={};gPrevLeaked={};gPrevTime=0;gDetailPid=0;gPrevLeakMap={};gPrevLeakTime=0;\n"
"      gCachedProcs=[];\n"
"      toast('已清除所有历史数据（含进程列表和持久化文件），刷新中...');\n"
"      closeClearModal();\n"
"      refresh();loadProcs();\n"
"      closeDetail();\n"
"    }else{toast('清除失败: '+(d.message||'未知错误'))}\n"
"    btn.disabled=false;btn.textContent='确认清除所有';\n"
"  }).catch(function(){\n"
"    toast('请求失败，请重试');\n"
"    btn.disabled=false;btn.textContent='确认清除所有';\n"
"  });\n"
"}\n"
"\n"
"/* ===== AUTO REFRESH ===== */\n"
"/* periodic cleanup of exited-PID history and resolved frames cache */\n"
"setInterval(function(){\n"
"  var live=new Set();\n"
"  if(gCachedProcs)for(var i=0;i<gCachedProcs.length;i++)live.add(gCachedProcs[i].pid);\n"
"  for(var k in gHistory){if(!live.has(+k))delete gHistory[k]}\n"
"  var rkeys=Object.keys(gResolvedFrames);\n"
"  if(rkeys.length>300){var drop=rkeys.slice(0,rkeys.length-200);for(var di=0;di<drop.length;di++)delete gResolvedFrames[drop[di]]}\n"
"},30000);\n"
"setInterval(function(){if(autoRefresh){refresh();loadProcs()}},3000);\n"
"setInterval(function(){\n"
"  var stale=Math.round(Date.now()/1000-gLastUpdateTime);\n"
"  var el=document.getElementById('stale');if(!el)return;\n"
"  if(stale>60)el.style.color='var(--orange)';else el.style.color=stale>15?'#cc0':'var(--text3)';\n"
"  el.textContent=stale>5?(autoRefresh?' (自动刷新失败 ':' (数据已过期 ')+stale+'s)':'';\n"
"},1000);\n"
"refresh();\n"
"\n"
"function toggleAuto(){\n"
"  autoRefresh=!autoRefresh;\n"
"  var btn=document.getElementById('btn-pause'),dot=document.getElementById('status-dot');\n"
"  if(autoRefresh){btn.textContent='暂停刷新';btn.classList.remove('warn');dot.classList.remove('off');refresh()}\n"
"  else{btn.textContent='恢复刷新';btn.classList.add('warn');dot.classList.add('off');document.getElementById('conn-status').textContent='已暂停'}\n"
"  toast(autoRefresh?'自动刷新已恢复':'自动刷新已暂停');\n"
"}\n"
"\n"
"function refresh(){\n"
"  fetch('/api/data').then(function(r){return r.json()}).then(function(d){\n"
"    failCount=0;document.getElementById('status-dot').classList.remove('off');\n"
"    document.getElementById('clock').textContent=new Date().toLocaleTimeString();\n"
"    document.getElementById('conn-status').textContent='在线';\n"
"    document.getElementById('kp-procs').textContent=d.nprocs;\n"
"    document.getElementById('kp-leaks').textContent=d.total_leaks;\n"
"    document.getElementById('kp-bytes').textContent=fmtBytes(d.total_bytes);\n"
"    var exited=0;for(var ei=0;ei<d.procs.length;ei++){if(!d.procs[ei].active)exited++}\n"
"    document.getElementById('kp-hist').textContent=exited;\n"
"    gCachedProcs=d.procs;\n"
"\n"
"    var now=Date.now()/1000;gLastUpdateTime=now;\n"
"    document.getElementById('stale').textContent='';\n"
"    var prevTotal=0,curTotal=0;\n"
"\n"
"    /* accumulate history & compute rates */\n"
"    for(var i=0;i<d.procs.length;i++){\n"
"      var p=d.procs[i];\n"
"      curTotal+=p.total_leaked;\n"
"      if(!gHistory[p.pid])gHistory[p.pid]=[];\n"
"      /* chart 纵轴用 current_bytes（追踪未释放）和 heap_rss（进程堆RSS）双指标 */\n"
"      gHistory[p.pid].push({t:now,bytes:p.current_bytes||0,heap:p.heap_rss_kb||0,allocs:p.alloc_count||0,frees:p.free_count||0});\n"
"      if(gHistory[p.pid].length>600)gHistory[p.pid].shift();\n"
"    }\n"
"    /* store snapshot for rate calc */\n"
"    gPrevLeaked={};gPrevTime=now;\n"
"    for(var i=0;i<d.procs.length;i++){\n"
"      var p=d.procs[i];\n"
"      gPrevLeaked[p.pid]=p.current_bytes||0;\n"
"    }\n"
"\n"
"    /* monitored table */\n"
"    var rows='';\n"
"    for(var i=0;i<d.procs.length;i++){\n"
"      var p=d.procs[i];\n"
"      var badge=p.active?'<span class=\"badge badge-live\">运行中</span>':'<span class=\"badge badge-gone\">已退出</span>';\n"
"      var seen=p.last_seen?new Date(p.last_seen*1000).toLocaleTimeString():'--';\n"
"      var hot=computeHotFunc(p.leaks);\n"
"      var rateBytes='--';\n"
"      if(gPrevLeaked&&gPrevLeaked[p.pid]!==undefined&&p.current_bytes!==undefined){\n"
"        rateBytes=fmtBytes(Math.max(0,p.current_bytes-gPrevLeaked[p.pid]));\n"
"        if(p.current_bytes>=gPrevLeaked[p.pid])rateBytes='+'+rateBytes;\n"
"      }\n"
"      var heapMB=(p.heap_rss_kb||0)>=1024?((p.heap_rss_kb||0)/1024).toFixed(1)+'MB':(p.heap_rss_kb||0)+'KB';\n"
"      var curFmt=fmtBytes(p.current_bytes||0);\n"
"      rows+='<tr class=\"clickable\" onclick=\"openDetail('+p.pid+')\">'+\n"
"        '<td>'+p.pid+'</td><td style=\"font-family:var(--font)\">'+esc(p.name)+'</td><td>'+badge+'</td>'+\n"
"        '<td>'+p.leak_count+'</td><td>'+fmtBytes(p.total_leaked)+'</td>'+\n"
"        '<td><span title=\"当前堆RSS: '+heapMB+' | 追踪未释放: '+curFmt+'\">'+curFmt+'</span></td>'+\n"
"        '<td style=\"font-family:var(--font);font-size:12px;max-width:140px;overflow:hidden;text-overflow:ellipsis\" title=\"'+escAttr(hot)+'\">'+esc(hot)+'</td>'+\n"
"        '<td style=\"font-size:11px;color:var(--text3)\">'+seen+'</td></tr>';\n"
"    }\n"
"    document.getElementById('mtb').innerHTML=rows||'<tr><td colspan=\"7\"><div class=\"empty\">等待进程接入...</div></td></tr>';\n"
"    document.getElementById('mc-cnt').textContent=d.nprocs>0?'('+d.nprocs+')':'';\n"
"\n"
"    /* build leak list (dedup by file:line per pid) */\n"
"    var leakMap={};\n"
"    for(var i=0;i<d.procs.length;i++){\n"
"      var pp=d.procs[i];\n"
"      for(var j=0;j<pp.leaks.length;j++){\n"
"        var l=pp.leaks[j];\n"
"        var key=pp.pid+':'+l.file+':'+(l.file==='?'&&l.line===0&&l.nframes>0?getTopUserFn(l):l.line);\n"
"        if(!leakMap[key])leakMap[key]={pid:pp.pid,name:pp.name,file:l.file,line:l.line,total:0,count:0,frames:l.frames,nframes:l.nframes};\n"
"        else if(leakMap[key].nframes===0&&l.nframes>0){leakMap[key].frames=l.frames;leakMap[key].nframes=l.nframes;}\n"
"        leakMap[key].total+=l.size;leakMap[key].count++;\n"
"      }\n"
"    }\n"
"    /* 计算每条泄漏站点的速率 (delta bytes / delta time) */\n"
"    var nowSec=Date.now()/1000;\n"
"    var dt=nowSec-(gPrevLeakTime||nowSec);\n"
"    if(dt<=0)dt=3;\n"
"    var prevMap=gPrevLeakMap||{};\n"
"    var keys=Object.keys(leakMap);\n"
"    for(var ki=0;ki<keys.length;ki++){\n"
"      var k=keys[ki],lk=leakMap[k];\n"
"      var prev=prevMap[k]||0;\n"
"      lk.rate=Math.max(0,(lk.total-prev))/dt;\n"
"    }\n"
"    gPrevLeakMap={};\n"
"    for(var ki=0;ki<keys.length;ki++){\n"
"      var k=keys[ki];\n"
"      gPrevLeakMap[k]=leakMap[k].total;\n"
"    }\n"
"    gPrevLeakTime=nowSec;\n"
"    gAllLeaks=Object.values(leakMap);\n"
"    /* 仅在泄漏排行面板可见时才触发 DOM 渲染，避免隐藏面板的无谓 layout */\n"
"    var rankingPanel=document.getElementById('panel-ranking');\n"
"    if(rankingPanel&&rankingPanel.style.display!=='none')renderLeaks();\n"
"    /* update detail panel if open */\n"
"    if(gDetailPid>0 && document.getElementById('detail').classList.contains('show')) renderDetailBody(gDetailPid);\n"
"  }).catch(function(){\n"
"    failCount++;document.getElementById('status-dot').classList.add('off');\n"
"    var txt='重试中...'+(failCount>1?' (x'+failCount+')':'');\n"
"    document.getElementById('conn-status').textContent=txt;\n"
"  });\n"
"}\n"
"\n"
"/* ===== LEAK RANKING ===== */\n"
"var gExpandedLeaks={},gResolvedFrames={};\n"
"function leakCardKey(l,pid){return pid+'::'+l.file+'::'+(l.file==='?'&&l.line===0&&l.nframes>0?getTopUserFn(l):l.line)}\n"
"function toggleLeakCard(key){\n"
"  if(gExpandedLeaks[key]){delete gExpandedLeaks[key]}\n"
"  else{gExpandedLeaks[key]=true}\n"
"  var expanded=!!gExpandedLeaks[key];\n"
"  var card=document.querySelector('.leak-card[data-key=\"'+CSS.escape(key)+'\"]');\n"
"  if(card){card.classList.toggle('expanded',expanded);var hdr=card.querySelector('.leak-hdr');if(hdr)hdr.setAttribute('aria-expanded',expanded?'true':'false')}\n"
"}\n"
"function resolveAndPersist(el,bin,off){\n"
"  var key=bin+':'+off;\n"
"  if(gResolvedFrames[key]){var old=el.querySelector('.src-tip');if(old)old.remove();var tip=document.createElement('span');tip.className='src-tip';tip.textContent=' @ '+gResolvedFrames[key];el.appendChild(tip);return}\n"
"  var fnEl=el.querySelector('.fn'),orig=fnEl.textContent;\n"
"  fnEl.textContent=orig+' (解析中...)';\n"
"  fetch('/api/addr2line?bin='+encodeURIComponent(bin)+'&off='+off).then(function(r){return r.json()}).then(function(d){\n"
"    gResolvedFrames[key]=d.result;fnEl.textContent=orig;\n"
"    var tip=el.querySelector('.src-tip');if(!tip){tip=document.createElement('span');tip.className='src-tip';el.appendChild(tip)}\n"
"    tip.textContent=' @ '+d.result;tip.title=d.result;\n"
"  }).catch(function(){fnEl.textContent=orig});\n"
"}\n"
"function setSort(m){\n"
"  gSortMode=m;\n"
"  document.getElementById('sort-bytes').classList.toggle('on',m==='bytes');\n"
"  document.getElementById('sort-rate').classList.toggle('on',m==='rate');\n"
"  document.getElementById('sort-count').classList.toggle('on',m==='count');\n"
"  renderLeaks();\n"
"}\n"
"\n"
"function renderLeaks(){\n"
"  var filter=(document.getElementById('leak-filter').value||'').toLowerCase();\n"
"  var arr=gAllLeaks;\n"
"  if(filter){\n"
"    arr=arr.filter(function(l){return (l.name&&l.name.toLowerCase().indexOf(filter)>=0)||(l.file&&l.file.toLowerCase().indexOf(filter)>=0)||String(l.pid).indexOf(filter)>=0});\n"
"  }\n"
"  if(gSortMode==='rate'){arr.sort(function(a,b){return b.rate-a.rate})}\n"
"  else if(gSortMode==='count'){arr.sort(function(a,b){return b.count-a.count})}\n"
"  else{arr.sort(function(a,b){return b.total-a.total})}\n"
"\n"
"  var top=arr.slice(0,15),html='';\n"
"  for(var i=0;i<top.length;i++){\n"
"    var l=top[i];\n"
"    var cardKey=leakCardKey(l,l.pid);\n"
"    var expanded=!!gExpandedLeaks[cardKey];\n"
"    var leakIdx=0;\n"
"    if(l.nframes>0){for(var j=0;j<l.nframes;j++){var pf=parseFrame(l.frames[j]||'?');var isInt=(pf.bin&&pf.bin.indexOf('libmemorytracetool')>=0)||(pf.fn&&(pf.fn.indexOf('mtt_')===0||pf.fn==='capture_stack'||pf.fn==='backtrace'));if(!isInt){leakIdx=j;break}}}\n"
"    var maxF=Math.min(l.nframes,10);\n"
"    html+='<div class=\"leak-card'+(expanded?' expanded':'')+'\" data-key=\"'+escAttr(cardKey)+'\">';\n"
"    html+='<div class=\"leak-hdr\" tabindex=\"0\" role=\"button\" aria-expanded=\"'+(expanded?'true':'false')+'\" onclick=\"toggleLeakCard(\\''+escAttr(cardKey)+'\\')\" onkeydown=\"if(event.key===\\'Enter\\'||event.key===\\' \\'){event.preventDefault();toggleLeakCard(\\''+escAttr(cardKey)+'\\')}\"><span class=\"sz\">'+fmtBytes(l.total)+'</span><span class=\"loc\">'+(l.file==='?'&&l.line===0?'?:0 <span class=\"tag\" style=\"background:rgba(255,184,0,.1);color:var(--orange)\" title=\"LD_PRELOAD 模式无法获取源文件位置\">Preload</span>':esc(l.file)+':'+l.line)+'</span><span class=\"n\">x'+l.count+'</span><span class=\"info\">PID '+l.pid+' · '+esc(l.name)+'</span></div>';\n"
"    html+='<div class=\"call-tree\">';\n"
"    if(l.nframes>0){\n"
"      for(var j=maxF-1;j>=0;j--){\n"
"        var cls=j===leakIdx?'cn lk':(j===maxF-1?'cn top':'cn');\n"
"        var parsed=parseFrame(l.frames[j]||'?');\n"
"        var resolved=gResolvedFrames[parsed.bin+':'+parsed.off]||'';\n"
"        html+='<div class=\"'+cls+'\"';\n"
"        if(parsed.bin&&parsed.off)html+=' onclick=\"event.stopPropagation();resolveAndPersist(this,\\''+escJSStr(parsed.bin)+'\\',\\''+escJSStr(parsed.off)+'\\')\" style=\"cursor:pointer\" title=\"点击解析源码\"';\n"
"        html+='><span class=\"fn\">'+esc(parsed.fn)+'</span>';\n"
"        if(parsed.lib)html+='<span class=\"lib\">'+esc(parsed.lib)+'</span>';\n"
"        if(resolved)html+='<span class=\"src-tip\"> @ '+esc(resolved)+'</span>';\n"
"        if(j===leakIdx)html+='<span class=\"tag\">泄漏点</span>';\n"
"        html+='</div>';\n"
"      }\n"
"    }else{html+='<div class=\"cn\"><span class=\"fn\" style=\"color:var(--text3)\">(无调用栈)</span></div>'}\n"
"    html+='</div></div>';\n"
"  }\n"
"  var total=arr.length,shown=filter?Math.min(top.length,15):Math.min(total,15);\n"
"  document.getElementById('leak-list').innerHTML=html||'<div class=\"empty\">'+(filter?'无匹配':'暂无泄漏')+'</div>';\n"
"  document.getElementById('lk-cnt').textContent=total>0?(filter?'(匹配'+shown+'/'+total+')':'(Top '+shown+'/'+total+')'):'';\n"
"  setTimeout(scheduleAutoResolve,500);\n"
"}\n"
"\n"
"/* ===== PROCESS LIST ===== */\n"
"function loadProcs(){\n"
"  var filter=(document.getElementById('proc-filter').value||'').toLowerCase();\n"
"  var seq=++gLoadSeq;\n"
"  fetch('/api/processes').then(function(r){return r.json()}).then(function(d){\n"
"    if(seq!==gLoadSeq)return;\n"
"    gAllProcs=d.processes;\n"
"    if(filter)gAllProcs=gAllProcs.filter(function(p){return p.name.toLowerCase().indexOf(filter)>=0});\n"
"    gProcPage=Math.min(gProcPage,Math.max(1,Math.ceil(gAllProcs.length/gPageSize)));\n"
"    renderProcPage();renderPager();\n"
"  }).catch(function(){document.getElementById('ptb').innerHTML='<tr><td colspan=\"7\"><div class=\"empty\">加载失败</div></td></tr>'});\n"
"}\n"
"\n"
"function renderProcPage(){\n"
"  var s=(gProcPage-1)*gPageSize,page=gAllProcs.slice(s,s+gPageSize),rows='';\n"
"  for(var i=0;i<page.length;i++){\n"
"    var p=page[i];\n"
"    var inj=p.injected&&p.inj_status===1?'<span class=\"badge-ok\">已注入</span>':\n"
"      (p.injected?'<span class=\"badge-fail\" title=\"'+escAttr(p.inj_err||'')+'\">失败</span>':'<span class=\"badge-pend\">未注入</span>');\n"
"    var btn=p.injected&&p.inj_status===1?'<span class=\"badge-ok\">已注入</span>':\n"
"      '<button class=\"btn-sm\" onclick=\"inject('+p.pid+',this)\">注入</button>';\n"
"    var heap=p.heap_kb>=1024?(p.heap_kb/1024).toFixed(1)+'MB':p.heap_kb+'KB';\n"
"    var uptime=fmtUptime(p.uptime_sec||0);\n"
"    var cl=p.cmdline||p.name;\n"
"    rows+='<tr>'+\n"
"      '<td>'+p.pid+'</td><td style=\"font-family:var(--font)\">'+esc(p.name)+'</td>'+\n"
"      '<td><span class=\"cmdline\" title=\"'+escAttr(cl)+'\">'+esc(cl)+'</span></td>'+\n"
"      '<td style=\"color:var(--text2)\">'+heap+'</td><td style=\"font-size:10px;color:var(--text3)\">'+uptime+'</td>'+\n"
"      '<td>'+inj+'</td><td>'+btn+'</td></tr>';\n"
"  }\n"
"  document.getElementById('ptb').innerHTML=rows||'<tr><td colspan=\"7\"><div class=\"empty\">'+(gAllProcs.length?'无匹配':'无可用进程')+'</div></td></tr>';\n"
"  document.getElementById('ic-cnt').textContent=gAllProcs.length?'('+gAllProcs.length+')':'';\n"
"}\n"
"\n"
"function renderPager(){\n"
"  var t=Math.max(1,Math.ceil(gAllProcs.length/gPageSize)),h='';\n"
"  h+='<button class=\"pg\" role=\"button\" tabindex=\"0\" '+(gProcPage<=1?'disabled':'')+' onclick=\"goPage('+(gProcPage-1)+')\">&laquo;</button>';\n"
"  /* show pages 1..8 plus ensure current page always visible */\n"
"  var shown=Math.min(8,t),pg=gProcPage;\n"
"  if(pg>8){shown=Math.min(pg+1,t);var start=Math.max(1,pg-6)}\n"
"  else{var start=1}\n"
"  for(var i=start;i<=shown;i++)h+='<button class=\"pg'+(i===pg?' on':'')+'\" onclick=\"goPage('+i+')\" role=\"button\" tabindex=\"0\">'+i+'</button>';\n"
"  if(shown<t)h+='<button class=\"pg\" onclick=\"goPage('+Math.max(9,t-3)+')\" title=\"跳转到后段\" role=\"button\" tabindex=\"0\">...'+t+'</button>';\n"
"  h+='<button class=\"pg\" role=\"button\" tabindex=\"0\" '+(gProcPage>=t?'disabled':'')+' onclick=\"goPage('+(gProcPage+1)+')\">&raquo;</button>';\n"
"  document.getElementById('pg').innerHTML=h;\n"
"}\n"
"\n"
"function goPage(n){gProcPage=n;renderProcPage();renderPager()}\n"
"\n"
"function inject(pid,btn){\n"
"  btn.disabled=true;btn.textContent='...';toast('注入 PID '+pid+' ...');\n"
"  fetch('/api/inject?pid='+pid).then(function(r){return r.json()}).then(function(d){\n"
"    if(d.status==='ok'){toast('注入成功! '+d.patched+' GOT');loadProcs()}\n"
"    else{toast('失败: '+d.error);btn.disabled=false;btn.textContent='重试'}\n"
"  }).catch(function(){toast('请求失败');btn.disabled=false;btn.textContent='重试'});\n"
"}\n"
"\n"
"loadProcs();\n"
"\n"
"/* ===== DETAIL PANEL ===== */\n"
"function openDetail(pid){\n"
"  gDetailPid=pid;\n"
"  trailPaused=true;\n"
"  chartZoom=1;chartPan=0;gLastDetailSig='';\n"
"  document.getElementById('overlay').classList.add('show');\n"
"  document.getElementById('detail').classList.add('show');\n"
"  renderDetailBody(pid);\n"
"}\n"
"\n"
"function closeDetail(){\n"
"  chartDragging=false;\n"
"  document.getElementById('overlay').classList.remove('show');\n"
"  document.getElementById('detail').classList.remove('show');\n"
"  gDetailPid=0;\n"
"  trailPaused=false;\n"
"}\n"
"\n"
"document.addEventListener('keydown',function(e){if(e.key==='Escape'){closeDetail();closeResetModal()}});\n"
"\n"
"function renderDetailBody(pid){\n"
"  if(gDetailPid!==pid)return;\n"
"  var hist=gHistory[pid]||[];\n"
"  if(!gCachedProcs){document.getElementById('dtl-title').textContent='加载中...';return}\n"
"  var proc=null;\n"
"  for(var i=0;i<gCachedProcs.length;i++){if(gCachedProcs[i].pid===pid){proc=gCachedProcs[i];break}}\n"
"  if(!proc){document.getElementById('dtl-title').textContent='PID '+pid+' (已退出)';document.getElementById('dtl-body').innerHTML='<div class=\"empty\">该进程已退出，无当前数据</div>';return}\n"
"  /* 数据未变时跳过 DOM 重建，仅刷新图表数据点 */\n"
"  var sig=proc.leak_count+':'+proc.total_leaked+':'+hist.length;\n"
"  if(sig===gLastDetailSig&&hist.length>0){var c=document.getElementById('chart');if(c){c._data=hist;drawChart(hist)};return}\n"
"  gLastDetailSig=sig;\n"
"\n"
"  document.getElementById('dtl-title').textContent=proc.name+' (PID '+pid+')';\n"
"  var rate=proc.current_bytes>0&&gPrevTime>0?'+'+fmtBytes(Math.max(0,proc.current_bytes-(gPrevLeaked[proc.pid]||0)))+'/轮':'--';\n"
"  var heapMB=proc.heap_rss_kb>=1024?((proc.heap_rss_kb)/1024).toFixed(1)+'MB':(proc.heap_rss_kb||0)+'KB';\n"
"\n"
"  var body='<div class=\"detail-stats\">'+\n"
"      '<div class=\"ds\"><div class=\"ds-val\">'+heapMB+'</div><div class=\"ds-label\">进程堆RSS</div></div>'+\n"
"      '<div class=\"ds\"><div class=\"ds-val\">'+fmtBytes(proc.current_bytes||0)+'</div><div class=\"ds-label\">追踪未释放</div></div>'+\n"
"      '<div class=\"ds\"><div class=\"ds-val\">'+proc.leak_count+'</div><div class=\"ds-label\">泄漏次数</div></div>'+\n"
"      '<div class=\"ds\"><div class=\"ds-val\">'+fmtBytes(proc.total_leaked)+'</div><div class=\"ds-label\">累计泄漏</div></div>'+\n"
"      '<div class=\"ds\"><div class=\"ds-val\">'+rate+'</div><div class=\"ds-label\">增速/轮</div></div>'+\n"
"      '<div class=\"ds\"><div class=\"ds-val\">'+(proc.active?'运行中':'已退出')+'</div><div class=\"ds-label\">状态</div></div>'+\n"
"      '</div>';\n"
"\n"
"    /* chart */\n"
"    body+='<div class=\"chart-wrap\"><canvas id=\"chart\" width=\"620\" height=\"240\"></canvas><div class=\"chart-tip\"><button id=\"chart-metric\" class=\"chart-zoom-btn\" onclick=\"toggleChartMetric()\" title=\"切换图表指标\" style=\"font-size:10px;padding:2px 8px\">进程堆RSS</button><button class=\"chart-zoom-btn\" onclick=\"chartZoomIn()\">-</button><span>'+chartZoom+'x</span><button class=\"chart-zoom-btn\" onclick=\"chartZoomOut()\">+</button><button class=\"chart-zoom-btn\" onclick=\"chartZoomReset()\">&#8634;</button><span style=\"margin-left:8px\">滚轮缩放 · 拖拽平移 · 悬停查看数值</span></div></div>';\n"
"\n"
"    /* leak details for this process */\n"
"    var leakMap={};\n"
"    for(var j=0;j<proc.leaks.length;j++){\n"
"      var l=proc.leaks[j],key=l.file+':'+(l.file==='?'&&l.line===0&&l.nframes>0?getTopUserFn(l):l.line);\n"
"      if(!leakMap[key])leakMap[key]={file:l.file,line:l.line,total:0,count:0,frames:l.frames,nframes:l.nframes};\n"
"      else if(leakMap[key].nframes===0&&l.nframes>0){leakMap[key].frames=l.frames;leakMap[key].nframes=l.nframes;}\n"
"      leakMap[key].total+=l.size;leakMap[key].count++;\n"
"    }\n"
"    var leaks=Object.values(leakMap);\n"
"    leaks.sort(function(a,b){return b.total-a.total});\n"
"    body+='<div class=\"leak-sec\"><h4>该进程泄漏明细 ('+leaks.length+' 个站点)</h4>';\n"
"    for(var j=0;j<Math.min(leaks.length,10);j++){\n"
"      var l=leaks[j],lkIdx=0;\n"
"      var cardKey=leakCardKey(l,pid);\n"
"      var expanded=!!gExpandedLeaks[cardKey];\n"
"      if(l.nframes>0){for(var k=0;k<l.nframes;k++){var pf=parseFrame(l.frames[k]||'?');if(!pf.bin||pf.bin.indexOf('libmemorytracetool')<0){if(!pf.fn||(pf.fn.indexOf('mtt_')!==0&&pf.fn!=='capture_stack'&&pf.fn!=='backtrace')){lkIdx=k;break}}}}\n"
"      var mf=Math.min(l.nframes,10);\n"
"      body+='<div class=\"leak-card'+(expanded?' expanded':'')+'\" data-key=\"'+escAttr(cardKey)+'\" style=\"margin-top:4px\">';\n"
"      body+='<div class=\"leak-hdr\" tabindex=\"0\" role=\"button\" aria-expanded=\"'+(expanded?'true':'false')+'\" onclick=\"toggleLeakCard(\\''+escAttr(cardKey)+'\\')\" onkeydown=\"if(event.key===\\'Enter\\'||event.key===\\' \\'){event.preventDefault();toggleLeakCard(\\''+escAttr(cardKey)+'\\')}\"><span class=\"sz\">'+fmtBytes(l.total)+'</span><span class=\"loc\">'+(l.file==='?'&&l.line===0?'?:0 <span class=\"tag\" style=\"background:rgba(255,184,0,.1);color:var(--orange)\" title=\"LD_PRELOAD 模式无法获取源文件位置\">Preload</span>':esc(l.file)+':'+l.line)+'</span><span class=\"n\">x'+l.count+'</span></div>';\n"
"      body+='<div class=\"call-tree\">';\n"
"      if(l.nframes>0){\n"
"        for(var k=mf-1;k>=0;k--){\n"
"          var cls=k===lkIdx?'cn lk':(k===mf-1?'cn top':'cn');\n"
"          var p2=parseFrame(l.frames[k]||'?');\n"
"          var resolved=gResolvedFrames[p2.bin+':'+p2.off]||'';\n"
"          body+='<div class=\"'+cls+'\"';\n"
"          if(p2.bin&&p2.off)body+=' onclick=\"event.stopPropagation();resolveAndPersist(this,\\''+escJSStr(p2.bin)+'\\',\\''+escJSStr(p2.off)+'\\')\" style=\"cursor:pointer\" title=\"点击解析源码\"';\n"
"          body+='><span class=\"fn\">'+esc(p2.fn)+'</span>';\n"
"          if(p2.lib)body+='<span class=\"lib\">'+esc(p2.lib)+'</span>';\n"
"          if(resolved)body+='<span class=\"src-tip\"> @ '+esc(resolved)+'</span>';\n"
"          if(k===lkIdx)body+='<span class=\"tag\">泄漏点</span>';\n"
"          body+='</div>';\n"
"        }\n"
"      }else{body+='<div class=\"cn\"><span class=\"fn\" style=\"color:var(--text3)\">(无调用栈)</span></div>'}\n"
"      body+='</div></div>';\n"
"    }\n"
"    body+='</div>';\n"
"    document.getElementById('dtl-body').innerHTML=body;\n"
"\n"
"    /* draw chart */\n"
"    setTimeout(function(){drawChart(hist)},100);\n"
"    setTimeout(scheduleAutoResolve,500);\n"
"}\n"
"\n"
"/* ===== CANVAS CHART ===== */\n"
"var chartZoom=1,chartPan=0,chartDragging=false,chartDragStart=0,chartPanStart=0;\n"
"var gChartMetric='heap'; /* heap=进程RSS | tracked=追踪未释放 | allocs=累计分配 */\n"
"function toggleChartMetric(){\n"
"  if(gChartMetric==='heap')gChartMetric='tracked';\n"
"  else if(gChartMetric==='tracked')gChartMetric='allocs';\n"
"  else gChartMetric='heap';\n"
"  var el=document.getElementById('chart-metric');\n"
"  if(el)el.textContent=gChartMetric==='heap'?'进程堆RSS':gChartMetric==='tracked'?'追踪未释放':'累计分配次数';\n"
"  var c=document.getElementById('chart');if(c&&c._data)drawChart(c._data);\n"
"}\n"
"function chartZoomIn(){if(chartZoom<32){chartZoom=Math.min(32,chartZoom*2);chartPan=Math.max(0,chartPan-2)};var c=document.getElementById('chart');if(c&&c._data)drawChart(c._data)}\n"
"function chartZoomOut(){if(chartZoom>1){chartZoom=Math.max(1,Math.floor(chartZoom/2));chartPan=0};var c=document.getElementById('chart');if(c&&c._data)drawChart(c._data)}\n"
"function chartZoomReset(){chartZoom=1;chartPan=0;var c=document.getElementById('chart');if(c&&c._data)drawChart(c._data)}\n"
"\n"
"function drawChart(data){\n"
"  var c=document.getElementById('chart');if(!c||data.length<2)return;\n"
"  var dpr=window.devicePixelRatio||1;\n"
"  var W=c.clientWidth,H=c.clientHeight;\n"
"  c.width=W*dpr;c.height=H*dpr;\n"
"  var ctx=c.getContext('2d');ctx.scale(dpr,dpr);\n"
"\n"
"  /* compute visible window */\n"
"  var totalPts=data.length;\n"
"  var winSize=Math.max(10,Math.floor(totalPts/chartZoom));\n"
"  var endIdx=totalPts-1-chartPan;\n"
"  var startIdx=Math.max(0,endIdx-winSize+1);\n"
"  if(startIdx>=endIdx){startIdx=endIdx-1;if(startIdx<0)startIdx=0}\n"
"  var vis=data.slice(startIdx,endIdx+1);\n"
"  if(vis.length<2)return;\n"
"\n"
"  /* 选择主指标: heap(进程RSS) vs tracked(追踪未释放) vs allocs(累计分配) */\n"
"  var metric=gChartMetric||'heap';\n"
"  var vals=vis.map(function(v){return metric==='heap'?(v.heap||0)*1024:metric==='allocs'?(v.allocs||0):(v.bytes||0)});\n"
"  function fmtVal(v){return metric==='allocs'?(v>=1e6?(v/1e6).toFixed(1)+'M':v>=1e3?(v/1e3).toFixed(1)+'K':String(v)):fmtBytes(v)}\n"
"  var minB=Infinity,maxB=-Infinity;\n"
"  for(var i=0;i<vals.length;i++){minB=Math.min(minB,vals[i]);maxB=Math.max(maxB,vals[i])}\n"
"  if(maxB===minB)maxB=minB+1;\n"
"\n"
"  /* grid & axes */\n"
"  var pad={l:55,r:16,t:24,b:36},pw=W-pad.l-pad.r,ph=H-pad.t-pad.b;\n"
"  ctx.clearRect(0,0,W,H);\n"
"\n"
"  /* bg fill */\n"
"  ctx.fillStyle='rgba(0,0,0,.15)';ctx.fillRect(pad.l,pad.t,pw,ph);\n"
"\n"
"  /* grid lines */\n"
"  ctx.strokeStyle='rgba(0,212,255,.04)';ctx.lineWidth=.5;\n"
"  var ySteps=5;\n"
"  for(var i=0;i<=ySteps;i++){\n"
"    var y=pad.t+(ph/ySteps)*i;\n"
"    ctx.beginPath();ctx.moveTo(pad.l,y);ctx.lineTo(W-pad.r,y);ctx.stroke();\n"
"    var val=minB+(maxB-minB)*(ySteps-i)/ySteps;\n"
"    ctx.fillStyle='var(--text3)';ctx.font='9px var(--mono)';ctx.textAlign='right';\n"
"    ctx.fillStyle='#8892a4';ctx.font='11px var(--mono)';ctx.fillText(fmtVal(val),pad.l-8,y-2);\n"
"  }\n"
"  var timeSpan=(vis[vis.length-1].t-vis[0].t);\n"
"  var xSteps=Math.min(7,Math.max(3,Math.floor(pw/80)));\n"
"  var xFmt;\n"
"  if(timeSpan<3600){xFmt=function(d){return d.toLocaleTimeString()}}\n"
"  else if(timeSpan<86400){xFmt=function(d){var p=d.toLocaleTimeString().split(':');return p[0]+':'+p[1]}}\n"
"  else{xFmt=function(d){return (d.getMonth()+1)+'-'+d.getDate()+' '+d.toLocaleTimeString().split(':').slice(0,2).join(':')}}\n"
"  /* date range annotation */\n"
"  var d0=new Date(vis[0].t*1000),d1=new Date(vis[vis.length-1].t*1000);\n"
"  ctx.fillStyle='#8892a4';ctx.font='10px var(--mono)';ctx.textAlign='left';\n"
"  ctx.fillText((d0.getMonth()+1)+'-'+d0.getDate()+' ~ '+(d1.getMonth()+1)+'-'+d1.getDate(),pad.l,pad.t-2);\n"
"  for(var i=0;i<=xSteps;i++){\n"
"    var xi=Math.floor(i*(vis.length-1)/Math.max(1,xSteps));\n"
"    var x=pad.l+(pw/(Math.max(1,vis.length-1)))*xi;\n"
"    ctx.strokeStyle='rgba(0,212,255,.04)';ctx.lineWidth=.5;\n"
"    ctx.beginPath();ctx.moveTo(x,pad.t);ctx.lineTo(x,H-pad.b);ctx.stroke();\n"
"    var d=new Date(vis[xi].t*1000);\n"
"    ctx.fillStyle='#8892a4';ctx.font='11px var(--mono)';ctx.textAlign='center';\n"
"    ctx.fillText(xFmt(d),x,H-pad.b+6);\n"
"  }\n"
"\n"
"  /* area fill */\n"
"  ctx.beginPath();\n"
"  for(var i=0;i<vis.length;i++){\n"
"    var sx=pad.l+(pw/(vis.length-1))*i,sy=pad.t+ph-((vals[i]-minB)/(maxB-minB))*ph;\n"
"    if(i===0)ctx.moveTo(sx,sy);else ctx.lineTo(sx,sy);\n"
"  }\n"
"  ctx.lineTo(pad.l+(pw/(vis.length-1))*(vis.length-1),pad.t+ph);\n"
"  ctx.lineTo(pad.l,pad.t+ph);ctx.closePath();\n"
"  var grad=ctx.createLinearGradient(0,pad.t,0,pad.t+ph);\n"
"  var clr=metric==='heap'?'rgba(0,212,255,.15)':metric==='allocs'?'rgba(0,255,136,.15)':'rgba(255,184,0,.15)';\n"
"  grad.addColorStop(0,clr);grad.addColorStop(1,'rgba(0,212,255,0)');\n"
"  ctx.fillStyle=grad;ctx.fill();\n"
"\n"
"  /* line */\n"
"  ctx.beginPath();ctx.strokeStyle=metric==='heap'?'#00d4ff':metric==='allocs'?'#00ff88':'#ffb800';ctx.lineWidth=1.5;ctx.lineJoin='round';\n"
"  for(var i=0;i<vis.length;i++){\n"
"    var sx=pad.l+(pw/(vis.length-1))*i,sy=pad.t+ph-((vals[i]-minB)/(maxB-minB))*ph;\n"
"    if(i===0)ctx.moveTo(sx,sy);else ctx.lineTo(sx,sy);\n"
"  }\n"
"  ctx.stroke();\n"
"\n"
"  /* last point dot */\n"
"  var lastVal=metric==='allocs'?(vis[vis.length-1].allocs||0):(metric==='heap'?(vis[vis.length-1].heap||0)*1024:(vis[vis.length-1].bytes||0));\n"
"  var lx=pad.l+pw,ly=pad.t+ph-((lastVal-minB)/(maxB-minB))*ph;\n"
"  ctx.beginPath();ctx.arc(lx,ly,3.5,0,Math.PI*2);ctx.fillStyle='#00d4ff';ctx.fill();\n"
"  ctx.beginPath();ctx.arc(lx,ly,7,0,Math.PI*2);ctx.fillStyle='rgba(0,212,255,.2)';ctx.fill();\n"
"\n"
"  /* zoom info */\n"
"  ctx.fillStyle='#8892a4';ctx.font='11px var(--mono)';ctx.textAlign='right';\n"
"  ctx.fillText(chartZoom+'x',W-pad.r-4,pad.t+10);\n"
"\n"
"  /* store chart state */\n"
"  c._data=data;c._minB=minB;c._maxB=maxB;c._pad=pad;c._vis=vis;c._pw=pw;c._ph=ph;\n"
"}\n"
"\n"
"/* chart interactions - dynamic canvas lookup fixes null-ref bug */\n"
"(function(){\n"
"  /* wheel zoom: only when mouse is on the chart canvas */\n"
"  document.addEventListener('wheel',function(e){\n"
"    if(!e.target.closest('#chart'))return;\n"
"    var c=document.getElementById('chart');\n"
"    if(!c||!c.closest('.detail.show'))return;\n"
"    e.preventDefault();\n"
"    var rect=c.getBoundingClientRect();\n"
"    var oldZoom=chartZoom,oldPan=chartPan;\n"
"    if(e.deltaY<0){chartZoom=Math.min(20,chartZoom*1.3)}else{chartZoom=Math.max(1,chartZoom/1.3)}\n"
"    if(c._data){\n"
"      var total=c._data.length,oldWin=Math.max(10,Math.floor(total/oldZoom));\n"
"      chartPan=Math.max(0,Math.min(total-oldWin,chartPan));\n"
"    }\n"
"    drawChart(c._data||[]);\n"
"  },{passive:false});\n"
"\n"
"  /* drag pan: mousedown on chart starts drag */\n"
"  document.addEventListener('mousedown',function(e){\n"
"    if(!e.target.closest('#chart'))return;\n"
"    if(chartZoom<=1)return;\n"
"    var c=document.getElementById('chart');\n"
"    chartDragging=true;chartDragStart=e.clientX;chartPanStart=chartPan;\n"
"    c.style.cursor='grabbing';\n"
"  });\n"
"  document.addEventListener('mousemove',function(e){\n"
"    if(!chartDragging)return;\n"
"    var c=document.getElementById('chart');\n"
"    var dx=e.clientX-chartDragStart;\n"
"    if(c&&c._data){\n"
"      var total=c._data.length,win=Math.max(10,Math.floor(total/chartZoom));\n"
"      var dp=Math.round(dx/c.clientWidth*win);\n"
"      chartPan=Math.max(0,Math.min(total-win,chartPanStart+dp));\n"
"    }\n"
"    drawChart(c&&c._data||[]);\n"
"  });\n"
"  document.addEventListener('mouseup',function(){\n"
"    chartDragging=false;\n"
"    var c=document.getElementById('chart');\n"
"    if(c)c.style.cursor='crosshair';\n"
"  });\n"
"\n"
"  /* hover crosshair: rAF-debounced, only on chart canvas */\n"
"  var chartHoverPending=0,chartHoverArgs=null;\n"
"  document.addEventListener('mousemove',function(e){\n"
"    if(chartDragging)return;\n"
"    if(!e.target.closest('#chart'))return;\n"
"    var c=document.getElementById('chart');\n"
"    if(!c||!c._vis)return;\n"
"    var rect=c.getBoundingClientRect(),mx=e.clientX-rect.left;\n"
"    var pad=c._pad;if(!pad||mx<pad.l||mx>pad.l+c._pw)return;\n"
"    var vis=c._vis,idx=Math.round((mx-pad.l)/c._pw*(vis.length-1));\n"
"    if(idx<0||idx>=vis.length)return;\n"
"    chartHoverArgs=[c,vis,pad,idx];\n"
"    if(!chartHoverPending){chartHoverPending=1;requestAnimationFrame(function(){\n"
"      chartHoverPending=0;var a=chartHoverArgs;if(!a)return;\n"
"      c=a[0];vis=a[1];pad=a[2];idx=a[3];\n"
"      drawChart(c._data);\n"
"      var ctx=c.getContext('2d');\n"
"      var cx=pad.l+(c._pw/(Math.max(1,vis.length-1)))*idx;\n"
"      var cy=pad.t+c._ph-((vis[idx].bytes-c._minB)/(c._maxB-c._minB))*c._ph;\n"
"      ctx.strokeStyle='rgba(0,212,255,.5)';ctx.lineWidth=1;\n"
"      ctx.beginPath();ctx.moveTo(cx,pad.t);ctx.lineTo(cx,pad.t+c._ph);ctx.stroke();\n"
"      ctx.beginPath();ctx.arc(cx,cy,4,0,Math.PI*2);ctx.fillStyle='#00d4ff';ctx.fill();\n"
"\n"
"      /* tooltip */\n"
"      var d=new Date(vis[idx].t*1000);\n"
"      var tw=ctx.measureText(d.toLocaleTimeString()+'  '+fmtBytes(vis[idx].bytes)).width;\n"
"      ctx.fillStyle='rgba(17,22,34,.9)';ctx.fillRect(cx-tw/2-6,cy-16,tw+12,22);\n"
"      ctx.fillStyle='#e4e7ec';ctx.font=\"11px 'Courier New','Liberation Mono','Consolas',monospace\";ctx.textAlign='center';\n"
"      ctx.fillText(d.toLocaleTimeString()+'  '+fmtBytes(vis[idx].bytes),cx,cy-2);\n"
"    })};\n"
"  });\n"
"})();\n"
"\n"
"/* canvas resize observer - redraw chart when container size changes */\n"
"if(window.ResizeObserver){\n"
"  new ResizeObserver(function(){\n"
"    var c=document.getElementById('chart');\n"
"    if(c&&c._data&&c.closest('.detail.show'))drawChart(c._data);\n"
"  }).observe(document.querySelector('.chart-wrap')||document.body);\n"
"}\n"
"\n"
"/* ===== HELPERS ===== */\n"
"/* 为 LD_PRELOAD 模式 (?:0) 提取首个用户帧函数名作为去重键 */\n"
"function getTopUserFn(l){\n"
"  if(!l.nframes)return'';\n"
"  for(var j=0;j<l.nframes;j++){\n"
"    var pf=parseFrame(l.frames[j]||'');\n"
"    var isInt=(pf.bin&&pf.bin.indexOf('libmemorytracetool')>=0)||(pf.fn&&(pf.fn.indexOf('mtt_')===0||pf.fn==='capture_stack'||pf.fn==='backtrace'));\n"
"    if(!isInt)return pf.fn||'';\n"
"  }\n"
"  return'';\n"
"}\n"
"function computeHotFunc(leaks){\n"
"  var map={};\n"
"  for(var i=0;i<leaks.length;i++){\n"
"    for(var j=0;j<leaks[i].nframes;j++){\n"
"      var pf=parseFrame(leaks[i].frames[j]||'');\n"
"      if(!pf.fn||pf.fn==='?'||pf.fn.indexOf('mtt_')===0||pf.fn==='capture_stack'||pf.fn==='backtrace')continue;\n"
"      map[pf.fn]=(map[pf.fn]||0)+leaks[i].size;\n"
"    }\n"
"  }\n"
"  var best='(none)',bestSz=0;\n"
"  for(var k in map){if(map[k]>bestSz){bestSz=map[k];best=k}}\n"
"  return best;\n"
"}\n"
"\n"
"function parseFrame(raw){\n"
"  if(!raw)return{fn:'?',lib:'',bin:'',off:''};\n"
"  var parts=raw.split('|'),display=parts[0]||raw;\n"
"  /* 统一格式: func+0xOFFSET (libname) */\n"
"  var m=display.match(/^(.+)\\+(0x[0-9a-fA-F]+)\\s+\\((.+?)\\)\\s*$/);\n"
"  if(m)return{fn:m[1]+'+'+m[2],lib:m[3],bin:parts[1]||'',off:parts[2]||''};\n"
"  /* 旧格式兼容: func (libname) */\n"
"  m=display.match(/^(.+?)\\s+\\((.+?)\\)\\s*$/);\n"
"  if(m)return{fn:m[1],lib:m[2],bin:parts[1]||'',off:parts[2]||''};\n"
"  /* 旧格式兼容: binary(+0xOFFSET) */\n"
"  m=display.match(/^(.+?)\\((.+?)\\)\\s*$/);\n"
"  if(m)return{fn:m[1],lib:'',bin:parts[1]||'',off:parts[2]||''};\n"
"  return{fn:display,lib:'',bin:parts[1]||'',off:parts[2]||''};\n"
"}\n"
"\n"
"function resolveFrame(el,bin,off){\n"
"  if(!bin||!off)return;\n"
"  var fnEl=el.querySelector('.fn'),orig=fnEl.textContent;\n"
"  fnEl.textContent=orig+' (解析中...)';\n"
"  fetch('/api/addr2line?bin='+encodeURIComponent(bin)+'&off='+off).then(function(r){return r.json()}).then(function(d){\n"
"    fnEl.textContent=orig;var tip=el.querySelector('.src-tip');\n"
"    if(!tip){tip=document.createElement('span');tip.className='src-tip';el.appendChild(tip)}\n"
"    tip.textContent=' @ '+d.result;tip.title=d.result;\n"
"  }).catch(function(){fnEl.textContent=orig});\n"
"}\n"
"\n"
"function fmtBytes(b){\n"
"  if(b<1024)return b+' B';if(b<1048576)return(b/1024).toFixed(1)+' KB';\n"
"  if(b<1073741824)return(b/1048576).toFixed(1)+' MB';return(b/1073741824).toFixed(2)+' GB';\n"
"}\n"
"\n"
"function fmtUptime(s){\n"
"  if(s<60)return s+'s';if(s<3600)return Math.floor(s/60)+'m';\n"
"  if(s<86400)return Math.floor(s/3600)+'h';return Math.floor(s/86400)+'d';\n"
"}\n"
"\n"
"function esc(s){if(!s)return'';return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/\"/g,'&quot;')}\n"
"function escAttr(s){if(!s)return'';return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/\"/g,'&quot;').replace(/'/g,'&#39;')}\n"
"function escJSStr(s){if(!s)return'';return s.replace(/\\\\/g,'\\\\\\\\').replace(/'/g,\"\\\\'\").replace(/&/g,'&amp;').replace(/\"/g,'&quot;').replace(/</g,'&lt;').replace(/>/g,'&gt;')}\n"
"\n"
"function toast(msg){\n"
"  toastQueue.push(msg);\n"
"  if(toastBusy)return;\n"
"  flushToast();\n"
"}\n"
"function flushToast(){\n"
"  if(toastQueue.length===0){toastBusy=0;return}\n"
"  toastBusy=1;\n"
"  var msg=toastQueue.shift();\n"
"  var t=document.getElementById('toast');t.textContent=msg;t.classList.add('show');\n"
"  clearTimeout(toastTimer);\n"
"  toastTimer=setTimeout(function(){t.classList.remove('show');setTimeout(flushToast,150)},2000);\n"
"}\n"
"</script>\n"
"\n"
"<!-- RESET CONFIRMATION MODAL -->\n"
"<div class=\"modal-overlay\" id=\"reset-modal-overlay\" onclick=\"closeResetModal()\"></div>\n"
"<div class=\"modal-dialog\" id=\"reset-modal\">\n"
"  <div class=\"modal-icon\">!</div>\n"
"  <h3 class=\"modal-title\">确认重新监控</h3>\n"
"  <p class=\"modal-body\">重新监控将<span class=\"modal-warn\">清除所有已记录的泄漏数据</span>，包括历史泄漏记录和调用栈信息。<br>已注入进程的注入状态会保留，下次内存分配时将自动重新报告。</p>\n"
"  <div class=\"modal-actions\">\n"
"    <button class=\"btn\" onclick=\"closeResetModal()\">取消</button>\n"
"    <button class=\"btn warn\" id=\"btn-confirm-reset\" onclick=\"confirmReset()\">确认重新监控</button>\n"
"  </div>\n"
"</div>\n"
"\n"
"<!-- CLEAR ALL CONFIRMATION MODAL -->\n"
"<div class=\"modal-overlay\" id=\"clear-modal-overlay\" onclick=\"closeClearModal()\"></div>\n"
"<div class=\"modal-dialog\" id=\"clear-modal\">\n"
"  <div class=\"modal-icon\">!!</div>\n"
"  <h3 class=\"modal-title\">确认清除所有历史数据</h3>\n"
"  <p class=\"modal-body\">此操作将<span class=\"modal-warn\">移除所有进程记录、泄漏数据、注入记录</span>，并<span class=\"modal-warn\">删除磁盘持久化文件</span>。<br>该操作不可撤销，已注入的进程不受影响，下次内存分配时将重新报告。</p>\n"
"  <div class=\"modal-actions\">\n"
"    <button class=\"btn\" onclick=\"closeClearModal()\">取消</button>\n"
"    <button class=\"btn warn\" id=\"btn-confirm-clear\" onclick=\"confirmClear()\">确认清除所有</button>\n"
"  </div>\n"
"</div>\n"
"\n"
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

        /* 获取热点函数摘要：遍历所有泄漏和栈帧，跳过 libmemorytracetool 内部帧 */
        char top_stack[256] = "(none)";
        int found_user_frame = 0;
        for (int j = 0; j < p->leak_count && !found_user_frame; j++) {
            for (int k = 0; k < p->leaks[j].nframes && !found_user_frame; k++) {
                const char* f = p->leaks[j].frames[k];
                if (!f[0]) continue;
                /* 跳过内部帧: libmemorytracetool, mtt_*, capture_stack, backtrace */
                if (strstr(f, "libmemorytracetool")) continue;
                if (strncmp(f, "mtt_", 4) == 0) continue;
                if (strstr(f, "capture_stack")) continue;
                if (strstr(f, "backtrace")) continue;
                snprintf(top_stack, sizeof(top_stack), "%s", f);
                found_user_frame = 1;
            }
        }

        char escaped[512];
        json_escape(escaped, p->name, sizeof(escaped));
        truncated |= (safe_append(buf, &pos, JSON_BUF_SIZE,
            "%s{\"pid\":%d,\"name\":\"%s\",\"active\":%s,"
            "\"leak_count\":%d,\"total_leaked\":%zu,"
            "\"heap_rss_kb\":%zu,\"current_bytes\":%zu,"
            "\"alloc_count\":%zu,\"free_count\":%zu,"
            "\"last_seen\":%ld,\"top_stack\":\"",
            i > 0 ? "," : "", p->pid, escaped,
            p->active ? "true" : "false",
            p->leak_count, p->total_leaked,
            p->heap_rss_kb, p->current_bytes,
            p->alloc_count, p->free_count,
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

/** libmemorytracetool.so 的搜索路径（按优先级排列） */
static const char* default_lib_paths[] = {
    "/usr/local/lib/libmemorytracetool.so",
    "/usr/lib/libmemorytracetool.so",
    NULL
};

/** 解析出注入库的绝对路径。按优先级搜索：安装路径 → mttd 相对路径。 */
static int resolve_lib_path(char* out, size_t out_sz)
{
    /* 第一优先级：绝对安装路径 */
    for (int i = 0; default_lib_paths[i]; i++) {
        char* resolved = realpath(default_lib_paths[i], NULL);
        if (resolved) {
            strncpy(out, resolved, out_sz - 1);
            out[out_sz - 1] = '\0';
            free(resolved);
            return 0;
        }
    }

    /* 第二优先级：从 mttd 自身路径推导（开发场景：build/mttd → lib/libmemorytracetool.so） */
    char self_exe[512];
    ssize_t n = readlink("/proc/self/exe", self_exe, sizeof(self_exe) - 1);
    if (n > 0) {
        self_exe[n] = '\0';
        char* slash = strrchr(self_exe, '/');
        if (slash) {
            *slash = '\0';
            char rel[640];
            snprintf(rel, sizeof(rel), "%s/../lib/libmemorytracetool.so", self_exe);
            char* resolved = realpath(rel, NULL);
            if (resolved) {
                strncpy(out, resolved, out_sz - 1);
                out[out_sz - 1] = '\0';
                free(resolved);
                return 0;
            }
        }
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
    char cmdline[256];       /* /proc/<pid>/cmdline，NULL字节替换为空格 */
    unsigned long uptime_sec; /* 进程运行时长（秒） */
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

    /* 读取系统运行时长（秒），用于计算进程运行时长 */
    double sys_uptime = 0.0;
    {
        FILE* fu = fopen("/proc/uptime", "r");
        if (fu) { fscanf(fu, "%lf", &sys_uptime); fclose(fu); }
    }

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
            unsigned long starttime = 0;
            char sline[1024];
            if (fgets(sline, sizeof(sline), fs)) {
                char* rp = strrchr(sline, ')');       /* 跳过进程名 "(name)" */
                if (rp) {
                    /* 字段(紧随 ')' 之后): state(1) ppid(2) … starttime(20)，
                     * 共 20 个字段，state 用 %c 读取，starttime 用 %lu，
                     * 中间 18 个字段用 %*s 跳过避免类型溢出。 */
                    sscanf(rp + 1, " %c %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %lu",
                           &state, &starttime);
                }
            }
            fclose(fs);
            if (state == 'Z' || state == 'X' || state == 'T') continue;

            /* 计算运行时长 = 当前时间 - 启动时间（单位:秒） */
            long ticks_per_sec = sysconf(_SC_CLK_TCK);
            if (ticks_per_sec <= 0) ticks_per_sec = 100;
            unsigned long uptime_sec = (starttime > 0 && sys_uptime > 0)
                ? (unsigned long)(sys_uptime - (double)starttime / (double)ticks_per_sec) : 0;

            /* 读取 cmdline（NULL 字节替换为空格）*/
            char cmdline[256] = "";
            char cl_path[64];
            snprintf(cl_path, sizeof(cl_path), "/proc/%d/cmdline", pid);
            FILE* fcl = fopen(cl_path, "r");
            if (fcl) {
                size_t nrd = fread(cmdline, 1, sizeof(cmdline) - 1, fcl);
                fclose(fcl);
                for (size_t ci = 0; ci < nrd; ci++)
                    if (cmdline[ci] == '\0') cmdline[ci] = ' ';
                cmdline[nrd] = '\0';
                /* trim trailing spaces */
                size_t clen = strlen(cmdline);
                while (clen > 0 && cmdline[clen - 1] == ' ') cmdline[--clen] = '\0';
            }

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
            pi->uptime_sec = uptime_sec;
            snprintf(pi->name, sizeof(pi->name), "%s", comm);
            snprintf(pi->cmdline, sizeof(pi->cmdline), "%s", cmdline);
            pthread_mutex_lock(&g_lock);
#ifndef WITHOUT_INJECTOR
            for (int i = 0; i < g_ninjected; i++) {
                if (g_injected[i].pid == pid) {
                    pi->inj_status = g_injected[i].inject_status;
                    snprintf(pi->inj_err, sizeof(pi->inj_err), "%s", g_injected[i].inject_err);
                    break;
                }
            }
#endif
            pthread_mutex_unlock(&g_lock);
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
        char esc_cmdline[640];
        json_escape(esc_cmdline, pi->cmdline, sizeof(esc_cmdline));
        safe_append(buf, &pos, size,
            "{\"pid\":%d,\"name\":\"%s\",\"state\":\"%c\","
            "\"injected\":%s,\"inj_status\":%d,\"inj_err\":\"%s\","
            "\"heap_kb\":%lu,\"cmdline\":\"%s\",\"uptime_sec\":%lu}",
            pi->pid, pi->name, pi->state,
            pi->inj_status == 1 ? "true" : "false",
            pi->inj_status, pi->inj_err,
            pi->heap_kb, esc_cmdline, pi->uptime_sec);
    }
    safe_append(buf, &pos, size, "]}");
    free(procs);

    send_all(fd, buf, pos);
}

#ifndef WITHOUT_INJECTOR
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
                char timebuf[64];
                strftime(timebuf, sizeof(timebuf), "%c",
                         localtime(&g_injected[i].inject_time));
                snprintf(resp, sizeof(resp),
                    "{\"pid\":%d,\"status\":\"already_injected\","
                    "\"error\":\"Already injected at %s\"}",
                    pid, timebuf);
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
        if (n > 0 && n < (int)sizeof(resp)) send_all(fd, resp, (size_t)n);
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
        if (hdrlen > 0 && hdrlen < (int)sizeof(hdr)) send_all(fd, hdr, (size_t)hdrlen);
        if (n > 0) send_all(fd, resp, (size_t)n);
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
        if (n > 0 && n < (int)sizeof(resp)) send_all(fd, resp, (size_t)n);
        return;
    }

    /* fork 子进程执行注入（避免 ptrace 阻塞主事件循环） */
    int pipefd[2];
    if (pipe(pipefd) == -1) {
        int n = snprintf(resp, sizeof(resp),
            "HTTP/1.1 500 Internal Error\r\nContent-Type: application/json\r\n"
            "Access-Control-Allow-Origin: *\r\nConnection: close\r\n\r\n"
            "{\"pid\":%d,\"status\":\"fail\",\"error\":\"pipe() failed\"}", pid);
        if (n > 0 && n < (int)sizeof(resp)) send_all(fd, resp, (size_t)n);
        return;
    }

    pid_t child = fork();
    if (child == -1) {
        close(pipefd[0]); close(pipefd[1]);
        int n = snprintf(resp, sizeof(resp),
            "HTTP/1.1 500 Internal Error\r\nContent-Type: application/json\r\n"
            "Access-Control-Allow-Origin: *\r\nConnection: close\r\n\r\n"
            "{\"pid\":%d,\"status\":\"fail\",\"error\":\"fork() failed\"}", pid);
        if (n > 0 && n < (int)sizeof(resp)) send_all(fd, resp, (size_t)n);
        return;
    }

    if (child == 0) {
        /* ---- 子进程: 执行注入 ---- */
        close(pipefd[0]);
        alarm(MTT_INJECT_TIMEOUT_SEC);
        inject_result_t r = inject_library(pid, lib_path);
        alarm(0);
        /* alarm(0) 取消定时器但不清除已 pending 的 SIGALRM。
           若 SIGALRM 恰好在 alarm(0) 之前被 pending，继续写管道
           会在信号递送时被 SIGALRM 杀掉，导致父进程收到超时错误。
           这里主动检查 pending 信号以避免该竞态。 */
        {
            sigset_t pending;
            sigemptyset(&pending);
            if (sigpending(&pending) == 0 && sigismember(&pending, SIGALRM)) {
                _exit(1); /* 超时: alarm 恰好在取消前触发 */
            }
        }
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

    /* 轮询子进程退出（每 100ms），避免长时间阻塞事件循环 */
    int wstatus = 0;
    int poll_count = 0;
    int max_polls = MTT_INJECT_TIMEOUT_SEC * 10;
    while (poll_count < max_polls) {
        pid_t w = waitpid(child, &wstatus, WNOHANG);
        if (w == child) break;
        if (w < 0) break;
        usleep(100000);
        poll_count++;
    }

    if (rbytes != sizeof(result)) {
        /* 子进程可能崩溃或管道中断 */
        int n = snprintf(resp, sizeof(resp),
            "HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=utf-8\r\n"
            "Access-Control-Allow-Origin: *\r\nConnection: close\r\n\r\n"
            "{\"pid\":%d,\"status\":\"fail\",\"error\":\"Injector child failed\"}",
            pid);
        if (n > 0 && n < (int)sizeof(resp)) send_all(fd, resp, (size_t)n);
        return;
    }

    /* 记录注入结果（g_lock 保护，防止与 send_api_processes 数据竞争） */
    pthread_mutex_lock(&g_lock);
    /* 检查是否已有此 PID 的注入记录，存在则更新而非追加 */
    int existing = -1;
    for (int i = 0; i < g_ninjected; i++) {
        if (g_injected[i].pid == pid) { existing = i; break; }
    }
    if (existing >= 0) {
        g_injected[existing].inject_time = time(NULL);
        g_injected[existing].inject_status = (result.status == INJECT_OK) ? 1 : 2;
        g_injected[existing].lib_base = result.lib_base;
        g_injected[existing].patched_count = result.patched_count;
        snprintf(g_injected[existing].inject_err,
                 sizeof(g_injected[existing].inject_err),
                 "%s", result.err_msg);
    } else if (g_ninjected < MTT_MAX_INJECTED) {
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
    pthread_mutex_unlock(&g_lock);

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
}
#endif /* WITHOUT_INJECTOR */

#ifndef WITHOUT_INJECTOR
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
#endif /* WITHOUT_INJECTOR */

/**
 * GET /api/reset — 清除所有泄漏历史数据。
 *
 * 释放所有被监控进程的泄漏记录数组，归零计数器，
 * 但保留 PID/进程名/活跃状态，已注入进程下次分配内存时会通过 HELLO 重新初始化。
 */
static void handle_api_reset(int fd)
{
    int removed = 0;

    pthread_mutex_lock(&g_lock);

    /* 释放所有泄漏数据 */
    for (int i = 0; i < g_nprocs; i++) {
        free(g_procs[i].leaks);
        g_procs[i].leaks = NULL;
        g_procs[i].leak_count = 0;
        g_procs[i].leak_cap = 0;
        g_procs[i].total_leaked = 0;
    }

    /* 移除已退出进程（active==0），仅保留仍在运行的 */
    int kept = 0;
    for (int i = 0; i < g_nprocs; i++) {
        if (g_procs[i].active) {
            if (kept != i) g_procs[kept] = g_procs[i];
            kept++;
        } else {
            /* 销毁已退出进程的互斥锁，加入黑名单防止 HELLO 重连 */
            block_pid(g_procs[i].pid);
            pthread_mutex_destroy(&g_procs[i].lock);
            removed++;
        }
    }
    g_nprocs = kept;

    atomic_store(&g_total_leaks_global, 0);
    pthread_mutex_unlock(&g_lock);

    /* 删除磁盘上所有持久化 JSON 文件 */
    const char* logdir = get_log_dir();
    DIR* d = opendir(logdir);
    if (d) {
        struct dirent* de;
        while ((de = readdir(d))) {
            if (de->d_name[0] == '.') continue;
            char path[512];
            snprintf(path, sizeof(path), "%s/%s", logdir, de->d_name);
            unlink(path);
        }
        closedir(d);
    }

    char resp[256];
    int n = snprintf(resp, sizeof(resp),
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: application/json; charset=utf-8\r\n"
        "Connection: close\r\n\r\n"
        "{\"status\":\"ok\",\"message\":\"cleared, removed %d dead processes\"}",
        removed);
    if (n > 0 && n < (int)sizeof(resp))
        send_all(fd, resp, (size_t)n);
}

/**
 * 清除所有历史数据（比 reset 更彻底）。
 *
 * 操作内容：
 *   1. 释放所有进程的泄漏数据并销毁互斥锁（包括活跃进程）
 *   2. 清空进程列表和注入记录
 *   3. 删除磁盘上所有持久化 JSON 文件
 *   4. 重置全局计数器
 */
static void handle_api_clear(int fd)
{
    int cleared_procs = 0;
    int cleared_injected = 0;

    pthread_mutex_lock(&g_lock);

    /* 释放所有进程（包括活跃进程），销毁互斥锁，加入黑名单防止 HELLO 重连 */
    for (int i = 0; i < g_nprocs; i++) {
        block_pid(g_procs[i].pid);
        free(g_procs[i].leaks);
        g_procs[i].leaks = NULL;
        pthread_mutex_destroy(&g_procs[i].lock);
        cleared_procs++;
    }
    g_nprocs = 0;

    /* 清空注入记录 */
    cleared_injected = g_ninjected;
    g_ninjected = 0;

    atomic_store(&g_total_leaks_global, 0);
    pthread_mutex_unlock(&g_lock);

    /* 删除磁盘上所有持久化 JSON 文件 */
    const char* logdir = get_log_dir();
    DIR* d = opendir(logdir);
    if (d) {
        struct dirent* de;
        while ((de = readdir(d))) {
            if (de->d_name[0] == '.') continue;
            char path[512];
            snprintf(path, sizeof(path), "%s/%s", logdir, de->d_name);
            unlink(path);
        }
        closedir(d);
    }

    char resp[512];
    int n = snprintf(resp, sizeof(resp),
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: application/json; charset=utf-8\r\n"
        "Connection: close\r\n\r\n"
        "{\"status\":\"ok\",\"message\":\"cleared %d processes and %d injection records\"}",
        cleared_procs, cleared_injected);
    if (n > 0 && n < (int)sizeof(resp))
        send_all(fd, resp, (size_t)n);
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
 *   GET /api/reset      → 清除泄漏历史（handle_api_reset）
 *   GET /api/clear      → 清除所有历史数据含进程列表（handle_api_clear）
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
    } else if (strncmp(buf, "GET /api/injected", 17) == 0) {
#ifndef WITHOUT_INJECTOR
        /* /api/injected 必须放在 /api/inject 之前，否则被短前缀截获 */
        send_api_injected(fd);
#else
        const char* noinj_resp =
            "HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=utf-8\r\n"
            "Access-Control-Allow-Origin: *\r\nConnection: close\r\n\r\n"
            "{\"injected\":[]}";
        send_all(fd, noinj_resp, strlen(noinj_resp));
#endif
    } else if (strncmp(buf, "GET /api/inject", 15) == 0) {
#ifndef WITHOUT_INJECTOR
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
#else
        const char* noinj_err =
            "HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=utf-8\r\n"
            "Access-Control-Allow-Origin: *\r\nConnection: close\r\n\r\n"
            "{\"status\":\"fail\",\"error\":\"injector not compiled (WITHOUT_INJECTOR=1)\"}";
        send_all(fd, noinj_err, strlen(noinj_err));
#endif
    } else if (strncmp(buf, "GET /api/reset", 14) == 0) {
        handle_api_reset(fd);
    } else if (strncmp(buf, "GET /api/clear", 14) == 0) {
        handle_api_clear(fd);
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

    struct sigaction sa = {0};
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT,  &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
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
    if (listen(unix_fd, 32) < 0) { perror("unix listen"); goto cleanup; }
    printf("[mttd] Unix socket: %s\n", MTT_SOCK_PATH);

    /* ---- HTTP Socket 初始化 ---- */
    int http_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (http_fd < 0) { perror("tcp socket"); goto cleanup; }

    int opt = 1;
    setsockopt(http_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in http_addr = {0};
    http_addr.sin_family = AF_INET;
    http_addr.sin_addr.s_addr = INADDR_ANY;
    http_addr.sin_port = htons(port);

    if (bind(http_fd, (struct sockaddr*)&http_addr, sizeof(http_addr)) < 0) {
        perror("http bind"); goto cleanup;
    }
    if (listen(http_fd, 32) < 0) { perror("http listen"); goto cleanup; }
    printf("[mttd] HTTP Dashboard: http://0.0.0.0:%d\n", port);

    /* ---- 客户端追踪数组 ---- */
    enum { MAX_CLIENTS = 32 };
    int clients[MAX_CLIENTS];
    int nclients = 0;
    unix_client_ctx_t client_ctxs[MAX_CLIENTS];
    mttd_proc_t* client_procs[MAX_CLIENTS];
    time_t client_conn_time[MAX_CLIENTS];
    for (int i = 0; i < MAX_CLIENTS; i++) {
        clients[i] = -1;
        client_procs[i] = NULL;
        client_conn_time[i] = 0;
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
            int timed_out = 0;
            if (clients[i] > 0) {
                if (client_procs[i]) {
                    if (now - client_procs[i]->last_seen > MTT_CLIENT_TIMEOUT_S)
                        timed_out = 1;
                } else {
                    /* 未完成 HELLO 握手的连接：基于 accept 时间超时 */
                    if (client_conn_time[i] > 0
                        && now - client_conn_time[i] > MTT_CLIENT_TIMEOUT_S)
                        timed_out = 1;
                }
            }
            if (timed_out) {
                shutdown(clients[i], SHUT_RDWR);
                close(clients[i]);
                for (int j = i; j < nclients - 1; j++) {
                    clients[j] = clients[j + 1];
                    client_ctxs[j] = client_ctxs[j + 1];
                    client_procs[j] = client_procs[j + 1];
                    client_conn_time[j] = client_conn_time[j + 1];
                }
                nclients--;
                continue;
            }
            i++;
        }

        /* 接受新的 Unix Socket 连接 */
        if (FD_ISSET(unix_fd, &rfds)) {
            int cfd = accept(unix_fd, NULL, NULL);
            if (cfd >= 0) {
                fprintf(stderr, "[mttd] new unix client fd=%d\n", cfd);
                set_nonblock(cfd);
                set_recv_timeout(cfd, MTT_CLIENT_TIMEOUT_S);
                if (nclients < MAX_CLIENTS) {
                    clients[nclients] = cfd;
                    memset(&client_ctxs[nclients], 0, sizeof(unix_client_ctx_t));
                    client_procs[nclients] = NULL;
                    client_conn_time[nclients] = time(NULL);
                    nclients++;
                } else {
                    fprintf(stderr, "[mttd] client slots full, rejecting fd=%d\n", cfd);
                    close(cfd); /* 客户端数已满 */
                }
            }
        }

        /* 接受新的 HTTP 连接（短连接，一次请求-响应即关闭） */
        if (FD_ISSET(http_fd, &rfds)) {
            int cfd = accept(http_fd, NULL, NULL);
            if (cfd >= 0) {
                /* 设置发送超时（5 秒），防止慢客户端阻塞事件循环 */
                struct timeval tv;
                tv.tv_sec = 5;
                tv.tv_usec = 0;
                setsockopt(cfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
                handle_http(cfd);
            }
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
                    fprintf(stderr, "[mttd] closing client fd=%d rc=%d (pid=%d name=%s)\n",
                            clients[i], rc,
                            proc ? proc->pid : -1,
                            proc ? proc->name : "?");
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

cleanup:
    if (unix_fd >= 0) close(unix_fd);
    if (http_fd >= 0) close(http_fd);
    unlink(MTT_SOCK_PATH);
    return 1;
}

/*
 * MemoryTraceTool — IPC 客户端（被监控进程 → 守护进程报告链路）。
 *
 * 通过 Unix Domain Socket 连接到 mttd 守护进程，
 * 使用基于文本行的协议发送泄漏报告。
 *
 * 协议格式：
 *   HELLO <pid> <进程名>\n        — 握手，标识进程身份
 *   LEAK <size> <file> <line> <栈帧数>\n — 泄漏基本信息
 *   FRAME <idx> <符号>\n          — 调用栈帧（每条 LEAK 后可跟多条 FRAME）
 *   BYE\n                         — 进程即将退出（最终报告）
 *
 * 本文件提供两个入口：
 *   - mtt_client_report():       中间报告，关闭连接时不含 BYE
 *   - mtt_client_report_final(): 最终报告，发送 BYE 后关闭
 *
 * 缺陷修复 #1: 使用 send_all 替换裸 send 防止部分写入。
 * 缺陷修复 #2: 添加 shutdown() 优雅关闭连接。
 * 缺陷修复 #3: 修复 backtrace_symbols 返回值释放方式。
 * 缺陷修复 #4: 修复 socket 泄漏（错误路径 close 保护）。
 * 缺陷修复 #23: 遍历桶时逐锁收集记录，安全读取链表。
 */
#define _GNU_SOURCE
#include "internal.h"
#include "daemon.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <execinfo.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <errno.h>

/* 缓存的套接字文件描述符，避免重复连接 */
static int g_sock_fd = -1;

/**
 * 安全的整行发送（处理部分写入和 EINTR）。
 *
 * 缺陷修复 #1: 替换裸 send() 调用，确保完整发送。
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
 * 使用 dladdr 将栈帧地址解析为人类可读的符号名称。
 *
 * 格式: "显示名|二进制路径|文件偏移"
 */
static void resolve_frame_symbol(void* addr, char* out, size_t out_size)
{
    Dl_info info;
    if (dladdr(addr, &info)) {
        const char* fullpath = info.dli_fname ? info.dli_fname : "??";
        const char* basename = strrchr(fullpath, '/');
        if (basename) basename++; else basename = fullpath;

        /* 计算文件内偏移（运行时地址 - 加载基地址） */
        ptrdiff_t file_off = (char*)addr - (char*)info.dli_fbase;

        if (info.dli_sname) {
            /* 有符号名：计算函数内偏移 */
            ptrdiff_t func_off = (char*)addr - (char*)info.dli_saddr;
            if (func_off > 0)
                snprintf(out, out_size, "%s+%#tx (%s)|%s|%#tx",
                         info.dli_sname, func_off, basename, fullpath, file_off);
            else
                snprintf(out, out_size, "%s (%s)|%s|%#tx",
                         info.dli_sname, basename, fullpath, file_off);
        } else {
            /* 无符号名但有文件信息，尝试 backtrace_symbols 补充符号名 */
            char* fallback = NULL;
            char** syms = backtrace_symbols(&addr, 1);
            if (syms && syms[0]) {
                char* paren = strchr(syms[0], '(');
                char* plus  = strchr(syms[0], '+');
                if (paren && plus && plus > paren) {
                    size_t name_len = (size_t)(plus - paren - 1);
                    if (name_len > 0 && name_len < 256) {
                        fallback = raw_malloc(name_len + 1);
                        if (fallback) {
                            memcpy(fallback, paren + 1, name_len);
                            fallback[name_len] = '\0';
                        }
                    }
                }
                if (fallback) {
                    snprintf(out, out_size, "%s+%#tx (%s)|%s|%#tx",
                             fallback, file_off, basename, fullpath, file_off);
                    raw_free(fallback);
                } else {
                    snprintf(out, out_size, "%s(+%#tx)|%s|%#tx",
                             basename, file_off, fullpath, file_off);
                }
                /* 缺陷修复 #3: 使用 free() 释放 backtrace_symbols 返回的内存 */
                free(syms);
            } else {
                snprintf(out, out_size, "%s(+%#tx)|%s|%#tx",
                         basename, file_off, fullpath, file_off);
            }
        }
    } else {
        /* dladdr 完全失败，fallback 到 backtrace_symbols */
        char** syms = backtrace_symbols(&addr, 1);
        if (syms && syms[0]) {
            snprintf(out, out_size, "%s||", syms[0]);
            free(syms);
        } else {
            snprintf(out, out_size, "%p||", addr);
        }
    }
}

/**
 * 连接到 mttd 守护进程的 Unix Domain Socket。
 */
static int connect_daemon(void)
{
    if (g_sock_fd >= 0) return g_sock_fd;

    g_sock_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (g_sock_fd < 0) return -1;

    struct sockaddr_un addr = {0};
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, MTT_SOCK_PATH, sizeof(addr.sun_path) - 1);

    if (connect(g_sock_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(g_sock_fd);
        g_sock_fd = -1;
        return -1;
    }

    /* 解析进程名：读取 /proc/<pid>/exe 软链接目标，提取纯文件名 */
    char exe_path[256];
    snprintf(exe_path, sizeof(exe_path), "/proc/%d/exe", getpid());
    char exe_name[256] = {0};
    ssize_t len = readlink(exe_path, exe_name, sizeof(exe_name) - 1);
    if (len > 0) {
        exe_name[len] = '\0';
        const char* base = strrchr(exe_name, '/');
        if (base) {
            memmove(exe_name, base + 1, strlen(base + 1) + 1);
        }
    } else {
        snprintf(exe_name, sizeof(exe_name), "process_%d", getpid());
    }

    char msg[512];
    int n = snprintf(msg, sizeof(msg), "HELLO %d %s\n", getpid(), exe_name);
    if (n > 0 && n < (int)sizeof(msg))
        send_all(g_sock_fd, msg, (size_t)n);

    return g_sock_fd;
}

/**
 * 通用的泄漏报告发送函数。
 *
 * 缺陷修复 #23: 逐锁收集记录到临时数组，避免无锁遍历链表。
 * 每个分段锁只持有一小段时间，收集完即释放。
 *
 * @param is_final  1=最终报告（发送BYE），0=中间报告
 */
static void do_client_report(int is_final)
{
    mtt_ensure_init();
    mtt_state_t* s = mtt_state_get();

    int fd = connect_daemon();
    if (fd < 0) return; /* 守护进程不可达，静默跳过 */

    /* 收集所有泄漏记录（逐锁遍历，避免长时间持锁） */
    int nleaks = 0;
    mtt_entry_t** entries = raw_malloc(MTT_MAX_LEAKS_PER_PROC * sizeof(mtt_entry_t*));
    if (!entries) { shutdown(fd, SHUT_RDWR); close(fd); g_sock_fd = -1; return; }

    for (unsigned lock_idx = 0; lock_idx < MTT_LOCK_STRIPES
         && nleaks < MTT_MAX_LEAKS_PER_PROC; lock_idx++) {
        pthread_mutex_lock(&s->bucket_locks[lock_idx]);
        for (unsigned b = lock_idx; b < s->bucket_count
             && nleaks < MTT_MAX_LEAKS_PER_PROC; b += MTT_LOCK_STRIPES) {
            mtt_entry_t* e = s->buckets[b];
            while (e && nleaks < MTT_MAX_LEAKS_PER_PROC) {
                entries[nleaks++] = e;
                e = e->next;
            }
        }
        pthread_mutex_unlock(&s->bucket_locks[lock_idx]);
    }

    /* 序列化并发送每条泄漏 */
    for (int i = 0; i < nleaks; i++) {
        mtt_entry_t* e = entries[i];

        char line[4096];
        int n = snprintf(line, sizeof(line),
            "LEAK %zu %s %d %d\n", e->size, e->file, e->line, e->stack_frames);
        if (n > 0 && n < (int)sizeof(line))
            send_all(fd, line, (size_t)n);

        /* 解析调用栈帧地址为可读符号 */
        for (int j = 0; j < e->stack_frames; j++) {
            char resolved[MTT_SYMBOL_MAX];
            resolve_frame_symbol(e->stack[j], resolved, sizeof(resolved));
            n = snprintf(line, sizeof(line), "FRAME %d %s\n", j, resolved);
            if (n > 0 && n < (int)sizeof(line))
                send_all(fd, line, (size_t)n);
        }
    }

    if (is_final) {
        send_all(fd, "BYE\n", 4);
    }

    /* 缺陷修复 #2: shutdown 后关闭，确保数据发送完毕 */
    shutdown(fd, SHUT_RDWR);
    close(fd);
    g_sock_fd = -1;

    raw_free(entries);
}

/**
 * 发送中间泄漏报告到守护进程。
 */
void mtt_client_report(void)
{
    do_client_report(0);
}

/**
 * 发送最终泄漏报告到守护进程（进程退出时调用）。
 */
void mtt_client_report_final(void)
{
    do_client_report(1);
}

/* ---- 周期性报告（实时看板） ---- */

static pthread_t g_reporter_thread;
static volatile int g_reporter_running = 1;

/** 后台报告线程：每 3 秒向守护进程推送当前泄漏数据 */
static void* reporter_thread_func(void* arg)
{
    (void)arg;
    while (g_reporter_running) {
        sleep(3);
        if (g_reporter_running)
            do_client_report(0);
    }
    return NULL;
}

/** 启动周期性报告线程（mtt_ensure_init 之后调用） */
void mtt_start_periodic_report(void)
{
    pthread_create(&g_reporter_thread, NULL, reporter_thread_func, NULL);
}

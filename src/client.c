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

/* 缓存的套接字文件描述符，避免重复连接 */
static int g_sock_fd = -1;

/**
 * 连接到 mttd 守护进程的 Unix Domain Socket。
 *
 * 连接成功后发送 HELLO 消息，其中包含进程 PID 和从
 * /proc/<pid>/exe 读取的进程名。在连接建立后缓存 socket fd，
 * 后续中间报告可能复用此连接（当前实现每次关闭后重建）。
 *
 * @return socket fd (>=0) 表示成功，-1 表示守护进程不可达
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
            /* memmove 处理重叠内存（同一数组内移动） */
            memmove(exe_name, base + 1, strlen(base + 1) + 1);
        }
    } else {
        /* /proc/<pid>/exe 不可读时的 fallback */
        snprintf(exe_name, sizeof(exe_name), "process_%d", getpid());
    }

    char msg[512];
    int n = snprintf(msg, sizeof(msg), "HELLO %d %s\n", getpid(), exe_name);
    send(g_sock_fd, msg, n, MSG_NOSIGNAL);

    return g_sock_fd;
}

/**
 * 发送中间泄漏报告到守护进程。
 *
 * 遍历所有哈希桶收集当前泄漏记录，序列化后发送。
 * 关闭连接时**不发送** BYE 消息 — 守护进程会保持该进程状态为 ACTIVE。
 *
 * 适用于：
 *   - SIGUSR1 信号触发（常驻进程周期性报告）
 *   - 程序逻辑中主动调用的 mtt_report_to_daemon()
 */
void mtt_client_report(void)
{
    mtt_ensure_init();
    mtt_state_t* s = mtt_state_get();

    int fd = connect_daemon();
    if (fd < 0) return; /* 守护进程不可达，静默跳过 */

    /* 收集所有泄漏记录到临时数组（避免在遍历时被锁阻塞） */
    int nleaks = 0;
    mtt_entry_t** entries = raw_malloc(MTT_MAX_LEAKS_PER_PROC * sizeof(mtt_entry_t*));
    if (!entries) return;

    for (unsigned b = 0; b < s->bucket_count && nleaks < MTT_MAX_LEAKS_PER_PROC; b++) {
        mtt_entry_t* e = s->buckets[b];
        while (e && nleaks < MTT_MAX_LEAKS_PER_PROC) {
            entries[nleaks++] = e;
            e = e->next;
        }
    }

    /* 序列化并发送每条泄漏 */
    for (int i = 0; i < nleaks; i++) {
        mtt_entry_t* e = entries[i];

        char line[4096];
        int n = snprintf(line, sizeof(line),
            "LEAK %zu %s %d %d\n", e->size, e->file, e->line, e->stack_frames);
        send(fd, line, n, MSG_NOSIGNAL);

        /* 解析调用栈帧地址为符号字符串 */
        if (e->stack_frames > 0) {
            char** symbols = backtrace_symbols(e->stack, e->stack_frames);
            if (symbols) {
                for (int j = 0; j < e->stack_frames; j++) {
                    int n2 = snprintf(line, sizeof(line),
                        "FRAME %d %s\n", j, symbols[j] ? symbols[j] : "??");
                    send(fd, line, n2, MSG_NOSIGNAL);
                }
                raw_free(symbols);
            }
        }
    }

    /* 关闭连接但不发送 BYE — 进程仍在运行 */
    close(fd);
    g_sock_fd = -1;

    raw_free(entries);
}

/**
 * 发送最终泄漏报告到守护进程（进程退出时调用）。
 *
 * 与 mtt_client_report 的区别在于关闭连接前会发送 BYE 消息，
 * 守护进程收到 BYE 后将该进程标记为 DONE（不再活跃）。
 *
 * 由 atexit 回调或进程退出路径调用。
 */
void mtt_client_report_final(void)
{
    mtt_ensure_init();
    mtt_state_t* s = mtt_state_get();

    int fd = connect_daemon();
    if (fd < 0) return;

    /* 收集所有泄漏记录 */
    int nleaks = 0;
    mtt_entry_t** entries = raw_malloc(MTT_MAX_LEAKS_PER_PROC * sizeof(mtt_entry_t*));
    if (!entries) return;

    for (unsigned b = 0; b < s->bucket_count && nleaks < MTT_MAX_LEAKS_PER_PROC; b++) {
        mtt_entry_t* e = s->buckets[b];
        while (e && nleaks < MTT_MAX_LEAKS_PER_PROC) {
            entries[nleaks++] = e;
            e = e->next;
        }
    }

    for (int i = 0; i < nleaks; i++) {
        mtt_entry_t* e = entries[i];

        char line[4096];
        int n = snprintf(line, sizeof(line),
            "LEAK %zu %s %d %d\n", e->size, e->file, e->line, e->stack_frames);
        send(fd, line, n, MSG_NOSIGNAL);

        if (e->stack_frames > 0) {
            char** symbols = backtrace_symbols(e->stack, e->stack_frames);
            if (symbols) {
                for (int j = 0; j < e->stack_frames; j++) {
                    int n2 = snprintf(line, sizeof(line),
                        "FRAME %d %s\n", j, symbols[j] ? symbols[j] : "??");
                    send(fd, line, n2, MSG_NOSIGNAL);
                }
                raw_free(symbols);
            }
        }
    }

    /* 发送 BYE 标记进程退出 */
    send(fd, "BYE\n", 4, MSG_NOSIGNAL);
    close(fd);
    g_sock_fd = -1;

    raw_free(entries);
}

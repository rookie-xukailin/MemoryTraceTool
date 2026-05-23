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

/* 缓存的套接字文件描述符，避免重复连接。
 * 由 g_sock_lock 保护，防止周期报告线程与 atexit 并发 double-close。 */
static int g_sock_fd = -1;
static pthread_mutex_t g_sock_lock = PTHREAD_MUTEX_INITIALIZER;

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
 * 统一输出格式: "函数+偏移 (库名)|二进制路径|文件偏移"
 * 三项组件始终齐全——函数名、偏移量、库名缺一不可。
 */
static void resolve_frame_symbol(void* addr, char* out, size_t out_size)
{
    char        func_name[256] = {0};
    const char* lib_name = "??";
    const char* bin_path = "";
    ptrdiff_t   func_off = 0;
    ptrdiff_t   file_off = 0;

    Dl_info info;
    if (dladdr(addr, &info)) {
        bin_path = info.dli_fname ? info.dli_fname : "??";
        /* 提取库/可执行文件基础名 */
        const char* slash = strrchr(bin_path, '/');
        lib_name = slash ? slash + 1 : bin_path;
        /* 文件内偏移（运行时地址 - 加载基地址） */
        file_off = (char*)addr - (char*)info.dli_fbase;

        if (info.dli_sname) {
            /* dladdr 提供符号名：计算函数内偏移，负值钳位为 0 */
            size_t nlen = strlen(info.dli_sname);
            if (nlen >= sizeof(func_name)) nlen = sizeof(func_name) - 1;
            memcpy(func_name, info.dli_sname, nlen);
            func_name[nlen] = '\0';
            func_off = (char*)addr - (char*)info.dli_saddr;
            if (func_off < 0) func_off = 0;
        } else {
            /* 无符号名，尝试 backtrace_symbols 提取函数名 */
            char** syms = backtrace_symbols(&addr, 1);
            if (syms && syms[0]) {
                char* paren = strchr(syms[0], '(');
                char* plus  = strchr(syms[0], '+');
                if (paren && plus && plus > paren) {
                    size_t nlen = (size_t)(plus - paren - 1);
                    if (nlen > 0 && nlen < sizeof(func_name)) {
                        memcpy(func_name, paren + 1, nlen);
                        func_name[nlen] = '\0';
                    }
                }
                free(syms);
            }
            /* 仍无符号名则用库名作为函数名 */
            if (!func_name[0]) {
                size_t llen = strlen(lib_name);
                if (llen >= sizeof(func_name)) llen = sizeof(func_name) - 1;
                memcpy(func_name, lib_name, llen);
                func_name[llen] = '\0';
            }
            /* 无 dli_saddr 则用文件偏移近似函数偏移 */
            func_off = file_off;
        }
    } else {
        /* dladdr 失败，从 backtrace_symbols 解析 */
        char** syms = backtrace_symbols(&addr, 1);
        if (syms && syms[0]) {
            /* 格式: "path(func+offset) [addr]" 或 "path(func) [addr]" */
            char* paren = strchr(syms[0], '(');
            char* plus  = paren ? strchr(paren, '+') : NULL;
            char* rparen = paren ? strchr(paren, ')') : NULL;

            if (paren && plus && rparen && plus > paren && plus < rparen) {
                /* 提取函数名 */
                size_t nlen = (size_t)(plus - paren - 1);
                if (nlen >= sizeof(func_name)) nlen = sizeof(func_name) - 1;
                memcpy(func_name, paren + 1, nlen);
                func_name[nlen] = '\0';
                /* 提取偏移（十六进制） */
                func_off = (ptrdiff_t)strtoul(plus + 1, NULL, 16);
                /* 从路径提取库名（括号前，取最后 / 之后） */
                const char* pstart = syms[0];
                const char* pslash = pstart;
                for (const char* s = pstart; s < paren; s++)
                    if (*s == '/') pslash = s + 1;
                lib_name = pslash;
                if (lib_name == paren) lib_name = "??";
            } else if (paren && rparen && rparen > paren + 1) {
                /* 无偏移但有函数名: "path(func)" */
                size_t nlen = (size_t)(rparen - paren - 1);
                if (nlen >= sizeof(func_name)) nlen = sizeof(func_name) - 1;
                memcpy(func_name, paren + 1, nlen);
                func_name[nlen] = '\0';
                func_off = 0;
            } else {
                /* 无法解析，用整个输出作为函数名 */
                size_t slen = strlen(syms[0]);
                if (slen >= sizeof(func_name)) slen = sizeof(func_name) - 1;
                memcpy(func_name, syms[0], slen);
                func_name[slen] = '\0';
                func_off = 0;
            }
            free(syms);
        } else {
            /* 完全无法解析：显示为十六进制地址 */
            snprintf(func_name, sizeof(func_name), "%p", addr);
            func_off = 0;
        }
        /* dladdr 失败时无库名和路径信息 */
        lib_name = "??";
        bin_path = "";
        file_off = 0;
    }

    /* 统一输出：三项组件始终齐全 */
    snprintf(out, out_size, "%s+%#tx (%s)|%s|%#tx",
             func_name, func_off, lib_name, bin_path, file_off);
}

/**
 * 连接到 mttd 守护进程的 Unix Domain Socket。
 */
static int connect_daemon(void)
{
    /* 调用者必须持有 g_sock_lock */
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
/* entry 快照：持锁期间拷贝字段，释放锁后安全访问，防止 UAF */
typedef struct {
    size_t size;
    char   file[MTT_FILE_MAX];
    int    line;
    int    stack_frames;
    void*  stack[MTT_STACK_DEPTH];
} mtt_entry_snap_t;

static void do_client_report(int is_final)
{
    mtt_ensure_init();
    mtt_state_t* s = mtt_state_get();

    /* g_sock_lock 保护整段 connect→I/O→close，避免多线程共享 fd 竞争 */
    pthread_mutex_lock(&g_sock_lock);

    int fd = connect_daemon();
    if (fd < 0) { pthread_mutex_unlock(&g_sock_lock); return; }

    /* 收集快照（逐锁遍历，持锁期间拷贝字段，避免 UAF） */
    int nleaks = 0;
    mtt_entry_snap_t* snaps = raw_malloc(MTT_MAX_LEAKS_PER_PROC * sizeof(mtt_entry_snap_t));
    if (!snaps) {
        shutdown(fd, SHUT_RDWR); close(fd); g_sock_fd = -1;
        pthread_mutex_unlock(&g_sock_lock);
        return;
    }

    for (unsigned lock_idx = 0; lock_idx < MTT_LOCK_STRIPES
         && nleaks < MTT_MAX_LEAKS_PER_PROC; lock_idx++) {
        pthread_mutex_lock(&s->bucket_locks[lock_idx]);
        for (unsigned b = lock_idx; b < s->bucket_count
             && nleaks < MTT_MAX_LEAKS_PER_PROC; b += MTT_LOCK_STRIPES) {
            mtt_entry_t* e = s->buckets[b];
            while (e && nleaks < MTT_MAX_LEAKS_PER_PROC) {
                mtt_entry_snap_t* sn = &snaps[nleaks++];
                sn->size = e->size;
                memcpy(sn->file, e->file, MTT_FILE_MAX);
                sn->line = e->line;
                sn->stack_frames = e->stack_frames;
                memcpy(sn->stack, e->stack, sizeof(void*) * e->stack_frames);
                e = e->next;
            }
        }
        pthread_mutex_unlock(&s->bucket_locks[lock_idx]);
    }

    /* 序列化并发送每条泄漏（锁已释放，只访问快照） */
    for (int i = 0; i < nleaks; i++) {
        mtt_entry_snap_t* sn = &snaps[i];

        char line[4096];
        int n = snprintf(line, sizeof(line),
            "LEAK %zu %s %d %d\n", sn->size, sn->file, sn->line, sn->stack_frames);
        if (n > 0 && n < (int)sizeof(line))
            send_all(fd, line, (size_t)n);

        /* 解析调用栈帧地址为可读符号 */
        for (int j = 0; j < sn->stack_frames; j++) {
            char resolved[MTT_SYMBOL_MAX];
            resolve_frame_symbol(sn->stack[j], resolved, sizeof(resolved));
            n = snprintf(line, sizeof(line), "FRAME %d %s\n", j, resolved);
            if (n > 0 && n < (int)sizeof(line))
                send_all(fd, line, (size_t)n);
        }
    }

    if (is_final) {
        send_all(fd, "BYE\n", 4);
    }

    shutdown(fd, SHUT_RDWR);
    close(fd);
    g_sock_fd = -1;
    pthread_mutex_unlock(&g_sock_lock);

    raw_free(snaps);
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

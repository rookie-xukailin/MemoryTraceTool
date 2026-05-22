/*
 * MemoryTraceTool — 核心实现。
 *
 * 本文件包含了内存泄漏检测的所有核心逻辑：
 *   - 原始分配器指针的延迟解析（绕过 LD_PRELOAD 钩子，避免无限递归）
 *   - 以指针地址为键的哈希表存储分配记录
 *   - 调用栈捕获（backtrace）和符号解析
 *   - SIGUSR1 信号驱动的在线报告（专为常驻进程设计）
 *   - fexit 最终报告与 IPC 客户端交互
 *
 * 集成模式：
 *   1. Macro:   在包含 memorytracetool.h 前 #define MEMORYTRACETOOL_ENABLE，
 *              链接 -lmemorytracetool
 *   2. Preload: 本文件中的 API 函数不会被直接调用，实际拦截工作由 hooks.c
 *              中的 LD_PRELOAD 钩子完成，钩子内部调用本文件提供的追踪函数
 *
 * 线程安全：所有公共 API 通过 g_state.lock 互斥锁保护全局状态。
 * 重入保护：backtrace 捕获通过 __thread 标志 g_in_capture 防止递归。
 */
#define _GNU_SOURCE
#include "internal.h"
#include "daemon.h"
#include "memorytracetool/memorytracetool.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <execinfo.h>
#include <unistd.h>
#include <dlfcn.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <signal.h>

/* ======================================================================== *
 *           原始分配器 — 始终调用真实的 libc malloc/free                    *
 *           以避免 LD_PRELOAD 模式下的无限递归                              *
 * ======================================================================== */

/* 全局函数指针，由构造函数 resolve_raw_allocators 自动初始化 */
raw_malloc_fn raw_malloc = NULL;
raw_free_fn   raw_free   = NULL;
raw_calloc_fn raw_calloc = NULL;

/**
 * 共享库构造函数，在动态库加载时自动执行。
 *
 * 使用 dlsym(RTLD_NEXT, ...) 查找真正的 libc 分配函数。
 * 在非 LD_PRELOAD 的 Macro 模式下，dlsym 返回 NULL，
 * 此时 fallback 到直接使用 malloc/free/calloc。
 */
__attribute__((constructor)) static void resolve_raw_allocators(void)
{
    raw_malloc = (raw_malloc_fn)dlsym(RTLD_NEXT, "malloc");
    raw_free   = (raw_free_fn)dlsym(RTLD_NEXT, "free");
    raw_calloc = (raw_calloc_fn)dlsym(RTLD_NEXT, "calloc");

    /* dlsym 失败时 fallback 到直接调用（Macro 模式） */
    if (!raw_malloc) raw_malloc = malloc;
    if (!raw_free)   raw_free   = free;
    if (!raw_calloc) raw_calloc = calloc;
}

/* ======================================================================== *
 *                          内部辅助函数                                     *
 * ======================================================================== */

static mtt_state_t g_state = {0};

/** 获取全局单例状态指针 */
mtt_state_t* mtt_state_get(void) { return &g_state; }

/**
 * 计算指针地址对应的哈希桶索引。
 *
 * 使用乘法哈希算法（Knuth 的黄金比例哈希变种）：
 * 先右移 3 位去除 malloc 对齐的低位零，再乘以大质数，
 * 最后用位掩码（bucket_count 必须为 2 的幂）取模。
 */
static unsigned hash_ptr(const void* ptr, unsigned bucket_count)
{
    unsigned long h = (unsigned long)ptr;
    h = (h >> 3) * 2654435761UL;
    return (unsigned)(h & (unsigned long)(bucket_count - 1));
}

/* thread-local 递归保护标志：backtrace 内部可能再次调用 malloc，
 * 在此标志置位时跳过栈捕获以避免无限递归和死锁 */
static __thread int g_in_capture = 0;

/**
 * 捕获当前调用栈并存入 entry->stack。
 *
 * 使用 backtrace() 获取调用栈帧地址，通过 g_in_capture
 * (thread-local 变量) 防止 backtrace 内部再次触发 malloc
 * 导致无限递归。
 */
static void capture_stack(mtt_entry_t* entry)
{
    if (g_in_capture) {
        entry->stack_frames = 0;
        return;
    }
    g_in_capture = 1;
    entry->stack_frames = backtrace(entry->stack, MTT_STACK_DEPTH);
    g_in_capture = 0;
}

/**
 * 在哈希桶中根据指针地址查找对应的分配记录。
 *
 * 调用者必须持有 s->lock 互斥锁。
 *
 * @param s    全局状态指针
 * @param ptr  要查找的内存指针地址
 * @return     找到则返回 entry 指针，否则返回 NULL
 */
mtt_entry_t* mtt_entry_find(mtt_state_t* s, const void* ptr)
{
    unsigned bucket = hash_ptr(ptr, s->bucket_count);
    mtt_entry_t* e = s->buckets[bucket];
    while (e) {
        if (e->ptr == ptr) return e;
        e = e->next;
    }
    return NULL;
}

/**
 * 从哈希桶中删除指定指针的分配记录，并释放 entry 自身的内存。
 *
 * 调用者必须持有 s->lock 互斥锁。
 */
void mtt_entry_remove(mtt_state_t* s, const void* ptr)
{
    unsigned bucket = hash_ptr(ptr, s->bucket_count);
    mtt_entry_t** pp = &s->buckets[bucket];
    while (*pp) {
        if ((*pp)->ptr == ptr) {
            mtt_entry_t* dead = *pp;
            *pp = dead->next;
            raw_free(dead);
            return;
        }
        pp = &(*pp)->next;
    }
}

/**
 * 将分配记录插入哈希桶头部（O(1) 插入）。
 *
 * 调用者必须持有 s->lock 互斥锁。
 */
void mtt_entry_add(mtt_state_t* s, mtt_entry_t* entry)
{
    unsigned bucket = hash_ptr(entry->ptr, s->bucket_count);
    entry->next = s->buckets[bucket];
    s->buckets[bucket] = entry;
}

/**
 * 创建新的分配追踪记录。
 *
 * 使用 raw_malloc 分配 entry 自身（不计入追踪统计），
 * 截取文件的纯文件名（去除路径前缀），捕获调用栈帧。
 *
 * @param ptr   分配的内存指针（可能为 NULL，由调用者后续设置）
 * @param size  分配的字节数
 * @param file  源文件路径（__FILE__ 或 "?"）
 * @param line  源文件行号（__LINE__ 或 0）
 * @return      新分配的 entry，或 NULL 表示 raw_malloc 失败
 */
mtt_entry_t* mtt_entry_new(void* ptr, size_t size,
                          const char* file, int line)
{
    mtt_entry_t* e = raw_malloc(sizeof(mtt_entry_t));
    if (!e) return NULL;

    e->ptr        = ptr;
    e->size       = size;
    e->line       = line;
    e->alloc_num  = 0;
    e->timestamp  = time(NULL);
    e->next       = NULL;

    /* 提取纯文件名：从完整路径中截取最后一个 '/' 之后的部分 */
    if (file) {
        const char* base = strrchr(file, '/');
        const char* name = base ? base + 1 : file;
        size_t len = strlen(name);
        size_t copy = len < (size_t)(MTT_FILE_MAX - 1) ? len : (size_t)(MTT_FILE_MAX - 1);
        memcpy(e->file, name, copy);
        e->file[copy] = '\0';
    } else {
        e->file[0] = '?';
        e->file[1] = '\0';
    }

    capture_stack(e);
    return e;
}

/* ---- 初始化与守护进程检测 ---- */

/* 守护进程模式标记：是否在 mtt_report_to_daemon() 中被主动设置 */
static int g_daemon_mode = 0;
/* 守护进程可达性缓存：避免每次报告都尝试连接 */
static int g_daemon_checked = 0;
static int g_daemon_available = 0;

/**
 * 检测守护进程是否可达（通过尝试连接到 Unix Socket）。
 *
 * 结果会被缓存到 g_daemon_available 中（一次性检测），
 * 后续调用直接返回缓存值。
 *
 * @return 1 表示守护进程可达，0 表示不可达
 */
static int check_daemon(void)
{
    if (g_daemon_checked) return g_daemon_available;
    g_daemon_checked = 1;
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return 0;
    struct sockaddr_un addr = {0};
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, MTT_SOCK_PATH, sizeof(addr.sun_path) - 1);
    if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
        g_daemon_available = 1;
        close(fd);
        return 1;
    }
    close(fd);
    return 0;
}

/* atexit 回调幂等保护：已注册 atexit 后，mtt_atexit_report 只执行一次 */
static int g_atexit_called = 0;

/**
 * atexit 回调：进程退出时自动生成最终泄漏报告。
 *
 * 如果守护进程可用，发送带 BYE 的最终报告；
 * 否则直接输出到 stderr。
 * 通过 g_atexit_called 保证只执行一次（防止多线程竞争）。
 */
static void mtt_atexit_report(void)
{
    if (g_atexit_called) return;
    g_atexit_called = 1;
    if (g_daemon_mode || check_daemon())
        mtt_client_report_final();
    else
        mtt_report();
}

/**
 * 将在线报告发送到守护进程（中间报告，不含 BYE）。
 *
 * 设置 g_daemon_mode 标记，后续 SIGUSR1 触发和报告
 * 都会优先尝试发送给守护进程。
 */
void mtt_report_to_daemon(void)
{
    g_daemon_mode = 1;
    mtt_ensure_init();
    mtt_client_report();
}

/**
 * 确保全局状态已完成初始化（惰性初始化，多次调用安全）。
 *
 * 初始化包括：
 * - 分配 MTT_BUCKETS 个桶的哈希表（使用 raw_calloc 零初始化）
 * - 初始化互斥锁
 * - 清零所有统计计数器
 * - 注册 atexit 回调
 *
 * 该函数在首次内存分配时自动被调用，也可手动提前调用。
 */
void mtt_ensure_init(void)
{
    mtt_state_t* s = &g_state;
    if (s->initialized) return;

    s->bucket_count = MTT_BUCKETS;
    /* 使用 raw_calloc 避免分配操作被自身追踪记录 */
    s->buckets = raw_calloc(s->bucket_count, sizeof(mtt_entry_t*));
    if (!s->buckets) {
        fprintf(stderr, "[MemoryTraceTool] FATAL: cannot allocate bucket table\n");
        return;
    }

    pthread_mutex_init(&s->lock, NULL);
    s->alloc_seq     = 0;
    s->alloc_count   = 0;
    s->free_count    = 0;
    s->current_bytes = 0;
    s->peak_bytes    = 0;
    s->total_bytes   = 0;
    s->initialized   = 1;

    atexit(mtt_atexit_report);
}

/** 显式初始化（等同于 mtt_ensure_init） */
void mtt_init(void) { mtt_ensure_init(); }

/* ---- 常驻进程信号驱动报告 ---- */

/* 信号处理器安装标志（原子类型，保证 sig_atomic_t 的读写可见性） */
static volatile sig_atomic_t g_signal_installed = 0;

/**
 * 信号处理线程的主函数。
 *
 * 使用 sigwait() 在独立线程中同步等待 SIGUSR1 信号。
 * 这种方式避免了异步信号处理器（signal handler）中的重入问题，
 * 因为在信号处理器中调用 printf/malloc 等函数是不安全的。
 * sigwait 在普通线程上下文中返回，可以安全调用任何函数。
 *
 * 收到 SIGUSR1 后：
 *   - 守护进程可用 → mtt_client_report() 发送中间报告
 *   - 守护进程不可用 → mtt_report() 输出到 stderr
 */
static void* signal_thread_fn(void* arg)
{
    (void)arg;
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGUSR1);

    while (1) {
        int sig;
        if (sigwait(&set, &sig) != 0) continue;

        if (g_daemon_mode || check_daemon())
            mtt_client_report();
        else
            mtt_report();
    }
    return NULL;
}

/**
 * 安装 SIGUSR1 信号处理器。
 *
 * 阻塞 SIGUSR1 信号，创建独立的 sigwait 线程等待信号。
 * 专为常驻进程（服务器、嵌入式设备）设计 — 进程不会主动退出，
 * 但可以通过 kill -USR1 <pid> 随时生成在线泄漏报告。
 *
 * 多次调用安全（幂等操作）。
 */
void mtt_install_signal_handler(void)
{
    if (g_signal_installed) return;
    g_signal_installed = 1;

    /* 在主线程中阻塞 SIGUSR1，使其不会被默认处理，
     * 而是被 sigwait 线程捕获 */
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGUSR1);
    pthread_sigmask(SIG_BLOCK, &set, NULL);

    pthread_t tid;
    pthread_create(&tid, NULL, signal_thread_fn, NULL);
    pthread_detach(tid); /* 分离线程，无需 join */
}

/* ======================================================================== *
 *                          公共 API                                        *
 * ======================================================================== */

/**
 * 分配 size 字节的内存，并记录分配信息。
 *
 * @param size  要分配的字节数
 * @param file  调用者源文件名（Macro 模式下自动填入 __FILE__）
 * @param line  调用者源文件行号（Macro 模式下自动填入 __LINE__）
 * @return      分配的内存指针，失败返回 NULL
 */
void* mtt_malloc(size_t size, const char* file, int line)
{
    mtt_ensure_init();
    mtt_state_t* s = &g_state;

    void* ptr = raw_malloc(size);
    if (!ptr) return NULL;

    mtt_entry_t* e = mtt_entry_new(ptr, size, file, line);
    if (!e) return ptr; /* entry 分配失败不阻塞业务代码，静默放行 */

    pthread_mutex_lock(&s->lock);
    e->alloc_num = ++s->alloc_seq;
    s->alloc_count++;
    s->current_bytes += size;
    s->total_bytes   += size;
    if (s->current_bytes > s->peak_bytes)
        s->peak_bytes = s->current_bytes;
    mtt_entry_add(s, e);
    pthread_mutex_unlock(&s->lock);

    return ptr;
}

/**
 * 分配并零初始化内存。
 *
 * 直接委托给 mtt_malloc 再执行 memset，避免重复代码。
 */
void* mtt_calloc(size_t count, size_t size, const char* file, int line)
{
    size_t total = count * size;
    void*  ptr   = mtt_malloc(total, file, line);
    if (ptr) memset(ptr, 0, total);
    return ptr;
}

/**
 * 释放内存并从追踪表中删除。
 *
 * 如果指针在追踪表中找不到，输出警告到 stderr
 *（可能是双重释放或非本工具分配的内存）。
 * 无论是否在表中找到，最终都会调用 raw_free 释放内存。
 */
void mtt_free(void* ptr)
{
    if (!ptr) return;

    mtt_ensure_init();
    mtt_state_t* s = &g_state;

    pthread_mutex_lock(&s->lock);
    mtt_entry_t* e = mtt_entry_find(s, ptr);
    if (e) {
        s->current_bytes -= e->size;
        s->free_count++;
        mtt_entry_remove(s, ptr);
    } else {
        fprintf(stderr,
            "[MemoryTraceTool] WARNING: free(%p) — untracked pointer "
            "(double-free or not allocated via mtt_malloc?)\n", ptr);
    }
    pthread_mutex_unlock(&s->lock);
    raw_free(ptr);
}

/**
 * 重新分配内存。
 *
 * 实现与标准 realloc 语义一致：
 * - ptr == NULL:   等同于 mtt_malloc(size)
 * - size == 0:    等同于 mtt_free(ptr)
 * - 其他:         分配新内存，拷贝旧数据，释放旧内存
 *
 * 如果新分配失败，旧内存保留不变（原子性保证）。
 */
void* mtt_realloc(void* ptr, size_t size, const char* file, int line)
{
    if (!ptr)  return mtt_malloc(size, file, line);
    if (!size) { mtt_free(ptr); return NULL; }

    mtt_ensure_init();
    mtt_state_t* s = &g_state;

    /* 从追踪表中删除旧记录 */
    pthread_mutex_lock(&s->lock);
    mtt_entry_t* old = mtt_entry_find(s, ptr);
    size_t old_size = old ? old->size : 0;
    if (old) {
        s->current_bytes -= old->size;
        s->free_count++;
        mtt_entry_remove(s, ptr);
    }
    pthread_mutex_unlock(&s->lock);

    void* new_ptr = raw_malloc(size);
    if (!new_ptr) {
        /* 分配失败，恢复旧记录（原子性保证） */
        if (old) {
            pthread_mutex_lock(&s->lock);
            s->current_bytes += old_size;
            s->free_count--;
            old->ptr = ptr;
            mtt_entry_add(s, old);
            pthread_mutex_unlock(&s->lock);
        }
        return NULL;
    }

    /* 拷贝旧数据（取较小值） */
    if (old && old_size > 0)
        memcpy(new_ptr, ptr, old_size < size ? old_size : size);

    mtt_entry_t* e = mtt_entry_new(new_ptr, size, file, line);
    if (!e) { raw_free(new_ptr); return NULL; }

    pthread_mutex_lock(&s->lock);
    e->alloc_num = ++s->alloc_seq;
    s->alloc_count++;
    s->current_bytes += size;
    s->total_bytes   += size;
    if (s->current_bytes > s->peak_bytes)
        s->peak_bytes = s->current_bytes;
    mtt_entry_add(s, e);
    pthread_mutex_unlock(&s->lock);

    raw_free(ptr);
    return new_ptr;
}

/**
 * strdup 的追踪版本。
 *
 * 先计算字符串长度（含结尾 '\0'），再调用 mtt_malloc 分配拷贝空间。
 */
char* mtt_strdup(const char* s, const char* file, int line)
{
    if (!s) return NULL;
    size_t len = strlen(s) + 1;
    char*  p   = mtt_malloc(len, file, line);
    if (p) memcpy(p, s, len);
    return p;
}

/* ---- 报告输出 ---- */

/**
 * 输出调用栈符号到 FILE 流。
 *
 * 优先使用 dladdr 解析函数名（即使二进制被 strip 也能从动态符号表获取），
 * 失败时回退到 backtrace_symbols 原始输出。
 */
static void print_stack_trace(mtt_entry_t* e, FILE* fp)
{
    if (e->stack_frames <= 0) return;

    fprintf(fp, "    Call stack:\n");
    for (int i = 0; i < e->stack_frames; i++) {
        Dl_info info;
        if (dladdr(e->stack[i], &info) && info.dli_sname) {
            const char* fname = info.dli_fname ? info.dli_fname : "??";
            const char* base = strrchr(fname, '/');
            if (base) fname = base + 1;
            ptrdiff_t offset = (char*)e->stack[i] - (char*)info.dli_saddr;
            if (offset > 0)
                fprintf(fp, "      #%-2d %s+%#tx (%s)\n",
                        i, info.dli_sname, offset, fname);
            else
                fprintf(fp, "      #%-2d %s (%s)\n",
                        i, info.dli_sname, fname);
        } else {
            /* dladdr 失败，回退到 backtrace_symbols */
            char** syms = backtrace_symbols(&e->stack[i], 1);
            if (syms && syms[0]) {
                fprintf(fp, "      #%-2d %s\n", i, syms[0]);
                raw_free(syms);
            } else {
                fprintf(fp, "      #%-2d %p\n", i, e->stack[i]);
            }
        }
    }
}

/** qsort 比较函数：按泄漏大小降序排列 */
static int entry_size_cmp(const void* a, const void* b)
{
    const mtt_entry_t* ea = *(const mtt_entry_t**)a;
    const mtt_entry_t* eb = *(const mtt_entry_t**)b;
    if (ea->size > eb->size) return -1;
    if (ea->size < eb->size) return  1;
    return 0;
}

/**
 * 将当前泄漏报告输出到指定文件描述符。
 *
 * 报告格式：
 *   1. 头部：泄漏数、字节数、统计信息
 *   2. 按泄漏大小降序排列的每条泄漏详情（含调用栈）
 *   3. 脚部标记
 *
 * 使用 dup(fd) 避免关闭 fd 时影响外部调用者。
 */
void mtt_report_to_fd(int fd)
{
    mtt_ensure_init();
    mtt_state_t* s = &g_state;

    FILE* fp = fdopen(dup(fd), "w");
    if (!fp) return;

    size_t count = s->alloc_count - s->free_count;
    if (count == 0) {
        fprintf(fp,
            "\n"
            "  ==========================================\n"
            "    MemoryTraceTool: No memory leaks detected.\n"
            "    Allocations: %zu | Frees: %zu\n"
            "    Peak usage:  %zu bytes (%.1f KB)\n"
            "    Total alloc: %zu bytes (%.1f KB)\n"
            "  ==========================================\n\n",
            s->alloc_count, s->free_count,
            s->peak_bytes,  (double)s->peak_bytes / 1024.0,
            s->total_bytes, (double)s->total_bytes / 1024.0);
        fclose(fp);
        return;
    }

    /* 收集所有泄漏记录到数组，用于排序 */
    mtt_entry_t** entries = raw_malloc(count * sizeof(mtt_entry_t*));
    if (!entries) { fclose(fp); return; }

    size_t idx = 0;
    for (unsigned b = 0; b < s->bucket_count && idx < count; b++) {
        mtt_entry_t* e = s->buckets[b];
        while (e && idx < count) {
            entries[idx++] = e;
            e = e->next;
        }
    }
    count = idx;

    qsort(entries, count, sizeof(mtt_entry_t*), entry_size_cmp);

    fprintf(fp,
        "\n"
        "  ==========================================\n"
        "    MemoryTraceTool: %zu leak(s) — %zu bytes\n"
        "    Allocations: %zu | Frees: %zu\n"
        "    Peak usage:  %zu bytes (%.1f KB)\n"
        "    Total alloc: %zu bytes (%.1f KB)\n"
        "  ==========================================\n\n",
        count, s->current_bytes,
        s->alloc_count, s->free_count,
        s->peak_bytes,  (double)s->peak_bytes / 1024.0,
        s->total_bytes, (double)s->total_bytes / 1024.0);

    for (size_t i = 0; i < count; i++) {
        mtt_entry_t* e = entries[i];
        fprintf(fp,
            "  Leak #%-3zu | %-6zu bytes | %s:%d | alloc #%lu\n",
            i + 1, e->size, e->file, e->line, e->alloc_num);
        print_stack_trace(e, fp);
        fprintf(fp, "\n");
    }

    fprintf(fp, "  ==========================================\n\n");
    raw_free(entries);
    fclose(fp);
}

/** 将报告输出到 stderr */
void mtt_report(void) { mtt_report_to_fd(STDERR_FILENO); }

/* ---- 统计查询 ---- */

size_t mtt_get_alloc_count(void)     { return g_state.alloc_count; }
size_t mtt_get_free_count(void)      { return g_state.free_count; }
size_t mtt_get_leak_count(void)      { return g_state.alloc_count - g_state.free_count; }
size_t mtt_get_current_usage(void)   { return g_state.current_bytes; }
size_t mtt_get_peak_usage(void)      { return g_state.peak_bytes; }
size_t mtt_get_total_allocated(void) { return g_state.total_bytes; }

/*
 * MemoryTraceTool — 核心实现。
 *
 * 本文件包含了内存泄漏检测的所有核心逻辑：
 *   - 原始分配器指针的延迟解析（绕过 LD_PRELOAD 钩子，避免无限递归）
 *   - 以指针地址为键的哈希表存储分配记录
 *   - 调用栈捕获（backtrace）和符号解析
 *   - SIGUSR1 信号驱动的在线报告（专为常驻进程设计）
 *   - atexit 最终报告与 IPC 客户端交互
 *
 * 集成模式：
 *   1. Macro:   在包含 memorytracetool.h 前 #define MEMORYTRACETOOL_ENABLE，
 *              链接 -lmemorytracetool
 *   2. Preload: 本文件中的 API 函数不会被直接调用，实际拦截工作由 hooks.c
 *              中的 LD_PRELOAD 钩子完成，钩子内部调用本文件提供的追踪函数
 *
 * 线程安全：使用 64 分段锁替代全局互斥锁，大幅降低高并发场景下的锁竞争。
 * 统计计数器全部使用原子变量，读取无需持锁。
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
#include <stdatomic.h>
#include <errno.h>
#include <malloc.h>

/* ======================================================================== *
 *           原始分配器 — 始终调用真实的 libc malloc/free                    *
 *           以避免 LD_PRELOAD 模式下的无限递归                              *
 * ======================================================================== */

/* 全局函数指针，由构造函数 resolve_raw_allocators 自动初始化 */
raw_malloc_fn raw_malloc = NULL;
raw_free_fn   raw_free   = NULL;
raw_calloc_fn raw_calloc = NULL;

/* 原子标志：防止构造函数被多次执行（多线程竞争） */
static atomic_int g_raw_resolved = 0;

/**
 * 共享库构造函数，在动态库加载时自动执行。
 *
 * 查找真正的 libc 分配函数（raw_malloc / raw_free / raw_calloc）。
 * 优先使用 RTLD_NEXT（LD_PRELOAD 模式），失败时显式打开 libc
 * 查找（dlopen/ptrace 注入模式），最后 fallback 到直接调用。
 *
 * 缺陷修复 #4: 使用 atomic_flag 确保只初始化一次，防止多线程竞争。
 * 缺陷修复 #26: dlopen 注入时 RTLD_NEXT 失败，显式打开 libc 查找符号。
 */
__attribute__((constructor)) static void resolve_raw_allocators(void)
{
    int expected = 0;
    if (!atomic_compare_exchange_strong(&g_raw_resolved, &expected, 1))
        return;

    raw_malloc = (raw_malloc_fn)dlsym(RTLD_NEXT, "malloc");
    raw_free   = (raw_free_fn)dlsym(RTLD_NEXT, "free");
    raw_calloc = (raw_calloc_fn)dlsym(RTLD_NEXT, "calloc");

    /* RTLD_NEXT 失败时显式打开 libc（dlopen/ptrace 注入路径） */
    if (!raw_malloc || !raw_free || !raw_calloc) {
        void* libc_handle = dlopen("libc.so.6", RTLD_LAZY);
        if (libc_handle) {
            if (!raw_malloc) raw_malloc = (raw_malloc_fn)dlsym(libc_handle, "malloc");
            if (!raw_free)   raw_free   = (raw_free_fn)dlsym(libc_handle, "free");
            if (!raw_calloc) raw_calloc = (raw_calloc_fn)dlsym(libc_handle, "calloc");
            dlclose(libc_handle);
        }
    }

    /* 最终 fallback */
    if (!raw_malloc) raw_malloc = (raw_malloc_fn)malloc;
    if (!raw_free)   raw_free   = (raw_free_fn)free;
    if (!raw_calloc) raw_calloc = (raw_calloc_fn)calloc;
}

/* ======================================================================== *
 *                          内部辅助函数                                     *
 * ======================================================================== */

static mtt_state_t g_state = {0};

/** 获取全局单例状态指针 */
mtt_state_t* mtt_state_get(void) { return &g_state; }

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

/* ---- 采样决策 ---- */

/**
 * 决定当前分配是否应被记录。
 *
 * 缺陷修复 #1: 引入随机采样机制，当采样周期 >0 时，
 * 通过原子计数器实现近似的每 N 次记录 1 次。
 * 高负载场景下可显著降低追踪开销。
 *
 * @param s   全局状态指针
 * @return    1 应记录，0 跳过
 */
static int should_track(mtt_state_t* s)
{
    if (s->sample_period == 0)
        return 1; /* 全量追踪 */

    /* 原子递增计数器，仅在命中采样点时记录 */
    unsigned long c = atomic_fetch_add(&s->sample_counter, 1);
    if ((c % s->sample_period) == 0)
        return 1;

    /* 非采样点：不记录以减少开销 */
    atomic_fetch_add(&s->skipped_sampled, 1);
    return 0;
}

/**
 * 检查哈希表是否已达容量上限。
 *
 * 缺陷修复 #2: 防止常驻进程（如服务器）的追踪表无限增长。
 *
 * @param s   全局状态指针
 * @return    1 已达上限，0 可继续添加
 */
static int is_over_capacity(mtt_state_t* s)
{
    unsigned long n = atomic_load(&s->entry_count);
    if (n >= atomic_load(&s->max_entries)) {
        atomic_fetch_add(&s->skipped_overcap, 1);
        return 1;
    }
    return 0;
}

/* ---- 哈希表操作（调用者必须持有对应的分段锁） ---- */

/**
 * 在哈希桶中根据指针地址查找对应的分配记录。
 *
 * 调用者必须持有指针对应的分段锁。
 */
mtt_entry_t* mtt_entry_find(mtt_state_t* s, const void* ptr)
{
    unsigned bucket = mtt_bucket_of(ptr, s->bucket_count, s->hash_seed);
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
 * 调用者必须持有指针对应的分段锁。
 */
void mtt_entry_remove(mtt_state_t* s, const void* ptr)
{
    unsigned bucket = mtt_bucket_of(ptr, s->bucket_count, s->hash_seed);
    mtt_entry_t** pp = &s->buckets[bucket];
    while (*pp) {
        if ((*pp)->ptr == ptr) {
            mtt_entry_t* dead = *pp;
            *pp = dead->next;
            raw_free(dead);
            atomic_fetch_sub(&s->entry_count, 1);
            return;
        }
        pp = &(*pp)->next;
    }
}

/**
 * 将分配记录插入哈希桶头部（O(1) 插入）。
 *
 * 调用者必须持有 entry 指针对应的分段锁。
 */
void mtt_entry_add(mtt_state_t* s, mtt_entry_t* entry)
{
    unsigned bucket = mtt_bucket_of(entry->ptr, s->bucket_count, s->hash_seed);
    entry->next = s->buckets[bucket];
    s->buckets[bucket] = entry;
    atomic_fetch_add(&s->entry_count, 1);
}

/**
 * 创建新的分配追踪记录。
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
 * 结果会被缓存到 g_daemon_available 中（一次性检测）。
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

/* 缺陷修复 #7: 使用原子变量替代普通 int 防止 atexit 竞态 */
static atomic_int g_atexit_called = 0;

/**
 * atexit 回调：进程退出时自动生成最终泄漏报告。
 */
static void mtt_atexit_report(void)
{
    int expected = 0;
    if (!atomic_compare_exchange_strong(&g_atexit_called, &expected, 1))
        return;
    if (g_daemon_mode || check_daemon())
        mtt_client_report_final();
    else
        mtt_report();
}

/**
 * 将在线报告发送到守护进程（中间报告，不含 BYE）。
 */
void mtt_report_to_daemon(void)
{
    g_daemon_mode = 1;
    mtt_ensure_init();
    mtt_client_report();
}

/**
 * peek 进程名（从 /proc/self/comm 读取，用于 PROC_FILTER 匹配）。
 * 失败时返回空字符串。
 */
static void get_proc_comm(char* buf, size_t size)
{
    buf[0] = '\0';
    FILE* fp = fopen("/proc/self/comm", "r");
    if (fp) {
        if (fgets(buf, (int)size, fp)) {
            size_t len = strlen(buf);
            if (len > 0 && buf[len - 1] == '\n')
                buf[len - 1] = '\0';
        }
        fclose(fp);
    }
}

/**
 * 检查环境变量（MTT_DISABLE / MTT_PROC_FILTER），决定是否应追踪当前进程。
 * 只执行一次，结果缓存在 s->disabled 中。
 */
static void check_env_switches(mtt_state_t* s)
{
    if (s->env_checked) return;
    s->env_checked = 1;

    /* MTT_DISABLE=1 完全禁用追踪 */
    const char* env_disable = getenv("MTT_DISABLE");
    if (env_disable && strcmp(env_disable, "1") == 0) {
        s->disabled = 1;
        return;
    }

    /* MTT_PROC_FILTER=name 仅追踪匹配名称的进程 */
    const char* env_filter = getenv("MTT_PROC_FILTER");
    if (env_filter && env_filter[0]) {
        strncpy(s->proc_filter, env_filter, sizeof(s->proc_filter) - 1);
        s->proc_filter[sizeof(s->proc_filter) - 1] = '\0';

        char comm[256];
        get_proc_comm(comm, sizeof(comm));
        if (comm[0] && strcmp(comm, s->proc_filter) != 0) {
            /* 进程名不匹配过滤器，禁用追踪 */
            s->disabled = 1;
        }
    }
}

/**
 * 确保全局状态已完成初始化（惰性初始化，多次调用安全）。
 *
 * 初始化包括：
 * - 分配 MTT_BUCKETS 个桶的哈希表（使用 raw_calloc 零初始化）
 * - 初始化 64 分段锁和随机种子
 * - 清零所有统计计数器
 * - 设置默认配置（采样周期 256、容量上限）
 * - 读取环境变量覆盖默认配置
 * - 注册 atexit 回调
 *
 * 缺陷修复 #9: 生成随机哈希种子防止碰撞攻击。
 * 缺陷修复 #1: 读取环境变量 MTT_SAMPLE, MTT_DISABLE, MTT_MAX_ENTRIES, MTT_PROC_FILTER。
 * 缺陷修复 #23: 64 分段锁替代全局互斥锁，大幅降低高并发竞争。
 */
void mtt_ensure_init(void)
{
    mtt_state_t* s = &g_state;

    /* 快速路径：初始化已完成 */
    if (atomic_load(&s->initialized))
        return;

    /* 缺陷修复 #25: 用静态锁保护初始化，防止多线程首次调用竞争。
     * 不能用 CAS（会在线程 B 看到 initialized=1 时立即返回，
     * 但此时桶表/互斥锁可能尚未初始化完成）。 */
    static pthread_mutex_t init_lock = PTHREAD_MUTEX_INITIALIZER;
    pthread_mutex_lock(&init_lock);

    /* 双重检查：可能在等锁期间已被其他线程初始化 */
    if (s->initialized) {
        pthread_mutex_unlock(&init_lock);
        return;
    }

    s->bucket_count = MTT_BUCKETS;
    /* 使用 raw_calloc 避免分配操作被自身追踪记录 */
    s->buckets = raw_calloc(s->bucket_count, sizeof(mtt_entry_t*));
    if (!s->buckets) {
        fprintf(stderr, "[MemoryTraceTool] FATAL: cannot allocate bucket table\n");
        pthread_mutex_unlock(&init_lock);
        return;
    }

    /* 生成随机哈希种子：混入时间戳和进程 PID */
    s->hash_seed = ((unsigned long)time(NULL) ^
                    ((unsigned long)getpid() << 16) ^
                    0x9e3779b97f4a7c15UL);

    /* 初始化 64 分段锁 */
    for (int i = 0; i < MTT_LOCK_STRIPES; i++)
        pthread_mutex_init(&s->bucket_locks[i], NULL);

    s->alloc_seq       = 0;
    s->alloc_count     = 0;
    s->free_count      = 0;
    s->current_bytes   = 0;
    s->peak_bytes      = 0;
    s->total_bytes     = 0;
    s->skipped_sampled = 0;
    s->skipped_overcap = 0;

    /* 默认采样与容量配置 */
    s->sample_period = MTT_SAMPLE_DEFAULT;
    s->max_entries   = MTT_MAX_ENTRIES;
    atomic_store(&s->sample_counter, 0);
    atomic_store(&s->entry_count, 0);

    /* 进程级开关（首次调用 getenv，后续使用缓存） */
    s->disabled    = 0;
    s->proc_filter[0] = '\0';
    s->env_checked = 0;
    check_env_switches(s);

    /* 环境变量覆盖采样和容量 */
    {
        const char* env_sample = getenv("MTT_SAMPLE");
        if (env_sample) {
            int sp = atoi(env_sample);
            if (sp >= 0 && sp <= MTT_SAMPLE_MAX_PERIOD)
                s->sample_period = (unsigned)sp;
        }

        const char* env_maxent = getenv("MTT_MAX_ENTRIES");
        if (env_maxent) {
            int me = atoi(env_maxent);
            if (me >= 256 && me <= 1048576)
                s->max_entries = (unsigned)me;
        }
    }

    /* initialized 必须在所有字段就绪后才置 1 */
    atomic_store(&s->initialized, 1);
    pthread_mutex_unlock(&init_lock);

    atexit(mtt_atexit_report);

    /* 启动周期性报告线程：每 3 秒向守护进程推送泄漏数据，供实时看板 */
    mtt_start_periodic_report();
}

/** 显式初始化（等同于 mtt_ensure_init） */
void mtt_init(void) { mtt_ensure_init(); }

/* ---- 运行时配置 API ---- */

/** 设置采样周期 */
void mtt_set_sample_period(unsigned period)
{
    mtt_ensure_init();
    if (period <= MTT_SAMPLE_MAX_PERIOD)
        atomic_store(&g_state.sample_period, period);
}

/** 获取采样周期 */
unsigned mtt_get_sample_period(void)
{
    mtt_ensure_init();
    return atomic_load(&g_state.sample_period);
}

/** 设置哈希表容量上限 */
void mtt_set_max_entries(unsigned limit)
{
    mtt_ensure_init();
    if (limit >= 256)
        atomic_store(&g_state.max_entries, limit);
}

/** 获取跳过的采样统计 */
size_t mtt_get_skipped_sampled(void) { return atomic_load(&g_state.skipped_sampled); }

/** 获取因超容量跳过的统计 */
size_t mtt_get_skipped_overcap(void) { return atomic_load(&g_state.skipped_overcap); }

/* ---- 常驻进程信号驱动报告 ---- */

/* 信号处理器安装标志（原子 CAS 防止重复安装） */
static atomic_int g_signal_installed = 0;

/* 信号线程退出控制 */
static volatile int g_signal_thread_stop = 0;

/**
 * 信号处理线程的主函数。
 *
 * 使用 sigwait() 在独立线程中同步等待 SIGUSR1 信号。
 *
 * 缺陷修复 #6: 使用 trylock 防止与主线程互斥锁死锁。
 * 缺陷修复 #8: 通过 g_signal_thread_stop 支持线程退出。
 */
static void* signal_thread_fn(void* arg)
{
    (void)arg;
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGUSR1);

    while (!g_signal_thread_stop) {
        struct timespec ts = { .tv_sec = 1, .tv_nsec = 0 };
        if (sigtimedwait(&set, NULL, &ts) < 0) {
            if (errno == EAGAIN || errno == EINTR)
                continue;
            break;
        }

        if (g_daemon_mode || check_daemon())
            mtt_client_report();
        else
            mtt_report();
    }
    return NULL;
}

/**
 * 安装 SIGUSR1 信号处理器。
 */
void mtt_install_signal_handler(void)
{
    int expected = 0;
    if (!atomic_compare_exchange_strong(&g_signal_installed, &expected, 1))
        return;

    /* 阻塞 SIGUSR1，使其被 sigwait 线程捕获 */
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGUSR1);
    pthread_sigmask(SIG_BLOCK, &set, NULL);

    g_signal_thread_stop = 0;
    pthread_t tid;
    int rc = pthread_create(&tid, NULL, signal_thread_fn, NULL);
    if (rc != 0) {
        fprintf(stderr, "[MemoryTraceTool] WARN: pthread_create signal thread failed: %s\n", strerror(rc));
        g_signal_installed = 0;
        return;
    }
    pthread_detach(tid);
}

/* ======================================================================== *
 *                          公共 API                                        *
 * ======================================================================== */

/**
 * 分配 size 字节的内存，并记录分配信息。
 *
 * 缺陷修复 #1: 引入采样机制 — 非采样点不创建追踪记录。
 * 缺陷修复 #2: 检查容量上限 — 超限时不创建记录。
 * 缺陷修复 #5: 在 realloc 回退路径正确处理 old entry 的生命周期。
 * 缺陷修复 #23: 使用分段锁替代表全局互斥锁。
 * 缺陷修复 #24: 检查 disabled 标志实现零开销关闭。
 */
void* mtt_malloc(size_t size, const char* file, int line)
{
    /* 0 字节分配按标准放行，不记录 */
    if (size == 0) return raw_malloc(0);

    mtt_ensure_init();
    mtt_state_t* s = &g_state;

    /* 完全禁用时直接透传 */
    if (s->disabled)
        return raw_malloc(size);

    void* ptr = raw_malloc(size);
    if (!ptr) return NULL;

    /* 采样决策 / 容量检查 */
    if (!should_track(s) || is_over_capacity(s))
        return ptr; /* 放行但不记录 */

    mtt_entry_t* e = mtt_entry_new(ptr, size, file, line);
    if (!e) return ptr; /* entry 分配失败不阻塞业务代码 */

    mtt_stripe_lock(s, ptr);
    e->alloc_num = ++s->alloc_seq;
    s->alloc_count++;
    s->current_bytes += size;
    s->total_bytes   += size;
    /* 原子更新峰值 */
    size_t cur = s->current_bytes;
    size_t old_peak = atomic_load(&s->peak_bytes);
    while (cur > old_peak) {
        if (atomic_compare_exchange_weak(&s->peak_bytes, &old_peak, cur))
            break;
    }
    mtt_entry_add(s, e);
    mtt_stripe_unlock(s, ptr);

    return ptr;
}

/**
 * 分配并零初始化内存。
 */
void* mtt_calloc(size_t count, size_t size, const char* file, int line)
{
    /* 整数溢出检查 */
    if (count > 0 && size > SIZE_MAX / count) {
        fprintf(stderr,
            "[MemoryTraceTool] ERROR: calloc(%zu, %zu) — integer overflow\n",
            count, size);
        return NULL;
    }
    size_t total = count * size;
    void*  ptr   = mtt_malloc(total, file, line);
    if (ptr) memset(ptr, 0, total);
    return ptr;
}

/**
 * 释放内存并从追踪表中删除。
 */
void mtt_free(void* ptr)
{
    if (!ptr) return;

    mtt_ensure_init();
    mtt_state_t* s = &g_state;

    if (s->disabled) {
        raw_free(ptr);
        return;
    }

    mtt_stripe_lock(s, ptr);
    mtt_entry_t* e = mtt_entry_find(s, ptr);
    if (e) {
        s->current_bytes -= e->size;
        s->free_count++;
        mtt_entry_remove(s, ptr);
    }
    mtt_stripe_unlock(s, ptr);
    raw_free(ptr);
}

/**
 * 重新分配内存。
 *
 * 缺陷修复 #5: 修复新 entry 分配失败路径 — 放行 new_ptr 但不追踪。
 */
void* mtt_realloc(void* ptr, size_t size, const char* file, int line)
{
    if (!ptr)  return mtt_malloc(size, file, line);
    if (!size) { mtt_free(ptr); return NULL; }

    mtt_ensure_init();
    mtt_state_t* s = &g_state;

    if (s->disabled) {
        /* 缺陷修复 #27: 先尝试新分配，失败则不释放旧指针（符合 realloc 语义） */
        void* new_ptr = raw_malloc(size);
        if (!new_ptr) return NULL;
        size_t old_size = malloc_usable_size(ptr);
        memcpy(new_ptr, ptr, old_size < size ? old_size : size);
        raw_free(ptr);
        return new_ptr;
    }

    /* 缺陷修复 #27: 先尝试分配新内存，成功后再修改追踪表。
     * 这保证了新分配失败时旧追踪记录和用户数据均未被修改。 */
    void* new_ptr = raw_malloc(size);
    if (!new_ptr) return NULL;

    /* 缺陷修复 #5: 先创建新追踪记录，失败则放弃本次 realloc。
     * 避免旧记录已删除但新记录创建失败时的追踪状态损坏。 */
    mtt_entry_t* e = mtt_entry_new(new_ptr, size, file, line);
    if (!e) {
        raw_free(new_ptr);
        return NULL;
    }

    /* 从追踪表中删除旧记录 */
    mtt_stripe_lock(s, ptr);
    mtt_entry_t* old = mtt_entry_find(s, ptr);
    size_t old_size = old ? old->size : malloc_usable_size(ptr);
    if (old) {
        s->current_bytes -= old->size;
        s->free_count++;
        mtt_entry_remove(s, ptr);
    }
    mtt_stripe_unlock(s, ptr);

    memcpy(new_ptr, ptr, old_size < size ? old_size : size);

    mtt_stripe_lock(s, new_ptr);
    e->alloc_num = ++s->alloc_seq;
    s->alloc_count++;
    s->current_bytes += size;
    s->total_bytes   += size;
    size_t cur = atomic_load(&s->current_bytes);
    size_t old_peak = atomic_load(&s->peak_bytes);
    while (cur > old_peak) {
        if (atomic_compare_exchange_weak(&s->peak_bytes, &old_peak, cur))
            break;
    }
    mtt_entry_add(s, e);
    mtt_stripe_unlock(s, new_ptr);

    raw_free(ptr);
    return new_ptr;
}

/**
 * strdup 的追踪版本。
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
 */
/** qsort 比较函数：按泄漏大小降序排列 */
/* entry 快照：持锁期间拷贝字段，释放锁后安全访问，防止 UAF */
typedef struct {
    size_t size;
    char   file[MTT_FILE_MAX];
    int    line;
    unsigned long alloc_num;
    int    stack_frames;
    void*  stack[MTT_STACK_DEPTH];
} mtt_entry_snap_t;

static int entry_size_cmp(const void* a, const void* b)
{
    const mtt_entry_snap_t* sa = (const mtt_entry_snap_t*)a;
    const mtt_entry_snap_t* sb = (const mtt_entry_snap_t*)b;
    if (sa->size > sb->size) return -1;
    if (sa->size < sb->size) return  1;
    return 0;
}

/**
 * 将当前泄漏报告输出到指定文件描述符。
 *
 * 缺陷修复 #23: 遍历所有桶时逐桶加锁收集记录，避免长时间持锁。
 */
void mtt_report_to_fd(int fd)
{
    mtt_ensure_init();
    mtt_state_t* s = &g_state;

    int dupfd = dup(fd);
    if (dupfd < 0) return;
    FILE* fp = fdopen(dupfd, "w");
    if (!fp) { close(dupfd); return; }

    size_t alloc_count = atomic_load(&s->alloc_count);
    size_t free_count  = atomic_load(&s->free_count);
    size_t count = alloc_count - free_count;

    if (count == 0) {
        fprintf(fp,
            "\n"
            "  ==========================================\n"
            "    MemoryTraceTool: No memory leaks detected.\n"
            "    Allocations: %zu | Frees: %zu\n"
            "    Peak usage:  %zu bytes (%.1f KB)\n"
            "    Total alloc: %zu bytes (%.1f KB)\n"
            "  ==========================================\n\n",
            alloc_count, free_count,
            atomic_load(&s->peak_bytes),
            (double)atomic_load(&s->peak_bytes) / 1024.0,
            atomic_load(&s->total_bytes),
            (double)atomic_load(&s->total_bytes) / 1024.0);
        fclose(fp);
        return;
    }

    /* 收集快照到数组（持锁期间拷贝字段，避免 UAF） */
    mtt_entry_snap_t* snaps = raw_malloc(count * sizeof(mtt_entry_snap_t));
    if (!snaps) { fclose(fp); return; }

    size_t idx = 0;
    /* 缺陷修复 #26: 逐锁遍历（0..63），每个锁一次覆盖所有映射到它的桶，
     * 避免原代码中 lock_idx=b&63 导致 64 号桶之后重复加锁遍历相同桶 */
    for (unsigned lock_idx = 0; lock_idx < MTT_LOCK_STRIPES && idx < count;
         lock_idx++) {
        pthread_mutex_lock(&s->bucket_locks[lock_idx]);
        for (unsigned b = lock_idx; b < s->bucket_count && idx < count;
             b += MTT_LOCK_STRIPES) {
            mtt_entry_t* e = s->buckets[b];
            while (e && idx < count) {
                mtt_entry_snap_t* sn = &snaps[idx++];
                sn->size = e->size;
                memcpy(sn->file, e->file, MTT_FILE_MAX);
                sn->line = e->line;
                sn->alloc_num = e->alloc_num;
                sn->stack_frames = e->stack_frames;
                memcpy(sn->stack, e->stack, sizeof(void*) * e->stack_frames);
                e = e->next;
            }
        }
        pthread_mutex_unlock(&s->bucket_locks[lock_idx]);
    }
    count = idx;

    qsort(snaps, count, sizeof(mtt_entry_snap_t), entry_size_cmp);

    fprintf(fp,
        "\n"
        "  ==========================================\n"
        "    MemoryTraceTool: %zu leak(s) — %zu bytes\n"
        "    Allocations: %zu | Frees: %zu\n"
        "    Peak usage:  %zu bytes (%.1f KB)\n"
        "    Total alloc: %zu bytes (%.1f KB)\n"
        "  ==========================================\n\n",
        count, atomic_load(&s->current_bytes),
        alloc_count, free_count,
        atomic_load(&s->peak_bytes),
        (double)atomic_load(&s->peak_bytes) / 1024.0,
        atomic_load(&s->total_bytes),
        (double)atomic_load(&s->total_bytes) / 1024.0);

    for (size_t i = 0; i < count; i++) {
        mtt_entry_snap_t* sn = &snaps[i];
        /* 改进 ?:0 显示：LD_PRELOAD 模式提示无源码位置 */
        if (sn->line == 0 && sn->file[0] == '?')
            fprintf(fp,
                "  Leak #%-3zu | %-6zu bytes | (LD_PRELOAD) | alloc #%lu\n",
                i + 1, sn->size, sn->alloc_num);
        else
            fprintf(fp,
                "  Leak #%-3zu | %-6zu bytes | %s:%d | alloc #%lu\n",
                i + 1, sn->size, sn->file, sn->line, sn->alloc_num);
        /* 内联栈帧输出（锁已释放，只访问快照）
         * 统一格式: #N 函数+偏移 (库名) */
        if (sn->stack_frames > 0) {
            fprintf(fp, "    Call stack:\n");
            for (int j = 0; j < sn->stack_frames; j++) {
                void* frame_addr = sn->stack[j];
                char   func_name[256] = {0};
                const char* lib_name = "??";
                ptrdiff_t   func_off = 0;
                ptrdiff_t   file_off = 0;

                Dl_info info;
                if (dladdr(frame_addr, &info)) {
                    const char* fname = info.dli_fname ? info.dli_fname : "??";
                    const char* base = strrchr(fname, '/');
                    if (base) fname = base + 1;
                    lib_name = fname;
                    file_off = (char*)frame_addr - (char*)info.dli_fbase;

                    if (info.dli_sname) {
                        size_t nlen = strlen(info.dli_sname);
                        if (nlen >= sizeof(func_name)) nlen = sizeof(func_name) - 1;
                        memcpy(func_name, info.dli_sname, nlen);
                        func_off = (char*)frame_addr - (char*)info.dli_saddr;
                        if (func_off < 0) func_off = 0;
                    } else {
                        /* 无符号名，用 backtrace_symbols 提取 */
                        char** syms = backtrace_symbols(&frame_addr, 1);
                        if (syms && syms[0]) {
                            char* paren = strchr(syms[0], '(');
                            char* plus  = strchr(syms[0], '+');
                            if (paren && plus && plus > paren) {
                                size_t nlen = (size_t)(plus - paren - 1);
                                if (nlen > 0 && nlen < sizeof(func_name))
                                    memcpy(func_name, paren + 1, nlen);
                            }
                            free(syms);
                        }
                        if (!func_name[0]) {
                            size_t llen = strlen(lib_name);
                            if (llen >= sizeof(func_name)) llen = sizeof(func_name) - 1;
                            memcpy(func_name, lib_name, llen);
                        }
                        func_off = file_off;
                    }
                } else {
                    /* dladdr 失败，从 backtrace_symbols 解析 */
                    char** syms = backtrace_symbols(&frame_addr, 1);
                    if (syms && syms[0]) {
                        char* paren = strchr(syms[0], '(');
                        char* plus  = paren ? strchr(paren, '+') : NULL;
                        char* rparen = paren ? strchr(paren, ')') : NULL;
                        if (paren && plus && rparen && plus > paren && plus < rparen) {
                            size_t nlen = (size_t)(plus - paren - 1);
                            if (nlen >= sizeof(func_name)) nlen = sizeof(func_name) - 1;
                            memcpy(func_name, paren + 1, nlen);
                            func_off = (ptrdiff_t)strtoul(plus + 1, NULL, 16);
                            const char* pstart = syms[0];
                            const char* pslash = pstart;
                            for (const char* s = pstart; s < paren; s++)
                                if (*s == '/') pslash = s + 1;
                            if (pslash < paren) lib_name = pslash;
                        } else if (paren && rparen && rparen > paren + 1) {
                            size_t nlen = (size_t)(rparen - paren - 1);
                            if (nlen >= sizeof(func_name)) nlen = sizeof(func_name) - 1;
                            memcpy(func_name, paren + 1, nlen);
                        } else {
                            size_t slen = strlen(syms[0]);
                            if (slen >= sizeof(func_name)) slen = sizeof(func_name) - 1;
                            memcpy(func_name, syms[0], slen);
                        }
                        free(syms);
                    } else {
                        snprintf(func_name, sizeof(func_name), "%p", frame_addr);
                    }
                }

                fprintf(fp, "      #%-2d %s+%#tx (%s)\n",
                        j, func_name, func_off, lib_name);
            }
        }
        fprintf(fp, "\n");
    }

    fprintf(fp, "  ==========================================\n\n");
    raw_free(snaps);
    fclose(fp);
}

/** 将报告输出到 stderr */
void mtt_report(void) { mtt_report_to_fd(STDERR_FILENO); }

/* ---- 统计查询（原子读取，无需持锁） ---- */

size_t mtt_get_alloc_count(void)     { return atomic_load(&g_state.alloc_count); }
size_t mtt_get_free_count(void)      { return atomic_load(&g_state.free_count); }
size_t mtt_get_leak_count(void)
{
    size_t a = atomic_load(&g_state.alloc_count);
    size_t f = atomic_load(&g_state.free_count);
    return a - f;
}
size_t mtt_get_current_usage(void)   { return atomic_load(&g_state.current_bytes); }
size_t mtt_get_peak_usage(void)      { return atomic_load(&g_state.peak_bytes); }
size_t mtt_get_total_allocated(void) { return atomic_load(&g_state.total_bytes); }

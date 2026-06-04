/*
 * MemoryTraceTool — 核心追踪引擎。
 *
 * 本文件实现了内存泄漏检测的所有核心逻辑：
 *   - 原始分配器指针的延迟解析（dlsym + bootstrap 缓冲区兜底）
 *   - 以指针地址为键的哈希表存储分配记录（4096 桶，64 分段锁）
 *   - 调用栈捕获（backtrace）和符号解析
 *   - 采样与容量上限控制
 *   - 全局状态懒初始化（线程安全，双重检查锁定）
 *
 * 防递归策略（多层防护）：
 *   - 第1层: raw_malloc/raw_free 直接调用 libc，不触发 hook
 *   - 第2层: g_in_hook (__thread) 置位时 hook 透传到 raw_*
 *   - 第3层: bootstrap 静态缓冲区在 dlsym 阶段兜底
 *   - 第4层: g_in_capture (__thread) 防止 backtrace 重入
 *
 * 原子操作内存序约定：
 *   - 统计计数器（alloc_count, free_count, current_bytes...）：relaxed
 *     仅在报告线程周期读取用于展示，近似值可接受
 *   - 控制标志（initialized, disabled, g_raw_ready）：acquire/release
 *     确保相关数据结构的初始化对其他线程可见
 *   - 序号/采样计数（alloc_seq, sample_counter）：relaxed
 *     仅需原子递增，不需要同步其他数据
 */
#define _GNU_SOURCE
#include "mtt_internal.h"
#include "reporter.h"
#include "time_series.h"
#include "http_server.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if MTT_HAS_BACKTRACE
#include <execinfo.h>
#endif
#include <unistd.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <stdatomic.h>

/* ======================================================================== *
 *                    全局单例状态                                             *
 * ======================================================================== */

/**
 * 获取全局单例状态指针。
 *
 * 将定义放在 .c 文件中（而非头文件的 static inline），
 * 确保所有翻译单元共享同一实例。
 */
mtt_state_t* mtt_state_get(void)
{
    static mtt_state_t g_state = {0};
    return &g_state;
}

/* ======================================================================== *
 *                    原始分配器 — 始终调用真实的 libc                         *
 * ======================================================================== */

/* 全局函数指针：由 mtt_resolve_raw_allocators() 懒解析初始化。
 * volatile 限定防止编译器在跨函数调用边界时将其缓存在寄存器中，
 * 确保 CAS loser 线程在下次进入本函数时读到 CAS winner 写入的最新值。
 * 初始值为 NULL，调用者必须确保只在这些指针非 NULL 时使用。 */
raw_malloc_fn  volatile raw_malloc  = NULL;
raw_free_fn    volatile raw_free    = NULL;
raw_calloc_fn  volatile raw_calloc  = NULL;
raw_realloc_fn volatile raw_realloc = NULL;

/* CAS 保护的一次性解析标志 */
static atomic_int g_raw_resolved = 0;

/* raw_* 指针是否已完成 dlsym 解析（发布/订阅屏障） */
static atomic_int g_raw_ready = 0;

/* 递归保护：dlsym 内部可能触发 malloc，防止 resolve 自身递归 */
static __thread int g_raw_resolving = 0;

/*
 * 防递归核心标志 (__thread)：
 * 置位期间，hooks.c 的 malloc/free 等函数直接透传到 raw_*，
 * 不做任何追踪、不分配 entry、不捕获栈。
 * 使用 save/restore 模式支持嵌套。
 */
__thread int g_in_hook = 0;

/* ======================================================================== *
 *                  Bootstrap 分配器（dlsym 阶段兜底）                         *
 * ======================================================================== */

/* 静态缓冲区：在 raw_* 解析完成前提供临时分配能力。
 * 多线程安全：使用原子偏移，各自分配不会破坏彼此数据。
 * 注意：bootstrap 分配的内存不回收，仅用于一次性初始化阶段。 */
static char           g_bootstrap_buf[MTT_BOOTSTRAP_BUF_SIZE];
static _Atomic size_t g_bootstrap_offset = 0;

static void* bootstrap_malloc(size_t size)
{
    /* 8 字节对齐 */
    size_t aligned = (size + 7) & ~((size_t)7);
    size_t old = atomic_fetch_add(&g_bootstrap_offset, aligned);
    if (old + aligned > MTT_BOOTSTRAP_BUF_SIZE)
        return NULL;
    return g_bootstrap_buf + old;
}

static void bootstrap_free(void *ptr)
{
    (void)ptr; /* bootstrap 分配不回收 */
}

static void* bootstrap_calloc(size_t count, size_t size)
{
    size_t total = count * size;
    void *p = bootstrap_malloc(total);
    if (p != NULL) {
        size_t actual = (total + 7) & ~((size_t)7);
        if (actual > 0) memset(p, 0, actual);
    }
    return p;
}

static void* bootstrap_realloc(void *ptr, size_t size)
{
    /* bootstrap realloc 简化实现：新分配 + 拷贝 + 释放旧（旧大小不可知） */
    if (ptr == NULL) return bootstrap_malloc(size);
    if (size == 0) { bootstrap_free(ptr); return NULL; }
    void *new_ptr = bootstrap_malloc(size);
    if (new_ptr == NULL) return NULL;
    /* 无法获取旧大小，保守拷贝 min(size, bootstrap 可用空间) */
    memcpy(new_ptr, ptr, size);
    bootstrap_free(ptr);
    return new_ptr;
}

/* ======================================================================== *
 *                 原始分配器解析（懒初始化 + CAS + 递归保护）                   *
 * ======================================================================== */

/**
 * libc 库名候选列表（按优先级排列）。
 * glibc → musl → Android bionic → 通用 POSIX。
 */
static const char* libc_candidates[] = {
    "libc.so.6",       /* glibc (Linux) */
    "libc.so",         /* musl libc, 通用 POSIX */
    "libc.musl-aarch64.so.1",  /* musl on ARM64 */
    NULL
};

/**
 * 解析真正的 libc 分配函数指针。
 *
 * 使用 dlsym(RTLD_NEXT) 获取 libc 的 malloc/free/calloc/realloc，
 * 避免 LD_PRELOAD 模式下调用自身导致无限递归。
 *
 * 懒初始化：首次 hook 调用时触发，此时动态链接器已完全就绪。
 * 线程安全：CAS 确保多线程下仅执行一次。
 * 递归保护：g_raw_resolving 标志防止 dlsym 内部 malloc 回调。
 */
void mtt_resolve_raw_allocators(void)
{
    /* 快速路径：已完全解析（acquire 确保 raw_* 指针对其他线程可见） */
    if (atomic_load_explicit(&g_raw_ready, memory_order_acquire))
        return;

    /* 快速路径：前一次 CAS 失败后预置了 bootstrap，但 winner 尚未完成 */
    if (raw_malloc != NULL)
        return;

    /* 递归保护：dlsym 内部可能触发 malloc */
    if (g_raw_resolving)
        return;

    /* 预置 bootstrap 分配器：必须在 CAS 之前完成。
     * 确保 CAS 失败线程使用 bootstrap_*（非 NULL），避免空指针崩溃。
     * CAS 失败后，线程在下一次 mtt_resolve_raw_allocators() 调用时
     * 通过 g_raw_ready 检查（而非 raw_malloc != NULL）得知真正完成。
     * Winner 线程在约 0.1ms 内完成 dlsym，bootstrap 缓冲区足以支撑。 */
    raw_malloc  = bootstrap_malloc;
    raw_free    = bootstrap_free;
    raw_calloc  = bootstrap_calloc;
    raw_realloc = bootstrap_realloc;

    /* CAS 确保仅单线程执行 dlsym 解析 */
    int expected = 0;
    if (!atomic_compare_exchange_strong(&g_raw_resolved, &expected, 1))
        return;

    g_raw_resolving = 1;

    /* dlsym 内部可能触发 malloc，设置 g_in_hook 确保递归调用全部透传 */
    int saved_hook = g_in_hook;
    g_in_hook = 1;

    raw_malloc_fn real_malloc   = (raw_malloc_fn)dlsym(RTLD_NEXT, "malloc");
    raw_free_fn   real_free     = (raw_free_fn)dlsym(RTLD_NEXT, "free");
    raw_calloc_fn real_calloc   = (raw_calloc_fn)dlsym(RTLD_NEXT, "calloc");
    raw_realloc_fn real_realloc = (raw_realloc_fn)dlsym(RTLD_NEXT, "realloc");

    if (real_malloc  != NULL) raw_malloc  = real_malloc;
    if (real_free    != NULL) raw_free    = real_free;
    if (real_calloc  != NULL) raw_calloc  = real_calloc;
    if (real_realloc != NULL) raw_realloc = real_realloc;

    /* RTLD_NEXT 失败时遍历 libc 候选库列表（dlopen/ptrace 注入路径） */
    if (raw_malloc == NULL || raw_free == NULL ||
        raw_calloc == NULL || raw_realloc == NULL) {
        for (int i = 0; libc_candidates[i] != NULL; i++) {
            void *libc_handle = dlopen(libc_candidates[i], RTLD_LAZY);
            if (libc_handle == NULL) continue;

            if (raw_malloc  == NULL)
                raw_malloc  = (raw_malloc_fn)dlsym(libc_handle, "malloc");
            if (raw_free    == NULL)
                raw_free    = (raw_free_fn)dlsym(libc_handle, "free");
            if (raw_calloc  == NULL)
                raw_calloc  = (raw_calloc_fn)dlsym(libc_handle, "calloc");
            if (raw_realloc == NULL)
                raw_realloc = (raw_realloc_fn)dlsym(libc_handle, "realloc");

            /* 不 dlclose：避免 raw_* 悬空。
             * 仅在全部解析完成后才跳出，否则继续尝试下一个候选库。 */
            if (raw_malloc != NULL && raw_free != NULL &&
                raw_calloc != NULL && raw_realloc != NULL)
                break;
        }
    }

    g_in_hook = saved_hook;
    g_raw_resolving = 0;

    /* 发布屏障：确保 raw_* 指针写入对所有线程可见后，再置 ready 标志 */
    atomic_store_explicit(&g_raw_ready, 1, memory_order_release);
}

/* ======================================================================== *
 *                       栈捕获（backtrace + 防重入）                          *
 * ======================================================================== */

/* __thread 递归保护：backtrace 内部可能触发 malloc */
static __thread int g_in_capture = 0;

/**
 * 捕获当前调用栈并存入 entry->stack[]。
 *
 * 使用 backtrace() 获取最多 MTT_STACK_DEPTH 帧的返回地址。
 * g_in_capture (__thread) 防止 backtrace 内部 malloc 导致的无限递归。
 * save/restore 模式支持嵌套调用。
 *
 * ARM32 Thumb 兼容：backtrace 返回的地址 bit 0 在 Thumb 模式下为 1，
 * 影响哈希计算和 dladdr 符号解析，此处统一清除。
 */
void mtt_capture_stack(mtt_entry_t *entry)
{
    if (entry == NULL) return;

    if (g_in_capture) {
        entry->stack_frames = 0;
        return;
    }

    int saved = g_in_capture;
    g_in_capture = 1;

#if MTT_HAS_BACKTRACE
    entry->stack_frames = backtrace(entry->stack, MTT_STACK_DEPTH);
    if (entry->stack_frames < 0)
        entry->stack_frames = 0;

    /* 清除 ARM32 Thumb 模式的地址 LSB (bit 0)，
     * 确保后续哈希计算和 dladdr() 符号解析正确。
     * 在 ARM (非 Thumb) / ARM64 / x86 上此操作为空操作（bit 0 本就是 0）。 */
    for (int i = 0; i < entry->stack_frames; i++) {
        entry->stack[i] = MTT_FIX_THUMB_ADDR(entry->stack[i]);
    }
#else
    /* 无 backtrace() 的平台上（musl / bionic），栈捕获不可用。
     * 仅设置空栈，泄漏检测仍可工作（按大小统计），但无法显示调用栈。 */
    entry->stack_frames = 0;
    memset(entry->stack, 0, sizeof(entry->stack));
#endif

    g_in_capture = saved;
}

/* ======================================================================== *
 *                       采样与容量控制                                       *
 * ======================================================================== */

/**
 * 决定当前分配是否应被记录。
 *
 * 支持两种采样模式（优先级从高到低）：
 *   1. 大分配豁免：size >= MTT_BIG_ALLOC_THRESHOLD（1MB）总是追踪
 *   2. 字节统计采样（sample_rate > 0）：按 2^sample_rate 字节平均步长概率采样
 *   3. 固定计数采样（sample_period > 0）：每 N 次 alloc 记录 1 次（旧模式）
 *   4. 全量追踪（两者均为 0）
 *
 * 字节统计采样使用累加器方式：每次 alloc 时将 size 累加到 sample_bytes_accum，
 * 当累加值超过 2^sample_rate 时，重置累加器并记录本次分配。
 * 这种方式确保大分配有更高概率被采样，小分配聚合后采样。
 *
 * @param s     全局状态指针（调用者已确保非 NULL）
 * @param size  本次分配的字节数
 * @return      1=应记录, 0=跳过
 */
int mtt_should_track(mtt_state_t *s, size_t size)
{
    /* 大分配总是追踪 */
    if (size >= MTT_BIG_ALLOC_THRESHOLD)
        return 1;

    /* 字节统计采样模式 */
    size_t rate = atomic_load_explicit(&s->sample_rate, memory_order_relaxed);
    if (rate > 0) {
        size_t step = (size_t)1 << rate; /* 2^sample_rate */
        size_t old_accum = atomic_fetch_add_explicit(&s->sample_bytes_accum, size,
                                                      memory_order_relaxed);
        if (old_accum + size >= step) {
            /* 达到采样阈值：重置累加器（减去 step）+ 记录本次 */
            atomic_fetch_sub_explicit(&s->sample_bytes_accum, step, memory_order_relaxed);
            return 1;
        }
        atomic_fetch_add_explicit(&s->skipped_sampled, 1, memory_order_relaxed);
        return 0;
    }

    /* 固定计数采样模式（旧模式，保持兼容） */
    unsigned period = atomic_load_explicit(&s->sample_period, memory_order_relaxed);
    if (period == 0)
        return 1; /* 全量追踪 */

    uint64_t c = atomic_fetch_add_explicit(&s->sample_counter, 1,
                                           memory_order_relaxed);
    if ((c % period) == 0)
        return 1;

    atomic_fetch_add_explicit(&s->skipped_sampled, 1, memory_order_relaxed);
    return 0;
}

/**
 * 检查调用栈帧中是否包含黑名单库（借鉴 libleak LEAK_LIB_BLACKLIST）。
 *
 * 遍历黑名单列表中逗号分隔的 .so 名称，
 * 逐一检查是否出现在符号字符串中（子串匹配）。
 *
 * @param s       全局状态指针
 * @param symbol  已解析的符号字符串，如 "func+0x1a4 (libblacklisted.so)"
 * @return        1=在黑名单中（应跳过）, 0=不在黑名单中
 */
int mtt_is_blacklisted(mtt_state_t *s, const char *symbol)
{
    if (s == NULL || symbol == NULL || !s->lib_blacklist_ready) return 0;
    if (s->lib_blacklist[0] == '\0') return 0;

    /* 遍历逗号分隔的黑名单列表，检查符号中是否包含目标库名 */
    char buf[512] = {0};
    memcpy(buf, s->lib_blacklist, sizeof(buf) - 1);
    char *token = strtok(buf, ",");
    while (token != NULL) {
        /* 跳过前导空白 */
        while (*token == ' ' || *token == '\t') token++;
        if (token[0] != '\0' && strstr(symbol, token) != NULL)
            return 1;
        token = strtok(NULL, ",");
    }
    return 0;
}

/**
 * 检查当前是否处于启动阶段（应跳过追踪）。
 *
 * 当 MTT_SKIP_STARTUP_SEC > 0 时，在指定时间内不追踪分配，
 * 避免初始化阶段的大量一次性分配污染泄漏报告。
 *
 * @param s  全局状态指针
 * @return   1=启动阶段中（跳过追踪）, 0=正常追踪
 */
int mtt_is_startup_phase(mtt_state_t *s)
{
    if (s == NULL) return 0;
    time_t until = atomic_load_explicit(&s->startup_until, memory_order_relaxed);
    if (until > 0 && time(NULL) < until)
        return 1;
    return 0;
}

/**
 * 检查哈希表是否已达容量上限。
 *
 * @param s  全局状态指针（调用者已确保非 NULL）
 * @return   1=已达上限, 0=可继续添加
 */
int mtt_is_over_capacity(mtt_state_t *s)
{
    uint64_t n = atomic_load_explicit(&s->entry_count, memory_order_relaxed);
    if (n >= MTT_MAX_ENTRIES) {
        atomic_fetch_add_explicit(&s->skipped_overcap, 1, memory_order_relaxed);
        return 1;
    }
    return 0;
}

/* ======================================================================== *
 *                    哈希表操作（调用者必须持有对应分段锁）                      *
 * ======================================================================== */

/**
 * 在哈希桶中根据指针地址查找分配记录。
 *
 * @param s    全局状态指针（调用者已确保非 NULL）
 * @param ptr  内存指针（哈希键）
 * @return     找到的条目指针，未找到返回 NULL
 */
mtt_entry_t* mtt_entry_find(mtt_state_t *s, const void *ptr)
{
    if (s == NULL || ptr == NULL || s->buckets == NULL) return NULL;

    unsigned bucket = mtt_bucket_of(ptr, s->bucket_count, s->hash_seed);
    mtt_entry_t *e = s->buckets[bucket];
    while (e != NULL) {
        if (e->ptr == ptr) return e;
        e = e->next;
    }
    return NULL;
}

/**
 * 从哈希桶中删除指定指针的分配记录。
 *
 * @param s    全局状态指针
 * @param ptr  内存指针
 */
void mtt_entry_remove(mtt_state_t *s, const void *ptr)
{
    if (s == NULL || ptr == NULL || s->buckets == NULL) return;

    unsigned bucket = mtt_bucket_of(ptr, s->bucket_count, s->hash_seed);
    mtt_entry_t **pp = &s->buckets[bucket];
    while (*pp != NULL) {
        if ((*pp)->ptr == ptr) {
            mtt_entry_t *dead = *pp;
            *pp = dead->next;
            if (raw_free != NULL) raw_free(dead);
            atomic_fetch_sub_explicit(&s->entry_count, 1, memory_order_relaxed);
            return;
        }
        pp = &(*pp)->next;
    }
}

/**
 * 将分配记录插入哈希桶头部（O(1) 插入）。
 *
 * @param s     全局状态指针
 * @param entry 要插入的条目（调用者已确保非 NULL）
 */
void mtt_entry_add(mtt_state_t *s, mtt_entry_t *entry)
{
    if (s == NULL || entry == NULL || s->buckets == NULL) return;

    unsigned bucket = mtt_bucket_of(entry->ptr, s->bucket_count, s->hash_seed);
    entry->next = s->buckets[bucket];
    s->buckets[bucket] = entry;
    atomic_fetch_add_explicit(&s->entry_count, 1, memory_order_relaxed);
}

/**
 * 创建新的分配追踪记录。
 *
 * 使用 raw_malloc 分配（不触发 hook），捕获调用栈和分配时间。
 * 仅在 raw_malloc 已解析完成后调用，否则需通过 bootstrap 路径。
 *
 * @param ptr   分配的用户内存指针（可为 NULL，由调用者后设）
 * @param size  分配字节数
 * @return      新条目指针，raw_malloc 失败时返回 NULL
 */
mtt_entry_t* mtt_entry_new(void *ptr, size_t size)
{
    if (raw_malloc == NULL) return NULL;

    mtt_entry_t *e = (mtt_entry_t*)raw_malloc(sizeof(mtt_entry_t));
    if (e == NULL) return NULL;

    e->ptr           = ptr;
    e->size          = size;
    e->alloc_num     = 0;
    e->timestamp     = time(NULL);
    e->next          = NULL;
    e->stack_frames  = 0;
    memset(e->stack, 0, sizeof(e->stack));

    /* 捕获调用栈（内部有防重入保护 + Thumb bit 清除） */
    mtt_capture_stack(e);

    return e;
}

/* ======================================================================== *
 *                   读取进程名（/proc/self/exe）                               *
 * ======================================================================== */

/**
 * 从 /proc/self/exe 读取当前进程的可执行文件名。
 *
 * 使用 readlink() 系统调用（不触发 malloc），
 * 提取路径中最后一个 '/' 之后的纯文件名部分。
 * 当 /proc 不可用时（某些 ARM 嵌入式内核未挂载），
 * 使用 prctl(PR_GET_NAME) 作为备用方案。
 *
 * @param buf   输出缓冲区
 * @param size  缓冲区大小
 */
static void get_process_name(char *buf, size_t size)
{
    if (buf == NULL || size == 0) return;
    buf[0] = '\0';

    char exe_path[256] = {0};
    ssize_t len = readlink("/proc/self/exe", exe_path, sizeof(exe_path) - 1);
    if (len > 0) {
        exe_path[len] = '\0';

        /* 提取最后一个 '/' 之后的纯文件名 */
        const char *base = strrchr(exe_path, '/');
        if (base != NULL)
            base = base + 1;
        else
            base = exe_path;

        size_t n = strlen(base);
        if (n >= size) n = size - 1;
        memcpy(buf, base, n);
        buf[n] = '\0';
        return;
    }

    /* /proc 不可用时的备用方案：尝试 prctl（linux 专有，无 malloc） */
#ifdef __linux__
    {
        char comm[16] = {0};
        /* 使用 raw syscall 号 15 = PR_GET_NAME（避免引入 <sys/prctl.h> 头文件依赖） */
        extern int prctl(int, ...);
        if (prctl(15, comm, 0, 0, 0) == 0 && comm[0] != '\0') {
            size_t n = strlen(comm);
            if (n >= size) n = size - 1;
            memcpy(buf, comm, n);
            buf[n] = '\0';
            return;
        }
    }
#endif

    snprintf(buf, size, "unknown");
}

/* ======================================================================== *
 *                       全局状态初始化                                        *
 * ======================================================================== */

/**
 * 惰性初始化全局追踪状态（线程安全，双重检查锁定）。
 *
 * 初始化分两阶段：
 *   阶段1（锁外）：读取环境变量（getenv 不触发 malloc）
 *   阶段2（锁内）：初始化桶表、分段锁、计数器（纯内存操作 + raw_calloc）
 *
 * 阶段分离避免了锁内调用 getenv 可能触发 malloc → hook → 递归死锁。
 * 采用双重检查锁定模式：快速路径用 acquire load 检查 initialized 标志。
 *
 * 致命错误处理：若桶表分配失败，设置 disabled=1 + initialized=1，
 * 后续所有 hook 调用直接透传到 raw_*，不再重试初始化。
 */
void mtt_ensure_init(void)
{
    mtt_state_t *s = mtt_state_get();
    if (s == NULL) return;

    /* 快速路径：已初始化（acquire 确保初始化数据可见） */
    if (atomic_load_explicit(&s->initialized, memory_order_acquire))
        return;

    /* 确保 raw_* 函数指针已解析 */
    mtt_resolve_raw_allocators();

    /* ---- 阶段1: 读取环境变量（无需持锁） ---- */
    int      want_disabled = 0;
    unsigned want_sample   = MTT_SAMPLE_DEFAULT;
    size_t   want_srate    = MTT_SAMPLE_RATE_DEFAULT; /* 默认使用字节统计采样 */
    time_t   want_leak_threshold = MTT_LEAK_THRESHOLD_DEFAULT;
    time_t   want_skip_startup   = MTT_SKIP_STARTUP_DEFAULT;

    {
        const char *env_disable = getenv("MTT_DISABLE");
        if (env_disable != NULL && strcmp(env_disable, "1") == 0)
            want_disabled = 1;

        const char *env_sample = getenv("MTT_SAMPLE");
        if (env_sample != NULL) {
            int sp = atoi(env_sample);
            if (sp >= 0 && sp <= MTT_SAMPLE_MAX_PERIOD) {
                want_sample = (unsigned)sp;
                want_srate = 0; /* 旧模式采样时禁用字节采样 */
            }
        }

        /* 字节统计采样率（MTT_SAMPLE_RATE=N → 平均 2^N 字节采样一次） */
        const char *env_srate = getenv("MTT_SAMPLE_RATE");
        if (env_srate != NULL) {
            int sr = atoi(env_srate);
            if (sr >= 0 && sr <= MTT_SAMPLE_RATE_MAX)
                want_srate = (size_t)sr;
        }

        /* 泄漏判定阈值（MTT_LEAK_THRESHOLD_SEC=N，存活超过 N 秒→probable leak） */
        const char *env_thresh = getenv("MTT_LEAK_THRESHOLD_SEC");
        if (env_thresh != NULL) {
            int lt = atoi(env_thresh);
            if (lt >= 0)
                want_leak_threshold = (time_t)lt;
        }

        /* 跳过启动阶段（MTT_SKIP_STARTUP_SEC=N，进程启动 N 秒后再开始追踪） */
        const char *env_skip = getenv("MTT_SKIP_STARTUP_SEC");
        if (env_skip != NULL) {
            int ss = atoi(env_skip);
            if (ss >= 0)
                want_skip_startup = (time_t)ss;
        }

        /* 库黑名单（MTT_LIB_BLACKLIST=libfoo.so,libbar.so — 借鉴 libleak） */
        const char *env_blacklist = getenv("MTT_LIB_BLACKLIST");
        if (env_blacklist != NULL && env_blacklist[0] != '\0') {
            size_t blen = strlen(env_blacklist);
            if (blen >= sizeof(s->lib_blacklist)) blen = sizeof(s->lib_blacklist) - 1;
            memcpy(s->lib_blacklist, env_blacklist, blen);
            s->lib_blacklist[blen] = '\0';
            s->lib_blacklist_ready = 1;
        } else {
            s->lib_blacklist[0] = '\0';
            s->lib_blacklist_ready = 0;
        }
    }

    /* ---- 阶段2: 持锁初始化数据结构（双重检查锁定） ---- */
    static pthread_mutex_t init_lock = PTHREAD_MUTEX_INITIALIZER;
    pthread_mutex_lock(&init_lock);

    /* 双重检查：可能在等锁期间已被其他线程初始化 */
    if (atomic_load_explicit(&s->initialized, memory_order_acquire)) {
        pthread_mutex_unlock(&init_lock);
        return;
    }

    /* 分配桶表 */
    s->bucket_count = MTT_BUCKETS;
    if (raw_calloc != NULL) {
        s->buckets = (mtt_entry_t**)raw_calloc(
            (size_t)s->bucket_count, sizeof(mtt_entry_t*));
    }
    if (s->buckets == NULL) {
        /* raw_calloc 失败或尚未就绪：使用 bootstrap_calloc */
        s->buckets = (mtt_entry_t**)bootstrap_calloc(
            (size_t)s->bucket_count, sizeof(mtt_entry_t*));
    }
    if (s->buckets == NULL) {
        /* 致命：无法分配桶表。
         * 设置 disabled=1 + initialized=1 永久降级，
         * 后续所有 hook 调用直接透传到 raw_*，不再重试初始化。 */
        atomic_store_explicit(&s->disabled, 1, memory_order_release);
        atomic_store_explicit(&s->initialized, 1, memory_order_release);
        pthread_mutex_unlock(&init_lock);
        return;
    }

    /* 生成随机哈希种子（64-bit，ARM32/ARM64 行为一致） */
    s->hash_seed = ((uint64_t)time(NULL) ^
                    ((uint64_t)getpid() << 16) ^
                    UINT64_C(0x9e3779b97f4a7c15));

    /* 初始化分段锁（缓存行对齐，避免 ARM 多核伪共享） */
    for (int i = 0; i < MTT_LOCK_STRIPES; i++)
        pthread_mutex_init(&s->bucket_locks[i].lock, NULL);

    /* 初始化原子计数器（relaxed：此时仅有当前线程可见，release store 最后做） */
    atomic_store_explicit(&s->alloc_seq,       0, memory_order_relaxed);
    atomic_store_explicit(&s->alloc_count,     0, memory_order_relaxed);
    atomic_store_explicit(&s->free_count,      0, memory_order_relaxed);
    atomic_store_explicit(&s->current_bytes,   0, memory_order_relaxed);
    atomic_store_explicit(&s->peak_bytes,      0, memory_order_relaxed);
    atomic_store_explicit(&s->total_bytes,     0, memory_order_relaxed);
    atomic_store_explicit(&s->skipped_sampled, 0, memory_order_relaxed);
    atomic_store_explicit(&s->skipped_overcap, 0, memory_order_relaxed);
    atomic_store_explicit(&s->sample_period,      want_sample, memory_order_relaxed);
    atomic_store_explicit(&s->sample_counter,     0, memory_order_relaxed);
    atomic_store_explicit(&s->sample_rate,        want_srate, memory_order_relaxed);
    atomic_store_explicit(&s->sample_bytes_accum, 0, memory_order_relaxed);
    atomic_store_explicit(&s->entry_count,        0, memory_order_relaxed);
    atomic_store_explicit(&s->disabled,           want_disabled, memory_order_relaxed);
    atomic_store_explicit(&s->peak_updated,       0, memory_order_relaxed);
    atomic_store_explicit(&s->leak_threshold_sec, want_leak_threshold, memory_order_relaxed);
    atomic_store_explicit(&s->temp_alloc_count,   0, memory_order_relaxed);
    atomic_store_explicit(&s->expired_alloc_count, 0, memory_order_relaxed);
    atomic_store_explicit(&s->free_expired_count,  0, memory_order_relaxed);

    /* 设置启动阶段结束时间（0=不跳过） */
    if (want_skip_startup > 0)
        atomic_store_explicit(&s->startup_until, time(NULL) + want_skip_startup, memory_order_relaxed);
    else
        atomic_store_explicit(&s->startup_until, 0, memory_order_relaxed);

    /* 读取进程名 */
    get_process_name(s->proc_name, sizeof(s->proc_name));
    s->proc_name_ready = 1;

    /* 标记初始化完成（release 确保上述所有初始化对其他线程可见） */
    atomic_store_explicit(&s->initialized, 1, memory_order_release);
    pthread_mutex_unlock(&init_lock);

    /* 启动周期报告线程（锁外，避免 pthread_create 内部 malloc → 递归） */
    mtt_reporter_start();

    /* 初始化时序数据采集（reporter 线程启动后） */
    mtt_ts_init();

    /* 启动 HTTP 服务器（从环境变量读取端口，0=禁用） */
    {
        uint16_t http_port = MTT_HTTP_DEFAULT_PORT;
        const char *env_port = getenv("MTT_HTTP_PORT");
        if (env_port != NULL) {
            int p = atoi(env_port);
            if (p > 0 && p <= 65535)
                http_port = (uint16_t)p;
            else if (p == 0)
                http_port = 0;
        }
        mtt_http_server_start(http_port);
    }

    /* 启动信号处理线程（SIGUSR1 触发即时报告） */
    mtt_signal_thread_start();
}

/* ======================================================================== *
 *                 信号处理线程（SIGUSR1 触发即时报告）                         *
 * ======================================================================== */

/** 信号线程运行标志 */
static _Atomic int g_signal_thread_running = 0;

/** 信号处理线程主函数。使用 sigwait() 阻塞等待 SIGUSR1，收到后触发即时扫描。 */
static void* mtt_signal_thread_fn(void *arg)
{
    (void)arg;
    pthread_detach(pthread_self());

    sigset_t sigset;
    sigemptyset(&sigset);
    sigaddset(&sigset, MTT_SIGNAL_REPORT);

    while (atomic_load_explicit(&g_signal_thread_running, memory_order_acquire)) {
        int sig;
        if (sigwait(&sigset, &sig) == 0 && sig == MTT_SIGNAL_REPORT) {
            /* 收到 SIGUSR1：记录时序点 + 触发即时扫描 */
            mtt_ts_record_point();
            /* 通过 reporter 接口触发扫描（需要 reporter 配合） */
            extern void mtt_reporter_signal_scan(void);
            mtt_reporter_signal_scan();
        }
    }
    return NULL;
}

/**
 * 启动信号处理线程。
 *
 * 在子线程中阻塞等待 SIGUSR1，收到后立即触发 scan_and_report()。
 * 在 mtt_ensure_init() 末尾调用，reporter 线程启动之后。
 */
void mtt_signal_thread_start(void)
{
    /* 防止重复启动 */
    int expected = 0;
    static atomic_int started = 0;
    if (!atomic_compare_exchange_strong(&started, &expected, 1))
        return;

    /* 在主线程中阻塞 SIGUSR1（子线程将通过 sigwait 接收） */
    sigset_t block_set;
    sigemptyset(&block_set);
    sigaddset(&block_set, MTT_SIGNAL_REPORT);
    pthread_sigmask(SIG_BLOCK, &block_set, NULL);

    atomic_store_explicit(&g_signal_thread_running, 1, memory_order_release);

    pthread_t tid;
    if (pthread_create(&tid, NULL, mtt_signal_thread_fn, NULL) != 0) {
        atomic_store_explicit(&g_signal_thread_running, 0, memory_order_release);
        return;
    }

    /* 诊断输出 */
    char diag[96] = {0};
    int len = snprintf(diag, sizeof(diag),
        "[MTT] Signal thread ready (kill -USR1 %d for instant report)\n",
        (int)getpid());
    if (len > 0 && len < (int)sizeof(diag))
        write(STDERR_FILENO, diag, (size_t)len);
}

/* ======================================================================== *
 *                    公共 API（宏模式使用）                                    *
 * ======================================================================== */

/**
 * 分配 size 字节内存并记录追踪信息。
 *
 * 先通过 raw_malloc 分配用户内存，再创建追踪记录。
 * 若追踪记录创建失败，用户分配仍成功（静默降级）。
 *
 * @param size  分配字节数
 * @return      分配的内存指针，失败返回 NULL
 */
void* mtt_malloc(size_t size)
{
    mtt_resolve_raw_allocators();

    if (raw_malloc == NULL) return NULL;
    if (size == 0) return raw_malloc(0); /* 标准行为：malloc(0) 合法 */

    mtt_ensure_init();
    mtt_state_t *s = mtt_state_get();
    if (s == NULL) return raw_malloc(size);

    if (atomic_load_explicit(&s->disabled, memory_order_acquire))
        return raw_malloc(size);

    /* 启动阶段：跳过追踪（减少初始化分配噪声） */
    if (mtt_is_startup_phase(s))
        return raw_malloc(size);

    /* 先分配用户内存 */
    void *ptr = raw_malloc(size);
    if (ptr == NULL) return NULL;

    /* 采样与容量检查 */
    if (!mtt_should_track(s, size) || mtt_is_over_capacity(s))
        return ptr; /* 放行但不追踪 */

    /* 创建追踪记录（raw_malloc 内部分配，不触发 hook） */
    mtt_entry_t *e = mtt_entry_new(ptr, size);
    if (e == NULL) return ptr; /* 追踪记录失败不阻塞业务 */

    /* 持锁插入哈希表 + 更新统计 */
    mtt_stripe_lock(s, ptr);

    /* 锁内二次检查容量：消除 TOCTOU 竞争窗口 */
    if (atomic_load_explicit(&s->entry_count, memory_order_relaxed) >= MTT_MAX_ENTRIES) {
        atomic_fetch_add_explicit(&s->skipped_overcap, 1, memory_order_relaxed);
        mtt_stripe_unlock(s, ptr);
        if (raw_free != NULL) raw_free(e);
        return ptr; /* 用户内存已分配，仅跳过追踪 */
    }

    e->alloc_num = atomic_fetch_add_explicit(&s->alloc_seq, 1, memory_order_relaxed) + 1;
    atomic_fetch_add_explicit(&s->alloc_count, 1, memory_order_relaxed);
    atomic_fetch_add_explicit(&s->current_bytes, size, memory_order_relaxed);
    atomic_fetch_add_explicit(&s->total_bytes,   size, memory_order_relaxed);

    /* CAS 更新峰值 */
    size_t cur = atomic_load_explicit(&s->current_bytes, memory_order_relaxed);
    size_t old_peak = atomic_load_explicit(&s->peak_bytes, memory_order_relaxed);
    while (cur > old_peak) {
        if (atomic_compare_exchange_weak_explicit(&s->peak_bytes, &old_peak, cur,
                memory_order_relaxed, memory_order_relaxed))
            break;
    }
    /* 通知 reporter 线程：峰值已更新（借鉴 jemalloc prof_gdump） */
    atomic_store_explicit(&s->peak_updated, 1, memory_order_relaxed);

    mtt_entry_add(s, e);
    mtt_stripe_unlock(s, ptr);

    return ptr;
}

/**
 * 释放内存并从追踪表删除。
 *
 * @param ptr  要释放的内存指针，NULL 时无操作
 */
void mtt_free(void *ptr)
{
    if (ptr == NULL) return;

    mtt_resolve_raw_allocators();
    if (raw_free == NULL) return;

    mtt_ensure_init();
    mtt_state_t *s = mtt_state_get();
    if (s == NULL) {
        raw_free(ptr);
        return;
    }

    if (atomic_load_explicit(&s->disabled, memory_order_acquire)) {
        raw_free(ptr);
        return;
    }

    mtt_stripe_lock(s, ptr);
    mtt_entry_t *e = mtt_entry_find(s, ptr);
    if (e != NULL) {
        /* 防止 current_bytes underflow */
        if (e->size <= atomic_load_explicit(&s->current_bytes, memory_order_relaxed))
            atomic_fetch_sub_explicit(&s->current_bytes, e->size, memory_order_relaxed);
        else
            atomic_store_explicit(&s->current_bytes, 0, memory_order_relaxed);
        atomic_fetch_add_explicit(&s->free_count, 1, memory_order_relaxed);
        mtt_entry_remove(s, ptr);
    }
    mtt_stripe_unlock(s, ptr);
    raw_free(ptr);
}

/**
 * 分配并零初始化内存。
 *
 * @param count  元素个数
 * @param size   每个元素大小
 * @return       零初始化的内存指针，溢出或分配失败返回 NULL
 */
void* mtt_calloc(size_t count, size_t size)
{
    /* 整数溢出检查 */
    if (count > 0 && size > SIZE_MAX / count)
        return NULL;
    size_t total = count * size;
    void *ptr = mtt_malloc(total);
    if (ptr != NULL) memset(ptr, 0, total);
    return ptr;
}

/**
 * 重新分配内存。
 *
 * 优先使用 raw_realloc（libc 原生 realloc），只在 raw_realloc 未就绪或
 * 旧指针不在追踪表中时才降级使用 raw_malloc+memcpy+raw_free 方案。
 *
 * @param ptr   旧指针（NULL 等价于 mtt_malloc(size)）
 * @param size  新大小（0 等价于 mtt_free(ptr)）
 * @return      新指针，失败返回 NULL
 */
void* mtt_realloc(void *ptr, size_t size)
{
    if (ptr == NULL) return mtt_malloc(size);
    if (size == 0) { mtt_free(ptr); return NULL; }

    mtt_resolve_raw_allocators();
    if (raw_malloc == NULL) return NULL;

    mtt_ensure_init();
    mtt_state_t *s = mtt_state_get();
    if (s == NULL || atomic_load_explicit(&s->disabled, memory_order_acquire)) {
        /* 降级路径：使用 raw_realloc（若可用），否则模拟 */
        if (raw_realloc != NULL)
            return raw_realloc(ptr, size);
        /* raw_realloc 不可用：malloc+memcpy+free 模拟。
         * 注意：无旧大小信息，若 size > 原始大小则 memcpy 越界读取。
         * 此路径仅在初始化失败时走到，正常情况 raw_realloc 始终可用。 */
        void *new_ptr = raw_malloc(size);
        if (new_ptr == NULL) return NULL;
        memcpy(new_ptr, ptr, size);
        raw_free(ptr);
        return new_ptr;
    }

    /* 先利用 raw_realloc 完成真正的内存重分配。 */
    if (raw_realloc != NULL) {
        /* 锁内查找旧条目（用于后续统计更新） */
        mtt_stripe_lock(s, ptr);
        mtt_entry_t *old_e = mtt_entry_find(s, ptr);
        mtt_stripe_unlock(s, ptr);

        void *new_ptr = raw_realloc(ptr, size);
        if (new_ptr == NULL) return NULL;

        if (old_e != NULL) {
            /* 旧指针存在于追踪表：更新统计 + 替换条目 */
            mtt_stripe_lock(s, ptr);
            old_e = mtt_entry_find(s, ptr); /* 锁内再次确认 */
            if (old_e != NULL) {
                if (old_e->size <= atomic_load_explicit(&s->current_bytes, memory_order_relaxed))
                    atomic_fetch_sub_explicit(&s->current_bytes, old_e->size, memory_order_relaxed);
                else
                    atomic_store_explicit(&s->current_bytes, 0, memory_order_relaxed);
                atomic_fetch_add_explicit(&s->free_count, 1, memory_order_relaxed);
                mtt_entry_remove(s, ptr);
            }
            mtt_stripe_unlock(s, ptr);

            /* 创建新追踪记录 */
            if (!mtt_is_over_capacity(s)) {
                mtt_entry_t *new_e = mtt_entry_new(new_ptr, size);
                if (new_e != NULL) {
                    mtt_stripe_lock(s, new_ptr);
                    if (atomic_load_explicit(&s->entry_count, memory_order_relaxed) < MTT_MAX_ENTRIES) {
                        new_e->alloc_num = atomic_fetch_add_explicit(&s->alloc_seq, 1, memory_order_relaxed) + 1;
                        atomic_fetch_add_explicit(&s->alloc_count, 1, memory_order_relaxed);
                        atomic_fetch_add_explicit(&s->current_bytes, size, memory_order_relaxed);
                        atomic_fetch_add_explicit(&s->total_bytes, size, memory_order_relaxed);

                        size_t cur = atomic_load_explicit(&s->current_bytes, memory_order_relaxed);
                        size_t old_peak = atomic_load_explicit(&s->peak_bytes, memory_order_relaxed);
                        while (cur > old_peak) {
                            if (atomic_compare_exchange_weak_explicit(&s->peak_bytes, &old_peak, cur,
                                    memory_order_relaxed, memory_order_relaxed))
                                break;
                        }
                        atomic_store_explicit(&s->peak_updated, 1, memory_order_relaxed);
                        mtt_entry_add(s, new_e);
                    } else {
                        atomic_fetch_add_explicit(&s->skipped_overcap, 1, memory_order_relaxed);
                        if (raw_free != NULL) raw_free(new_e);
                    }
                    mtt_stripe_unlock(s, new_ptr);
                }
            }
        }
        return new_ptr;
    }

    /* raw_realloc 不可用时的降级路径（极端情况：bootstrap 阶段或平台无 realloc）。
     * 使用 malloc+memcpy+free 模拟。此处 s != NULL 且未禁用，可从追踪表获取旧大小。 */
    void *new_ptr = raw_malloc(size);
    if (new_ptr == NULL) return NULL;

    mtt_entry_t *new_e = mtt_entry_new(new_ptr, size);
    if (new_e == NULL) {
        raw_free(new_ptr);
        return NULL;
    }

    /* 删除旧追踪记录（并获取旧大小以安全拷贝） */
    mtt_stripe_lock(s, ptr);
    mtt_entry_t *old_e = mtt_entry_find(s, ptr);
    size_t old_size = (old_e != NULL) ? old_e->size : 0;
    if (old_e != NULL) {
        if (old_e->size <= atomic_load_explicit(&s->current_bytes, memory_order_relaxed))
            atomic_fetch_sub_explicit(&s->current_bytes, old_e->size, memory_order_relaxed);
        else
            atomic_store_explicit(&s->current_bytes, 0, memory_order_relaxed);
        atomic_fetch_add_explicit(&s->free_count, 1, memory_order_relaxed);
        mtt_entry_remove(s, ptr);
    }
    mtt_stripe_unlock(s, ptr);

    /* 安全拷贝：仅拷贝已知的旧大小字节数（old_size==0 时由 raw_realloc 处理） */
    size_t copy_n = (old_size > 0) ? ((old_size < size) ? old_size : size) : 0;
    if (copy_n > 0)
        memcpy(new_ptr, ptr, copy_n);

    /* 插入新追踪记录 */
    mtt_stripe_lock(s, new_ptr);

    if (atomic_load_explicit(&s->entry_count, memory_order_relaxed) >= MTT_MAX_ENTRIES) {
        atomic_fetch_add_explicit(&s->skipped_overcap, 1, memory_order_relaxed);
        mtt_stripe_unlock(s, new_ptr);
        if (raw_free != NULL) raw_free(new_e);
        raw_free(ptr);
        return new_ptr;
    }

    new_e->alloc_num = atomic_fetch_add_explicit(&s->alloc_seq, 1, memory_order_relaxed) + 1;
    atomic_fetch_add_explicit(&s->alloc_count, 1, memory_order_relaxed);
    atomic_fetch_add_explicit(&s->current_bytes, size, memory_order_relaxed);
    atomic_fetch_add_explicit(&s->total_bytes,   size, memory_order_relaxed);

    size_t cur = atomic_load_explicit(&s->current_bytes, memory_order_relaxed);
    size_t old_peak = atomic_load_explicit(&s->peak_bytes, memory_order_relaxed);
    while (cur > old_peak) {
        if (atomic_compare_exchange_weak_explicit(&s->peak_bytes, &old_peak, cur,
                memory_order_relaxed, memory_order_relaxed))
            break;
    }
    atomic_store_explicit(&s->peak_updated, 1, memory_order_relaxed);

    mtt_entry_add(s, new_e);
    mtt_stripe_unlock(s, new_ptr);

    raw_free(ptr);
    return new_ptr;
}

/* ---- 统计查询（relaxed 原子读取，无需持锁） ---- */

size_t mtt_get_alloc_count(void)
{
    mtt_state_t *s = mtt_state_get();
    return (s != NULL) ? atomic_load_explicit(&s->alloc_count, memory_order_relaxed) : 0;
}

size_t mtt_get_free_count(void)
{
    mtt_state_t *s = mtt_state_get();
    return (s != NULL) ? atomic_load_explicit(&s->free_count, memory_order_relaxed) : 0;
}

size_t mtt_get_leak_count(void)
{
    mtt_state_t *s = mtt_state_get();
    if (s == NULL) return 0;
    size_t a = atomic_load_explicit(&s->alloc_count, memory_order_relaxed);
    size_t f = atomic_load_explicit(&s->free_count, memory_order_relaxed);
    return (a > f) ? (a - f) : 0;
}

size_t mtt_get_current_usage(void)
{
    mtt_state_t *s = mtt_state_get();
    return (s != NULL) ? atomic_load_explicit(&s->current_bytes, memory_order_relaxed) : 0;
}

size_t mtt_get_peak_usage(void)
{
    mtt_state_t *s = mtt_state_get();
    return (s != NULL) ? atomic_load_explicit(&s->peak_bytes, memory_order_relaxed) : 0;
}

size_t mtt_get_total_allocated(void)
{
    mtt_state_t *s = mtt_state_get();
    return (s != NULL) ? atomic_load_explicit(&s->total_bytes, memory_order_relaxed) : 0;
}

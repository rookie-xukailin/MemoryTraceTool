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
 */

#define _GNU_SOURCE
#include "mtt_internal.h"
#include "reporter.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <execinfo.h>
#include <unistd.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <errno.h>
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
 * 初始值为 NULL，调用者必须确保只在这些指针非 NULL 时使用。 */
raw_malloc_fn raw_malloc = NULL;
raw_free_fn   raw_free   = NULL;
raw_calloc_fn raw_calloc = NULL;

/* CAS 保护的一次性解析标志 */
static atomic_int g_raw_resolved = 0;

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

/* ======================================================================== *
 *                 原始分配器解析（懒初始化 + CAS + 递归保护）                   *
 * ======================================================================== */

/**
 * 解析真正的 libc 分配函数指针。
 *
 * 使用 dlsym(RTLD_NEXT) 获取 libc 的 malloc/free/calloc，
 * 避免 LD_PRELOAD 模式下调用自身导致无限递归。
 *
 * 懒初始化：首次 hook 调用时触发，此时动态链接器已完全就绪。
 * 线程安全：CAS 确保多线程下仅执行一次。
 * 递归保护：g_raw_resolving 标志防止 dlsym 内部 malloc 回调。
 */
void mtt_resolve_raw_allocators(void)
{
    /* 快速路径：已解析完成 */
    if (raw_malloc != NULL)
        return;

    /* 递归保护：dlsym 内部可能触发 malloc */
    if (g_raw_resolving)
        return;

    /* 预置 bootstrap 分配器：必须在 CAS 之前完成。
     * 确保 CAS 失败线程使用 bootstrap_*（非 NULL），避免空指针崩溃。 */
    raw_malloc = bootstrap_malloc;
    raw_free   = bootstrap_free;
    raw_calloc = bootstrap_calloc;

    /* CAS 确保仅单线程执行 dlsym 解析 */
    int expected = 0;
    if (!atomic_compare_exchange_strong(&g_raw_resolved, &expected, 1))
        return;

    g_raw_resolving = 1;

    /* dlsym 内部可能触发 malloc，设置 g_in_hook 确保递归调用全部透传 */
    int saved_hook = g_in_hook;
    g_in_hook = 1;

    raw_malloc_fn real_malloc = (raw_malloc_fn)dlsym(RTLD_NEXT, "malloc");
    raw_free_fn   real_free   = (raw_free_fn)dlsym(RTLD_NEXT, "free");
    raw_calloc_fn real_calloc = (raw_calloc_fn)dlsym(RTLD_NEXT, "calloc");

    if (real_malloc != NULL) raw_malloc = real_malloc;
    if (real_free   != NULL) raw_free   = real_free;
    if (real_calloc != NULL) raw_calloc = real_calloc;

    /* RTLD_NEXT 失败时显式打开 libc（dlopen/ptrace 注入路径） */
    if (raw_malloc == NULL || raw_free == NULL || raw_calloc == NULL) {
        void *libc_handle = dlopen("libc.so.6", RTLD_LAZY);
        if (libc_handle != NULL) {
            if (raw_malloc == NULL)
                raw_malloc = (raw_malloc_fn)dlsym(libc_handle, "malloc");
            if (raw_free == NULL)
                raw_free   = (raw_free_fn)dlsym(libc_handle, "free");
            if (raw_calloc == NULL)
                raw_calloc = (raw_calloc_fn)dlsym(libc_handle, "calloc");
            /* 不 dlclose：避免 raw_* 悬空 */
        }
    }

    g_in_hook = saved_hook;
    g_raw_resolving = 0;

    /* 两种路径均失败时保留 bootstrap 分配器（至少不崩溃） */
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

    entry->stack_frames = backtrace(entry->stack, MTT_STACK_DEPTH);
    if (entry->stack_frames < 0)
        entry->stack_frames = 0;

    g_in_capture = saved;
}

/* ======================================================================== *
 *                       采样与容量控制                                       *
 * ======================================================================== */

/**
 * 决定当前分配是否应被记录。
 *
 * @param s  全局状态指针（调用者已确保非 NULL）
 * @return   1=应记录, 0=跳过
 */
int mtt_should_track(mtt_state_t *s)
{
    unsigned period = atomic_load(&s->sample_period);
    if (period == 0)
        return 1; /* 全量追踪 */

    unsigned long c = atomic_fetch_add(&s->sample_counter, 1);
    if ((c % period) == 0)
        return 1;

    atomic_fetch_add(&s->skipped_sampled, 1);
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
    unsigned long n = atomic_load(&s->entry_count);
    if (n >= MTT_MAX_ENTRIES) {
        atomic_fetch_add(&s->skipped_overcap, 1);
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
 * @param s     全局状态指针
 * @param entry 要插入的条目（调用者已确保非 NULL）
 */
void mtt_entry_add(mtt_state_t *s, mtt_entry_t *entry)
{
    if (s == NULL || entry == NULL || s->buckets == NULL) return;

    unsigned bucket = mtt_bucket_of(entry->ptr, s->bucket_count, s->hash_seed);
    entry->next = s->buckets[bucket];
    s->buckets[bucket] = entry;
    atomic_fetch_add(&s->entry_count, 1);
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

    /* 捕获调用栈（内部有防重入保护） */
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
    if (len <= 0) {
        snprintf(buf, size, "unknown");
        return;
    }
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
 * 采用双重检查锁定模式：快速路径用 atomic_load 检查 initialized 标志。
 */
void mtt_ensure_init(void)
{
    mtt_state_t *s = mtt_state_get();
    if (s == NULL) return;

    /* 快速路径：已初始化 */
    if (atomic_load(&s->initialized))
        return;

    /* 确保 raw_* 函数指针已解析 */
    mtt_resolve_raw_allocators();

    /* ---- 阶段1: 读取环境变量（无需持锁） ---- */
    int      want_disabled = 0;
    unsigned want_sample   = MTT_SAMPLE_DEFAULT;

    {
        const char *env_disable = getenv("MTT_DISABLE");
        if (env_disable != NULL && strcmp(env_disable, "1") == 0)
            want_disabled = 1;

        const char *env_sample = getenv("MTT_SAMPLE");
        if (env_sample != NULL) {
            int sp = atoi(env_sample);
            if (sp >= 0 && sp <= MTT_SAMPLE_MAX_PERIOD)
                want_sample = (unsigned)sp;
        }
    }

    /* ---- 阶段2: 持锁初始化数据结构（双重检查锁定） ---- */
    static pthread_mutex_t init_lock = PTHREAD_MUTEX_INITIALIZER;
    pthread_mutex_lock(&init_lock);

    /* 双重检查：可能在等锁期间已被其他线程初始化 */
    if (atomic_load(&s->initialized)) {
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
        pthread_mutex_unlock(&init_lock);
        return; /* 致命：无法分配桶表，静默降级 */
    }

    /* 生成随机哈希种子 */
    s->hash_seed = ((unsigned long)time(NULL) ^
                    ((unsigned long)getpid() << 16) ^
                    0x9e3779b97f4a7c15UL);

    /* 初始化分段锁 */
    for (int i = 0; i < MTT_LOCK_STRIPES; i++)
        pthread_mutex_init(&s->bucket_locks[i], NULL);

    /* 初始化原子计数器 */
    atomic_store(&s->alloc_seq,       0);
    atomic_store(&s->alloc_count,     0);
    atomic_store(&s->free_count,      0);
    atomic_store(&s->current_bytes,   0);
    atomic_store(&s->peak_bytes,      0);
    atomic_store(&s->total_bytes,     0);
    atomic_store(&s->skipped_sampled, 0);
    atomic_store(&s->skipped_overcap, 0);
    atomic_store(&s->sample_period,   want_sample);
    atomic_store(&s->sample_counter,  0);
    atomic_store(&s->entry_count,     0);
    atomic_store(&s->disabled,        want_disabled);

    /* 读取进程名 */
    get_process_name(s->proc_name, sizeof(s->proc_name));
    s->proc_name_ready = 1;

    /* 标记初始化完成（写屏障，确保上述所有初始化对其他线程可见） */
    atomic_store(&s->initialized, 1);
    pthread_mutex_unlock(&init_lock);

    /* 启动周期报告线程（锁外，避免 pthread_create 内部 malloc → 递归） */
    mtt_reporter_start();
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

    if (atomic_load(&s->disabled))
        return raw_malloc(size);

    /* 先分配用户内存 */
    void *ptr = raw_malloc(size);
    if (ptr == NULL) return NULL;

    /* 采样与容量检查 */
    if (!mtt_should_track(s) || mtt_is_over_capacity(s))
        return ptr; /* 放行但不追踪 */

    /* 创建追踪记录（raw_malloc 内部分配，不触发 hook） */
    mtt_entry_t *e = mtt_entry_new(ptr, size);
    if (e == NULL) return ptr; /* 追踪记录失败不阻塞业务 */

    /* 持锁插入哈希表 + 更新统计 */
    mtt_stripe_lock(s, ptr);
    e->alloc_num = atomic_fetch_add(&s->alloc_seq, 1) + 1;
    atomic_fetch_add(&s->alloc_count, 1);
    atomic_fetch_add(&s->current_bytes, size);
    atomic_fetch_add(&s->total_bytes,   size);

    /* CAS 更新峰值 */
    size_t cur = atomic_load(&s->current_bytes);
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

    if (atomic_load(&s->disabled)) {
        raw_free(ptr);
        return;
    }

    mtt_stripe_lock(s, ptr);
    mtt_entry_t *e = mtt_entry_find(s, ptr);
    if (e != NULL) {
        /* 防止 current_bytes underflow */
        if (e->size <= atomic_load(&s->current_bytes))
            atomic_fetch_sub(&s->current_bytes, e->size);
        else
            atomic_store(&s->current_bytes, 0);
        atomic_fetch_add(&s->free_count, 1);
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
    if (s == NULL) {
        /* 降级：直接 raw_realloc 模拟 */
        void *new_ptr = raw_malloc(size);
        if (new_ptr == NULL) return NULL;
        /* 无法获取旧大小，保守拷贝 min(size, ?) — 此处无完美方案 */
        memcpy(new_ptr, ptr, size); /* 可能越界，但无旧大小信息 */
        raw_free(ptr);
        return new_ptr;
    }

    if (atomic_load(&s->disabled)) {
        void *new_ptr = raw_malloc(size);
        if (new_ptr == NULL) return NULL;
        mtt_stripe_lock(s, ptr);
        mtt_entry_t *old_e = mtt_entry_find(s, ptr);
        size_t old_size = (old_e != NULL) ? old_e->size : size;
        mtt_stripe_unlock(s, ptr);
        size_t copy_n = (old_size < size) ? old_size : size;
        memcpy(new_ptr, ptr, copy_n);
        raw_free(ptr);
        return new_ptr;
    }

    /* 先分配新内存（失败不破坏旧状态） */
    void *new_ptr = raw_malloc(size);
    if (new_ptr == NULL) return NULL;

    /* 创建新追踪记录（失败放弃本次 realloc） */
    mtt_entry_t *new_e = mtt_entry_new(new_ptr, size);
    if (new_e == NULL) {
        raw_free(new_ptr);
        return NULL;
    }

    /* 删除旧追踪记录 */
    mtt_stripe_lock(s, ptr);
    mtt_entry_t *old_e = mtt_entry_find(s, ptr);
    size_t old_size = (old_e != NULL) ? old_e->size : size;
    if (old_e != NULL) {
        if (old_e->size <= atomic_load(&s->current_bytes))
            atomic_fetch_sub(&s->current_bytes, old_e->size);
        else
            atomic_store(&s->current_bytes, 0);
        atomic_fetch_add(&s->free_count, 1);
        mtt_entry_remove(s, ptr);
    }
    mtt_stripe_unlock(s, ptr);

    /* 拷贝数据 */
    size_t copy_n = (old_size < size) ? old_size : size;
    memcpy(new_ptr, ptr, copy_n);

    /* 插入新追踪记录 */
    mtt_stripe_lock(s, new_ptr);
    new_e->alloc_num = atomic_fetch_add(&s->alloc_seq, 1) + 1;
    atomic_fetch_add(&s->alloc_count, 1);
    atomic_fetch_add(&s->current_bytes, size);
    atomic_fetch_add(&s->total_bytes,   size);

    size_t cur = atomic_load(&s->current_bytes);
    size_t old_peak = atomic_load(&s->peak_bytes);
    while (cur > old_peak) {
        if (atomic_compare_exchange_weak(&s->peak_bytes, &old_peak, cur))
            break;
    }

    mtt_entry_add(s, new_e);
    mtt_stripe_unlock(s, new_ptr);

    raw_free(ptr);
    return new_ptr;
}

/* ---- 统计查询（原子读取，无需持锁） ---- */

size_t mtt_get_alloc_count(void)
{
    mtt_state_t *s = mtt_state_get();
    return (s != NULL) ? atomic_load(&s->alloc_count) : 0;
}

size_t mtt_get_free_count(void)
{
    mtt_state_t *s = mtt_state_get();
    return (s != NULL) ? atomic_load(&s->free_count) : 0;
}

size_t mtt_get_leak_count(void)
{
    mtt_state_t *s = mtt_state_get();
    if (s == NULL) return 0;
    size_t a = atomic_load(&s->alloc_count);
    size_t f = atomic_load(&s->free_count);
    return (a > f) ? (a - f) : 0;
}

size_t mtt_get_current_usage(void)
{
    mtt_state_t *s = mtt_state_get();
    return (s != NULL) ? atomic_load(&s->current_bytes) : 0;
}

size_t mtt_get_peak_usage(void)
{
    mtt_state_t *s = mtt_state_get();
    return (s != NULL) ? atomic_load(&s->peak_bytes) : 0;
}

size_t mtt_get_total_allocated(void)
{
    mtt_state_t *s = mtt_state_get();
    return (s != NULL) ? atomic_load(&s->total_bytes) : 0;
}

/*
 * MemoryTraceTool — LD_PRELOAD 拦截钩子。
 *
 * 本文件重写了 libc 的 malloc / calloc / realloc / free 符号，
 * 编译进动态库（libmemorytracetool.so）中。
 * 通过 LD_PRELOAD 加载后，无需修改任何源码即可拦截目标进程中
 * 所有的堆内存分配和释放操作。
 *
 * 防递归策略：
 *   - g_in_hook (__thread): 置位时直接透传到 raw_*，不做任何追踪
 *   - save/restore 模式支持嵌套调用
 *   - 所有内部分配使用 raw_malloc/raw_free（直接调用 libc）
 *   - bootstrap 缓冲区在 raw_* 未就绪时兜底
 *   - 不在 hook 路径中使用 fprintf/printf（内部触发 malloc）
 *   - 错误诊断使用 write() 系统调用（无 malloc）
 *
 * 线程安全：64 分段锁保护全局状态。
 *
 * 原子操作内存序：统计计数器用 relaxed，控制标志用 acquire/release。
 */

#define _GNU_SOURCE
#include "mtt_internal.h"
#include "per_thread.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <stdarg.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <errno.h>

/*
 * 所有诊断输出使用 write() 系统调用（无 malloc）。
 * 注意：snprintf 仅格式化到栈缓冲区，不触发堆分配。 */

/* ---- hook 诊断计数器（仅首次记录，避免高频 IO） ---- */

static _Atomic int g_first_malloc_diag  = 1;
static _Atomic int g_first_free_diag    = 1;
static _Atomic int g_first_calloc_diag  = 1;
static _Atomic int g_first_realloc_diag = 1;

/** 仅在首次调用时输出诊断（确认 hook 被调用） */
static void first_call_diag(const char *func_name, _Atomic int *flag)
{
    int expected = 1;
    if (atomic_compare_exchange_strong(flag, &expected, 0)) {
        char buf[128] = {0};
        int len = snprintf(buf, sizeof(buf),
            "[MTT] hook: %s first call (pid=%d)\n", func_name, (int)getpid());
        if (len > 0 && len < (int)sizeof(buf))
            MTT_DIAG_WRITE(STDERR_FILENO, buf, (size_t)len);
    }
}

/* ======================================================================== *
 *                     LD_PRELOAD 拦截入口                                     *
 * ======================================================================== */

/* 深度计数器已迁移至 per_thread.h 槽位数组。
 * mtt_hook_enter/inc/dec 内部通过 mtt_thread_get() 访问。 */

/** 获取当前 hook 调用深度，首次调用时自动修正脏值。
 * 若槽位满返回 -1（降级：视为递归，直接透传 raw_*） */
static inline int mtt_hook_enter(void)
{
    mtt_per_thread_t * __restrict__ ctx = mtt_thread_get();
    if (ctx == NULL) return -1; /* 降级：无槽位时保守视为递归 */
    if (ctx->depth_inited != 0x2A) {
        ctx->hook_depth = 0;
        ctx->depth_inited = 0x2A;
    }
    return ctx->hook_depth;
}

static inline void mtt_hook_inc_depth(void)
{
    mtt_per_thread_t * __restrict__ ctx = mtt_thread_get();
    if (ctx == NULL) return; /* 降级：无槽位时跳过 */
    int init_ok = (ctx->depth_inited == 0x2A);
    if (!init_ok) { ctx->hook_depth = 0; ctx->depth_inited = 0x2A; }
    ctx->hook_depth++;
}

static inline void mtt_hook_dec_depth(void)
{
    mtt_per_thread_t * __restrict__ ctx = mtt_thread_get();
    if (ctx == NULL) return; /* 降级：无槽位时跳过 */
    if (ctx->hook_depth > 0)
        ctx->hook_depth--;
    else
        ctx->hook_depth = 0;
}

/**
 * LD_PRELOAD 拦截的 malloc。
 *
 * 执行流程：
 *   1. g_in_hook 递归保护（save/restore）
 *   2. 解析 raw_* 分配器
 *   3. g_in_hook 置位 → 直接透传
 *   4. 懒初始化全局状态
 *   5. disabled/采样/容量检查
 *   6. raw_malloc 分配用户内存
 *   7. 创建追踪记录 → 插入哈希表 → 更新统计
 */
void* malloc(size_t size)
{
    /* 首次调用诊断 */
    first_call_diag("malloc", &g_first_malloc_diag);

    /* 递归保护：__thread 深度计数器（哨兵自动修正脏值） */
    {
        int depth = mtt_hook_enter();
        if (depth > 0) {
            mtt_resolve_raw_allocators();
            return (raw_malloc != NULL) ? raw_malloc(size) : NULL;
        }
    }
    mtt_per_thread_t *ctx = mtt_thread_get();
    if (ctx == NULL) {
        /* 槽位满：降级透传，不追踪 */
        mtt_resolve_raw_allocators();
        return (raw_malloc != NULL) ? raw_malloc(size) : NULL;
    }
    mtt_hook_inc_depth();
    int saved_hook = ctx->in_hook;
    ctx->in_hook = 1;

    mtt_resolve_raw_allocators();

    /* 工具内部线程（reporter/HTTP）：直接透传，不追踪 */
    if (ctx->tool_internal) {
        void *ret = (raw_malloc != NULL) ? raw_malloc(size) : NULL;
    mtt_hook_dec_depth();
    ctx->in_hook = saved_hook;
        return ret;
    }

    if (raw_malloc == NULL) {
    mtt_hook_dec_depth();
    ctx->in_hook = saved_hook;
        return NULL;
    }

    /* 0 字节分配：标准行为 */
    if (size == 0) {
        void *ret = raw_malloc(0);
    mtt_hook_dec_depth();
    ctx->in_hook = saved_hook;
        return ret;
    }

    mtt_ensure_init();
    mtt_state_t *s = mtt_state_get();

    /* 启动阶段宽限：跳过追踪，直接透传 */
    if (s != NULL && mtt_is_startup_phase(s)) {
        void *ret = raw_malloc(size);
    mtt_hook_dec_depth();
    ctx->in_hook = saved_hook;
        return ret;
    }
    if (s == NULL) {
        void *ret = raw_malloc(size);
    mtt_hook_dec_depth();
    ctx->in_hook = saved_hook;
        return ret;
    }

    /* 紧急禁用：直接透传 */
    if (atomic_load_explicit(&s->disabled, memory_order_acquire)) {
        void *ret = raw_malloc(size);
    mtt_hook_dec_depth();
    ctx->in_hook = saved_hook;
        return ret;
    }

    /* 先分配用户内存 */
    void *ptr = raw_malloc(size);
    if (ptr == NULL) {
    mtt_hook_dec_depth();
    ctx->in_hook = saved_hook;
        return NULL;
    }

    /* 采样与容量检查（不满足条件则放行不追踪） */
    {
        int track_ok = mtt_should_track(s, size);
        int over_cap = mtt_is_over_capacity(s);
        if (!track_ok || over_cap) {
    mtt_hook_dec_depth();
    ctx->in_hook = saved_hook;
            return ptr;
        }
    }

    /* 创建追踪记录（内部使用 raw_malloc） */
    mtt_entry_t *e = mtt_entry_new(ptr, size);
    if (e == NULL) {
    mtt_hook_dec_depth();
    ctx->in_hook = saved_hook;
        return ptr; /* 追踪失败不阻塞业务 */
    }

    /* 持锁插入哈希表 + 原子更新计数器 */
    mtt_stripe_lock(s, ptr);

    /* 锁内二次检查容量:已达上限则跳过追踪,用户分配已成功。
     * 原 LRU 淘汰逻辑违反分段锁契约(只持 1/64 锁却遍历全部 4096 桶),
     * 与其他线程的 free 路径竞争 entry->next 指针,可能 UAF 或双释放。
     * 与 tracker.c:mtt_malloc 路径保持一致的简单跳过策略。 */
    if (atomic_load_explicit(&s->entry_count, memory_order_relaxed) >= MTT_MAX_ENTRIES) {
        atomic_fetch_add_explicit(&s->skipped_overcap, 1, memory_order_relaxed);
        mtt_stripe_unlock(s, ptr);
        if (raw_free != NULL) raw_free(e);
    mtt_hook_dec_depth();
    ctx->in_hook = saved_hook;
        return ptr;
    }

    e->alloc_num = atomic_fetch_add_explicit(&s->alloc_seq, 1, memory_order_relaxed) + 1;
    atomic_fetch_add_explicit(&s->alloc_count, 1, memory_order_relaxed);
    atomic_fetch_add_explicit(&s->current_bytes, size, memory_order_relaxed);
    atomic_fetch_add_explicit(&s->total_bytes,   size, memory_order_relaxed);

    /* CAS 更新峰值 */
    {
        int peak_changed = 0;
        size_t cur = atomic_load_explicit(&s->current_bytes, memory_order_relaxed);
        size_t old_peak = atomic_load_explicit(&s->peak_bytes, memory_order_relaxed);
        while (cur > old_peak) {
            if (atomic_compare_exchange_weak_explicit(&s->peak_bytes, &old_peak, cur,
                    memory_order_relaxed, memory_order_relaxed)) {
                peak_changed = 1;
                break;
            }
        }
        /* 峰值更新后通知 reporter 线程（借鉴 jemalloc prof_gdump）。
         * 仅在 LD_PRELOAD 路径（hooks.c）中设置，mtt_malloc API 路径中也设置。
         * ARM32: relaxed store 成本低廉，避免峰值漏报导致的延迟报告。 */
        if (peak_changed)
            atomic_store_explicit(&s->peak_updated, 1, memory_order_relaxed);
    }

    mtt_entry_add(s, e);
    mtt_stripe_unlock(s, ptr);

    mtt_hook_dec_depth();
    ctx->in_hook = saved_hook;
    return ptr;
}

/**
 * LD_PRELOAD 拦截的 free。
 */
void free(void *ptr)
{
    first_call_diag("free", &g_first_free_diag);

    if (ptr == NULL) return;

    /* 递归保护：栈回溯检测 */
    if (mtt_hook_enter() > 0) {
        mtt_resolve_raw_allocators();
        if (raw_free != NULL) raw_free(ptr);
        return;
    }
    mtt_per_thread_t *ctx = mtt_thread_get();
    if (ctx == NULL) {
        /* 槽位满：降级直接释放 */
        mtt_resolve_raw_allocators();
        if (raw_free != NULL) raw_free(ptr);
        return;
    }
    mtt_hook_inc_depth();
    int saved_hook = ctx->in_hook;
    ctx->in_hook = 1;

    mtt_resolve_raw_allocators();

    /* 工具内部线程：直接透传 */
    if (ctx->tool_internal) {
        if (raw_free != NULL) raw_free(ptr);
    mtt_hook_dec_depth();
    ctx->in_hook = saved_hook;
        return;
    }

    if (raw_free == NULL) {
    mtt_hook_dec_depth();
    ctx->in_hook = saved_hook;
        return;
    }

    mtt_ensure_init();
    mtt_state_t *s = mtt_state_get();
    if (s == NULL) {
        raw_free(ptr);
    mtt_hook_dec_depth();
    ctx->in_hook = saved_hook;
        return;
    }

    if (atomic_load_explicit(&s->disabled, memory_order_acquire)) {
        raw_free(ptr);
    mtt_hook_dec_depth();
    ctx->in_hook = saved_hook;
        return;
    }

    mtt_stripe_lock(s, ptr);
    mtt_entry_t *e = mtt_entry_find(s, ptr);
    if (e != NULL) {
        if (e->size <= atomic_load_explicit(&s->current_bytes, memory_order_relaxed))
            atomic_fetch_sub_explicit(&s->current_bytes, e->size, memory_order_relaxed);
        else
            atomic_store_explicit(&s->current_bytes, 0, memory_order_relaxed);
        atomic_fetch_add_explicit(&s->free_count, 1, memory_order_relaxed);
        /* 临时分配检测：寿命<1秒→大概率非泄漏（借鉴 heaptrack 临时分配检测） */
        if (time(NULL) - e->timestamp <= 1)
            atomic_fetch_add_explicit(&s->temp_alloc_count, 1, memory_order_relaxed);
        /* 延迟释放追踪：若释放时已超泄漏阈值→曾是"可疑泄漏"但后来释放了（借鉴 libleak late-free） */
        {
            time_t threshold = atomic_load_explicit(&s->leak_threshold_sec, memory_order_relaxed);
            if (threshold > 0 && (time(NULL) - e->timestamp) > threshold)
                atomic_fetch_add_explicit(&s->free_expired_count, 1, memory_order_relaxed);
        }
        mtt_entry_remove(s, ptr);
    }
    mtt_stripe_unlock(s, ptr);
    raw_free(ptr);
    mtt_hook_dec_depth();
    ctx->in_hook = saved_hook;
}

/**
 * LD_PRELOAD 拦截的 calloc。
 */
void* calloc(size_t count, size_t size)
{
    first_call_diag("calloc", &g_first_calloc_diag);

    /* 递归保护：栈回溯检测 */
    if (mtt_hook_enter() > 0) {
        mtt_resolve_raw_allocators();
        if (raw_malloc == NULL) return NULL;
        if (count > 0 && size > SIZE_MAX / count) return NULL;
        size_t total = count * size;
        void *p = raw_malloc(total);
        if (p != NULL) memset(p, 0, total);
        return p;
    }
    mtt_per_thread_t *ctx = mtt_thread_get();
    if (ctx == NULL) {
        /* 槽位满：降级，直接 raw_malloc + memset */
        mtt_resolve_raw_allocators();
        if (raw_malloc == NULL) return NULL;
        if (count > 0 && size > SIZE_MAX / count) return NULL;
        size_t total = count * size;
        void *p = raw_malloc(total);
        if (p != NULL) memset(p, 0, total);
        return p;
    }
    /* 工具内部线程：直接透传 raw_malloc + memset，不追踪 */
    if (ctx->tool_internal) {
        mtt_resolve_raw_allocators();
        if (raw_malloc == NULL) return NULL;
        if (count > 0 && size > SIZE_MAX / count) return NULL;
        size_t t = count * size;
        void *p = raw_malloc(t);
        if (p != NULL) memset(p, 0, t);
        return p;
    }

    /* 整数溢出检查 */
    if (count > 0 && size > SIZE_MAX / count)
        return NULL;
    size_t total = count * size;

    /* 通过本文件的 malloc() 分配并追踪。
     * mtt_is_recursive_call() 确保 calloc→malloc 链路中
     * malloc 能正确识别调用栈中的 calloc 帧并绕过追踪。
     * g_in_hook 由 malloc 内部自行 save/restore。 */
    void *ptr = malloc(total);
    if (ptr != NULL) memset(ptr, 0, total);

    return ptr;
}

/**
 * LD_PRELOAD 拦截的 realloc。
 *
 * 优先使用 raw_realloc（libc 原生 realloc），避免手动 memcpy 带来的
 * 越界读取风险。仅在 raw_realloc 不可用（bootstrap 阶段）时降级为
 * malloc+memcpy+free 方案。
 */
void* realloc(void *ptr, size_t size)
{
    first_call_diag("realloc", &g_first_realloc_diag);

    if (ptr == NULL) return malloc(size);
    if (size == 0) { free(ptr); return NULL; }

    /* 递归保护：栈回溯检测 */
    if (mtt_hook_enter() > 0) {
        mtt_resolve_raw_allocators();
        if (raw_realloc != NULL)
            return raw_realloc(ptr, size);
        if (raw_malloc == NULL) return NULL;
        void *new_ptr = raw_malloc(size);
        if (new_ptr == NULL) return NULL;
        if (raw_free != NULL) raw_free(ptr);
        return new_ptr;
    }
    mtt_per_thread_t *ctx = mtt_thread_get();
    if (ctx == NULL) {
        /* 槽位满：降级使用 raw_realloc */
        mtt_resolve_raw_allocators();
        if (raw_realloc != NULL) return raw_realloc(ptr, size);
        if (raw_malloc == NULL) return NULL;
        void *np = raw_malloc(size);
        if (np == NULL) return NULL;
        if (raw_free != NULL) raw_free(ptr);
        return np;
    }
    mtt_hook_inc_depth();
    int saved_hook = ctx->in_hook;
    ctx->in_hook = 1;

    mtt_resolve_raw_allocators();

    /* 工具内部线程：直接透传 */
    if (ctx->tool_internal) {
        void *ret;
        if (raw_realloc != NULL) {
            ret = raw_realloc(ptr, size);
        } else {
            ret = (raw_malloc != NULL) ? raw_malloc(size) : NULL;
            if (ret != NULL && raw_free != NULL) raw_free(ptr);
        }
    mtt_hook_dec_depth();
    ctx->in_hook = saved_hook;
        return ret;
    }

    if (raw_malloc == NULL) {
    mtt_hook_dec_depth();
    ctx->in_hook = saved_hook;
        return NULL;
    }

    mtt_ensure_init();
    mtt_state_t *s = mtt_state_get();
    if (s == NULL || atomic_load_explicit(&s->disabled, memory_order_acquire)) {
        /* 降级：优先使用 raw_realloc */
        if (raw_realloc != NULL) {
            void *ret = raw_realloc(ptr, size);
    mtt_hook_dec_depth();
    ctx->in_hook = saved_hook;
            return ret;
        }
        /* 无 raw_realloc：malloc + free 模拟(不拷贝,避免越界读)。
         * 旧 size 未知,若用 size 作为 memcpy 长度,新 size > 旧 size 时
         * 会越界读 ptr 之后的堆数据。与 tracker.c:mtt_realloc 同路径保持一致。
         * 此分支仅在初始化失败时走到,正常情况 raw_realloc 始终可用。 */
        void *new_ptr = raw_malloc(size);
        if (new_ptr == NULL) {
    mtt_hook_dec_depth();
    ctx->in_hook = saved_hook;
            return NULL;
        }
        if (raw_free != NULL) raw_free(ptr);
    mtt_hook_dec_depth();
    ctx->in_hook = saved_hook;
        return new_ptr;
    }

    /* ---- 正常追踪路径：使用 raw_realloc ---- */

    if (raw_realloc != NULL) {
        /* 分配前从追踪表读取旧条目（用于后续统计更新） */
        mtt_stripe_lock(s, ptr);
        mtt_entry_t *old_e = mtt_entry_find(s, ptr);
        mtt_stripe_unlock(s, ptr);

        void *new_ptr = raw_realloc(ptr, size);
        if (new_ptr == NULL) {
    mtt_hook_dec_depth();
    ctx->in_hook = saved_hook;
            return NULL;
        }

        if (old_e != NULL) {
            /* 旧指针有追踪记录：更新统计 + 替换条目 */
            mtt_stripe_lock(s, ptr);
            old_e = mtt_entry_find(s, ptr); /* 锁内再次确认 */
            if (old_e != NULL) {
                size_t sub_size = (old_e->size <= atomic_load_explicit(&s->current_bytes, memory_order_relaxed))
                    ? old_e->size : 0;
                if (sub_size > 0)
                    atomic_fetch_sub_explicit(&s->current_bytes, sub_size, memory_order_relaxed);
                else
                    atomic_store_explicit(&s->current_bytes, 0, memory_order_relaxed);
                atomic_fetch_add_explicit(&s->free_count, 1, memory_order_relaxed);
                mtt_entry_remove(s, ptr);
            }
            mtt_stripe_unlock(s, ptr);

            /* 创建新追踪记录（不阻塞业务） */
            if (!mtt_is_over_capacity(s)) {
                mtt_entry_t *new_e = mtt_entry_new(new_ptr, size);
                if (new_e != NULL) {
                    mtt_stripe_lock(s, new_ptr);
                    if (atomic_load_explicit(&s->entry_count, memory_order_relaxed) < MTT_MAX_ENTRIES) {
                        new_e->alloc_num = atomic_fetch_add_explicit(&s->alloc_seq, 1, memory_order_relaxed) + 1;
                        atomic_fetch_add_explicit(&s->alloc_count, 1, memory_order_relaxed);
                        atomic_fetch_add_explicit(&s->current_bytes, size, memory_order_relaxed);
                        atomic_fetch_add_explicit(&s->total_bytes, size, memory_order_relaxed);

                        {
                            int peak_changed = 0;
                            size_t cur = atomic_load_explicit(&s->current_bytes, memory_order_relaxed);
                            size_t old_peak = atomic_load_explicit(&s->peak_bytes, memory_order_relaxed);
                            while (cur > old_peak) {
                                if (atomic_compare_exchange_weak_explicit(&s->peak_bytes, &old_peak, cur,
                                        memory_order_relaxed, memory_order_relaxed)) {
                                    peak_changed = 1;
                                    break;
                                }
                            }
                            if (peak_changed)
                                atomic_store_explicit(&s->peak_updated, 1, memory_order_relaxed);
                        }
                        mtt_entry_add(s, new_e);
                    } else {
                        atomic_fetch_add_explicit(&s->skipped_overcap, 1, memory_order_relaxed);
                        if (raw_free != NULL) raw_free(new_e);
                    }
                    mtt_stripe_unlock(s, new_ptr);
                }
            }
        }
        /* else: 旧指针不在追踪表中（tracking 之前分配的），
         * raw_realloc 已完成实际内存操作，无需维护追踪表 */

    mtt_hook_dec_depth();
    ctx->in_hook = saved_hook;
        return new_ptr;
    }

    /* ---- raw_realloc 不可用（bootstrap 阶段）的降级路径 ---- */

    /* 先分配新内存（失败不破坏旧状态） */
    void *new_ptr = raw_malloc(size);
    if (new_ptr == NULL) {
    mtt_hook_dec_depth();
    ctx->in_hook = saved_hook;
        return NULL;
    }

    /* 创建新追踪记录 */
    mtt_entry_t *new_e = mtt_entry_new(new_ptr, size);
    if (new_e == NULL) {
        raw_free(new_ptr);
    mtt_hook_dec_depth();
    ctx->in_hook = saved_hook;
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

    /* 安全拷贝：仅拷贝已知的旧大小字节数，避免越界读取 */
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
    mtt_hook_dec_depth();
    ctx->in_hook = saved_hook;
        return new_ptr;
    }

    new_e->alloc_num = atomic_fetch_add_explicit(&s->alloc_seq, 1, memory_order_relaxed) + 1;
    atomic_fetch_add_explicit(&s->alloc_count, 1, memory_order_relaxed);
    atomic_fetch_add_explicit(&s->current_bytes, size, memory_order_relaxed);
    atomic_fetch_add_explicit(&s->total_bytes,   size, memory_order_relaxed);

    {
        int peak_changed = 0;
        size_t cur = atomic_load_explicit(&s->current_bytes, memory_order_relaxed);
        size_t old_peak = atomic_load_explicit(&s->peak_bytes, memory_order_relaxed);
        while (cur > old_peak) {
            if (atomic_compare_exchange_weak_explicit(&s->peak_bytes, &old_peak, cur,
                    memory_order_relaxed, memory_order_relaxed)) {
                peak_changed = 1;
                break;
            }
        }
        if (peak_changed)
            atomic_store_explicit(&s->peak_updated, 1, memory_order_relaxed);
    }

    mtt_entry_add(s, new_e);
    mtt_stripe_unlock(s, new_ptr);

    raw_free(ptr);
    mtt_hook_dec_depth();
    ctx->in_hook = saved_hook;
    return new_ptr;
}

/* ======================================================================== *
 *              aligned_alloc / posix_memalign / reallocarray                 *
 * ======================================================================== */

/**
 * LD_PRELOAD 拦截的 aligned_alloc (C11)。
 * 手动实现对齐逻辑，通过 raw_malloc 分配，绕过 hook 递归。
 */
void* aligned_alloc(size_t alignment, size_t size)
{
    mtt_resolve_raw_allocators();
    if (raw_malloc == NULL) return NULL;

    /* 对齐必须为 2 的幂且 >= sizeof(void*) */
    if (alignment < sizeof(void*)) alignment = sizeof(void*);
    if ((alignment & (alignment - 1)) != 0) return NULL;
    if (size == 0) size = 1;
    /* 向上取整为 alignment 倍数 */
    size = (size + alignment - 1) & ~(alignment - 1);

    /* 多分配 alignment + sizeof(void*) 用于对齐和存储原始指针 */
    size_t total = size + alignment + sizeof(void*);
    char *raw = (char*)raw_malloc(total);
    if (raw == NULL) return NULL;

    /* 对齐到 alignment 边界，保留空间存原始指针 */
    uintptr_t addr = (uintptr_t)(raw + sizeof(void*));
    addr = (addr + alignment - 1) & ~((uintptr_t)(alignment - 1));
    void *aligned = (void*)addr;
    /* 在对齐指针前存储原始 raw 指针，供 aligned_free 使用 */
    ((void**)aligned)[-1] = raw;

    return aligned;
}

/** LD_PRELOAD 拦截的 posix_memalign (POSIX) */
int posix_memalign(void **memptr, size_t alignment, size_t size)
{
    if (alignment < sizeof(void*)) alignment = sizeof(void*);
    if ((alignment & (alignment - 1)) != 0) return 22; /* EINVAL */
    void *p = aligned_alloc(alignment, size);
    if (p == NULL) return 12; /* ENOMEM */
    *memptr = p;
    return 0;
}

/** LD_PRELOAD 拦截的 reallocarray (BSD) */
void* reallocarray(void *ptr, size_t nmemb, size_t size)
{
    if (nmemb > 0 && size > SIZE_MAX / nmemb) {
        errno = 12; /* ENOMEM */
        return NULL;
    }
    return realloc(ptr, nmemb * size);
}

/** LD_PRELOAD 拦截的 memalign (过时) */
void* memalign(size_t alignment, size_t size)
{
    return aligned_alloc(alignment, size);
}

/** LD_PRELOAD 拦截的 valloc (过时) */
void* valloc(size_t size)
{
    return aligned_alloc((size_t)getpagesize(), size);
}

/* ======================================================================== *
 *            strdup / asprintf — 优化调用栈（跳过 libc 包装帧）                *
 * ======================================================================== */

/** LD_PRELOAD 拦截的 strdup：直接调 malloc，栈回溯跳过 strdup 自身 */
char* strdup(const char *s)
{
    size_t len = strlen(s) + 1;
    char *p = (char*)malloc(len);
    if (p != NULL) memcpy(p, s, len);
    return p;
}

/** LD_PRELOAD 拦截的 strndup */
char* strndup(const char *s, size_t n)
{
    size_t len = strnlen(s, n);
    char *p = (char*)malloc(len + 1);
    if (p != NULL) {
        memcpy(p, s, len);
        p[len] = '\0';
    }
    return p;
}

/** LD_PRELOAD 拦截的 asprintf */
int asprintf(char **strp, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    int ret = vasprintf(strp, fmt, ap);
    va_end(ap);
    return ret;
}

/** LD_PRELOAD 拦截的 vasprintf */
int vasprintf(char **strp, const char *fmt, va_list ap)
{
    if (strp == NULL) return -1;
    va_list ap2;
    va_copy(ap2, ap);
    int len = vsnprintf(NULL, 0, fmt, ap);
    if (len < 0) { va_end(ap2); return -1; }
    char *buf = (char*)malloc((size_t)len + 1);
    if (buf == NULL) { va_end(ap2); return -1; }
    int written = vsnprintf(buf, (size_t)len + 1, fmt, ap2);
    va_end(ap2);
    if (written < 0) { free(buf); return -1; }
    *strp = buf;
    return written;
}

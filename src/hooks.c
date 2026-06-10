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

/* 递归深度计数器：替代 __thread int g_in_hook 用于递归检测。
 * pthread_getspecific/setspecific 使用 glibc 内部 TCB（线程控制块），
 * pthread_getspecific 在某些 ARM64 设备上可能对未设置 key 的线程返回脏值，
 * 改用 __thread int 作为深度计数器：BSS 零初始化，每个线程独立，更可靠。 */
static __thread int g_hook_depth = 0;

/** 获取当前 hook 调用深度（entry 前），entry 后 depth+1 */
static inline int mtt_hook_enter(void)
{
    return g_hook_depth;
}

static inline void mtt_hook_inc_depth(void)
{
    g_hook_depth++;
}

static inline void mtt_hook_dec_depth(void)
{
    if (g_hook_depth > 0)
        g_hook_depth--;
    else
        g_hook_depth = 0; /* 防御：异常归零，避免一直卡在负值 */
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
    /* 最简诊断：直接用write(2)，无snprintf无变量，零失败可能 */
    if (size == 10) {
        char m10[48];
        int len = snprintf(m10, sizeof(m10),
            "[MTT] M10 tid=%d\n", (int)syscall(SYS_gettid));
        if (len > 0 && len < (int)sizeof(m10))
            MTT_DIAG_WRITE(STDERR_FILENO, m10, (size_t)len);
    }

    /* 首次调用诊断 */
    first_call_diag("malloc", &g_first_malloc_diag);

    /* 第2层递归保护：pthread深度计数器 + g_in_hook双重检查。
     * depth>0 → 真正的递归调用 → bypass
     * g_in_hook && depth==0 → __thread被异常污染 → 清零后继续追踪 */
    int depth = mtt_hook_enter();
    if (depth > 0) {
        if (size == 10) {
            char dbuf[56];
            int dlen = snprintf(dbuf, sizeof(dbuf),
                "[MTT] BYPASS:depth d=%d tid=%d\n",
                depth, (int)syscall(SYS_gettid));
            if (dlen > 0 && dlen < (int)sizeof(dbuf))
                MTT_DIAG_WRITE(2, dbuf, (size_t)dlen);
        }
        mtt_resolve_raw_allocators();
        return (raw_malloc != NULL) ? raw_malloc(size) : NULL;
    }
    /* depth==0: 用户代码直接调用，非递归 */
    if (size == 10) {
        char m[48];
        int len = snprintf(m, sizeof(m),
            "[MTT] M10-ENTER tid=%d\n", (int)syscall(SYS_gettid));
        if (len > 0 && len < (int)sizeof(m))
            MTT_DIAG_WRITE(2, m, (size_t)len);
    }
    if (g_in_hook) {
        if (size == 10) { static const char m[]="[MTT] BYPASS:hook\n"; MTT_DIAG_WRITE(2,m,sizeof(m)-1); }
        g_in_hook = 0; /* __thread卡在1，清零，继续追踪 */
    }
    mtt_hook_inc_depth();
    int saved_hook = g_in_hook;
    g_in_hook = 1;

    mtt_resolve_raw_allocators();

    /* 工具内部线程（reporter/HTTP）：直接透传，不追踪 */
    if (g_tool_internal) {
        if (size == 10) { static const char m[]="[MTT] BYPASS:internal\n"; MTT_DIAG_WRITE(2,m,sizeof(m)-1); }
        void *ret = (raw_malloc != NULL) ? raw_malloc(size) : NULL;
    mtt_hook_dec_depth();
    g_in_hook = saved_hook;
        return ret;
    }

    if (raw_malloc == NULL) {
        if (size == 10) { static const char m[]="[MTT] BYPASS:rawmalloc_null\n"; MTT_DIAG_WRITE(2,m,sizeof(m)-1); }
    mtt_hook_dec_depth();
    g_in_hook = saved_hook;
        return NULL;
    }

    /* 0 字节分配：标准行为 */
    if (size == 0) {
        void *ret = raw_malloc(0);
    mtt_hook_dec_depth();
    g_in_hook = saved_hook;
        return ret;
    }

    mtt_ensure_init();
    mtt_state_t *s = mtt_state_get();

    /* 启动阶段宽限：跳过追踪，直接透传 */
    if (s != NULL && mtt_is_startup_phase(s)) {
        if (size == 10) { static const char m[]="[MTT] BYPASS:startup\n"; MTT_DIAG_WRITE(2,m,sizeof(m)-1); }
        void *ret = raw_malloc(size);
    mtt_hook_dec_depth();
    g_in_hook = saved_hook;
        return ret;
    }
    if (s == NULL) {
        if (size == 10) { static const char m[]="[MTT] BYPASS:s_null\n"; MTT_DIAG_WRITE(2,m,sizeof(m)-1); }
        void *ret = raw_malloc(size);
    mtt_hook_dec_depth();
    g_in_hook = saved_hook;
        return ret;
    }

    /* 紧急禁用：直接透传 */
    if (atomic_load_explicit(&s->disabled, memory_order_acquire)) {
        if (size == 10) { static const char m[]="[MTT] BYPASS:disabled\n"; MTT_DIAG_WRITE(2,m,sizeof(m)-1); }
        void *ret = raw_malloc(size);
    mtt_hook_dec_depth();
    g_in_hook = saved_hook;
        return ret;
    }

    /* 先分配用户内存 */
    void *ptr = raw_malloc(size);
    if (ptr == NULL) {
        if (size == 10) { static const char m[]="[MTT] BYPASS:malloc_fail\n"; MTT_DIAG_WRITE(2,m,sizeof(m)-1); }
    mtt_hook_dec_depth();
    g_in_hook = saved_hook;
        return NULL;
    }

    /* 采样与容量检查（不满足条件则放行不追踪） */
    {
        int track_ok = mtt_should_track(s, size);
        int over_cap = mtt_is_over_capacity(s);
        if (!track_ok || over_cap) {
            if (size <= 128) {
                char dbuf[96];
                int dlen = snprintf(dbuf, sizeof(dbuf),
                    "[MTT] hook: malloc(%zu) SKIP track=%d overcap=%d\n",
                    size, track_ok, over_cap);
                if (dlen > 0 && dlen < (int)sizeof(dbuf))
                    MTT_DIAG_WRITE(STDERR_FILENO, dbuf, (size_t)dlen);
            }
    mtt_hook_dec_depth();
    g_in_hook = saved_hook;
            return ptr;
        }
    }

    /* 创建追踪记录（内部使用 raw_malloc） */
    mtt_entry_t *e = mtt_entry_new(ptr, size);
    if (e == NULL) {
        if (size <= 128) {
            char dbuf[64];
            int dlen = snprintf(dbuf, sizeof(dbuf),
                "[MTT] hook: malloc(%zu) entry_new FAILED\n", size);
            if (dlen > 0 && dlen < (int)sizeof(dbuf))
                MTT_DIAG_WRITE(STDERR_FILENO, dbuf, (size_t)dlen);
        }
    mtt_hook_dec_depth();
    g_in_hook = saved_hook;
        return ptr; /* 追踪失败不阻塞业务 */
    }

    /* 诊断：小分配追踪成功 */
    if (size <= 128) {
        char dbuf[64];
        int dlen = snprintf(dbuf, sizeof(dbuf),
            "[MTT] hook: malloc(%zu) tracked, entry=%llu\n",
            size, (unsigned long long)atomic_load_explicit(
                &s->entry_count, memory_order_relaxed));
        if (dlen > 0 && dlen < (int)sizeof(dbuf))
            MTT_DIAG_WRITE(STDERR_FILENO, dbuf, (size_t)dlen);
    }

    /* 持锁插入哈希表 + 原子更新计数器 */
    mtt_stripe_lock(s, ptr);

    /* 锁内二次检查容量 + LRU 淘汰。
     * 若已满，尝试淘汰最旧的条目为新分配腾出空间。 */
    if (atomic_load_explicit(&s->entry_count, memory_order_relaxed) >= MTT_MAX_ENTRIES) {
        /* 尝试淘汰 1 个条目：遍历桶表找到最旧的条目并移除 */
        mtt_entry_t *oldest = NULL;
        unsigned oldest_bucket = 0;
        uint64_t oldest_seq = UINT64_MAX;
        for (unsigned b = 0; b < (unsigned)s->bucket_count; b++) {
            for (mtt_entry_t *cur = s->buckets[b]; cur != NULL; cur = cur->next) {
                if (cur->alloc_num < oldest_seq) {
                    oldest_seq = cur->alloc_num;
                    oldest = cur;
                    oldest_bucket = b;
                }
            }
        }
        if (oldest != NULL) {
            /* 从链表中移除 oldest */
            mtt_entry_t **prev = &s->buckets[oldest_bucket];
            while (*prev != NULL && *prev != oldest)
                prev = &(*prev)->next;
            if (*prev == oldest) {
                *prev = oldest->next;
                atomic_fetch_sub_explicit(&s->current_bytes, oldest->size, memory_order_relaxed);
                atomic_fetch_sub_explicit(&s->entry_count, 1, memory_order_relaxed);
                atomic_fetch_add_explicit(&s->skipped_overcap, 1, memory_order_relaxed);
                if (raw_free != NULL) raw_free(oldest);
            }
        } else {
            /* 没有可淘汰的条目（极少情况） */
            atomic_fetch_add_explicit(&s->skipped_overcap, 1, memory_order_relaxed);
            mtt_stripe_unlock(s, ptr);
            if (raw_free != NULL) raw_free(e);
    mtt_hook_dec_depth();
    g_in_hook = saved_hook;
            return ptr;
        }
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
    g_in_hook = saved_hook;
    return ptr;
}

/**
 * LD_PRELOAD 拦截的 free。
 */
void free(void *ptr)
{
    first_call_diag("free", &g_first_free_diag);

    if (ptr == NULL) return;

    /* 递归保护：深度计数器 + g_in_hook双重检查 */
    int depth = mtt_hook_enter();
    if (depth > 0) {
        mtt_resolve_raw_allocators();
        if (raw_free != NULL) raw_free(ptr);
        return;
    }
    if (g_in_hook) g_in_hook = 0;
    mtt_hook_inc_depth();
    int saved_hook = g_in_hook;
    g_in_hook = 1;

    mtt_resolve_raw_allocators();

    /* 工具内部线程：直接透传 */
    if (g_tool_internal) {
        if (raw_free != NULL) raw_free(ptr);
    mtt_hook_dec_depth();
    g_in_hook = saved_hook;
        return;
    }

    if (raw_free == NULL) {
    mtt_hook_dec_depth();
    g_in_hook = saved_hook;
        return;
    }

    mtt_ensure_init();
    mtt_state_t *s = mtt_state_get();
    if (s == NULL) {
        raw_free(ptr);
    mtt_hook_dec_depth();
    g_in_hook = saved_hook;
        return;
    }

    if (atomic_load_explicit(&s->disabled, memory_order_acquire)) {
        raw_free(ptr);
    mtt_hook_dec_depth();
    g_in_hook = saved_hook;
        return;
    }

    mtt_stripe_lock(s, ptr);
    mtt_entry_t *e = mtt_entry_find(s, ptr);
    if (e != NULL) {
        /* 诊断：10字节分配被释放（关键路径） */
        if (e->size == 10) {
            char dbuf[80];
            int dlen = snprintf(dbuf, sizeof(dbuf),
                "[MTT] FREE10: ptr=%p age=%lds\n",
                ptr, (long)(time(NULL) - e->timestamp));
            if (dlen > 0 && dlen < (int)sizeof(dbuf))
                MTT_DIAG_WRITE(STDERR_FILENO, dbuf, (size_t)dlen);
        }
        /* 诊断：小分配被释放 */
        if (e->size <= 128 && e->size != 10) {
            char dbuf[80];
            int dlen = snprintf(dbuf, sizeof(dbuf),
                "[MTT] hook: free(%zu) ptr=%p age=%lds\n",
                e->size, ptr, (long)(time(NULL) - e->timestamp));
            if (dlen > 0 && dlen < (int)sizeof(dbuf))
                MTT_DIAG_WRITE(STDERR_FILENO, dbuf, (size_t)dlen);
        }
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
    g_in_hook = saved_hook;
}

/**
 * LD_PRELOAD 拦截的 calloc。
 */
void* calloc(size_t count, size_t size)
{
    first_call_diag("calloc", &g_first_calloc_diag);

    /* 递归保护：深度计数器 + g_in_hook双重检查 */
    int depth = mtt_hook_enter();
    if (depth > 0) {
        mtt_resolve_raw_allocators();
        if (raw_malloc == NULL) return NULL;
        if (count > 0 && size > SIZE_MAX / count) return NULL;
        size_t total = count * size;
        void *p = raw_malloc(total);
        if (p != NULL) memset(p, 0, total);
        return p;
    }
    if (g_in_hook) g_in_hook = 0;
    mtt_hook_inc_depth();

    /* 工具内部线程：直接透传 raw_malloc + memset，不追踪 */
    if (g_tool_internal) {
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
     * 注意：不在此处设置 g_in_hook，让 malloc() 内部自行管理
     * 其 save/restore。之前 g_in_hook=1 导致 malloc() 透传到 raw_malloc
     * 而不创建追踪记录，calloc 分配的内存完全不被追踪。 */
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

    /* 递归保护：深度计数器 + g_in_hook双重检查 */
    int depth = mtt_hook_enter();
    if (depth > 0) {
        mtt_resolve_raw_allocators();
        if (raw_realloc != NULL)
            return raw_realloc(ptr, size);
        if (raw_malloc == NULL) return NULL;
        void *new_ptr = raw_malloc(size);
        if (new_ptr == NULL) return NULL;
        if (raw_free != NULL) raw_free(ptr);
        return new_ptr;
    }
    if (g_in_hook) g_in_hook = 0;
    mtt_hook_inc_depth();
    int saved_hook = g_in_hook;
    g_in_hook = 1;

    mtt_resolve_raw_allocators();

    /* 工具内部线程：直接透传 */
    if (g_tool_internal) {
        void *ret;
        if (raw_realloc != NULL) {
            ret = raw_realloc(ptr, size);
        } else {
            ret = (raw_malloc != NULL) ? raw_malloc(size) : NULL;
            if (ret != NULL && raw_free != NULL) raw_free(ptr);
        }
    mtt_hook_dec_depth();
    g_in_hook = saved_hook;
        return ret;
    }

    if (raw_malloc == NULL) {
    mtt_hook_dec_depth();
    g_in_hook = saved_hook;
        return NULL;
    }

    mtt_ensure_init();
    mtt_state_t *s = mtt_state_get();
    if (s == NULL || atomic_load_explicit(&s->disabled, memory_order_acquire)) {
        /* 降级：优先使用 raw_realloc */
        if (raw_realloc != NULL) {
            void *ret = raw_realloc(ptr, size);
    mtt_hook_dec_depth();
    g_in_hook = saved_hook;
            return ret;
        }
        /* 无 raw_realloc：malloc+memcpy+free 降级 */
        void *new_ptr = raw_malloc(size);
        if (new_ptr == NULL) {
    mtt_hook_dec_depth();
    g_in_hook = saved_hook;
            return NULL;
        }
        memcpy(new_ptr, ptr, size);
        if (raw_free != NULL) raw_free(ptr);
    mtt_hook_dec_depth();
    g_in_hook = saved_hook;
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
    g_in_hook = saved_hook;
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
    g_in_hook = saved_hook;
        return new_ptr;
    }

    /* ---- raw_realloc 不可用（bootstrap 阶段）的降级路径 ---- */

    /* 先分配新内存（失败不破坏旧状态） */
    void *new_ptr = raw_malloc(size);
    if (new_ptr == NULL) {
    mtt_hook_dec_depth();
    g_in_hook = saved_hook;
        return NULL;
    }

    /* 创建新追踪记录 */
    mtt_entry_t *new_e = mtt_entry_new(new_ptr, size);
    if (new_e == NULL) {
        raw_free(new_ptr);
    mtt_hook_dec_depth();
    g_in_hook = saved_hook;
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
    g_in_hook = saved_hook;
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
    g_in_hook = saved_hook;
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
    if (memptr == NULL) return 22; /* EINVAL */
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
    if (s == NULL) return NULL;
    size_t len = strlen(s) + 1;
    char *p = (char*)malloc(len);
    if (p != NULL) memcpy(p, s, len);
    return p;
}

/** LD_PRELOAD 拦截的 strndup */
char* strndup(const char *s, size_t n)
{
    if (s == NULL) return NULL;
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

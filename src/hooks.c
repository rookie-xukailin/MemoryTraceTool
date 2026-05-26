/*
 * MemoryTraceTool — LD_PRELOAD 拦截钩子。
 *
 * 本文件重写了 libc 的 malloc / calloc / realloc / free 符号，
 * 仅被编译进动态库（libmemorytracetool.so）中。
 * 通过 LD_PRELOAD 加载后，无需修改任何源码即可拦截目标进程中
 * 所有的堆内存分配和释放操作。
 *
 * 与 memorytracetool.c 中 Macro 模式函数的关键区别：
 *   - 函数签名与标准 libc 一致（无 file/line 参数）
 *   - entry 中文件记录为 "?"，行号为 0
 *   - 调用栈仍然会被捕获，可辅助定位泄漏（但不如 Macro 精确）
 *
 * 线程安全：通过 64 分段锁保护全局状态。
 * 重入安全：内部追踪记录分配使用 raw_malloc/raw_free，
 *          这些指针指向真正的 libc 函数，不会再次触发钩子。
 *
 * 缺陷修复 #1: 支持采样（通过 should_track 决策）。
 * 缺陷修复 #2: 容量上限检查（通过 is_over_capacity）。
 * 缺陷修复 #3: calloc 整数溢出检测。
 * 缺陷修复 #5: realloc 新 entry 分配失败时不丢失用户数据。
 * 缺陷修复 #23: 分段锁替代表全局互斥锁。
 * 缺陷修复 #24: MTT_DISABLE 检查实现零开销关闭。
 */
#define _GNU_SOURCE
#include "internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <malloc.h>

/* ---- hook 调用诊断计数器 ----
 * 每 HOOK_LOG_INTERVAL 次分配输出一次诊断信息到 stderr，
 * 用于确认 GOT 修补后钩子是否被调用、追踪是否生效。
 * 使用 write() 而非 fprintf() 避免触发 malloc 递归。 */
#define HOOK_LOG_INTERVAL 128
static _Atomic unsigned long g_hook_malloc_calls = 0;
static _Atomic unsigned long g_hook_free_calls   = 0;
/* trace 节流：避免每次钩子调用都写 trace 文件，产生 IO 风暴 */
static _Atomic unsigned long g_hook_trace_throttle = 0;
static _Atomic unsigned long g_hook_calloc_throttle = 0;
static _Atomic unsigned long g_hook_realloc_throttle = 0;
#define HOOK_TRACE_INTERVAL 256

static void hook_diag_tick(void)
{
    unsigned long n = atomic_fetch_add(&g_hook_malloc_calls, 1);
    if ((n % HOOK_LOG_INTERVAL) == (HOOK_LOG_INTERVAL - 1)) {
        char buf[128];
        int len = snprintf(buf, sizeof(buf),
            "[mtt-hook] malloc called %lu times (pid=%d)\n", n + 1, (int)getpid());
        if (len > 0 && len < (int)sizeof(buf))
            write(STDERR_FILENO, buf, (size_t)len);
    }
}

/**
 * 采样决策的简化版（内联到 hooks.c 中）。
 *
 * 由于 should_track 是 memorytracetool.c 的 static 函数，
 * hooks.c 中直接内联实现避免跨文件依赖。
 */
static inline int hook_should_track(mtt_state_t* s)
{
    if (s->sample_period == 0)
        return 1;

    unsigned long c = atomic_fetch_add(&s->sample_counter, 1);
    if ((c % s->sample_period) == 0)
        return 1;

    atomic_fetch_add(&s->skipped_sampled, 1);
    return 0;
}

static inline int hook_is_over_capacity(mtt_state_t* s)
{
    unsigned long n = atomic_load(&s->entry_count);
    if (n >= s->max_entries) {
        atomic_fetch_add(&s->skipped_overcap, 1);
        return 1;
    }
    return 0;
}

/**
 * LD_PRELOAD 拦截的 malloc。
 *
 * 缺陷修复 #24: MTT_DISABLE=1 时直接透传到 raw_malloc。
 */
void* malloc(size_t size)
{
    /* 首次钩子调用 trace：确认 GOT 修补后钩子确实被触发 */
    {
        unsigned long nth = atomic_fetch_add(&g_hook_trace_throttle, 1);
        if (nth == 0) {
            char tr[96];
            snprintf(tr, sizeof(tr), "hook: FIRST malloc(size=%zu) pid=%d — hooks ARE firing",
                size, (int)getpid());
            client_trace(tr);
        } else if ((nth % HOOK_TRACE_INTERVAL) == 0) {
            mtt_state_t* ts = mtt_state_get();
            char tr[160];
            snprintf(tr, sizeof(tr),
                "hook: malloc #%lu cur_bytes=%zu allocs=%zu frees=%zu",
                nth, atomic_load(&ts->current_bytes),
                atomic_load(&ts->alloc_count), atomic_load(&ts->free_count));
            client_trace(tr);
        }
    }

    hook_diag_tick();
    mtt_resolve_raw_allocators();

    /* 0 字节分配按标准放行 */
    if (size == 0) return raw_malloc(0);

    /* 解析器窗口内直接透传：此时 raw_* 可能是 bootstrap 分配器，
     * 追踪记录后续被 real free 释放会导致堆损坏 */
    if (g_in_resolver)
        return raw_malloc(size);

    mtt_ensure_init();
    mtt_state_t* s = mtt_state_get();

    /* 完全禁用时直接透传 */
    if (s->disabled)
        return raw_malloc(size);

    /* 采样与容量检查 */
    if (!hook_should_track(s) || hook_is_over_capacity(s)) {
        return raw_malloc(size);
    }

    /* 先创建追踪 entry（内部使用 raw_malloc），再分配用户内存 */
    mtt_entry_t* e = mtt_entry_new(NULL, size, "?", 0);
    void* ptr = raw_malloc(size);

    if (!ptr) { raw_free(e); return NULL; }
    if (!e)   return ptr; /* entry 分配失败，静默放行 */

    e->ptr = ptr;

    mtt_stripe_lock(s, ptr);
    e->alloc_num = ++s->alloc_seq;
    s->alloc_count++;
    s->current_bytes += size;
    s->total_bytes   += size;
    /* 原子更新峰值 */
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
 * LD_PRELOAD 拦截的 calloc。
 *
 * 缺陷修复 #3: 添加整数溢出检测。
 * 缺陷修复 #24: MTT_DISABLE 时直接透传。
 */
void* calloc(size_t count, size_t size)
{
    /* 首次钩子调用 trace */
    {
        unsigned long nth = atomic_fetch_add(&g_hook_calloc_throttle, 1);
        if (nth == 0) {
            char tr[128];
            snprintf(tr, sizeof(tr), "hook: FIRST calloc(count=%zu,size=%zu) pid=%d",
                count, size, (int)getpid());
            client_trace(tr);
        } else if ((nth % HOOK_TRACE_INTERVAL) == 0) {
            char tr[160];
            snprintf(tr, sizeof(tr),
                "hook: calloc #%lu count=%zu size=%zu total=%zu",
                nth, count, size, count * size);
            client_trace(tr);
        }
    }

    mtt_resolve_raw_allocators();
    if (g_in_resolver) {
        if (count > 0 && size > SIZE_MAX / count) return NULL;
        size_t total = count * size;
        void* ptr = raw_malloc(total);
        if (ptr) memset(ptr, 0, total);
        return ptr;
    }
    mtt_ensure_init();
    mtt_state_t* s = mtt_state_get();

    /* 完全禁用时直接透传到 raw_calloc */
    if (s->disabled) {
        /* 仍然做整数溢出检查 */
        if (count > 0 && size > SIZE_MAX / count) {
            return NULL;
        }
        size_t total = count * size;
        void* ptr = raw_malloc(total);
        if (ptr) memset(ptr, 0, total);
        return ptr;
    }

    /* 整数溢出检查 */
    if (count > 0 && size > SIZE_MAX / count) {
        fprintf(stderr,
            "[MemoryTraceTool] ERROR: calloc(%zu, %zu) — integer overflow\n",
            count, size);
        return NULL;
    }
    size_t total = count * size;
    void*  ptr   = malloc(total); /* 调用本文件的 LD_PRELOAD 版 malloc */
    if (ptr) memset(ptr, 0, total);
    return ptr;
}

/**
 * LD_PRELOAD 拦截的 realloc。
 *
 * 缺陷修复 #5: 修复新 entry 分配失败时丢失数据的路径。
 * 缺陷修复 #24: MTT_DISABLE 时直接透传。
 */
void* realloc(void* ptr, size_t size)
{
    /* 首次钩子调用 trace */
    {
        unsigned long nth = atomic_fetch_add(&g_hook_realloc_throttle, 1);
        if (nth == 0) {
            char tr[128];
            snprintf(tr, sizeof(tr), "hook: FIRST realloc(ptr=%p,size=%zu) pid=%d",
                ptr, size, (int)getpid());
            client_trace(tr);
        } else if ((nth % HOOK_TRACE_INTERVAL) == 0) {
            char tr[160];
            snprintf(tr, sizeof(tr),
                "hook: realloc #%lu ptr=%p size=%zu",
                nth, ptr, size);
            client_trace(tr);
        }
    }

    mtt_resolve_raw_allocators();
    if (!ptr) return malloc(size);
    if (!size) { free(ptr); return NULL; }

    /* 解析器窗口：跳过追踪直接操作 */
    if (g_in_resolver) {
        void* new_ptr = raw_malloc(size);
        if (!new_ptr) return NULL;
        size_t old_size = malloc_usable_size(ptr);
        memcpy(new_ptr, ptr, old_size < size ? old_size : size);
        raw_free(ptr);
        return new_ptr;
    }

    mtt_ensure_init();
    mtt_state_t* s = mtt_state_get();

    if (s->disabled) {
        /* 缺陷修复 #27: 先尝试新分配，失败则不释放旧指针 */
        void* new_ptr = raw_malloc(size);
        if (!new_ptr) return NULL;
        size_t old_size = malloc_usable_size(ptr);
        memcpy(new_ptr, ptr, old_size < size ? old_size : size);
        raw_free(ptr);
        return new_ptr;
    }

    /* 缺陷修复 #27: 先尝试分配新内存，成功后再修改追踪表 */
    void* new_ptr = raw_malloc(size);
    if (!new_ptr) return NULL;

    /* 缺陷修复 #5: 先创建新追踪记录，失败则放弃本次 realloc */
    mtt_entry_t* e = mtt_entry_new(new_ptr, size, "?", 0);
    if (!e) {
        raw_free(new_ptr);
        return NULL;
    }

    /* 从追踪表删除旧记录 */
    mtt_stripe_lock(s, ptr);
    mtt_entry_t* old = mtt_entry_find(s, ptr);
    size_t old_size = old ? old->size : malloc_usable_size(ptr);
    if (old) {
        if (old->size <= s->current_bytes)
            s->current_bytes -= old->size;
        else
            s->current_bytes = 0;
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
 * LD_PRELOAD 拦截的 free。
 *
 * 缺陷修复 #24: MTT_DISABLE 时直接透传。
 */
void free(void* ptr)
{
    mtt_resolve_raw_allocators();
    if (!ptr) return;
    /* 解析器窗口内不释放：bootstrap 内存不可 free，若 raw_* 已切换
     * 为 real free 则会导致堆损坏。少量泄漏可接受（一次性）。 */
    if (g_in_resolver) return;
    mtt_ensure_init();
    mtt_state_t* s = mtt_state_get();

    /* free 节流 trace：仅首次和每 512 次输出 */
    {
        unsigned long n = atomic_fetch_add(&g_hook_free_calls, 1);
        if (n == 0) {
            char tr[96];
            snprintf(tr, sizeof(tr), "hook: FIRST free(ptr=%p) pid=%d", ptr, (int)getpid());
            client_trace(tr);
        } else if ((n % 512) == 0) {
            char tr[128];
            snprintf(tr, sizeof(tr), "hook: free #%lu cur_bytes=%zu allocs=%zu frees=%zu",
                n, atomic_load(&s->current_bytes),
                atomic_load(&s->alloc_count), atomic_load(&s->free_count));
            client_trace(tr);
        }
    }

    if (s->disabled) {
        raw_free(ptr);
        return;
    }

    mtt_stripe_lock(s, ptr);
    mtt_entry_t* e = mtt_entry_find(s, ptr);
    if (e) {
        if (e->size <= s->current_bytes)
            s->current_bytes -= e->size;
        else
            s->current_bytes = 0;
        s->free_count++;
        mtt_entry_remove(s, ptr);
    }
    mtt_stripe_unlock(s, ptr);
    raw_free(ptr);
}

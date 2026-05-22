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
 * 线程安全：通过 g_state.lock 互斥锁保护全局状态。
 * 重入安全：内部追踪记录分配使用 raw_malloc/raw_free，
 *          这些指针指向真正的 libc 函数，不会再次触发钩子。
 *
 * 缺陷修复 #1: 支持采样（通过 should_track 决策）。
 * 缺陷修复 #2: 容量上限检查（通过 is_over_capacity）。
 * 缺陷修复 #3: calloc 整数溢出检测。
 * 缺陷修复 #5: realloc 新 entry 分配失败时不丢失用户数据。
 */
#define _GNU_SOURCE
#include "internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

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

    unsigned long c = __atomic_fetch_add(&s->sample_counter, 1, __ATOMIC_RELAXED);
    if ((c % s->sample_period) == 0)
        return 1;

    s->skipped_sampled++;
    return 0;
}

static inline int hook_is_over_capacity(mtt_state_t* s)
{
    unsigned long n = __atomic_load_n(&s->entry_count, __ATOMIC_RELAXED);
    if (n >= s->max_entries) {
        s->skipped_overcap++;
        return 1;
    }
    return 0;
}

/**
 * LD_PRELOAD 拦截的 malloc。
 *
 * 1. 用 raw_malloc 分配真实内存
 * 2. 创建追踪记录（文件="?", 行号=0）
 * 3. 将记录插入哈希表并更新统计
 *
 * 缺陷修复 #1: 支持采样 — 非采样点不创建追踪记录。
 * 缺陷修复 #2: 容量上限 — 超限时不创建记录。
 *
 * 注意：mtt_entry_new 必须在 raw_malloc 之前调用，
 * 因为它的内部也使用 raw_malloc 分配 entry 结构，
 * 顺序保证了 entry 的分配不会被当前这次 malloc 调用的记录覆盖。
 */
void* malloc(size_t size)
{
    /* 0 字节分配按标准放行 */
    if (size == 0) return raw_malloc(0);

    mtt_ensure_init();
    mtt_state_t* s = mtt_state_get();

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
 * LD_PRELOAD 拦截的 calloc。
 *
 * 缺陷修复 #3: 添加整数溢出检测。
 * 委托给 LD_PRELOAD 版的 malloc（而非 raw_malloc），
 * 以确保分配也被追踪。分配后零初始化内存。
 */
void* calloc(size_t count, size_t size)
{
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
 * 实现与 mtt_realloc 逻辑一致：先从追踪表中移除旧记录，
 * 分配新内存后插入新记录，拷贝数据，最后释放旧内存。
 *
 * 缺陷修复 #5: 修复新 entry 分配失败时丢失数据的路径。
 * - 如果 raw_malloc(new_size) 成功但 mtt_entry_new() 失败，
 *   放行新指针但不追踪（比数据丢失更安全）。
 * - 旧记录在此时已被删除（包括 entry 结构已 free），无法恢复。
 */
void* realloc(void* ptr, size_t size)
{
    if (!ptr) return malloc(size);
    if (!size) { free(ptr); return NULL; }

    mtt_ensure_init();
    mtt_state_t* s = mtt_state_get();

    /* 从追踪表删除旧记录 */
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
        /* 新分配失败: 旧记录已被删除且其 entry 结构已被 free。
         * 用户旧数据仍在 ptr 上，未丢失。
         * 无法恢复追踪记录（old 结构已释放），但数据安全。 */
        return NULL;
    }

    if (old_size > 0)
        memcpy(new_ptr, ptr, old_size < size ? old_size : size);

    mtt_entry_t* e = mtt_entry_new(new_ptr, size, "?", 0);
    if (!e) {
        /* 缺陷修复 #5: entry 分配失败，但新内存已成功分配。
         * 折中方案：放行 new_ptr 但不追踪。
         * 相比直接返回 NULL 丢失数据，这是更安全的选择。 */
        raw_free(ptr);
        return new_ptr;
    }

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
 * LD_PRELOAD 拦截的 free。
 *
 * 从追踪表查找并删除对应记录，然后调用真正的 free 释放内存。
 * 如果指针不在追踪表中，静默释放（不输出警告，避免高负载场景
 * 下因系统库内部通过其他分配器分配的内存产生日志风暴）。
 *
 * 缺陷修复: 不再输出 WARNING 到 stderr。
 */
void free(void* ptr)
{
    if (!ptr) return;
    mtt_ensure_init();
    mtt_state_t* s = mtt_state_get();

    pthread_mutex_lock(&s->lock);
    mtt_entry_t* e = mtt_entry_find(s, ptr);
    if (e) {
        s->current_bytes -= e->size;
        s->free_count++;
        mtt_entry_remove(s, ptr);
    }
    pthread_mutex_unlock(&s->lock);
    raw_free(ptr);
}

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
 */
#define _GNU_SOURCE
#include "internal.h"

#include <stdio.h>
#include <string.h>

/**
 * LD_PRELOAD 拦截的 malloc。
 *
 * 1. 用 raw_malloc 分配真实内存
 * 2. 创建追踪记录（文件="?", 行号=0）
 * 3. 将记录插入哈希表并更新统计
 *
 * 注意：mtt_entry_new 必须在 raw_malloc 之前调用，
 * 因为它的内部也使用 raw_malloc 分配 entry 结构，
 * 顺序保证了 entry 的分配不会被当前这次 malloc 调用的记录覆盖。
 */
void* malloc(size_t size)
{
    mtt_ensure_init();
    /* 先创建追踪 entry（内部使用 raw_malloc），再分配用户内存 */
    mtt_entry_t* e = mtt_entry_new(NULL, size, "?", 0);
    void* ptr = raw_malloc(size);

    if (!ptr) { raw_free(e); return NULL; }
    if (!e)   return ptr; /* entry 分配失败，静默放行 */

    mtt_state_t* s = mtt_state_get();
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
 * 委托给 LD_PRELOAD 版的 malloc（而非 raw_malloc），
 * 以确保分配也被追踪。分配后零初始化内存。
 */
void* calloc(size_t count, size_t size)
{
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
 * 新分配失败时恢复旧记录以保证原子性。
 */
void* realloc(void* ptr, size_t size)
{
    if (!ptr) return malloc(size);

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
        /* 新分配失败，恢复旧记录 */
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

    if (old && old_size > 0)
        memcpy(new_ptr, ptr, old_size < size ? old_size : size);

    mtt_entry_t* e = mtt_entry_new(new_ptr, size, "?", 0);
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
 * LD_PRELOAD 拦截的 free。
 *
 * 从追踪表查找并删除对应记录，然后调用真正的 free 释放内存。
 * 如果指针不在追踪表中，静默释放（不输出警告，避免干扰被注入程序）。
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

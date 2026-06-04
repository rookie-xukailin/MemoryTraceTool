/*
 * MemoryTraceTool — 栈帧缓存模块。
 *
 * 同一调用路径的数千次分配共享一份栈帧缓存和符号解析结果，
 * 避免对相同调用栈重复进行 dladdr() 解析。
 *
 * 线程安全：仅由 reporter 后台线程访问（单写者），无竞争。
 * 硬上限：MTT_STACK_CACHE_SIZE（4096 条目），超限后新栈不缓存。
 */
#ifndef MTT_STACK_CACHE_H
#define MTT_STACK_CACHE_H

#include "mtt_internal.h"

/* ---- 栈缓存条目 ---- */

/** 单条栈帧缓存，存储原始帧地址和懒解析符号 */
typedef struct mtt_stack_entry {
    uint64_t  hash;                                    /* xxHash64 计算结果 */
    void     *frames[MTT_STACK_DEPTH];                 /* 原始帧地址数组 */
    int       frame_count;                             /* 实际帧数 */
    char      resolved[MTT_STACK_DEPTH][MTT_SYMBOL_MAX]; /* 懒解析结果缓存 */
    int       is_resolved;                             /* 0=未解析, 1=已解析 */
    struct mtt_stack_entry *next;                      /* 哈希碰撞链表 */
} mtt_stack_entry_t;

/** 栈帧缓存表（开放哈希，数组+链表） */
typedef struct {
    mtt_stack_entry_t *entries[MTT_STACK_CACHE_SIZE];  /* 桶数组 */
    size_t             count;                          /* 当前缓存的栈条目数 */
    pthread_mutex_t    lock;                           /* 保护锁（仅 reporter 线程使用） */
} mtt_stack_cache_t;

/* ---- API ---- */

/** 获取全局栈缓存单例 */
mtt_stack_cache_t* mtt_stack_cache_get(void);

/**
 * 查找或插入栈帧缓存条目。
 *
 * 根据帧地址数组计算 hash，在缓存中查找匹配条目。
 * 若找到则返回已有条目；若未找到且缓存未满则插入新条目。
 * 缓存满时返回 NULL（调用者可继续计算 hash 但不缓存）。
 *
 * @param frames       原始帧地址数组（来自 backtrace）
 * @param frame_count  帧数
 * @return             缓存条目指针，缓存满且未命中时返回 NULL
 */
mtt_stack_entry_t* mtt_stack_cache_lookup(void **frames, int frame_count);

/**
 * 懒解析栈帧符号。
 *
 * 遍历 entry->frames[]，对每帧调用 dladdr() 解析为
 * "func+0xOFFSET (libname)" 格式，结果存入 entry->resolved[]。
 * 仅解析一次（is_resolved 标志），后续调用直接返回。
 *
 * @param entry  栈缓存条目
 */
void mtt_stack_resolve(mtt_stack_entry_t *entry);

#endif /* MTT_STACK_CACHE_H */

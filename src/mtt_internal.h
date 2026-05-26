/*
 * MemoryTraceTool — 内部数据结构与常量定义。
 *
 * 本文件定义了内存追踪的核心数据结构，包括：
 *   - mtt_entry_t:   单次分配的追踪记录
 *   - mtt_state_t:   全局状态（哈希桶表、分段锁、原子计数器）
 *   - raw_malloc/free: 绕过自定义钩子直接调用 libc 分配器的函数指针
 *
 * 所有硬上限常量均在此定义，确保 ARM 嵌入式设备上内存可控。
 */
#ifndef MTT_INTERNAL_H
#define MTT_INTERNAL_H

#include <stddef.h>
#include <stdint.h>
#include <time.h>
#include <pthread.h>
#include <stdatomic.h>

/* ======================================================================== *
 *                        硬上限常量（资源受限设备可调整）                      *
 * ======================================================================== */

#define MTT_BUCKETS             4096    /* 哈希桶数量（必须为 2 的幂，用于位掩码取模） */
#define MTT_MAX_ENTRIES         65536   /* 分配追踪表最大条目数 */
#define MTT_STACK_DEPTH         16      /* 调用栈最大深度 */
#define MTT_STACK_CACHE_SIZE    4096    /* 栈帧缓存最大条目（去重后） */
#define MTT_LEAK_DEDUP_SIZE     2048    /* 泄漏去重表最大条目（报告输出上限） */
#define MTT_SYMBOL_MAX          256     /* 单帧符号字符串最大长度 */
#define MTT_LOCK_STRIPES        64      /* 分段锁数量（将 4096 桶映射到 64 把锁） */
#define MTT_REPORT_INTERVAL_SEC 60      /* 报告间隔（秒） */

/* 采样配置 */
#define MTT_SAMPLE_DEFAULT      0       /* 默认全量追踪，>0 时每 N 次记录 1 次 */
#define MTT_SAMPLE_MAX_PERIOD   1024    /* 最大采样周期 */

/* Bootstrap 分配器缓冲区大小（dlsym 阶段兜底） */
#define MTT_BOOTSTRAP_BUF_SIZE  65536

/* ======================================================================== *
 *                       原始分配器函数指针类型                                *
 * ======================================================================== */

typedef void* (*raw_malloc_fn)(size_t);
typedef void  (*raw_free_fn)(void*);
typedef void* (*raw_calloc_fn)(size_t, size_t);

/* 全局原始分配器指针（在 tracker.c 中定义） */
extern raw_malloc_fn raw_malloc;
extern raw_free_fn   raw_free;
extern raw_calloc_fn raw_calloc;

/* __thread 递归保护标志（在 tracker.c 中定义，hooks.c/reporter.c 引用） */
extern __thread int g_in_hook;

/* ======================================================================== *
 *                         分配追踪记录                                       *
 * ======================================================================== */

/**
 * 单次堆分配追踪记录（哈希桶链表节点）。
 *
 * key = ptr（返回给调用者的内存指针），通过乘法哈希映射到桶。
 * 释放时通过 ptr 查找并删除，O(1) 期望查找（链表长度取决于碰撞）。
 */
typedef struct mtt_entry {
    void            *ptr;                           /* 返回给调用者的内存指针（哈希键） */
    size_t           size;                          /* 分配字节数 */
    time_t           timestamp;                     /* 分配时刻 Unix 时间戳 */
    unsigned long    alloc_num;                     /* 全局单调递增的分配序号 */
    void            *stack[MTT_STACK_DEPTH];        /* backtrace 返回的调用栈帧地址 */
    int              stack_frames;                  /* 实际栈帧数 */
    struct mtt_entry *next;                         /* 哈希桶内单向链表指针 */
} mtt_entry_t;

/* ======================================================================== *
 *                         全局追踪状态                                       *
 * ======================================================================== */

/**
 * 全局追踪状态（单例，整个进程唯一实例）。
 *
 * 线程安全设计：
 *   - 64 分段锁保护哈希桶链表：锁 i 保护所有 bucket % 64 == i 的桶
 *   - 统计计数器全部原子变量，读取无需持锁
 *   - initialized 标志通过 CAS 实现一次性懒初始化
 */
typedef struct {
    mtt_entry_t       **buckets;                    /* 哈希桶表（raw_calloc 分配） */
    unsigned            bucket_count;               /* 桶数量（= MTT_BUCKETS） */
    pthread_mutex_t     bucket_locks[MTT_LOCK_STRIPES]; /* 分段锁数组 */
    unsigned long       hash_seed;                  /* 哈希随机种子（启动时生成） */

    /* 统计计数器（全部原子变量，无锁读取） */
    _Atomic int         initialized;                /* 是否已完成初始化（0=未, 1=已） */
    _Atomic int         disabled;                   /* 紧急禁用标志（MTT_DISABLE=1） */
    _Atomic unsigned long alloc_seq;                /* 分配序号（单调递增） */
    _Atomic size_t      alloc_count;                /* 累计分配次数 */
    _Atomic size_t      free_count;                 /* 累计释放次数 */
    _Atomic size_t      current_bytes;              /* 当前仍未释放的字节数 */
    _Atomic size_t      peak_bytes;                 /* 历史峰值 current_bytes */
    _Atomic size_t      total_bytes;                /* 累计分配字节总数 */
    _Atomic unsigned long entry_count;              /* 当前哈希表条目数 */
    _Atomic unsigned    sample_period;              /* 采样周期：0=全量, N>0=每N次记录1次 */
    _Atomic unsigned long sample_counter;           /* 采样计数器 */
    _Atomic size_t      skipped_sampled;            /* 因采样跳过的分配次数 */
    _Atomic size_t      skipped_overcap;            /* 因超容量上限跳过的记录次数 */

    /* 进程信息 */
    char                proc_name[256];             /* 进程名（来自 /proc/self/exe） */
    int                 proc_name_ready;            /* 进程名是否已读取（0=未, 1=已） */
} mtt_state_t;

/* ======================================================================== *
 *                       内联辅助函数                                         *
 * ======================================================================== */

/** 获取全局单例状态指针（定义在 tracker.c，确保跨模块共享同一实例） */
mtt_state_t* mtt_state_get(void);

/**
 * 计算指针地址对应的哈希桶索引。
 *
 * 使用乘法哈希（Fibonacci hashing）：(ptr >> 3) * 2654435761UL
 * 右移 3 位剔除 malloc 对齐引入的低位零，乘 magic constant 扩散熵。
 * 再与 hash_seed 异或以增加随机性，最后与 (bucket_count-1) 取模。
 *
 * @param ptr           内存指针（8/16 字节对齐，低 3 位恒为 0）
 * @param bucket_count  桶总数（必须为 2 的幂）
 * @param seed          随机种子
 * @return              桶索引 [0, bucket_count)
 */
static inline unsigned mtt_bucket_of(const void *ptr, unsigned bucket_count,
                                     unsigned long seed)
{
    unsigned long h = (unsigned long)ptr;
    h = (h >> 3) * 2654435761UL;
    h ^= seed;
    return (unsigned)(h & (unsigned long)(bucket_count - 1));
}

/** 获取 ptr 对应的分段锁索引 */
static inline unsigned mtt_stripe_of(const void *ptr, unsigned bucket_count,
                                     unsigned long seed)
{
    return mtt_bucket_of(ptr, bucket_count, seed) & (MTT_LOCK_STRIPES - 1);
}

/** 获取指针对应的分段锁并加锁 */
static inline void mtt_stripe_lock(mtt_state_t *s, const void *ptr)
{
    if (s == NULL) return;
    unsigned idx = mtt_stripe_of(ptr, s->bucket_count, s->hash_seed);
    pthread_mutex_lock(&s->bucket_locks[idx]);
}

/** 释放指针对应的分段锁 */
static inline void mtt_stripe_unlock(mtt_state_t *s, const void *ptr)
{
    if (s == NULL) return;
    unsigned idx = mtt_stripe_of(ptr, s->bucket_count, s->hash_seed);
    pthread_mutex_unlock(&s->bucket_locks[idx]);
}

/* ======================================================================== *
 *                  共享函数声明（跨模块调用）                                  *
 * ======================================================================== */

/* tracker.c */
void         mtt_ensure_init(void);
void         mtt_resolve_raw_allocators(void);
mtt_entry_t* mtt_entry_new(void *ptr, size_t size);
void         mtt_entry_add(mtt_state_t *s, mtt_entry_t *e);
mtt_entry_t* mtt_entry_find(mtt_state_t *s, const void *ptr);
void         mtt_entry_remove(mtt_state_t *s, const void *ptr);
int          mtt_should_track(mtt_state_t *s);
int          mtt_is_over_capacity(mtt_state_t *s);
void         mtt_capture_stack(mtt_entry_t *entry);

/* reporter.c */
void mtt_reporter_start(void);

/* stack_cache.c */
uint64_t mtt_stack_hash_compute(void **frames, int frame_count);

#endif /* MTT_INTERNAL_H */

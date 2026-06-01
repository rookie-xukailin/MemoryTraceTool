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
#include <assert.h>

/* ======================================================================== *
 *                    ARM Thumb 模式兼容性                                     *
 * ======================================================================== */

/**
 * ARM32 Thumb 模式下 backtrace() 返回地址的 bit 0 为 1（Thumb 状态标志），
 * 需清除该位才能正确进行哈希计算和 dladdr() 符号解析。
 * 在非 ARM / 非 Thumb 平台上，此宏为零开销（地址 bit 0 本身为 0）。
 */
#define MTT_FIX_THUMB_ADDR(addr) \
    ((void*)((uintptr_t)(addr) & ~(uintptr_t)1))

/* ======================================================================== *
 *                    backtrace() 兼容性检测                                   *
 * ======================================================================== */

/**
 * backtrace() 和 backtrace_symbols() 是 glibc 专有扩展（<execinfo.h>）。
 * 在 musl / bionic (Android) 等非 glibc ARM 平台上可能不存在。
 * GCC 5+ / Clang 支持 __has_include；旧编译器通过 __GLIBC__ 宏判断。
 */
#if defined(__has_include) && __has_include(<execinfo.h>)
    #define MTT_HAS_BACKTRACE 1
#elif defined(__GLIBC__)
    #define MTT_HAS_BACKTRACE 1
#else
    #define MTT_HAS_BACKTRACE 0
#endif

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

/* ARM 缓存行大小（用于避免分段锁伪共享） */
#define MTT_CACHELINE_SIZE      64

/* ======================================================================== *
 *                       原始分配器函数指针类型                                *
 * ======================================================================== */

typedef void* (*raw_malloc_fn)(size_t);
typedef void  (*raw_free_fn)(void*);
typedef void* (*raw_calloc_fn)(size_t, size_t);
typedef void* (*raw_realloc_fn)(void*, size_t);

/* 全局原始分配器指针（在 tracker.c 中定义）。
 * volatile 限定符：防止编译器将跨函数调用的读取优化为寄存器缓存，
 * 确保在 mtt_resolve_raw_allocators() 中由 CAS winner 写入后，
 * CAS loser 线程在下次函数入口处读到最新值。 */
extern raw_malloc_fn  volatile raw_malloc;
extern raw_free_fn    volatile raw_free;
extern raw_calloc_fn  volatile raw_calloc;
extern raw_realloc_fn volatile raw_realloc;

/* __thread 递归保护标志（在 tracker.c 中定义，hooks.c/reporter.c 引用） */
extern __thread int g_in_hook;

/* ======================================================================== *
 *                       缓存行对齐的互斥锁（避免伪共享）                        *
 * ======================================================================== */

/**
 * 将 pthread_mutex_t 包装为 64 字节大小，确保分段锁数组中相邻元素
 * 位于不同缓存行，避免 ARM 多核 CPU 上的伪共享性能损失。
 */
typedef union {
    pthread_mutex_t lock;
    char            __padding[MTT_CACHELINE_SIZE];
} __attribute__((aligned(MTT_CACHELINE_SIZE))) mtt_aligned_mutex_t;

/* 编译期断言：确保 union 大小等于缓存行 */
_Static_assert(sizeof(mtt_aligned_mutex_t) == MTT_CACHELINE_SIZE,
               "mtt_aligned_mutex_t must be cacheline-sized");

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
    uint64_t         alloc_num;                     /* 全局单调递增的分配序号（64-bit 防回绕） */
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
 *   - 64 分段锁（缓存行对齐）保护哈希桶链表：锁 i 保护所有 bucket % 64 == i 的桶
 *   - 统计计数器全部原子变量，读取无需持锁
 *   - initialized 标志通过 CAS 实现一次性懒初始化
 *   - 原子操作内存序：统计计数器用 relaxed（仅报告展示用），控制标志用 acquire/release
 */
typedef struct {
    mtt_entry_t       **buckets;                        /* 哈希桶表（raw_calloc 分配） */
    unsigned            bucket_count;                   /* 桶数量（= MTT_BUCKETS） */
    mtt_aligned_mutex_t bucket_locks[MTT_LOCK_STRIPES]; /* 分段锁数组（缓存行对齐） */
    uint64_t            hash_seed;                      /* 哈希随机种子（启动时生成，64-bit） */

    /* 统计计数器（全部原子变量，无锁读取） */
    _Atomic int         initialized;                /* 是否已完成初始化（0=未, 1=已） */
    _Atomic int         disabled;                   /* 紧急禁用标志（MTT_DISABLE=1） */
    _Atomic uint64_t    alloc_seq;                  /* 分配序号（64-bit 单调递增，防回绕） */
    _Atomic size_t      alloc_count;                /* 累计分配次数 */
    _Atomic size_t      free_count;                 /* 累计释放次数 */
    _Atomic size_t      current_bytes;              /* 当前仍未释放的字节数 */
    _Atomic size_t      peak_bytes;                 /* 历史峰值 current_bytes */
    _Atomic size_t      total_bytes;                /* 累计分配字节总数 */
    _Atomic uint64_t    entry_count;                /* 当前哈希表条目数（64-bit 防回绕） */
    _Atomic unsigned    sample_period;              /* 采样周期：0=全量, N>0=每N次记录1次 */
    _Atomic uint64_t    sample_counter;             /* 采样计数器（64-bit 防回绕） */
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
 * 使用乘法哈希（Fibonacci hashing）：(ptr >> 3) * 斐波那契哈希乘数。
 * 右移 3 位剔除 malloc 对齐引入的低位零，乘 magic constant 扩散熵。
 * 使用 uint64_t 运算确保在 ARM32/ARM64 上行为一致，
 * 64-bit 乘数 0x9E3779B97F4A7C15（= 2^64 / φ）在两种位宽上都正确混洗。
 * 再与 hash_seed 异或以增加随机性，最后与 (bucket_count-1) 取模。
 *
 * @param ptr           内存指针（8/16 字节对齐，低 3 位恒为 0）
 * @param bucket_count  桶总数（必须为 2 的幂）
 * @param seed          64-bit 随机种子
 * @return              桶索引 [0, bucket_count)
 */
static inline unsigned mtt_bucket_of(const void *ptr, unsigned bucket_count,
                                     uint64_t seed)
{
    uint64_t h = (uint64_t)(uintptr_t)ptr;
    h = (h >> 3) * UINT64_C(11400714819323198485); /* 2^64 / φ */
    h ^= seed;
    return (unsigned)(h & (uint64_t)(bucket_count - 1));
}

/** 获取 ptr 对应的分段锁索引 */
static inline unsigned mtt_stripe_of(const void *ptr, unsigned bucket_count,
                                     uint64_t seed)
{
    return mtt_bucket_of(ptr, bucket_count, seed) & (MTT_LOCK_STRIPES - 1);
}

/** 获取指针对应的分段锁并加锁（调用者已确保 s != NULL） */
static inline void mtt_stripe_lock(mtt_state_t *s, const void *ptr)
{
    assert(s != NULL);
    unsigned idx = mtt_stripe_of(ptr, s->bucket_count, s->hash_seed);
    pthread_mutex_lock(&s->bucket_locks[idx].lock);
}

/** 释放指针对应的分段锁（调用者已确保 s != NULL） */
static inline void mtt_stripe_unlock(mtt_state_t *s, const void *ptr)
{
    assert(s != NULL);
    unsigned idx = mtt_stripe_of(ptr, s->bucket_count, s->hash_seed);
    pthread_mutex_unlock(&s->bucket_locks[idx].lock);
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

/*
 * MemoryTraceTool 内部数据结构和共享辅助函数声明。
 *
 * 本文件定义了内存追踪的核心数据结构，包括：
 *   - mtt_entry_t:   单次分配的追踪记录（指针、大小、文件、行号、调用栈等）
 *   - mtt_state_t:   全局状态，包含哈希桶表、统计计数器、分段锁
 *   - raw_malloc/free/calloc: 绕过自定义钩子直接调用 libc 分配器的函数指针
 *
 * 所有编译器开关常量（桶数、栈深度、最大泄漏数）也在此集中定义，
 * 方便在资源受限的嵌入式设备上调整参数。
 */
#ifndef MEMORYTRACETOOL_INTERNAL_H
#define MEMORYTRACETOOL_INTERNAL_H

#include <stddef.h>
#include <time.h>
#include <pthread.h>
#include <stdatomic.h>

/* 可调参数：资源受限设备上可适当降低这些值 */
#define MTT_BUCKETS             4096   /* 哈希桶数量（需为 2 的幂，用于位掩码取模） */
#define MTT_FILE_MAX            128    /* 源文件路径最大长度 */
#define MTT_STACK_DEPTH         16     /* 调用栈最大深度 */
#define MTT_MAX_LEAKS_PER_PROC  2048   /* 每个进程最多追踪的泄漏数 */

/* 追踪表容量上限：防止常驻进程无限增长耗尽内存 */
#define MTT_MAX_ENTRIES         65536  /* 哈希表最大条目数 */

/* 采样配置：高负载场景下默认每 256 次分配采样 1 次以降低开销 */
#define MTT_SAMPLE_DEFAULT      0      /* 默认全量追踪，0=全量追踪 */
#define MTT_SAMPLE_MAX_PERIOD   1024   /* 最大采样周期 */

/* 分段锁数量：将 4096 个桶映射到 64 把锁上，大幅降低竞争 */
#define MTT_LOCK_STRIPES        64

/* 长期监控安全限制（24H+ 运行） */
#define MTT_DAEMON_MAX_TOTAL_LEAKS  131072  /* 守护进程全局泄漏记录总数上限 */
#define MTT_DAEMON_MEM_WARN_MB      512     /* 守护进程自身内存警告阈值 (MB) */
#define MTT_INJECT_TIMEOUT_SEC      15      /* 注入操作超时（秒） */

/* ---- 分配记录 ---- */

/** 单次堆分配追踪记录（哈希桶链表节点） */
typedef struct mtt_entry {
    void*            ptr;               /* 返回给调用者的内存指针 */
    size_t           size;              /* 分配字节数 */
    char             file[MTT_FILE_MAX];/* 源文件基础名（Macro 模式）或 "?"（LD_PRELOAD 模式） */
    int              line;              /* 源文件行号（LD_PRELOAD 模式下为 0） */
    unsigned long    alloc_num;         /* 全局单调递增的分配序号 */
    time_t           timestamp;         /* 分配时刻的 Unix 时间戳 */
    void*            stack[MTT_STACK_DEPTH]; /* backtrace 返回的调用栈帧地址 */
    int              stack_frames;      /* 实际栈帧数（可能 < MTT_STACK_DEPTH） */
    struct mtt_entry* next;             /* 哈希桶内单向链表 */
} mtt_entry_t;

/* ---- 全局状态 ---- */

/** 全局追踪状态，整个进程只有一份实例（单例模式） */
typedef struct {
    mtt_entry_t**    buckets;      /* 哈希桶表（raw_calloc 分配） */
    unsigned         bucket_count; /* 桶数量（= MTT_BUCKETS） */
    pthread_mutex_t  bucket_locks[MTT_LOCK_STRIPES]; /* 分段锁：锁 i 保护所有 bucket % 64 == i 的桶 */
    unsigned long    hash_seed;    /* 哈希随机种子（启动时生成，防碰撞攻击） */

    /* 统计计数器全部改为原子变量，无需持锁即可读取 */
    _Atomic unsigned long alloc_seq;     /* 分配序号（单调递增） */
    _Atomic size_t    alloc_count;       /* 累计分配次数 */
    _Atomic size_t    free_count;        /* 累计释放次数 */
    _Atomic size_t    current_bytes;     /* 当前仍未释放的字节数 */
    _Atomic size_t    peak_bytes;        /* 历史峰值 current_bytes */
    _Atomic size_t    total_bytes;       /* 累计分配字节总数 */

    /* 采样与限流 */
    _Atomic unsigned long sample_counter; /* 原子计数器，用于采样决策 */
    _Atomic unsigned sample_period;       /* >0 时每 N 次分配记录 1 次，0=全量 */
    _Atomic unsigned long entry_count;    /* 当前哈希表中条目数（原子操作） */
    _Atomic unsigned max_entries;         /* 哈希表容量上限 */

    /* 统计 */
    _Atomic size_t   skipped_sampled;     /* 因采样跳过的分配次数 */
    _Atomic size_t   skipped_overcap;     /* 因超容量上限跳过的记录次数 */

    /* 进程级开关 */
    int              disabled;            /* MTT_DISABLE=1 完全禁用追踪 */
    char             proc_filter[256];    /* MTT_PROC_FILTER 按进程名过滤 */
    int              env_checked;         /* 环境变量是否已检查 */

    atomic_int       initialized;         /* mtt_ensure_init 是否已完成（CAS 保护） */
} mtt_state_t;

/** 获取全局单例状态指针 */
mtt_state_t* mtt_state_get(void);

/* ---- 原始分配器（绕过自定义钩子） ---- */

/*
 * 内部使用的原始分配器函数指针类型及实例。
 * 在 LD_PRELOAD 模式下，我们的 malloc 等函数通过 dlsym(RTLD_NEXT)
 * 获取真正的 libc 函数指针，以防无限递归调用自身。
 * 在 Macro 模式下，fallback 到直接使用 malloc/free/calloc。
 */
typedef void* (*raw_malloc_fn)(size_t);
typedef void  (*raw_free_fn)(void*);
typedef void* (*raw_calloc_fn)(size_t, size_t);

extern raw_malloc_fn raw_malloc;
extern raw_free_fn   raw_free;
extern raw_calloc_fn raw_calloc;

/* ---- 分段锁辅助（内联，可被 hooks.c 等复用） ---- */

/** 计算指针地址对应的哈希桶索引 */
static inline unsigned mtt_bucket_of(const void* ptr, unsigned bucket_count,
                                     unsigned long seed)
{
    unsigned long h = (unsigned long)ptr;
    h = (h >> 3) * 2654435761UL;
    h ^= seed;
    return (unsigned)(h & (unsigned long)(bucket_count - 1));
}

/** 获取 ptr 对应的分段锁索引 */
static inline unsigned mtt_stripe_of(const void* ptr, unsigned bucket_count,
                                     unsigned long seed)
{
    return mtt_bucket_of(ptr, bucket_count, seed) & (MTT_LOCK_STRIPES - 1);
}

/** 获取指针对应的分段锁并加锁 */
static inline void mtt_stripe_lock(mtt_state_t* s, const void* ptr)
{
    unsigned idx = mtt_stripe_of(ptr, s->bucket_count, s->hash_seed);
    pthread_mutex_lock(&s->bucket_locks[idx]);
}

/** 释放指针对应的分段锁 */
static inline void mtt_stripe_unlock(mtt_state_t* s, const void* ptr)
{
    unsigned idx = mtt_stripe_of(ptr, s->bucket_count, s->hash_seed);
    pthread_mutex_unlock(&s->bucket_locks[idx]);
}

/* ---- 共享内部辅助函数（供 hooks.c 等文件使用） ---- */

/** 解析 libc 原始分配器函数指针（raw_malloc/raw_free/raw_calloc），懒加载+递归保护 */
void        mtt_resolve_raw_allocators(void);
/** 解析器活跃标志：置位期间 hooks.c 跳过追踪直接透传 raw_*，
 *  防止 bootstrap 分配器分配的内存后续被 real free 释放导致堆损坏 */
extern __thread int g_in_resolver;
/** 惰性初始化全局状态（线程安全，多次调用安全） */
void        mtt_ensure_init(void);
/** 创建新的分配追踪记录，填入文件、行号、时间戳和调用栈 */
mtt_entry_t* mtt_entry_new(void* ptr, size_t size, const char* file, int line);
/** 将追踪记录插入哈希桶（调用者必须持有对应的分段锁） */
void        mtt_entry_add(mtt_state_t* s, mtt_entry_t* e);
/** 根据内存指针在哈希桶中查找追踪记录（调用者必须持有对应的分段锁） */
mtt_entry_t* mtt_entry_find(mtt_state_t* s, const void* ptr);
/** 根据内存指针从哈希桶中删除追踪记录（调用者必须持有对应的分段锁） */
void        mtt_entry_remove(mtt_state_t* s, const void* ptr);

/* ---- 客户端 IPC（向守护进程发送泄漏报告） ---- */

/** 发送中间报告到守护进程（不含 BYE，进程继续运行） */
void        mtt_client_report(void);
/** 发送最终报告到守护进程（含 BYE，进程即将退出） */
void        mtt_client_report_final(void);
/** 启动周期性报告线程（每 3 秒推送一次，供实时看板使用） */
void        mtt_start_periodic_report(void);

#endif /* MEMORYTRACETOOL_INTERNAL_H */

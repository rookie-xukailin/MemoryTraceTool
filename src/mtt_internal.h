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
/* 禁用unistd.h: 交叉编译器自带路径, 不引入额外头文件依赖 */

/* 安全忽略 write() 返回值（诊断输出场景，失败无影响）。
 * GCC 14+ / 13+ 中 (void)write() 无法抑制 warn_unused_result，
 * 必须通过实际捕获返回值来消除警告。
 * 调用者需自行 #include <unistd.h> 获取 write() 声明。 */
#define MTT_DIAG_WRITE(fd, buf, len) \
    do { long __mtt_w = (long)write((fd), (buf), (len)); (void)__mtt_w; } while(0)
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
#define MTT_MAX_ENTRIES         65536   /* 分配追踪表最大条目数（同时是池子上限） */
#define MTT_STACK_DEPTH         64      /* 调用栈最大深度（RPC 回调链 + 多层 .so 嵌套场景需要） */

/* entry 池配置 */
#define MTT_POOL_ENTRIES_DEFAULT 16384  /* 池子默认 entry 数（约 10MB，可被环境变量 MTT_POOL_ENTRIES 覆盖） */
#define MTT_POOL_ENTRIES_MIN     1024   /* 池子最小 entry 数 */
#define MTT_POOL_ENTRIES_MAX     65536  /* 池子最大 entry 数（与 MTT_MAX_ENTRIES 一致，避免改 hash 硬上限） */

/* 池子模式标识（atomic_int 存储于 mtt_state_t.pool_mode） */
#define MTT_POOL_MODE_NONE       0      /* 尚未初始化 */
#define MTT_POOL_MODE_ACTIVE     1      /* 池子模式：entry 从预申请大块内存复用 */
#define MTT_POOL_MODE_FALLBACK   2      /* 降级模式：池子申请失败，退回旧 raw_malloc 单条申请 */
#define MTT_STACK_CACHE_SIZE    4096    /* 栈帧缓存最大条目（去重后） */
#define MTT_LEAK_DEDUP_SIZE     2048    /* 泄漏去重表最大条目（报告输出上限） */
#define MTT_SYMBOL_MAX          256     /* 单帧符号字符串最大长度 */
#define MTT_LOCK_STRIPES        64      /* 分段锁数量（将 4096 桶映射到 64 把锁） */
#define MTT_REPORT_INTERVAL_SEC 60      /* 报告间隔（秒） */

/* 采样配置 */
#define MTT_SAMPLE_DEFAULT      0       /* 默认全量追踪，>0 时每 N 次记录 1 次 */
#define MTT_SAMPLE_MAX_PERIOD   1024    /* 最大采样周期 */
#define MTT_SAMPLE_RATE_DEFAULT 0       /* 默认不启用字节采样（全量追踪），>0 时启用 */
#define MTT_SAMPLE_RATE_MAX     30      /* 最大采样率（2^30 = 1GB） */
#define MTT_BIG_ALLOC_THRESHOLD (1024 * 1024)  /* 大分配阈值（1MB），大分配总是追踪 */

/* 时序数据采集 */
#define MTT_TS_MAX_POINTS       3600    /* 环形缓冲区容量（1 小时 @ 1Hz） */
#define MTT_TS_INTERVAL_SEC     1       /* 采集间隔（秒） */

/* HTTP 服务器 */
#define MTT_HTTP_DEFAULT_PORT   0       /* 默认禁用 HTTP 服务器 */
#define MTT_HTTP_BACKLOG        8       /* listen backlog */
#define MTT_HTTP_BUF_SIZE       8192    /* HTTP 请求缓冲区大小 */
#define MTT_HTTP_MAX_PATH       256     /* URL 路径最大长度 */

/* SIGUSR1 信号触发即时报告 */
#define MTT_SIGNAL_REPORT       SIGUSR1 /* 触发即时报告的信号 */

/* 诊断日志开关（MTT_DEBUG=1 开, =0 关）。
 * 默认打开; 关闭后只保留泄漏报告写到 /var/log/mtt 下、
 * 60s heartbeat 写到 /var/log/mtt/下 <pid>_heartbeat.log、HTTP API、SIGUSR1 即时报告。
 * 所有 stderr 诊断(init 状态/scan 进度/heartbeat/线程启动)都被屏蔽。 */
#define MTT_DEBUG_DEFAULT       1

/* 60s heartbeat 资源监控输出文件 */
#define MTT_HEARTBEAT_DIR       "/var/log/mtt"

/* 泄漏判定相关常量 */
#define MTT_LEAK_THRESHOLD_DEFAULT 300  /* 默认泄漏阈值（秒）：存活超过此值→probable leak */
#define MTT_SKIP_STARTUP_DEFAULT    0   /* 默认不跳过启动阶段 */
#define MTT_STARTUP_GRACE_DEFAULT   3   /* 默认启动宽限期（秒），首次 g_raw_ready 或超时后结束 */
#define MTT_TEMP_ALLOC_THRESHOLD_MS 100 /* 临时分配阈值（毫秒级，用 alloc_seq 近似） */

/* 离线报告 */
#define MTT_REPORT_FILE_DEFAULT NULL     /* 默认不启用离线 JSON 报告 */
#define MTT_REPORT_HTML_DEFAULT NULL     /* 默认不启用离线 HTML 报告 */

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
typedef int   (*raw_posix_memalign_fn)(void**, size_t, size_t);

/* 全局原始分配器指针（在 tracker.c 中定义）。
 * volatile 限定符：防止编译器将跨函数调用的读取优化为寄存器缓存，
 * 确保在 mtt_resolve_raw_allocators() 中由 CAS winner 写入后，
 * CAS loser 线程在下次函数入口处读到最新值。 */
extern raw_malloc_fn  volatile raw_malloc;
extern raw_free_fn    volatile raw_free;
extern raw_calloc_fn  volatile raw_calloc;
extern raw_realloc_fn volatile raw_realloc;
extern raw_posix_memalign_fn volatile raw_posix_memalign;

/* 每线程上下文：替代 __thread，通过 TID 索引槽位数组管理。
 * 见 src/per_thread.h — mtt_thread_get() 获取当前线程上下文 */
#include "per_thread.h"

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

    /* entry 池：启动时一次性申请的大块内存，所有 entry 复用槽位。
     * 设计目标：减少 libc malloc/free 调用频次，工具自身内存占用可视化。
     * 关键不变量：池子在用数 == entry_count == 桶链表总节点数；
     *            free list 长度 == pool_capacity - pool_used。
     * entry->next 在桶链表里指向同桶下一个；在 free list 里指向下一个空闲
     * （同一时刻 entry 只在其中一个链中，语义复用安全）。 */
    mtt_entry_t        *pool;                           /* 池子起始地址（raw_malloc 大块） */
    mtt_entry_t        *pool_free_list;                 /* 空闲 entry 链头（用 entry->next 串） */
    pthread_mutex_t     pool_lock;                      /* free list 操作互斥锁 */
    size_t              pool_capacity;                  /* 池子总 entry 数（启动时确定） */
    size_t              pool_raw_size;                  /* 池子原始字节数 = capacity * sizeof(mtt_entry_t) */
    _Atomic size_t      pool_used;                      /* 当前在用 entry 数（无锁读取） */
    _Atomic int         pool_mode;                      /* 模式：MTT_POOL_MODE_* */

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
    _Atomic size_t      sample_rate;                /* 字节采样率：0=旧模式, >0=log2步长 */
    _Atomic size_t      sample_bytes_accum;         /* 字节采样累加器（按分配大小累加） */
    _Atomic size_t      skipped_sampled;            /* 因采样跳过的分配次数 */
    _Atomic size_t      skipped_overcap;            /* 因超容量上限跳过的记录次数 */
    _Atomic int         peak_updated;               /* peak_bytes 刚更新时为1（reporter 秒级检查） */
    _Atomic time_t      leak_threshold_sec;          /* 泄漏阈值（秒）：存活超过此值→probable leak */
    _Atomic time_t      startup_until;              /* 启动阶段结束时间：此时刻之前不追踪 */
    _Atomic size_t      temp_alloc_count;           /* 临时分配计数（短生命周期） */
    _Atomic size_t      expired_alloc_count;        /* 过期但未释放的分配计数 */
    _Atomic size_t      free_expired_count;         /* 过期后被释放的计数（late-free） */

    /* 库黑名单（借鉴 libleak LEAK_LIB_BLACKLIST） */
    char                lib_blacklist[512];          /* 逗号分隔的 .so 名列表 */
    int                 lib_blacklist_ready;          /* 黑名单是否已解析 */

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
int          mtt_should_track(mtt_state_t *s, size_t size);
int          mtt_is_over_capacity(mtt_state_t *s);
int          mtt_is_startup_phase(mtt_state_t *s);
int          mtt_is_blacklisted(mtt_state_t *s, const char *symbol);
void         mtt_capture_stack(mtt_entry_t *entry);
int          mtt_pool_contains(const void *ptr);   /* 判断 ptr 是否落在 entry 池范围内（防止误 free） */

/* 诊断日志开关（tracker.c 定义）。
 * =1: 输出 init 状态/scan 进度等诊断信息到 stderr
 * =0: 静默运行,只输出 leak 报告 + heartbeat
 * 由环境变量 MTT_DEBUG 控制,默认开。
 * 所有非热路径的诊断打印都应判断此标志。 */
extern _Atomic int mtt_debug_enabled;

/* 工具自身的 stderr 诊断打印宏(仅非热路径用)。
 * 默认开,关闭时编译期不消除但运行时短路(单次分支判断,可忽略)。
 * pool init 日志、关键 ERROR/WARNING 不受此开关控制(始终输出)。 */
#define MTT_DIAG_LOG(buf, len) \
    do { \
        if (atomic_load_explicit(&mtt_debug_enabled, memory_order_relaxed)) { \
            long __mtt_w = (long)write(STDERR_FILENO, (buf), (len)); \
            (void)__mtt_w; \
        } \
    } while (0)

/* reporter.c */
void mtt_reporter_start(void);
void mtt_heartbeat_write(void);   /* 60s 资源监控写独立文件 */

/* stack_cache.c */
uint64_t mtt_stack_hash_compute(void **frames, int frame_count);

/* time_series.c */
void mtt_ts_init(void);

/* signal handling (tracker.c) */
void mtt_signal_thread_start(void);

#endif /* MTT_INTERNAL_H */

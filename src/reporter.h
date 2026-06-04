/*
 * MemoryTraceTool — 周期报告引擎。
 *
 * 后台线程每 60 秒扫描分配追踪表，按调用栈去重后生成泄漏报告，
 * 原子写入 /var/log/mtt/<pid>_<name>.log。
 *
 * 线程安全：本模块仅在单个后台线程中运行，与 hooks.c 高频路径零竞争。
 * 防递归：报告线程全程设置 g_in_hook=1，所有 libc 调用绕过 hook。
 */
#ifndef MTT_REPORTER_H
#define MTT_REPORTER_H

#define _GNU_SOURCE
#include "mtt_internal.h"
#include "time_series.h"

/* ---- 泄漏去重记录 ---- */

/** 单条泄漏站点记录（按调用栈 hash 去重） */
typedef struct mtt_leak_site {
    uint64_t  stack_hash;      /* 关联的栈帧 hash */
    time_t    first_seen;      /* 首次观察到的时间 */
    time_t    last_seen;       /* 最近一次扫描观察到的时间 */
    size_t    count;           /* 当前未释放的分配次数 */
    size_t    per_leak_size;   /* 单次泄漏大小（字节） */
    size_t    total_size;      /* 累计泄漏大小（count × per_leak_size） */
    size_t    diff_size;       /* 与上次扫描的总大小差值（借鉴 jemalloc --base） */
    int       is_expired;      /* 是否存活超过阈值（1=probable leak, 0=possible leak） */
    struct mtt_leak_site *next; /* 哈希碰撞链表 */
} mtt_leak_site_t;

/** 泄漏站点 → 栈缓存的配对记录（报告输出用） */
typedef struct {
    mtt_leak_site_t  *site;               /* 泄漏站点指针 */
    struct mtt_stack_entry *stack_entry;  /* 已解析的栈缓存条目 */
} site_stack_pair_t;

/** 泄漏去重表（开放哈希，数组+链表） */
typedef struct {
    mtt_leak_site_t *entries[MTT_LEAK_DEDUP_SIZE];
    size_t           count;                       /* 当前站点数 */
    pthread_mutex_t  lock;
} mtt_leak_table_t;

/** 报告器全局状态（单例，仅 reporter 线程 + atexit 处理器 + HTTP 线程访问） */
typedef struct {
    pthread_t        thread;
    _Atomic int      running;                    /* 原子标志：1=运行中, 0=停止请求 */
    pthread_mutex_t  scan_mutex;                 /* 串行化 scan_and_report（reporter 线程 vs atexit） */
    mtt_leak_table_t leak_table;
    time_t           session_start;
    char             log_path[512];              /* 正式日志文件路径 */
    char             tmp_path[512];              /* 临时文件路径（write+rename 原子写入） */

    /* HTTP 泄漏缓存：reporter 线程写入，HTTP 线程读取 */
    mtt_leak_site_t **cached_sites;              /* 排序后的泄漏站点指针数组（raw_malloc） */
    size_t            cached_site_count;         /* 缓存站点数 */
    void             *cached_pairs;              /* site_stack_pair_t 结构体数组 */
    mtt_ts_point_t   *cached_ts_data;            /* 时序数据副本 */
    uint32_t          cached_ts_count;           /* 时序数据点数 */
    pthread_mutex_t   cache_lock;                /* 保护缓存读写 */

    /* 差值报告：上次扫描结果（借鉴 jemalloc --base） */
    uint64_t         *prev_diff_hashes;          /* 上次站点 hash 数组 */
    size_t           *prev_diff_sizes;           /* 上次站点 total_size 数组 */
    size_t            prev_diff_count;           /* 上次站点数量 */
    time_t            prev_scan_time;            /* 上次扫描时间 */
} mtt_reporter_t;

/* ---- API ---- */

/**
 * 启动周期报告后台线程。
 *
 * 初始化日志路径 /var/log/mtt/<pid>_<name>.log，
 * 创建 detach 线程，每 MTT_REPORT_INTERVAL_SEC 秒执行一次 scan_and_report()。
 * 线程安全：通过 CAS 确保仅启动一次。
 */
void mtt_reporter_start(void);

/**
 * 请求报告线程停止并执行最后一次扫描。
 *
 * 设置 running=0 标志，等待当前扫描完成（最多等待 5 秒），
 * 执行最终 scan_and_report() 后线程退出。
 * 由 mtt_atexit_report() 调用。
 */
void mtt_reporter_stop(void);
void mtt_reporter_signal_scan(void);

/**
 * 获取报告器单例指针（供 HTTP 服务器读取缓存数据）。
 *
 * @return 报告器全局状态指针（永不为 NULL）
 */
mtt_reporter_t* mtt_reporter_get(void);

#endif /* MTT_REPORTER_H */

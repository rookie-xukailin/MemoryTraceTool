/*
 * MemoryTraceTool — 时序数据采集模块。
 *
 * 环形缓冲区存储进程内存使用情况的时序快照点，
 * 为 Web 仪表盘图表提供数据源。
 * 容量 3600 点（1 小时 @ 1Hz），约 172 KB，适合 ARM 嵌入式设备。
 *
 * 线程安全：独立的 pthread_mutex_t 保护读写操作。
 */
#ifndef MTT_TIME_SERIES_H
#define MTT_TIME_SERIES_H

#include "mtt_internal.h"

/** 时序数据最大点数（1 小时 @ 1Hz） */
#define MTT_TS_MAX_POINTS  3600

/** 时序数据采集间隔（秒） */
#define MTT_TS_INTERVAL_SEC 1

/** 单条时序数据点：记录某一时刻的内存快照 */
typedef struct {
    time_t   timestamp;      /* 采集时刻 Unix 时间戳 */
    size_t   current_bytes;  /* 当前未释放字节数 */
    size_t   peak_bytes;     /* 历史峰值字节数 */
    size_t   alloc_count;    /* 累计分配次数 */
    size_t   free_count;     /* 累计释放次数 */
    size_t   entry_count;    /* 哈希表中活跃条目数 */
} mtt_ts_point_t;

/** 时序数据环形缓冲区 */
typedef struct {
    mtt_ts_point_t points[MTT_TS_MAX_POINTS];  /* 环形缓冲区（固定大小，无动态分配） */
    _Atomic uint32_t head;                      /* 写入位置 [0, MTT_TS_MAX_POINTS) */
    _Atomic uint32_t count;                     /* 累计写入点数（可能超过 MAX，用于计算有效范围） */
    pthread_mutex_t  lock;                      /* 保护读 vs 写并发 */
} mtt_time_series_t;

/* ---- API ---- */

/**
 * 初始化时序数据环形缓冲区。
 *
 * 初始化互斥锁和原子计数器，在 reporter 线程启动前调用一次。
 */
void mtt_ts_init(void);

/**
 * 采集一条时序数据点并写入环形缓冲区。
 *
 * 从全局状态中原子读取当前统计值，持锁写入环形缓冲区。
 * 当 head 到达缓冲区末尾时自动绕回（覆盖最旧数据）。
 * 由 reporter 线程每秒调用一次。
 */
void mtt_ts_record_point(void);

/**
 * 读取指定范围的时序数据点。
 *
 * @param start_idx  起始索引（0 = 最早可用点）
 * @param out        输出数组（调用者分配）
 * @param max_out    输出数组最大容量
 * @param out_count  输出：实际写入的点数
 * @return           0=成功, -1=参数无效
 */
int mtt_ts_get_range(uint32_t start_idx, mtt_ts_point_t *out,
                     uint32_t max_out, uint32_t *out_count);

/**
 * 检查时序数据模块是否已初始化。
 *
 * @return 1=已初始化, 0=未初始化
 */
int mtt_ts_is_ready(void);

#endif /* MTT_TIME_SERIES_H */

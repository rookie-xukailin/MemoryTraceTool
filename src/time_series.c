/*
 * MemoryTraceTool — 时序数据采集模块实现。
 *
 * 环形缓冲区存储进程内存使用情况的时序快照点，
 * 为 Web 仪表盘图表提供数据源。
 *
 * 容量 3600 点（1 小时 @ 1Hz），到达上限后自动绕回覆盖最旧数据。
 * 线程安全：pthread_mutex_t 保护读写，原子计数器跟踪位置。
 */
#define _GNU_SOURCE
#include "time_series.h"
#include <string.h>
#include <stdlib.h>

/** 全局时序数据环形缓冲区（单例） */
static mtt_time_series_t g_time_series;
static int g_ts_initialized = 0;

/* ======================================================================== *
 *                       公共 API                                            *
 * ======================================================================== */

/**
 * 初始化时序数据环形缓冲区。
 *
 * 初始化互斥锁和原子计数器，在 reporter 线程启动前调用一次。
 * 多次调用安全：通过 g_ts_initialized 标志保证仅初始化一次。
 */
void mtt_ts_init(void)
{
    if (g_ts_initialized) return;
    g_ts_initialized = 1;

    memset(&g_time_series, 0, sizeof(g_time_series));
    atomic_store_explicit(&g_time_series.head, 0, memory_order_relaxed);
    atomic_store_explicit(&g_time_series.count, 0, memory_order_relaxed);
    pthread_mutex_init(&g_time_series.lock, NULL);
}

/**
 * 采集一条时序数据点并写入环形缓冲区。
 *
 * 从全局状态中原子读取当前统计值（relaxed 内存序，近似值可接受），
 * 持锁写入环形缓冲区。当 head 到达 MTT_TS_MAX_POINTS 时自动绕回 0，
 * 覆盖最旧的数据点。写入后递增 count 供 get_range 计算有效范围。
 *
 * 由 reporter 线程每秒调用一次。
 */
void mtt_ts_record_point(void)
{
    mtt_state_t *s = mtt_state_get();
    if (s == NULL) return;

    /* 从全局状态读取当前统计值（relaxed 读取，近似值可接受） */
    mtt_ts_point_t pt;
    pt.timestamp     = time(NULL);
    pt.current_bytes = atomic_load_explicit(&s->current_bytes, memory_order_relaxed);
    pt.peak_bytes    = atomic_load_explicit(&s->peak_bytes,    memory_order_relaxed);
    pt.alloc_count   = atomic_load_explicit(&s->alloc_count,  memory_order_relaxed);
    pt.free_count    = atomic_load_explicit(&s->free_count,   memory_order_relaxed);
    pt.entry_count   = (size_t)atomic_load_explicit(&s->entry_count, memory_order_relaxed);

    pthread_mutex_lock(&g_time_series.lock);

    /* 环形写入：head 到达末尾时绕回 0 */
    uint32_t head = atomic_load_explicit(&g_time_series.head, memory_order_relaxed);
    g_time_series.points[head] = pt;

    head++;
    if (head >= MTT_TS_MAX_POINTS)
        head = 0;
    atomic_store_explicit(&g_time_series.head, head, memory_order_relaxed);

    /* 累计写入点数（不绕回，用于计算有效范围） */
    atomic_fetch_add_explicit(&g_time_series.count, 1, memory_order_relaxed);

    pthread_mutex_unlock(&g_time_series.lock);
}

/**
 * 读取指定范围的时序数据点。
 *
 * 根据 count 和 head 计算环形缓冲区中的有效数据范围。
 * 从 oldest（最旧有效点）开始读取最多 max_out 个点。
 * start_idx 相对于 oldest 偏移。
 *
 * @param start_idx  起始索引（0 = 最早可用点）
 * @param out        输出数组（调用者分配，至少 max_out 个元素）
 * @param max_out    最多读取点数
 * @param out_count  输出：实际写入的点数
 * @return           0=成功, -1=参数无效
 */
int mtt_ts_get_range(uint32_t start_idx, mtt_ts_point_t *out,
                     uint32_t max_out, uint32_t *out_count)
{
    if (out == NULL || out_count == NULL || max_out == 0) return -1;

    *out_count = 0;

    pthread_mutex_lock(&g_time_series.lock);

    uint32_t total = atomic_load_explicit(&g_time_series.count, memory_order_relaxed);
    if (total == 0) {
        pthread_mutex_unlock(&g_time_series.lock);
        return 0; /* 无数据 */
    }

    /* 计算有效数据范围：
     * - 若 total <= MAX，数据从 0 到 head-1
     * - 若 total > MAX，数据为整个缓冲区（head 是最旧的，head-1 是最新的） */
    uint32_t valid_count;
    uint32_t oldest; /* 最旧数据在 points[] 中的索引 */

    if (total <= MTT_TS_MAX_POINTS) {
        valid_count = total;
        oldest = 0;
    } else {
        valid_count = MTT_TS_MAX_POINTS;
        oldest = atomic_load_explicit(&g_time_series.head, memory_order_relaxed);
    }

    uint32_t head = atomic_load_explicit(&g_time_series.head, memory_order_relaxed);

    /* 从 start_idx 开始读取 */
    uint32_t read_count = 0;
    for (uint32_t i = start_idx; i < valid_count && read_count < max_out; i++) {
        uint32_t idx;
        if (total <= MTT_TS_MAX_POINTS) {
            idx = i;
        } else {
            /* 缓冲区已满：从 oldest 开始绕回 */
            idx = (oldest + i) % MTT_TS_MAX_POINTS;
        }
        out[read_count++] = g_time_series.points[idx];
    }

    *out_count = read_count;

    pthread_mutex_unlock(&g_time_series.lock);
    return 0;
}

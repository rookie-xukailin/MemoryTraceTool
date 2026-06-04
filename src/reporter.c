/*
 * MemoryTraceTool — 周期报告引擎。
 *
 * 后台线程每 MTT_REPORT_INTERVAL_SEC（60）秒唤醒一次，
 * 扫描分配追踪表，按栈帧 hash 去重后生成泄漏报告，
 * 原子写入 /var/log/mtt/<pid>_<name>.log。
 *
 * 线程安全：仅在单个后台线程中运行，与 hooks.c 高频路径零竞争。
 * 防递归：报告线程全程 g_in_hook=1，所有 libc 调用绕过 hook。
 * 内存控制：快照数组在每次扫描时动态分配，分配失败时按降级策略处理。
 */

#define _GNU_SOURCE
#include "reporter.h"
#include "stack_cache.h"
#include "time_series.h"
#include "flamegraph.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <time.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>

/* ---- 报告器全局状态（单例，仅 reporter 线程访问） ---- */

mtt_reporter_t g_reporter = {0};
static atomic_int      g_reporter_started = 0;
static int             g_atexit_registered = 0;
static int             g_atexit_done      = 0;

static void mtt_atexit_handler(void)
{
    if (g_atexit_done) return;
    g_atexit_done = 1;

    extern _Atomic int g_signal_thread_running;
    atomic_store_explicit(&g_signal_thread_running, 0, memory_order_release);
    atomic_store_explicit(&g_reporter.running, 0, memory_order_release);

    /* 短暂等待 reporter 完成最终扫描（1s睡眠间隔 + 扫描耗时） */
    struct timespec ts = {2, 0};
    nanosleep(&ts, NULL);
}

/** 获取报告器单例（供 HTTP 服务器等外部模块访问） */
mtt_reporter_t* mtt_reporter_get(void)
{
    return &g_reporter;
}

/* ---- 快照条目（逐锁拷贝，避免持锁期间访问链表） ---- */

typedef struct {
    void   *ptr;
    size_t  size;
    time_t  timestamp;
    void   *stack[MTT_STACK_DEPTH];
    int     stack_frames;
} mtt_alloc_snap_t;

/* ======================================================================== *
 *                      日志目录与文件路径                                      *
 * ======================================================================== */

/**
 * 获取日志目录路径。
 *
 * 优先 /var/log/mtt，若不可写则 fallback 到 /tmp/mtt-logs。
 * 尝试创建目录（0755），失败时使用 fallback。
 * 修复了原 mkdir/access 之间的 TOCTOU 竞态：通过检查 errno 区分
 * "目录已存在"与"权限不足/文件系统只读"两种情况。
 *
 * @param buf   输出缓冲区
 * @param size  缓冲区大小
 * @return      日志目录路径
 */
static const char* ensure_log_dir(char *buf, size_t size)
{
    if (buf == NULL || size == 0) return "/tmp";

    const char *primary = "/var/log/mtt";
    if (mkdir(primary, 0755) == 0 || errno == EEXIST) {
        /* 目录创建成功或已存在 — 检查可写性 */
        if (access(primary, W_OK) == 0) {
            snprintf(buf, size, "%s", primary);
            return buf;
        }
        /* 目录存在但不可写（权限问题），跳过 primary */
    }
    /* mkdir 因 EROFS（只读文件系统）/ EACCES（权限不足）等失败，
     * 或目录存在但不可写 — 统一 fallback */

    const char *fallback = "/tmp/mtt-logs";
    mkdir(fallback, 0755);
    snprintf(buf, size, "%s", fallback);
    return buf;
}

/* ======================================================================== *
 *                     格式化输出辅助函数                                       *
 * ======================================================================== */

/** 格式化字节数为人类可读的带单位字符串 */
static const char* fmt_bytes(size_t bytes, char *buf, size_t buf_size)
{
    if (buf == NULL || buf_size == 0) return "";
    buf[0] = '\0';

    if (bytes >= 1048576) {
        double mb = (double)bytes / 1048576.0;
        snprintf(buf, buf_size, "%.2f MB", mb);
    } else if (bytes >= 1024) {
        double kb = (double)bytes / 1024.0;
        snprintf(buf, buf_size, "%.2f KB", kb);
    } else {
        snprintf(buf, buf_size, "%zu B", bytes);
    }
    return buf;
}

/** 格式化时间戳为本地时间字符串 "YYYY-MM-DD HH:MM:SS" */
static const char* fmt_time(time_t t, char *buf, size_t buf_size)
{
    if (buf == NULL || buf_size == 0) return "";
    buf[0] = '\0';

    struct tm tm_buf;
    memset(&tm_buf, 0, sizeof(tm_buf));
    if (localtime_r(&t, &tm_buf) != NULL) {
        strftime(buf, buf_size, "%Y-%m-%d %H:%M:%S", &tm_buf);
    } else {
        snprintf(buf, buf_size, "%ld", (long)t);
    }
    return buf;
}

/** 格式化时间间隔为可读字符串 "HH:MM:SS" */
static const char* fmt_duration(time_t seconds, char *buf, size_t buf_size)
{
    if (buf == NULL || buf_size == 0) return "";
    buf[0] = '\0';

    long h = (long)(seconds / 3600);
    long m = (long)((seconds % 3600) / 60);
    long s = (long)(seconds % 60);
    snprintf(buf, buf_size, "%02ld:%02ld:%02ld", h, m, s);
    return buf;
}

/** 格式化频率：leaks/sec 和 "every N sec" */
static void fmt_frequency(double leaks_per_sec, char *buf, size_t buf_size)
{
    if (buf == NULL || buf_size == 0) return;
    buf[0] = '\0';

    if (leaks_per_sec > 0.0) {
        double interval = 1.0 / leaks_per_sec;
        snprintf(buf, buf_size, "%.4f leaks/sec  (every %.1f sec)",
                 leaks_per_sec, interval);
    } else {
        snprintf(buf, buf_size, "N/A (first scan)");
    }
}

/** 判断帧是否为内部帧（应被过滤） */
static int is_internal_frame(const char *symbol)
{
    if (symbol == NULL) return 1;
    if (symbol[0] == '\0') return 1;
    if (strstr(symbol, "libmemorytracetool") != NULL) return 1;
    if (strstr(symbol, "mtt_") == symbol) return 1;        /* 以 mtt_ 开头 */
    if (strstr(symbol, "capture_stack") != NULL) return 1;
    if (strstr(symbol, "backtrace") != NULL) return 1;
    if (strstr(symbol, "__libc_start") != NULL) return 0;   /* libc 入口可以显示 */

    /* 检查库黑名单（借鉴 libleak LEAK_LIB_BLACKLIST） */
    mtt_state_t *st = mtt_state_get();
    if (st != NULL && st->lib_blacklist_ready && st->lib_blacklist[0] != '\0') {
        char blist[512] = {0};
        memcpy(blist, st->lib_blacklist, sizeof(blist) - 1);
        char *token = strtok(blist, ",");
        while (token != NULL) {
            while (*token == ' ' || *token == '\t') token++;
            if (token[0] != '\0' && strstr(symbol, token) != NULL)
                return 1;
            token = strtok(NULL, ",");
        }
    }

    return 0;
}

/* ======================================================================== *
 *                   qsort 比较函数：按 total_size 降序                        *
 * ======================================================================== */

static int cmp_leak_by_size(const void *a, const void *b)
{
    const mtt_leak_site_t *sa = *(const mtt_leak_site_t**)a;
    const mtt_leak_site_t *sb = *(const mtt_leak_site_t**)b;
    if (sb->total_size > sa->total_size) return  1;
    if (sb->total_size < sa->total_size) return -1;
    return 0;
}

/* ======================================================================== *
 *                    核心扫描与报告函数                                       *
 * ======================================================================== */

/**
 * 执行一次完整的扫描与报告。
 *
 * 流程：
 *   1. 逐分段锁快照所有活跃分配条目
 *   2. 按调用栈 hash 去重，构建泄漏站点表
 *   3. 懒解析栈符号
 *   4. 排序后写入报告文件（原子 write+rename）
 *
 * 内存降级策略：
 *   快照数组分配失败时，尝试以半数容量重试，若仍失败则跳过本次扫描。
 *   下次扫描（60s 后）条目数可能减少，届时再尝试。
 */
/** scan_and_report 内部实现（假定调用者持有 g_reporter.scan_mutex） */
static void scan_and_report_locked(void)
{
    mtt_state_t *s = mtt_state_get();
    if (s == NULL) return;
    if (!atomic_load_explicit(&s->initialized, memory_order_acquire)) return;

    time_t now = time(NULL);
    uint64_t entry_total_orig = atomic_load_explicit(&s->entry_count, memory_order_relaxed);
    uint64_t entry_total = entry_total_orig;

    /* ---- 阶段 0: 时序数据缓存更新（独立于扫描，始终执行） ----
     * 必须在快照分配之前更新，即使后续快照分配失败跳过扫描，
     * HTTP 仪表盘仍能获取最新的时序数据用于图表渲染。
     * 若移除此前置更新，skip_scan 路径会跳过 Stage 7 的缓存更新，
     * 导致 /api/data 返回 time_series:[]。 */
    if (mtt_ts_is_ready() && raw_malloc != NULL) {
        mtt_ts_point_t *ts_buf = (mtt_ts_point_t*)raw_malloc(
            360 * sizeof(mtt_ts_point_t));
        if (ts_buf != NULL) {
            memset(ts_buf, 0, 360 * sizeof(mtt_ts_point_t));
            uint32_t ts_count = 0;
            if (mtt_ts_get_range(0, ts_buf, 360, &ts_count) == 0 && ts_count > 0) {
                mtt_ts_point_t *new_data = (mtt_ts_point_t*)raw_malloc(
                    ts_count * sizeof(mtt_ts_point_t));
                if (new_data != NULL) {
                    memcpy(new_data, ts_buf,
                           ts_count * sizeof(mtt_ts_point_t));
                    pthread_mutex_lock(&g_reporter.cache_lock);
                    /* 新数据就绪后才释放旧数据，避免中间态 */
                    if (g_reporter.cached_ts_data != NULL && raw_free != NULL)
                        raw_free(g_reporter.cached_ts_data);
                    g_reporter.cached_ts_data = new_data;
                    g_reporter.cached_ts_count = ts_count;
                    pthread_mutex_unlock(&g_reporter.cache_lock);
                }
                /* 若 new_data 分配失败，保留旧 cached_ts_data 不变 */
            }
            raw_free(ts_buf);
        }
    }

    /* ---- 阶段 1: 逐锁快照活跃条目 ---- */
    mtt_alloc_snap_t *snaps = NULL;
    size_t snap_count = 0;

    if (entry_total > 0) {
        /* 尝试分配快照数组。
         * 在 ARM 内存受限设备上可能失败 — 降级为半数容量重试。 */
        size_t alloc_size = (size_t)(entry_total * sizeof(mtt_alloc_snap_t));
        snaps = (mtt_alloc_snap_t*)raw_malloc(alloc_size);

        if (snaps == NULL && entry_total > 1024) {
            /* 降级：尝试半数容量（仍能覆盖大部分泄漏） */
            entry_total = entry_total / 2;
            alloc_size = (size_t)(entry_total * sizeof(mtt_alloc_snap_t));
            snaps = (mtt_alloc_snap_t*)raw_malloc(alloc_size);
        }

        if (snaps == NULL) {
            /* 分配完全失败：跳过本次扫描，下个周期重试 */
            goto skip_scan;
        }
        memset(snaps, 0, alloc_size);

        /* 逐锁遍历所有桶，持锁期间拷贝字段，释放锁后安全访问 */
        for (unsigned lock_idx = 0;
             lock_idx < MTT_LOCK_STRIPES && snap_count < entry_total;
             lock_idx++) {
            pthread_mutex_lock(&s->bucket_locks[lock_idx].lock);
            for (unsigned b = lock_idx;
                 b < s->bucket_count && snap_count < entry_total;
                 b += MTT_LOCK_STRIPES) {
                mtt_entry_t *e = s->buckets[b];
                while (e != NULL && snap_count < entry_total) {
                    mtt_alloc_snap_t *sn = &snaps[snap_count++];
                    sn->ptr      = e->ptr;
                    sn->size     = e->size;
                    sn->timestamp = e->timestamp;
                    sn->stack_frames = e->stack_frames;
                    memset(sn->stack, 0, sizeof(sn->stack));
                    memcpy(sn->stack, e->stack,
                           (size_t)e->stack_frames * sizeof(void*));
                    e = e->next;
                }
            }
            pthread_mutex_unlock(&s->bucket_locks[lock_idx].lock);
        }
    }

    /* ---- 阶段 2: 去重 —— 按栈 hash 分组到泄漏站点表 ---- */
    /* leak_table 大小约 16KB（64-bit）或 8KB（32-bit），不放在栈上：
     * ARM32 默认线程栈仅 8KB（Android bionic），直接溢出破坏相邻局部变量
     * (sorted / site_count / snaps)，导致 first_seen 垃圾值 + time_series 为空 */
    static mtt_leak_table_t leak_table;
    memset(&leak_table, 0, sizeof(leak_table));

    for (size_t i = 0; i < snap_count; i++) {
        mtt_alloc_snap_t *sn = &snaps[i];

        /* 跳过空栈（捕获失败） */
        if (sn->stack_frames <= 0) continue;

        /* 获取栈缓存条目（含 hash） */
        mtt_stack_entry_t *stack_entry = mtt_stack_cache_lookup(
            sn->stack, sn->stack_frames);

        uint64_t hash;
        if (stack_entry != NULL) {
            hash = stack_entry->hash;
        } else {
            /* 缓存满或分配失败，直接计算 hash（不去重缓存但不影响去重） */
            hash = mtt_stack_hash_compute(sn->stack, sn->stack_frames);
        }

        /* 查/插泄漏站点 */
        unsigned bucket = (unsigned)(hash & (uint64_t)(MTT_LEAK_DEDUP_SIZE - 1));
        mtt_leak_site_t *site = leak_table.entries[bucket];

        while (site != NULL) {
            if (site->stack_hash == hash) {
                break;
            }
            site = site->next;
        }

        if (site != NULL) {
            /* 命中已有站点：累加 */
            /* 防御：若 first_seen 因历史原因未设置（值为 0），回填为当前快照时间或扫描时间 */
            if (site->first_seen == 0)
                site->first_seen = (sn->timestamp > 0) ? sn->timestamp : now;
            site->count++;
            site->total_size += sn->size;
            if (sn->timestamp > site->last_seen)
                site->last_seen = sn->timestamp;
            /* 存活时间判定（借鉴 libleak LEAK_EXPIRE） */
            if (!site->is_expired) {
                time_t threshold = atomic_load_explicit(&s->leak_threshold_sec, memory_order_relaxed);
                if (threshold > 0 && (now - sn->timestamp) > (long)threshold)
                    site->is_expired = 1;
            }
        } else if (leak_table.count < MTT_LEAK_DEDUP_SIZE) {
            /* 新建站点 */
            mtt_leak_site_t *new_site = (mtt_leak_site_t*)raw_malloc(
                sizeof(mtt_leak_site_t));
            if (new_site == NULL) continue; /* 跳过，继续处理下一条 */

            memset(new_site, 0, sizeof(*new_site));
            new_site->stack_hash    = hash;
            /* 防御：若快照时间戳异常（0），回退为当前扫描时间 */
            new_site->first_seen    = (sn->timestamp > 0) ? sn->timestamp : now;
            new_site->last_seen     = sn->timestamp;
            new_site->count         = 1;
            new_site->per_leak_size = sn->size;
            new_site->total_size    = sn->size;
            new_site->diff_size     = 0;
            /* 存活时间判定 */
            {
                time_t threshold = atomic_load_explicit(&s->leak_threshold_sec, memory_order_relaxed);
                new_site->is_expired = (threshold > 0 && (now - sn->timestamp) > (long)threshold) ? 1 : 0;
            }

            /* 插入链表头部 */
            new_site->next = leak_table.entries[bucket];
            leak_table.entries[bucket] = new_site;
            leak_table.count++;
        }
        /* else: 泄漏表满，静默跳过 */
    }

    /* ---- 阶段 3: 懒解析栈符号 ---- */
    for (unsigned b = 0; b < MTT_LEAK_DEDUP_SIZE; b++) {
        mtt_leak_site_t *site = leak_table.entries[b];
        while (site != NULL) {
             /* 遍历快照找到对应 hash 的栈帧并懒解析 */
            for (size_t i = 0; i < snap_count; i++) {
                mtt_alloc_snap_t *sn = &snaps[i];
                if (sn->stack_frames <= 0) continue;
                uint64_t h = mtt_stack_hash_compute(sn->stack, sn->stack_frames);
                if (h == site->stack_hash) {
                    mtt_stack_entry_t *se = mtt_stack_cache_lookup(
                        sn->stack, sn->stack_frames);
                    if (se != NULL && !se->is_resolved)
                        mtt_stack_resolve(se);
                    /* 找到一个就跳出，后续同 hash 的已解析 */
                    break;
                }
            }
            site = site->next;
        }
    }

    /* ---- 阶段 4: 构建排序数组 ---- */
    size_t site_count = leak_table.count;
    mtt_leak_site_t **sorted = NULL;
    if (site_count > 0) {
        sorted = (mtt_leak_site_t**)raw_malloc(
            site_count * sizeof(mtt_leak_site_t*));
        if (sorted != NULL) {
            size_t idx = 0;
            for (unsigned b = 0; b < MTT_LEAK_DEDUP_SIZE && idx < site_count; b++) {
                mtt_leak_site_t *site = leak_table.entries[b];
                while (site != NULL && idx < site_count) {
                    sorted[idx++] = site;
                    site = site->next;
                }
            }
            /* 按 total_size 降序排列 */
            qsort(sorted, idx, sizeof(mtt_leak_site_t*), cmp_leak_by_size);
            site_count = idx;
        }
    }

    /* ---- 阶段 4.5: 差值计算（借鉴 jemalloc --base） ---- */
    if (sorted != NULL && site_count > 0) {
        for (size_t i = 0; i < site_count; i++) {
            size_t prev_total = 0;
            for (size_t j = 0; j < g_reporter.prev_diff_count; j++) {
                if (g_reporter.prev_diff_hashes[j] == sorted[i]->stack_hash) {
                    prev_total = g_reporter.prev_diff_sizes[j];
                    break;
                }
            }
            sorted[i]->diff_size = (sorted[i]->total_size > prev_total)
                ? (sorted[i]->total_size - prev_total) : 0;
        }
    }

    /* ---- 阶段 4.6: 统计过期/未过期计数 + 更新全局计数器 ---- */
    {
        size_t expired_count = 0;
        for (size_t i = 0; i < site_count; i++) {
            if (sorted != NULL && sorted[i]->is_expired)
                expired_count++;
        }
        if (s != NULL) {
            atomic_store_explicit(&s->expired_alloc_count, expired_count, memory_order_relaxed);
        }
    }

    /* ---- 阶段 5: 收集符号缓存（用于写入报告） ---- */
    site_stack_pair_t *pairs = NULL;
    if (sorted != NULL && site_count > 0) {
        pairs = (site_stack_pair_t*)raw_malloc(
            site_count * sizeof(site_stack_pair_t));
        if (pairs != NULL) {
            memset(pairs, 0, site_count * sizeof(site_stack_pair_t));
            for (size_t i = 0; i < site_count; i++) {
                pairs[i].site = sorted[i];
                pairs[i].stack_entry = NULL;
                /* 在快照中寻找匹配的栈 */
                for (size_t j = 0; j < snap_count; j++) {
                    mtt_alloc_snap_t *sn = &snaps[j];
                    if (sn->stack_frames <= 0) continue;
                    uint64_t h = mtt_stack_hash_compute(
                        sn->stack, sn->stack_frames);
                    if (h == sorted[i]->stack_hash) {
                        pairs[i].stack_entry = mtt_stack_cache_lookup(
                            sn->stack, sn->stack_frames);
                        break;
                    }
                }
            }
        }
    }

    /* ---- 阶段 6: 写入报告文件 ---- */
    {
        /* 确保日志目录存在 */
        char log_dir[256] = {0};
        ensure_log_dir(log_dir, sizeof(log_dir));

        /* 构建文件路径：/var/log/mtt/<pid>_<name>.log */
        mtt_state_t *st = mtt_state_get();
        const char *proc_name = "unknown";
        if (st != NULL && st->proc_name_ready && st->proc_name[0] != '\0')
            proc_name = st->proc_name;

        char log_path[512] = {0};
        char tmp_path[512] = {0};
        snprintf(log_path, sizeof(log_path), "%s/%d_%s.log",
                 log_dir, (int)getpid(), proc_name);
        snprintf(tmp_path, sizeof(tmp_path), "%s/%d_%s.log.tmp",
                 log_dir, (int)getpid(), proc_name);

        /* 更新全局路径 */
        snprintf(g_reporter.log_path, sizeof(g_reporter.log_path),
                 "%s", log_path);
        snprintf(g_reporter.tmp_path, sizeof(g_reporter.tmp_path),
                 "%s", tmp_path);

        FILE *fp = fopen(tmp_path, "w");
        if (fp == NULL) {
            /* 写文件失败：记录错误到 stderr（使用 write 避免 malloc） */
            char err_buf[128] = {0};
            int err_len = snprintf(err_buf, sizeof(err_buf),
                "[MTT] ERROR: cannot open %s for writing: %s\n",
                tmp_path, strerror(errno));
            if (err_len > 0 && err_len < (int)sizeof(err_buf))
                write(STDERR_FILENO, err_buf, (size_t)err_len);
            goto cleanup;
        }

        /* 报告头部 */
        time_t session_start = (g_reporter.session_start != 0)
            ? g_reporter.session_start : now;
        time_t elapsed = now - session_start;

        {
            char time_buf[32] = {0};
            char dur_buf[32]  = {0};
            char size_buf[32] = {0};
            char peak_buf[32] = {0};

            fprintf(fp,
                "=== MemoryTraceTool Leak Report ===\n"
                "PID: %d  Process: %s\n"
                "Session:  %s  Duration: %s\n"
                "Scanned:  %s  |  Active allocs: %zu  |  Unique leaks: %zu\n",
                (int)getpid(), proc_name,
                fmt_time(session_start, time_buf, sizeof(time_buf)),
                fmt_duration(elapsed, dur_buf, sizeof(dur_buf)),
                fmt_time(now, time_buf, sizeof(time_buf)),
                snap_count, site_count);

            size_t cur_bytes  = atomic_load_explicit(&st->current_bytes, memory_order_relaxed);
            size_t peak_bytes = atomic_load_explicit(&st->peak_bytes, memory_order_relaxed);
            size_t allocs     = atomic_load_explicit(&st->alloc_count, memory_order_relaxed);
            size_t frees      = atomic_load_explicit(&st->free_count, memory_order_relaxed);

            size_t temp_allocs = atomic_load_explicit(&st->temp_alloc_count, memory_order_relaxed);
            size_t expired    = atomic_load_explicit(&st->expired_alloc_count, memory_order_relaxed);
            size_t free_expired = atomic_load_explicit(&st->free_expired_count, memory_order_relaxed);

            fprintf(fp,
                "Total unfreed: %s  |  Peak: %s\n"
                "Allocations: %zu  |  Frees: %zu\n"
                "Temp allocs (<1s): %zu  |  Expired: %zu  |  Late-free: %zu\n"
                "Skipped (sample): %zu  |  Skipped (overflow): %zu\n"
                "\n",
                fmt_bytes(cur_bytes, size_buf, sizeof(size_buf)),
                fmt_bytes(peak_bytes, peak_buf, sizeof(peak_buf)),
                allocs, frees,
                temp_allocs, expired, free_expired,
                atomic_load_explicit(&st->skipped_sampled, memory_order_relaxed),
                atomic_load_explicit(&st->skipped_overcap, memory_order_relaxed));
        }

        /* 每条泄漏站点 */
        if (pairs != NULL) {
            for (size_t i = 0; i < site_count; i++) {
                mtt_leak_site_t *site = pairs[i].site;
                if (site == NULL || site->count == 0) continue;

                char size_buf[32] = {0};
                char total_buf[32] = {0};
                char freq_buf[64] = {0};
                char time_buf1[32] = {0};
                char time_buf2[32] = {0};

                double elapsed_sec = difftime(site->last_seen, site->first_seen);
                double frequency = 0.0;
                if (elapsed_sec > 0.0 && site->count > 0)
                    frequency = (double)site->count / elapsed_sec;

                fprintf(fp,
                    "--- Leak #%zu ---\n"
                    "Count:        %zu\n"
                    "Per-leak:     %s\n"
                    "Total:        %s\n",
                    i + 1,
                    site->count,
                    fmt_bytes(site->per_leak_size, size_buf, sizeof(size_buf)),
                    fmt_bytes(site->total_size, total_buf, sizeof(total_buf)));

                /* 差值显示（借鉴 jemalloc --base） */
                if (site->diff_size > 0) {
                    char diff_buf[32] = {0};
                    fprintf(fp, "Growth:       +%s (since last scan)\n",
                            fmt_bytes(site->diff_size, diff_buf, sizeof(diff_buf)));
                }

                /* 存活时间判定（借鉴 libleak LEAK_EXPIRE） */
                fprintf(fp, "Confidence:   %s\n",
                        site->is_expired ? "probable leak" : "possible leak");

                fprintf(fp, "Frequency:    ");
                fmt_frequency(frequency, freq_buf, sizeof(freq_buf));
                fprintf(fp, "%s\n", freq_buf);

                fprintf(fp,
                    "First seen:   %s\n"
                    "Last seen:    %s\n"
                    "\nStack trace (top = malloc call site):\n",
                    fmt_time(site->first_seen, time_buf1, sizeof(time_buf1)),
                    fmt_time(site->last_seen,  time_buf2, sizeof(time_buf2)));

                /* 输出栈帧（跳过内部帧） */
                mtt_stack_entry_t *stack_entry = pairs[i].stack_entry;
                if (stack_entry != NULL && stack_entry->is_resolved) {
                    int frame_idx = 0;
                    for (int j = 0; j < stack_entry->frame_count; j++) {
                        const char *sym = stack_entry->resolved[j];
                        if (is_internal_frame(sym)) continue;

                        const char *marker = (frame_idx == 0)
                            ? "  <-- LEAK HERE" : "";
                        fprintf(fp, "  #%-2d %s%s\n", frame_idx, sym, marker);
                        frame_idx++;
                    }
                } else {
                    fprintf(fp, "  (symbols not resolved)\n");
                }
                fprintf(fp, "\n");
            }
        } else if (snap_count > 0) {
            fprintf(fp, "(No leak sites — all allocations freed or dedup table full)\n\n");
        } else {
            fprintf(fp, "(No active allocations — no leaks detected)\n\n");
        }

        fprintf(fp, "=== End of Report ===\n");
        fclose(fp);

        /* 原子替换：rename 在同一文件系统上是原子操作 */
        if (rename(tmp_path, log_path) != 0) {
            /* rename 失败：删除临时文件 */
            unlink(tmp_path);
        }

        /* 同时输出 collapsed stacks 文件（兼容 flamegraph.pl） */
        mtt_flamegraph_write(log_dir, proc_name, sorted, site_count,
                             (void*)pairs);
    }

    /* ---- 阶段 6.5: 保存本次结果用于下次扫描差值计算（借鉴 jemalloc --base） ---- */
    if (raw_free != NULL) {
        if (g_reporter.prev_diff_hashes) raw_free(g_reporter.prev_diff_hashes);
        if (g_reporter.prev_diff_sizes) raw_free(g_reporter.prev_diff_sizes);
    }
    g_reporter.prev_diff_hashes = NULL;
    g_reporter.prev_diff_sizes = NULL;
    g_reporter.prev_diff_count = 0;

    if (sorted != NULL && site_count > 0 && raw_malloc != NULL) {
        g_reporter.prev_diff_hashes = (uint64_t*)raw_malloc(
            site_count * sizeof(uint64_t));
        g_reporter.prev_diff_sizes = (size_t*)raw_malloc(
            site_count * sizeof(size_t));
        if (g_reporter.prev_diff_hashes != NULL && g_reporter.prev_diff_sizes != NULL) {
            for (size_t i = 0; i < site_count; i++) {
                g_reporter.prev_diff_hashes[i] = sorted[i]->stack_hash;
                g_reporter.prev_diff_sizes[i] = sorted[i]->total_size;
            }
            g_reporter.prev_diff_count = site_count;
        }
    }
    g_reporter.prev_scan_time = now;

    /* ---- 阶段 7: 更新 HTTP 缓存 ---- */
    {
        pthread_mutex_lock(&g_reporter.cache_lock);

        /* 释放旧的缓存数据（包括深拷贝的 leak site 结构体） */
        if (g_reporter.cached_sites != NULL && raw_free != NULL) {
            /* 先释放每个深拷贝的 leak site 结构体指针 */
            for (size_t i = 0; i < g_reporter.cached_site_count; i++) {
                if (g_reporter.cached_sites[i] != NULL)
                    raw_free(g_reporter.cached_sites[i]);
            }
            raw_free(g_reporter.cached_sites);
            g_reporter.cached_sites = NULL;
        }
        if (g_reporter.cached_pairs != NULL && raw_free != NULL) {
            raw_free(g_reporter.cached_pairs);
            g_reporter.cached_pairs = NULL;
        }

        /* 深拷贝 sorted 数组 — 必须深拷贝每个 leak site 结构体，
         * 因为 cleanup 阶段会释放 leak_table 中的原始 struct，
         * 若仅拷贝指针会导致 HTTP 线程读取已释放内存（use-after-free）。 */
        if (sorted != NULL && site_count > 0) {
            size_t sorted_bytes = site_count * sizeof(mtt_leak_site_t*);
            g_reporter.cached_sites = (mtt_leak_site_t**)raw_malloc(sorted_bytes);
            if (g_reporter.cached_sites != NULL) {
                for (size_t i = 0; i < site_count; i++) {
                    mtt_leak_site_t *copy = (mtt_leak_site_t*)raw_malloc(
                        sizeof(mtt_leak_site_t));
                    if (copy != NULL) {
                        memcpy(copy, sorted[i], sizeof(mtt_leak_site_t));
                        copy->next = NULL; /* 不复刻链表指针（外泄） */
                        g_reporter.cached_sites[i] = copy;
                    } else {
                        g_reporter.cached_sites[i] = NULL;
                    }
                }
                g_reporter.cached_site_count = site_count;
            }
        } else {
            g_reporter.cached_site_count = 0;
        }

        /* 深拷贝 pairs 结构体数组。
         * 注意：pairs[i].site 指向 sorted[i]（原始 leak_table 节点），
         * cleanup 阶段会释放原始节点，导致 cached_pairs 中的 site 指针悬空。
         * 必须在深拷贝 cached_sites 之后，将 pairs 的 site 指针修正为
         * 指向深拷贝后的 cached_sites[i]，否则 HTTP 线程通过指针比较
         * 查找 stack_entry 时永远无法匹配（指针不同），栈帧始终为空。 */
        if (pairs != NULL && site_count > 0) {
            size_t pairs_bytes = site_count * sizeof(site_stack_pair_t);
            g_reporter.cached_pairs = raw_malloc(pairs_bytes);
            if (g_reporter.cached_pairs != NULL) {
                memcpy(g_reporter.cached_pairs, pairs, pairs_bytes);
                /* 修正 site 指针：指向深拷贝后的 cached_sites 而非即将释放的原始节点 */
                if (g_reporter.cached_sites != NULL) {
                    site_stack_pair_t *pp = (site_stack_pair_t*)g_reporter.cached_pairs;
                    for (size_t i = 0; i < site_count; i++) {
                        pp[i].site = g_reporter.cached_sites[i];
                    }
                }
            }
        }

        /* 复制时序数据（最多 360 点）。
         * 使用堆分配（非栈上 VLA）以避免 ARM 嵌入式系统默认栈过小导致溢出。
         * 360 * sizeof(mtt_ts_point_t) ≈ 17KB（64-bit）或 8.5KB（32-bit），
         * 可能超出默认 pthread 栈大小（嵌入式系统通常仅 8KB）。
         * 栈溢出会静默破坏相邻栈帧中的局部变量（如 sorted、site_count 等），
         * 导致 first_seen 等字段被写入随机数据。 */
        if (mtt_ts_is_ready() && raw_malloc != NULL) {
            mtt_ts_point_t *ts_buf = (mtt_ts_point_t*)raw_malloc(
                360 * sizeof(mtt_ts_point_t));
            if (ts_buf != NULL) {
                memset(ts_buf, 0, 360 * sizeof(mtt_ts_point_t));
                uint32_t ts_count = 0;
                if (mtt_ts_get_range(0, ts_buf, 360, &ts_count) == 0 && ts_count > 0) {
                    mtt_ts_point_t *new_data = (mtt_ts_point_t*)raw_malloc(
                        ts_count * sizeof(mtt_ts_point_t));
                    if (new_data != NULL) {
                        memcpy(new_data, ts_buf,
                               ts_count * sizeof(mtt_ts_point_t));
                        /* 新数据就绪后才释放旧数据，避免中间态 */
                        if (g_reporter.cached_ts_data != NULL && raw_free != NULL)
                            raw_free(g_reporter.cached_ts_data);
                        g_reporter.cached_ts_data = new_data;
                        g_reporter.cached_ts_count = ts_count;
                    }
                    /* 若 new_data 分配失败，保留旧 cached_ts_data 不变 */
                }
                raw_free(ts_buf);
            }
        }

        pthread_mutex_unlock(&g_reporter.cache_lock);
    }

cleanup:
    /* 释放快照数组（raw_free 非 NULL 检查，防御性编程） */
    if (snaps != NULL && raw_free != NULL) raw_free(snaps);
    /* 释放排序数组 */
    if (sorted != NULL && raw_free != NULL) raw_free(sorted);
    if (pairs != NULL && raw_free != NULL) raw_free(pairs);
    /* 释放泄漏站点链表 */
    for (unsigned b = 0; b < MTT_LEAK_DEDUP_SIZE; b++) {
        mtt_leak_site_t *site = leak_table.entries[b];
        while (site != NULL) {
            mtt_leak_site_t *next = site->next;
            if (raw_free != NULL) raw_free(site);
            site = next;
        }
    }
    return;

skip_scan:
    /* 快照分配失败 — 静默跳过本次扫描 */
    {
        char err_buf[128] = {0};
        int err_len = snprintf(err_buf, sizeof(err_buf),
            "[MTT] WARNING: snapshot alloc failed for %llu entries, skipping scan\n",
            (unsigned long long)entry_total_orig);
        if (err_len > 0 && err_len < (int)sizeof(err_buf))
            write(STDERR_FILENO, err_buf, (size_t)err_len);
    }
}

/** scan_and_report 加锁包装器（串行化 reporter 线程与 atexit 处理器） */
static void scan_and_report(void)
{
    pthread_mutex_lock(&g_reporter.scan_mutex);
    scan_and_report_locked();
    pthread_mutex_unlock(&g_reporter.scan_mutex);
}

/* ======================================================================== *
 *                     后台报告线程                                           *
 * ======================================================================== */

/** 后台报告线程主函数 */
static void* reporter_thread_fn(void *arg)
{
    (void)arg;
    pthread_detach(pthread_self());

    /* 报告线程全程设置 g_in_hook，确保所有 libc 调用绕过 hook，
     * 避免 fopen/fprintf/snprintf 等内部 malloc 导致递归死锁。 */
    int saved_hook = g_in_hook;
    g_in_hook = 1;

    /* 等 1 秒让业务代码启动并产生分配，然后做首次扫描 */
    sleep(1);
    /* 记录第一个时序数据点 — 必须在首次 scan_and_report 之前，
     * 否则首次扫描的缓存中 time_series 将为空数组。 */
    mtt_ts_record_point();
    scan_and_report();

    while (atomic_load_explicit(&g_reporter.running, memory_order_acquire)) {
        /* 分段睡眠，每 1 秒检查一次 running 标志（响应退出请求） */
        for (int i = 0;
             i < MTT_REPORT_INTERVAL_SEC &&
             atomic_load_explicit(&g_reporter.running, memory_order_acquire);
             i++) {
            sleep(1);
            /* 每秒记录时序数据点 */
            mtt_ts_record_point();

            /* 检查峰值是否刚被更新（借鉴 jemalloc prof_gdump） */
            mtt_state_t *st = mtt_state_get();
            if (st != NULL &&
                atomic_exchange_explicit(&st->peak_updated, 0, memory_order_relaxed)) {
                /* 新高水位：立即触发一次扫描，不漏峰值 */
                break;
            }
        }

        if (atomic_load_explicit(&g_reporter.running, memory_order_acquire))
            scan_and_report();
    }

    /* 运行标志已清除，执行最后一次扫描 */
    scan_and_report();

    g_in_hook = saved_hook;
    return NULL;
}

/* ======================================================================== *
 *                     atexit 处理（进程退出时生成最终报告）                       *
 * ======================================================================== */

/**
 * 进程退出时执行最终扫描。
 *
 * 先通知后台线程停止，再同步调用 scan_and_report() 输出最终报告。
 * atexit 在 main 返回/exit 调用后执行，此时主线程外的大部分线程已结束。
 */
/* atexit 不安全：libc 清理顺序不确定，不做同步扫描。
 * reporter 线程在运行标志被清除后会自行执行最后一次扫描。 */

/* ======================================================================== *
 *                     公共接口                                              *
 * ======================================================================== */

/**
 * 启动周期报告后台线程。
 *
 * 初始化日志路径和会话起始时间，创建 detach 线程。
 * 通过 CAS 确保仅启动一次。
 *
 * 修复了 atexit 注册时序：先创建线程成功，再注册 atexit，
 * 避免线程创建失败但 atexit 已注册导致重复调用。
 */
void mtt_reporter_start(void)
{
    int expected = 0;
    if (!atomic_compare_exchange_strong(&g_reporter_started, &expected, 1))
        return;

    mtt_state_t *s = mtt_state_get();

    /* 初始化互斥锁 */
    pthread_mutex_init(&g_reporter.scan_mutex, NULL);
    pthread_mutex_init(&g_reporter.cache_lock, NULL);

    atomic_store_explicit(&g_reporter.running, 1, memory_order_release);
    g_reporter.session_start = time(NULL);

    /* 构建日志路径 */
    const char *proc_name = "unknown";
    if (s != NULL && s->proc_name_ready && s->proc_name[0] != '\0')
        proc_name = s->proc_name;

    char log_dir[256] = {0};
    ensure_log_dir(log_dir, sizeof(log_dir));
    snprintf(g_reporter.log_path, sizeof(g_reporter.log_path),
             "%s/%d_%s.log", log_dir, (int)getpid(), proc_name);
    snprintf(g_reporter.tmp_path, sizeof(g_reporter.tmp_path),
             "%s/%d_%s.log.tmp", log_dir, (int)getpid(), proc_name);

    memset(&g_reporter.leak_table, 0, sizeof(g_reporter.leak_table));

    pthread_t tid;
    int rc = pthread_create(&tid, NULL, reporter_thread_fn, NULL);
    if (rc != 0) {
        /* 创建线程失败：静默降级，重置状态，不注册 atexit */
        atomic_store_explicit(&g_reporter.running, 0, memory_order_release);
        atomic_store(&g_reporter_started, 0);
        return;
    }

    /* 注册 atexit：仅设标志让 reporter 线程做扫描，不直接调用 scan_and_report */
    if (!g_atexit_registered) {
        atexit(mtt_atexit_handler);
        g_atexit_registered = 1;
    }

    /* 首次诊断输出（使用 write 避免 malloc） */
    char diag[256] = {0};
    int len = snprintf(diag, sizeof(diag),
        "[MTT] Reporter thread started (pid=%d, log=%s, interval=%ds)\n",
        (int)getpid(), g_reporter.log_path, MTT_REPORT_INTERVAL_SEC);
    if (len > 0 && len < (int)sizeof(diag))
        write(STDERR_FILENO, diag, (size_t)len);
}

/**
 * 停止报告线程并执行最后一次扫描。
 *
 * 由 atexit 回调调用。设置 running=0，等待线程自然退出
 * 后（最多等待约 MTT_REPORT_INTERVAL_SEC），线程会执行最终扫描。
 */
void mtt_reporter_stop(void)
{
    atomic_store_explicit(&g_reporter.running, 0, memory_order_release);
    /* 不 join：线程是 detached，会在下一次检查 running 时自行退出。
     * atexit 上下文中 pthread_join 可能导致死锁。 */
}

/**
 * 信号触发的即时扫描（由 mtt_signal_thread_start 的信号线程调用）。
 *
 * 与 reporter 线程和 atexit 处理器共享 scan_mutex 以确保串行化。
 * kill -USR1 <pid> 即可触发，无需等待 60s 报告间隔。
 */
void mtt_reporter_signal_scan(void)
{
    if (!atomic_load_explicit(&g_reporter.running, memory_order_acquire))
        return;

    /* 持锁扫描（与 reporter 线程和 atexit 串行化） */
    pthread_mutex_lock(&g_reporter.scan_mutex);
    scan_and_report_locked();
    pthread_mutex_unlock(&g_reporter.scan_mutex);
}

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
#include "http_server.h"
#include "addr_validate.h"
#include "mtt_internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <time.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>

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

    /* 停止 HTTP 服务器（关闭 listen_fd，让 HTTP 线程在下一次 select 超时后退出） */
    mtt_http_server_stop();

    /* 短暂等待 reporter 完成最终扫描（1s睡眠间隔 + 扫描耗时） */
    struct timespec ts = {2, 0};
    nanosleep(&ts, NULL);

    /* 清理 reporter 堆分配的缓存数据。
     * reporter 线程在检测到 running=0 后会执行最后一次 scan_and_report，
     * 完成后线程退出。此处等待 2 秒后清理是安全的最佳努力时机，
     * reporter 线程的末尾扫描通常在 <0.1 秒内完成。 */
    if (raw_free != NULL) {
        pthread_mutex_lock(&g_reporter.cache_lock);

        if (g_reporter.cached_sites != NULL) {
            for (size_t i = 0; i < g_reporter.cached_site_count; i++) {
                if (g_reporter.cached_sites[i] != NULL)
                    raw_free(g_reporter.cached_sites[i]);
            }
            raw_free(g_reporter.cached_sites);
            g_reporter.cached_sites = NULL;
        }
        if (g_reporter.cached_pairs != NULL) {
            raw_free(g_reporter.cached_pairs);
            g_reporter.cached_pairs = NULL;
        }
        if (g_reporter.cached_ts_data != NULL) {
            raw_free(g_reporter.cached_ts_data);
            g_reporter.cached_ts_data = NULL;
        }
        g_reporter.cached_site_count = 0;
        g_reporter.cached_ts_count = 0;

        pthread_mutex_unlock(&g_reporter.cache_lock);

        /* 清理上一次扫描差值数据（在 cache_lock 外，因为 reporter 不再更新） */
        if (g_reporter.prev_diff_hashes) raw_free(g_reporter.prev_diff_hashes);
        if (g_reporter.prev_diff_sizes) raw_free(g_reporter.prev_diff_sizes);
        g_reporter.prev_diff_hashes = NULL;
        g_reporter.prev_diff_sizes = NULL;
        g_reporter.prev_diff_count = 0;
    }
}

/** 获取报告器单例（供 HTTP 服务器等外部模块访问） */
mtt_reporter_t* mtt_reporter_get(void)
{
    return &g_reporter;
}

/* ======================================================================== *
 *          late-free 证据环 + 跨扫描站点历史表（分类引擎）                     *
 * ======================================================================== *
 *
 * 周期作用域内存识别的核心证据链：
 *   1. free hook 在释放"已超阈值的老化分配"时，把栈 hash 推入环形缓冲
 *      （mtt_late_free_note，多生产者，原子写指针，满则丢弃）。
 *   2. reporter 扫描线程每次扫描 drain 环，把证据归并到按栈 hash 索引的
 *      持久站点历史表（跨扫描存活，不随 leak_table 重建）。
 *   3. 分类时综合：老化（单调时钟）+ 存活数是否超过历史峰值 + 是否有
 *      late-free 证据 → probable / session_scoped / long_lived / possible。
 *
 * 线程契约：历史表仅 reporter 线程读写（scan_mutex 串行化）；
 * 环形缓冲为 SPSC 变体（多生产者单消费者），drain 用 atomic_exchange，
 * 交换瞬间的生产者写入会丢失 — 良性竞态：周期作用域证据会随周期重现。
 */

static uint64_t g_late_free_ring[MTT_LATE_FREE_RING_SIZE];
static _Atomic uint64_t g_late_free_head = 0;

/** free hook 生产者入口：记录一次老化释放的栈 hash（无锁、无分配） */
void mtt_late_free_note(uint64_t stack_hash)
{
    if (stack_hash == 0) return;
    uint64_t idx = atomic_fetch_add_explicit(&g_late_free_head, 1,
                                             memory_order_relaxed);
    if (idx < MTT_LATE_FREE_RING_SIZE)
        g_late_free_ring[idx] = stack_hash;
    /* else: 环满丢弃（reporter 消费慢），可接受：证据随周期重复出现 */
}

/** 站点历史大小（2 的幂，开放寻址线性探测） */
#define MTT_SITE_HISTORY_SIZE 4096

typedef struct {
    uint64_t hash;            /* 栈 hash（key） */
    size_t   peak_count;      /* 历史最高同时存活数 */
    size_t   last_count;      /* 上次扫描存活数 */
    uint32_t late_free_count; /* 累计观察到的老化释放次数（周期作用域证据） */
    uint32_t scans_seen;      /* 出现在扫描中的次数 */
    uint8_t  used;
} mtt_site_hist_t;

static mtt_site_hist_t g_site_history[MTT_SITE_HISTORY_SIZE];
static size_t g_site_history_used = 0;

/** 查找或创建站点历史条目（仅 reporter 线程调用；表满返回 NULL → 退化纯时间判定） */
static mtt_site_hist_t* site_hist_get(uint64_t hash, int create)
{
    if (hash == 0) return NULL;
    unsigned start = (unsigned)(hash & (uint64_t)(MTT_SITE_HISTORY_SIZE - 1));
    for (unsigned i = 0; i < MTT_SITE_HISTORY_SIZE; i++) {
        unsigned idx = (start + i) & (MTT_SITE_HISTORY_SIZE - 1);
        mtt_site_hist_t *h = &g_site_history[idx];
        if (h->used && h->hash == hash)
            return h;
        if (!h->used) {
            if (!create) return NULL;
            h->used = 1;
            h->hash = hash;
            h->peak_count = 0;
            h->last_count = 0;
            h->late_free_count = 0;
            h->scans_seen = 0;
            g_site_history_used++;
            return h;
        }
    }
    return NULL; /* 表满 */
}

/** drain late-free 环，把证据归并到历史表（仅 reporter 线程调用） */
static void late_free_drain(void)
{
    uint64_t n = atomic_exchange_explicit(&g_late_free_head, 0,
                                          memory_order_relaxed);
    if (n > MTT_LATE_FREE_RING_SIZE)
        n = MTT_LATE_FREE_RING_SIZE; /* 溢出部分已丢弃 */
    for (uint64_t i = 0; i < n; i++) {
        uint64_t h = g_late_free_ring[i];
        if (h == 0) continue;
        mtt_site_hist_t *hist = site_hist_get(h, 1);
        if (hist != NULL && hist->late_free_count < UINT32_MAX)
            hist->late_free_count++;
    }
    if (n > 0) {
        char dbuf[96];
        int dlen = snprintf(dbuf, sizeof(dbuf),
            "[MTT] classify: drained %llu late-free events\n",
            (unsigned long long)n);
        if (dlen > 0 && dlen < (int)sizeof(dbuf))
            MTT_DIAG_LOG(dbuf, (size_t)dlen);
    }
}

/** 四级分类 → 短字符串（文本报告与 HTTP JSON 共用） */
const char* mtt_conf_str(int conf)
{
    switch (conf) {
    case MTT_CONF_PROBABLE:       return "probable";
    case MTT_CONF_SESSION_SCOPED: return "session_scoped";
    case MTT_CONF_LONG_LIVED:     return "long_lived";
    default:                      return "possible";
    }
}

/**
 * 对单个站点做四级分类并更新历史（仅 reporter 线程调用）。
 *
 * 分类规则（classic_leak=1 时跳过，保持旧纯时间行为）：
 *   possible       未老化，或历史观测不足（首次出现）
 *   probable       已老化 && 存活数超过历史峰值（只增不减，真泄漏特征）
 *   session_scoped 未超峰值 && 历史上观察到过老化释放（周期作用域，非泄漏）
 *   long_lived     未超峰值 && 从未观察到释放（长存活稳定，信息级）
 *
 * 峰值棘轮（peak 只增不减）保证：
 *   - 真泄漏每轮扫描 count 刷新峰值 → 持续 probable；
 *   - 周期作用域内存全量释放后重新出现，count 回到原水位不超过峰值
 *     → late-free 证据生效 → session_scoped。
 */
static void classify_site(mtt_leak_site_t *site, int classic)
{
    mtt_site_hist_t *hist = site_hist_get(site->stack_hash, 1);

    if (classic) {
        /* 回退模式：与旧版完全一致的两级判定 */
        site->conf = site->is_expired ? MTT_CONF_PROBABLE : MTT_CONF_POSSIBLE;
        site->late_free_count = (hist != NULL) ? hist->late_free_count : 0;
    } else {
        int has_prior = (hist != NULL) && (hist->scans_seen >= 1);
        int exceeds_peak = has_prior && (site->count > hist->peak_count);

        if (!site->is_expired)
            site->conf = MTT_CONF_POSSIBLE;
        else if (!has_prior)
            site->conf = MTT_CONF_POSSIBLE; /* 首次观测不判 probable，压首扫误报 */
        else if (exceeds_peak)
            site->conf = MTT_CONF_PROBABLE;
        else if (hist->late_free_count > 0)
            site->conf = MTT_CONF_SESSION_SCOPED;
        else
            site->conf = MTT_CONF_LONG_LIVED;

        site->late_free_count = (hist != NULL) ? hist->late_free_count : 0;
    }

    /* 更新历史（无论分类结果，峰值棘轮都要推进） */
    if (hist != NULL) {
        if (hist->scans_seen < UINT32_MAX) hist->scans_seen++;
        hist->last_count = site->count;
        if (site->count > hist->peak_count)
            hist->peak_count = site->count;
    }
}

/* ======================================================================== *
 *                    扫描历史归档（JSONL 追加写）                              *
 * ======================================================================== *
 * 现有报告/JSON/folded/heartbeat 均为覆盖写（只保留最新一次扫描），
 * 数小时压测后无法回溯中间轮次。归档文件每次扫描追加一行站点级快照
 * （不含栈，体积可控），单文件超 MTT_ARCHIVE_MAX_BYTES 轮转保留 2 代。
 * MTT_ARCHIVE=0 关闭（默认开启）。 */

#define MTT_ARCHIVE_MAX_BYTES (8 * 1024 * 1024)  /* 单文件 8MB，.1/.2 两代，上限 24MB/进程 */

/** 归档开关（MTT_ARCHIVE 环境变量，只读一次；默认开启，"0" 关闭） */
static int archive_enabled(void)
{
    static int enabled = -1;
    if (enabled < 0) {
        const char *env = getenv("MTT_ARCHIVE");
        enabled = (env != NULL && strcmp(env, "0") == 0) ? 0 : 1;
    }
    return enabled;
}

/** 归档轮转：path→path.1（旧 .1→.2，.2 删除） */
static void archive_rotate(const char *path)
{
    char p1[800], p2[800];
    if (snprintf(p2, sizeof(p2), "%s.2", path) < 0) return;
    unlink(p2);
    if (snprintf(p1, sizeof(p1), "%s.1", path) < 0) return;
    rename(p1, p2);   /* .1 → .2（不存在时失败无害） */
    rename(path, p1); /* 当前 → .1 */
}

/** 追加一行扫描快照到归档文件（仅 reporter 线程调用） */
static void archive_write(mtt_state_t *s, size_t site_count,
                          mtt_leak_site_t **sorted, time_t now)
{
    if (!archive_enabled()) return;
    if (g_reporter.archive_path[0] == '\0') return;

    struct stat st;
    if (stat(g_reporter.archive_path, &st) == 0 &&
        (unsigned long long)st.st_size > (unsigned long long)MTT_ARCHIVE_MAX_BYTES)
        archive_rotate(g_reporter.archive_path);

    FILE *fp = fopen(g_reporter.archive_path, "a");
    if (fp == NULL) return;

    g_reporter.scan_seq++;

    size_t cur  = atomic_load_explicit(&s->current_bytes, memory_order_relaxed);
    size_t peak = atomic_load_explicit(&s->peak_bytes, memory_order_relaxed);
    unsigned long long allocs = atomic_load_explicit(&s->alloc_count, memory_order_relaxed);
    unsigned long long frees  = atomic_load_explicit(&s->free_count, memory_order_relaxed);
    unsigned long long lfree  = atomic_load_explicit(&s->free_expired_count, memory_order_relaxed);
    size_t sk_ovc = atomic_load_explicit(&s->skipped_overcap, memory_order_relaxed);
    size_t sk_slot = atomic_load_explicit(&s->skipped_slots, memory_order_relaxed);

    fprintf(fp,
        "{\"scan\":%llu,\"ts\":%lld,\"pid\":%d,"
        "\"cur\":%zu,\"peak\":%zu,\"allocs\":%llu,\"frees\":%llu,"
        "\"late_free\":%llu,\"sk_ovc\":%zu,\"sk_slot\":%zu,\"sites\":[",
        (unsigned long long)g_reporter.scan_seq, (long long)now, (int)getpid(),
        cur, peak, allocs, frees, lfree, sk_ovc, sk_slot);

    int wrote = 0;
    for (size_t i = 0; i < site_count; i++) {
        mtt_leak_site_t *site = sorted[i];
        if (site == NULL || site->count == 0) continue;
        fprintf(fp, "%s{\"h\":\"%llx\",\"n\":%zu,\"sz\":%zu,\"conf\":\"%s\","
                    "\"lf\":%u,\"df\":%zu}",
                wrote ? "," : "",
                (unsigned long long)site->stack_hash,
                site->count, site->total_size,
                mtt_conf_str(site->conf),
                site->late_free_count, site->diff_size);
        wrote = 1;
    }
    fprintf(fp, "]}\n");
    fclose(fp);
}

/* ---- 快照条目（逐锁拷贝，避免持锁期间访问链表） ---- */

typedef struct {
    void     *ptr;
    size_t    size;
    time_t    timestamp;   /* 墙钟（first_seen/last_seen 展示用） */
    uint64_t  mono_ts;     /* 单调时钟毫秒（老化判定用，免疫 NTP 跳变） */
    void     *stack[MTT_STACK_DEPTH];
    int       stack_frames;
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
 *                   qsort 比较函数：按 count 降序,次级 total_size            *
 * ======================================================================== */

static int cmp_leak_by_count(const void *a, const void *b)
{
    const mtt_leak_site_t *sa = *(const mtt_leak_site_t**)a;
    const mtt_leak_site_t *sb = *(const mtt_leak_site_t**)b;
    /* 主排序:count(泄漏次数)降序 */
    if (sb->count > sa->count) return  1;
    if (sb->count < sa->count) return -1;
    /* 次级排序:total_size(总占用)降序,保证同 count 时大泄漏在前 */
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
    uint64_t now_mono = mtt_now_mono_ms();  /* 老化判定基准（单调时钟，免疫 NTP 跳变） */
    uint64_t entry_total_orig = atomic_load_explicit(&s->entry_count, memory_order_relaxed);
    uint64_t entry_total = entry_total_orig;

    /* 刷新可执行段缓存:目标进程可能在两次扫描之间 dlopen 加载了新 .so，
     * 新映射的 r-xp 段需进入缓存才能通过 mtt_addr_is_executable 校验，
     * 让后续 mtt_capture_stack 的 FP chain 兜底能识别新 .so 中的返回地址。
     * 频率：每次扫描（60s）一次，开销可忽略。 */
    mtt_addr_validate_refresh();

    /* 诊断：记录每次扫描入口(MTT_DEBUG=0 时屏蔽) */
    {
        char dbuf[96];
        int dlen = snprintf(dbuf, sizeof(dbuf),
            "[MTT] scan enter: entry=%llu\n",
            (unsigned long long)entry_total_orig);
        if (dlen > 0 && dlen < (int)sizeof(dbuf))
            MTT_DIAG_LOG(dbuf, (size_t)dlen);
    }

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
        /* 尝试分配快照数组，逐步减半直到成功 */
        uint64_t try_entries = entry_total;
        size_t alloc_size = 0;
        do {
            alloc_size = (size_t)(try_entries * sizeof(mtt_alloc_snap_t));
            snaps = (mtt_alloc_snap_t*)raw_malloc(alloc_size);
            if (snaps != NULL) break;
            try_entries /= 2;
        } while (try_entries >= 1024);

        if (snaps == NULL)
            goto skip_scan;
        if (try_entries < entry_total)
            entry_total = try_entries;
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
                    sn->mono_ts   = e->mono_ts;
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

    /* 诊断：统计 10 字节快照条目数 */
    {
        size_t n10 = 0;
        for (size_t i = 0; i < snap_count; i++) {
            if (snaps[i].size == 10) n10++;
        }
        if (n10 > 0) {
            char dbuf[80];
            int dlen = snprintf(dbuf, sizeof(dbuf),
                "[MTT] scan: 10B snaps=%zu / total snaps=%zu\n", n10, snap_count);
            if (dlen > 0 && dlen < (int)sizeof(dbuf))
                MTT_DIAG_LOG(dbuf, (size_t)dlen);
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

        uint64_t hash;
        if (sn->stack_frames > 0) {
            /* 获取栈缓存条目（含 hash），同步解析符号。
             * 在条目首次创建时立即调用 mtt_stack_resolve，而非延迟到 Stage 3。
             * 此顺序修正了原 Stage 3 中独立 hash 重匹配可能遗漏条目的问题：
             * 若缓存满导致 mtt_stack_cache_lookup 返回 NULL，Stage 3 中同一条目的
             * lookup 依然为 NULL，mtt_stack_resolve 永远不会被调用。现在在 Stage 2
             * 条目创建时同步解析，确保每个缓存条目在写入 HTTP 缓存之前均已完成解析，
             * 消除 ARM32 QEMU 下第二泄漏站点显示原始 hex 地址的问题。 */
            mtt_stack_entry_t *stack_entry = mtt_stack_cache_lookup(
                sn->stack, sn->stack_frames);
            if (stack_entry != NULL && !stack_entry->is_resolved)
                mtt_stack_resolve(stack_entry);

            if (stack_entry != NULL) {
                hash = stack_entry->hash;
            } else {
                /* 缓存满或分配失败，直接计算 hash（不去重缓存但不影响去重） */
                hash = mtt_stack_hash_compute(sn->stack, sn->stack_frames);
            }
        } else {
            /* 无栈回溯可用（musl/bionic无backtrace平台的兜底策略）：
             * 按分配大小生成hash键，同大小分配归入同一泄漏站点。
             * 虽然丢失调用栈信息，但能按大小维度展示泄漏分布。 */
            hash = (uint64_t)sn->size * UINT64_C(0x9E3779B97F4A7C15);
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
            /* 存活时间判定（借鉴 libleak LEAK_EXPIRE）：单调时钟差值 */
            if (!site->is_expired) {
                time_t threshold = atomic_load_explicit(&s->leak_threshold_sec, memory_order_relaxed);
                if (threshold > 0 && (now_mono - sn->mono_ts) > (uint64_t)threshold * 1000)
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
            /* 存活时间判定（单调时钟差值） */
            {
                time_t threshold = atomic_load_explicit(&s->leak_threshold_sec, memory_order_relaxed);
                new_site->is_expired = (threshold > 0 &&
                    (now_mono - sn->mono_ts) > (uint64_t)threshold * 1000) ? 1 : 0;
            }

            /* 插入链表头部 */
            new_site->next = leak_table.entries[bucket];
            leak_table.entries[bucket] = new_site;
            leak_table.count++;
        }
        /* else: 泄漏表满，静默跳过 */
    }

    /* 诊断：统计 10 字节泄漏站点 */
    {
        size_t n10_sites = 0, n10_total = 0;
        for (unsigned b = 0; b < MTT_LEAK_DEDUP_SIZE; b++) {
            mtt_leak_site_t *site = leak_table.entries[b];
            while (site != NULL) {
                if (site->per_leak_size == 10) { n10_sites++; n10_total += site->count; }
                site = site->next;
            }
        }
        char dbuf[128];
        int dlen = snprintf(dbuf, sizeof(dbuf),
            "[MTT] dedup: 10B_sites=%zu 10B_total=%zu  all_sites=%zu  snaps=%zu\n",
            n10_sites, n10_total, leak_table.count, snap_count);
        if (dlen > 0 && dlen < (int)sizeof(dbuf))
            MTT_DIAG_LOG(dbuf, (size_t)dlen);
    }

    /* 累加所有 leak_site.total_size → s->leak_bytes_total,供时序图红线使用。
     * leak_bytes_total 单调反映"已识别泄漏累积字节",与瞬时 current_bytes 不同:
     * 即使业务 alloc/free 平衡导致 current 看不出趋势,leak_bytes 仍能直显泄漏增长。
     * 每次 scan 重新计算(覆盖写),不累计,因为 leak_table 自身记录的是当前未释放站点。 */
    {
        size_t leak_total = 0;
        for (unsigned b = 0; b < MTT_LEAK_DEDUP_SIZE; b++) {
            mtt_leak_site_t *site = leak_table.entries[b];
            while (site != NULL) {
                leak_total += site->total_size;
                site = site->next;
            }
        }
        atomic_store_explicit(&s->leak_bytes_total, leak_total, memory_order_relaxed);
    }

    /* ---- 阶段 2.5: 泄漏分类（late-free 证据 + 跨扫描站点历史） ----
     * 先 drain free hook 上报的老化释放证据，再对每个站点做四级分类。
     * classic_leak=1 时分类退化为旧的两级判定（is_expired → probable）。 */
    {
        int classic = (s != NULL)
            ? atomic_load_explicit(&s->classic_leak, memory_order_relaxed)
            : 0;
        late_free_drain();
        for (unsigned b = 0; b < MTT_LEAK_DEDUP_SIZE; b++) {
            mtt_leak_site_t *site = leak_table.entries[b];
            while (site != NULL) {
                classify_site(site, classic);
                site = site->next;
            }
        }
    }

    /* ---- 阶段 3: 懒解析栈符号（安全网：补解析阶段 2 遗漏的条目） ----
     * 正常情况下阶段 2 已将首次创建缓存条目时所关联栈全部解析完毕，
     * 此阶段仅处理极端边界情况（如哈希碰撞导致 site->stack_hash 匹配了
     * 另一个不同 stack 的快照）。正常情况下所有条目在阶段 2 已解析，
     * se->is_resolved 为 1，此处直接跳过不重复解析。 */
    for (unsigned b = 0; b < MTT_LEAK_DEDUP_SIZE; b++) {
        mtt_leak_site_t *site = leak_table.entries[b];
        while (site != NULL) {
            for (size_t i = 0; i < snap_count; i++) {
                mtt_alloc_snap_t *sn = &snaps[i];
                if (sn->stack_frames <= 0) continue;
                uint64_t h = mtt_stack_hash_compute(sn->stack, sn->stack_frames);
                if (h == site->stack_hash) {
                    mtt_stack_entry_t *se = mtt_stack_cache_lookup(
                        sn->stack, sn->stack_frames);
                    if (se != NULL && !se->is_resolved)
                        mtt_stack_resolve(se);
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
            qsort(sorted, idx, sizeof(mtt_leak_site_t*), cmp_leak_by_count);
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

        char log_path[768] = {0};
        char tmp_path[768] = {0};
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
                MTT_DIAG_WRITE(STDERR_FILENO, err_buf, (size_t)err_len);
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
                "Skipped (sample): %zu  |  Skipped (overflow): %zu  |  Skipped (slots): %zu\n"
                "\n",
                fmt_bytes(cur_bytes, size_buf, sizeof(size_buf)),
                fmt_bytes(peak_bytes, peak_buf, sizeof(peak_buf)),
                allocs, frees,
                temp_allocs, expired, free_expired,
                atomic_load_explicit(&st->skipped_sampled, memory_order_relaxed),
                atomic_load_explicit(&st->skipped_overcap, memory_order_relaxed),
                atomic_load_explicit(&st->skipped_slots, memory_order_relaxed));
        }

        /* 每条泄漏站点：疑似泄漏（probable/possible）完整输出，格式与旧版一致；
         * session_scoped / long_lived 站点移入下方精简信息区（不刷全量栈回溯），
         * 消除周期作用域内存在压测报告中的大量误报栈 */
        if (pairs != NULL) {
            size_t suspect_idx = 0;
            for (size_t i = 0; i < site_count; i++) {
                mtt_leak_site_t *site = pairs[i].site;
                if (site == NULL || site->count == 0) continue;
                if (site->conf == MTT_CONF_SESSION_SCOPED ||
                    site->conf == MTT_CONF_LONG_LIVED)
                    continue;

                suspect_idx++;
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
                    suspect_idx,
                    site->count,
                    fmt_bytes(site->per_leak_size, size_buf, sizeof(size_buf)),
                    fmt_bytes(site->total_size, total_buf, sizeof(total_buf)));

                /* 差值显示（借鉴 jemalloc --base） */
                if (site->diff_size > 0) {
                    char diff_buf[32] = {0};
                    fprintf(fp, "Growth:       +%s (since last scan)\n",
                            fmt_bytes(site->diff_size, diff_buf, sizeof(diff_buf)));
                }

                /* 存活时间判定（借鉴 libleak LEAK_EXPIRE）。
                 * probable 对应旧格式 "probable leak"，其余 "possible leak"，
                 * 保持旧报告解析脚本的兼容性 */
                fprintf(fp, "Confidence:   %s\n",
                        (site->conf == MTT_CONF_PROBABLE)
                            ? "probable leak" : "possible leak");
                if (site->late_free_count > 0) {
                    fprintf(fp, "Evidence:     late_free=%u (observed released)\n",
                            site->late_free_count);
                }

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

            /* 精简信息区：周期作用域（观察到释放）与长存活稳定分配。
             * 每站点单行摘要 + 栈顶 1 帧，供人工复核，不参与泄漏计数 */
            {
                size_t info_count = 0;
                for (size_t i = 0; i < site_count; i++) {
                    mtt_leak_site_t *site = pairs[i].site;
                    if (site == NULL || site->count == 0) continue;
                    if (site->conf != MTT_CONF_SESSION_SCOPED &&
                        site->conf != MTT_CONF_LONG_LIVED)
                        continue;
                    info_count++;
                }
                if (info_count > 0) {
                    char total_buf[32] = {0};
                    char time_buf1[32] = {0};
                    char time_buf2[32] = {0};
                    fprintf(fp,
                        "=== Long-lived allocations (not classified as leaks) ===\n"
                        "Sites: %zu  (session_scoped = 观察到过释放; "
                        "long_lived = 数量稳定未观察过释放)\n\n",
                        info_count);
                    size_t info_idx = 0;
                    for (size_t i = 0; i < site_count; i++) {
                        mtt_leak_site_t *site = pairs[i].site;
                        if (site == NULL || site->count == 0) continue;
                        if (site->conf != MTT_CONF_SESSION_SCOPED &&
                            site->conf != MTT_CONF_LONG_LIVED)
                            continue;
                        info_idx++;
                        fprintf(fp,
                            "--- LongLived #%zu ---  class=%s  count=%zu  "
                            "total=%s  late_free=%u\n"
                            "First seen:   %s  Last seen: %s\n",
                            info_idx, mtt_conf_str(site->conf),
                            site->count,
                            fmt_bytes(site->total_size, total_buf, sizeof(total_buf)),
                            site->late_free_count,
                            fmt_time(site->first_seen, time_buf1, sizeof(time_buf1)),
                            fmt_time(site->last_seen,  time_buf2, sizeof(time_buf2)));
                        /* 栈顶 1 帧（首个非内部帧） */
                        mtt_stack_entry_t *stack_entry = pairs[i].stack_entry;
                        if (stack_entry != NULL && stack_entry->is_resolved) {
                            for (int j = 0; j < stack_entry->frame_count; j++) {
                                const char *sym = stack_entry->resolved[j];
                                if (is_internal_frame(sym)) continue;
                                fprintf(fp, "  top: %s\n\n", sym);
                                break;
                            }
                        } else {
                            fprintf(fp, "  top: (symbols not resolved)\n\n");
                        }
                    }
                }
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

        /* 同时输出 collapsed stacks 文件（兼容 flamegraph.pl）。
         * 只包含疑似泄漏站点（probable/possible）；session_scoped/long_lived
         * 不进火焰图，避免压测侧按 folded 口径统计时被周期作用域内存干扰。
         * 分配失败时回退为全量输出（保持旧行为）。 */
        {
            mtt_leak_site_t **fg_sites = NULL;
            site_stack_pair_t *fg_pairs = NULL;
            size_t fg_count = 0;
            if (sorted != NULL && pairs != NULL && site_count > 0 &&
                raw_malloc != NULL) {
                fg_sites = (mtt_leak_site_t**)raw_malloc(
                    site_count * sizeof(mtt_leak_site_t*));
                fg_pairs = (site_stack_pair_t*)raw_malloc(
                    site_count * sizeof(site_stack_pair_t));
                if (fg_sites != NULL && fg_pairs != NULL) {
                    for (size_t i = 0; i < site_count; i++) {
                        if (sorted[i] == NULL) continue;
                        if (sorted[i]->conf == MTT_CONF_SESSION_SCOPED ||
                            sorted[i]->conf == MTT_CONF_LONG_LIVED)
                            continue;
                        fg_sites[fg_count] = sorted[i];
                        fg_pairs[fg_count] = pairs[i];
                        fg_count++;
                    }
                } else {
                    /* 过滤数组分配失败：回退全量（等价旧行为） */
                    if (fg_sites != NULL) { raw_free(fg_sites); fg_sites = NULL; }
                    if (fg_pairs != NULL) { raw_free(fg_pairs); fg_pairs = NULL; }
                    fg_sites = sorted;
                    fg_pairs = pairs;
                    fg_count = site_count;
                }
            }
            if (fg_sites != NULL && fg_pairs != NULL && fg_count > 0) {
                mtt_flamegraph_write(log_dir, proc_name, fg_sites, fg_count,
                                     (void*)fg_pairs);
            }
            if (fg_sites != NULL && fg_sites != sorted && raw_free != NULL)
                raw_free(fg_sites);
            if (fg_pairs != NULL && fg_pairs != pairs && raw_free != NULL)
                raw_free(fg_pairs);
        }

        /* 离线 JSON 报告：MTT_REPORT_FILE 环境变量指定输出路径。
         * 新增 "conf"/"late_free" 字段（旧字段名与顺序保持不变） */
        {
            static const char *json_path = NULL;
            static int json_checked = 0;
            if (!json_checked) {
                json_path = getenv("MTT_REPORT_FILE");
                json_checked = 1;
            }
            if (json_path != NULL && json_path[0] != '\0') {
                char json_tmp[512];
                snprintf(json_tmp, sizeof(json_tmp), "%s.tmp", json_path);
                FILE *jf = fopen(json_tmp, "w");
                if (jf != NULL) {
                    fprintf(jf, "{\"pid\":%d,\"ts\":%ld,\"leaks\":[",
                            (int)getpid(), (long)now);
                    int jw = 0;
                    for (size_t i = 0; i < site_count; i++) {
                        mtt_leak_site_t *site = sorted[i];
                        if (site == NULL || site->count == 0) continue;
                        fprintf(jf,
                                "%s{\"count\":%zu,\"size\":%zu,"
                                "\"hash\":\"%llx\",\"conf\":\"%s\","
                                "\"late_free\":%u,\"is_expired\":%d}",
                                jw ? "," : "",
                                site->count, site->total_size,
                                (unsigned long long)site->stack_hash,
                                mtt_conf_str(site->conf),
                                site->late_free_count, site->is_expired);
                        jw = 1;
                    }
                    fprintf(jf, "]}\n");
                    fclose(jf);
                    rename(json_tmp, json_path);
                }
            }
        }

        /* 扫描历史归档（JSONL 追加写，压测后可回溯每轮扫描） */
        if (sorted != NULL || site_count == 0)
            archive_write(s, site_count, sorted, now);
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

    /* 浅栈比例监控:统计本次快照中 frame_count < 4 的比例,
     * 超过 20% 且样本数 > 100 时一次性 stderr 警告。
     * 触发场景:目标二进制 -O2 -fomit-frame-pointer 且无 -funwind-tables,
     * glibc backtrace 拿不到完整栈,即使 FP chain 兜底也补不全。
     * 警告只在首次满足条件时输出(g_shallow_warned 哨兵),
     * 避免日志噪声。等级 >= 1 输出(关键诊断)。
     *
     * 注意:必须在 cleanup: 释放 snaps 之前访问,否则 use-after-free。 */
    if (snaps != NULL && snap_count > 100) {
        size_t shallow = 0;
        size_t total_with_stack = 0;
        for (size_t i = 0; i < snap_count; i++) {
            if (snaps[i].stack_frames > 0) {
                total_with_stack++;
                if (snaps[i].stack_frames < 4) shallow++;
            }
        }
        /* 20% 阈值:shallow * 5 > total_with_stack 等价于 shallow/total > 20% */
        if (total_with_stack > 100 && shallow * 5 > total_with_stack) {
            static atomic_int g_shallow_warned = 0;
            int expected = 0;
            if (atomic_compare_exchange_strong_explicit(&g_shallow_warned,
                    &expected, 1, memory_order_acq_rel, memory_order_acquire)) {
                char wbuf[256];
                int wlen = snprintf(wbuf, sizeof(wbuf),
                    "[MTT] WARNING: %zu/%zu (%.0f%%) allocations have <4 frames. "
                    "Backtrace likely truncated by -fomit-frame-pointer. "
                    "Rebuild target with -funwind-tables -fno-omit-frame-pointer.\n",
                    shallow, total_with_stack,
                    (double)shallow * 100.0 / (double)total_with_stack);
                if (wlen > 0 && wlen < (int)sizeof(wbuf))
                    MTT_LOG_INFO(wbuf, (size_t)wlen);
            }
        }
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

    /* 诊断：扫描正常完成(MTT_DEBUG=0 时屏蔽) */
    {
        char dbuf[64];
        int dlen = snprintf(dbuf, sizeof(dbuf),
            "[MTT] scan done: sites=%zu\n", site_count);
        if (dlen > 0 && dlen < (int)sizeof(dbuf))
            MTT_DIAG_LOG(dbuf, (size_t)dlen);
    }
    return;

skip_scan:
    /* 快照分配失败 — 跳过本次扫描(WARNING 等级 1+ 输出) */
    {
        char err_buf[128] = {0};
        int err_len = snprintf(err_buf, sizeof(err_buf),
            "[MTT] WARNING: snapshot alloc failed for %llu entries, skipping scan\n",
            (unsigned long long)entry_total_orig);
        if (err_len > 0 && err_len < (int)sizeof(err_buf))
            MTT_LOG_INFO(err_buf, (size_t)err_len);
    }
}

/** scan_and_report 加锁包装器（串行化 reporter 线程与 atexit 处理器） */
static void scan_and_report(void)
{
    pthread_mutex_lock(&g_reporter.scan_mutex);
    scan_and_report_locked();
    pthread_mutex_unlock(&g_reporter.scan_mutex);
}

/**
 * 60s heartbeat 资源监控:写一行紧凑格式到独立文件。
 *
 * 文件路径:/var/log/mtt/<pid>_heartbeat.log(覆盖写,只保留最新一行)
 * 字段:rss/pool/entries/leaks/siteuniq/skipped
 *
 * 性能要点:
 *   - 单次 read /proc/self/statm(几十字节),单次 open+write+close
 *   - 所有数据 atomic relaxed read,无锁竞争
 *   - 失败时静默跳过(下次 60s 再试)
 *   - 不与 leak 报告共用文件,避免长报告撑大 heartbeat 文件
 */
void mtt_heartbeat_write(void)
{
    mtt_state_t *s = mtt_state_get();
    if (s == NULL) return;

    /* 读 RSS(单位:字节) */
    size_t rss_bytes = 0;
    int rss_fd = open("/proc/self/statm", O_RDONLY);
    if (rss_fd >= 0) {
        char statm_buf[128];
        ssize_t n = read(rss_fd, statm_buf, sizeof(statm_buf) - 1);
        close(rss_fd);
        if (n > 0) {
            statm_buf[n] = '\0';
            long rss_pages = 0;
            /* statm 格式:size resident shared text lib data dt */
            if (sscanf(statm_buf, "%*s %ld", &rss_pages) == 1 && rss_pages > 0) {
                rss_bytes = (size_t)rss_pages * (size_t)sysconf(_SC_PAGESIZE);
            }
        }
    }

    /* 收集所有指标(全部 atomic relaxed,无锁) */
    size_t pool_used   = atomic_load_explicit(&s->pool_used, memory_order_relaxed);
    size_t pool_cap    = s->pool_capacity;
    size_t entries     = (size_t)atomic_load_explicit(&s->entry_count, memory_order_relaxed);
    size_t allocs      = atomic_load_explicit(&s->alloc_count, memory_order_relaxed);
    size_t frees       = atomic_load_explicit(&s->free_count, memory_order_relaxed);
    size_t cur_bytes   = atomic_load_explicit(&s->current_bytes, memory_order_relaxed);
    size_t skipped_ovc = atomic_load_explicit(&s->skipped_overcap, memory_order_relaxed);
    size_t skipped_smp = atomic_load_explicit(&s->skipped_sampled, memory_order_relaxed);
    size_t skipped_slot = atomic_load_explicit(&s->skipped_slots, memory_order_relaxed);
    size_t leaks_n     = (allocs > frees) ? (allocs - frees) : 0;
    int    pool_mode   = atomic_load_explicit(&s->pool_mode, memory_order_relaxed);

    /* pool 使用率(0-100) */
    int pool_pct = (pool_cap > 0) ? (int)((pool_used * 100) / pool_cap) : 0;

    /* 站点数(从 reporter 上次 scan 结果取,缓存字段) */
    size_t sites_uniq = g_reporter.cached_site_count;

    /* 写文件路径:/var/log/mtt/<pid>_heartbeat.log(覆盖写,只留最新行) */
    char path[256];
    int plen = snprintf(path, sizeof(path), "%s/%d_heartbeat.log",
                        MTT_HEARTBEAT_DIR, (int)getpid());
    if (plen <= 0 || plen >= (int)sizeof(path)) return;

    /* 不用 O_APPEND,要覆盖(只保留最新一行,避免无限增长) */
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) return;

    /* 紧凑格式:rss/pool/entries/leaks/siteuniq/skipped */
    char line[288];
    time_t now = time(NULL);
    int llen = snprintf(line, sizeof(line),
        "ts=%lld rss=%zukB pool=%zu/%zu(%d%%,mode=%d) entries=%zu "
        "cur_bytes=%zukB leaks=%zu siteuniq=%zu skipped=%zu/%zu slots=%zu\n",
        (long long)now,
        rss_bytes / 1024,
        pool_used, pool_cap, pool_pct, pool_mode,
        entries,
        cur_bytes / 1024,
        leaks_n, sites_uniq,
        skipped_ovc, skipped_smp, skipped_slot);
    if (llen > 0) {
        MTT_DIAG_WRITE(fd, line, (size_t)llen);
    }
    close(fd);
}

/* ======================================================================== *
 *                     后台报告线程                                           *
 * ======================================================================== */

/** 后台报告线程主函数 */
static void* reporter_thread_fn(void *arg)
{
    (void)arg;
    pthread_detach(pthread_self());

    /* 标记为工具内部线程：所有分配直接透传 raw_*，不进入追踪系统 */
    mtt_per_thread_t *ctx = mtt_thread_get();
    if (ctx != NULL) {
        ctx->tool_internal = 1;
    }

    /* 报告线程全程设置 in_hook，确保所有 libc 调用绕过 hook，
     * 避免 fopen/fprintf/snprintf 等内部 malloc 导致递归死锁。 */
    int saved_hook = (ctx != NULL) ? ctx->in_hook : 0;
    if (ctx != NULL) ctx->in_hook = 1;

    /* 等 1 秒让业务代码启动并产生分配，然后做首次扫描 */
    sleep(1);
    /* 记录第一个时序数据点 — 必须在首次 scan_and_report 之前，
     * 否则首次扫描的缓存中 time_series 将为空数组。 */
    mtt_ts_record_point();
    scan_and_report();
    {
        char dbuf[64];
        int dlen = snprintf(dbuf, sizeof(dbuf),
            "[MTT] reporter: first scan done, entering loop\n");
        if (dlen > 0 && dlen < (int)sizeof(dbuf))
            MTT_DIAG_LOG(dbuf, (size_t)dlen);
    }

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

        if (atomic_load_explicit(&g_reporter.running, memory_order_acquire)) {
            /* 心跳日志:每 MTT_REPORT_INTERVAL_SEC(60s) 一条,等级 1 输出。
             * 用途:串口/控制台长时间无输出会断连,需要工具表明"还在工作"。
             * 等级 0(MTT_DEBUG=0) 仍静默,文件 heartbeat 继续写到 /var/log/mtt/。
             * 带 entry_count 让用户能粗略看分配趋势,不必打开 heartbeat 文件 */
            {
                mtt_state_t *st = mtt_state_get();
                uint64_t ec = 0;
                if (st != NULL) {
                    ec = atomic_load_explicit(&st->entry_count,
                                              memory_order_relaxed);
                }
                char hbuf[128];
                int hlen = snprintf(hbuf, sizeof(hbuf),
                    "[MTT] heartbeat: running ts=%ld entries=%llu interval=%ds\n",
                    (long)time(NULL),
                    (unsigned long long)ec,
                    MTT_REPORT_INTERVAL_SEC);
                if (hlen > 0 && hlen < (int)sizeof(hbuf))
                    MTT_LOG_INFO(hbuf, (size_t)hlen);
            }
            {
                char dbuf[64];
                int dlen = snprintf(dbuf, sizeof(dbuf),
                    "[MTT] reporter: periodic scan start\n");
                if (dlen > 0 && dlen < (int)sizeof(dbuf))
                    MTT_DIAG_LOG(dbuf, (size_t)dlen);
            }
            scan_and_report();
            /* 每轮 scan 结束后写一次 heartbeat 文件(60s 一次) */
            mtt_heartbeat_write();
        }
    }

    /* 运行标志已清除，执行最后一次扫描 */
    {
        char dbuf[64];
        int dlen = snprintf(dbuf, sizeof(dbuf),
            "[MTT] reporter: final scan before exit\n");
        if (dlen > 0 && dlen < (int)sizeof(dbuf))
            MTT_LOG_INFO(dbuf, (size_t)dlen);
    }
    scan_and_report();

    if (ctx != NULL) ctx->in_hook = saved_hook;
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

    /* 扫描历史归档路径：<log_dir>/<pid>_<name>.archive.jsonl
     * （含 pid，fork 子进程 re-init 时会用子进程 pid 重建） */
    snprintf(g_reporter.archive_path, sizeof(g_reporter.archive_path),
             "%s/%d_%s.archive.jsonl", log_dir, (int)getpid(), proc_name);
    g_reporter.scan_seq = 0;

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

    /* 首次诊断输出:Reporter 启动属关键事件(等级 >= 1 输出) */
    char diag[256] = {0};
    int len = snprintf(diag, sizeof(diag),
        "[MTT] Reporter thread started (pid=%d, log=%s, interval=%ds)\n",
        (int)getpid(), g_reporter.log_path, MTT_REPORT_INTERVAL_SEC);
    if (len > 0 && len < (int)sizeof(diag))
        MTT_LOG_INFO(diag, (size_t)len);
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

/**
 * fork 子进程后重置 reporter 状态(tracker.c mtt_fork_child 调用)。
 *
 * fork 后:
 *   - reporter 线程不存在(fork 不复制其他线程)
 *   - g_reporter_started / g_atexit_registered / running 仍为 1(继承的脏值)
 *   - scan_mutex / cache_lock 状态未定义(其他线程可能 fork 时持锁)
 *
 * 本函数重置这些标志和锁,让子进程下次 mtt_reporter_start 走完整启动流程
 * (包括重新创建 reporter 线程 + 重新注册 atexit + 重新构建 log_path)。
 *
 * 注意:本函数在 fork child 上下文中调用,不调 pthread_create(async-signal-safe)。
 * 实际的 reporter 线程重启由 mtt_ensure_init(子进程下次 malloc 触发)负责。
 */
void mtt_reporter_reset_for_fork(void)
{
    /* 重置"已启动"标志,让 mtt_reporter_start 不再跳过 */
    atomic_store(&g_reporter_started, 0);
    atomic_store_explicit(&g_reporter.running, 0, memory_order_release);
    g_atexit_registered = 0;
    g_atexit_done = 0;

    /* fork 后 mutex 状态未定义,重新初始化 */
    pthread_mutex_init(&g_reporter.scan_mutex, NULL);
    pthread_mutex_init(&g_reporter.cache_lock, NULL);

    /* 清空 leak_table(子进程从零开始追踪) */
    memset(&g_reporter.leak_table, 0, sizeof(g_reporter.leak_table));

    /* 清空分类引擎状态(子进程全新追踪,父进程的站点历史/late-free 证据
     * 无意义;归档路径含父进程 pid,由 mtt_reporter_start 重建) */
    memset(g_site_history, 0, sizeof(g_site_history));
    g_site_history_used = 0;
    atomic_store_explicit(&g_late_free_head, 0, memory_order_relaxed);
    g_reporter.scan_seq = 0;
    g_reporter.archive_path[0] = '\0';
}

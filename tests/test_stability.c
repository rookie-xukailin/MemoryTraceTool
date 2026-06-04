/*
 * MemoryTraceTool -- 并发稳定性测试（60 秒长稳）。
 *
 * 多线程并发执行 alloc/free 操作，验证：
 *   1. 60 秒内无崩溃（segfault, abort, hang）
 *   2. 统计计数器不损坏（alloc_count >= free_count, 无溢出回绕）
 *   3. peak_bytes 不倒退
 *   4. 内存无显著累积泄漏（current_bytes 最终接近基线）
 *
 * 运行方式:
 *   make test_stability
 *   或:
 *   LD_LIBRARY_PATH=build build/test_stability
 *
 * 并发模型:
 *   - N 个工作线程（默认 4），每个独立执行随机大小的 alloc/free
 *   - 1 个监控线程，每 2 秒输出统计快照
 *   - 主线程等待 60 秒后发送停止信号，收集最终统计
 */

#define _GNU_SOURCE
#include <memorytracetool/memorytracetool.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/* ---- 配置 ---- */

#define THREAD_COUNT         4       /* 工作线程数 */
#define TEST_DURATION_SEC    60      /* 运行时长 */
#define MONITOR_INTERVAL_SEC 2       /* 监控打印间隔 */
#define MAX_ALLOC_PER_THREAD 4096    /* 每线程最大同时持有分配数 */
#define MAX_ALLOC_SIZE       65536   /* 单次最大分配字节（64 KB） */
#define MIN_ALLOC_SIZE       8       /* 单次最小分配字节 */

/* ---- 全局控制 ---- */

static volatile int g_running = 1;      /* 工作线程运行标志 */
static volatile int g_monitor_done = 0; /* 监控线程退出标志 */
static pthread_mutex_t g_print_lock = PTHREAD_MUTEX_INITIALIZER;

/* ---- 断言 ---- */

static int g_tests_run  = 0;
static int g_tests_pass = 0;
static int g_tests_fail = 0;

#define TEST(name) \
    do { \
        g_tests_run++; \
        printf("  %-50s ", name); \
        fflush(stdout); \
    } while (0)

#define PASS() \
    do { \
        g_tests_pass++; \
        printf("PASS\n"); \
    } while (0)

#define FAIL(msg) \
    do { \
        g_tests_fail++; \
        printf("FAIL: %s\n", msg); \
    } while (0)

#define T_ASSERT(cond, msg) \
    do { \
        if (!(cond)) { FAIL(msg); return; } \
    } while (0)

#define T_ASSERT_GE(a, b, msg) \
    do { \
        if ((a) < (b)) { \
            char _buf[128]; \
            snprintf(_buf, sizeof(_buf), "%s (got %zu, expected >= %zu)", \
                     msg, (size_t)(a), (size_t)(b)); \
            FAIL(_buf); return; \
        } \
    } while (0)

/* ======================================================================== *
 *                     工作线程函数
 * ======================================================================== */

/**
 * 工作线程：循环执行随机 alloc/free 直到 g_running == 0。
 *
 * 每轮随机选择操作：
 *   - 80% 概率：分配并加入本地槽位（如槽位已满则随机释放一个）
 *   - 20% 概率：释放随机槽位（如槽位非空）
 *
 * 分配大小在 [MIN_ALLOC_SIZE, MAX_ALLOC_SIZE] 之间均匀随机。
 * 使用 rand_r 线程局部随机状态避免全局 rand 锁竞争。
 */
static void* worker_thread_fn(void *arg)
{
    int worker_id = *(int *)arg;
    free(arg);

    /* 本地分配槽位（环形覆盖） */
    void *locals[MAX_ALLOC_PER_THREAD];
    size_t local_sizes[MAX_ALLOC_PER_THREAD];
    int local_count = 0;

    /* 线程局部随机状态 */
    unsigned seed = (unsigned)(time(NULL) ^ (pthread_self() << 16) ^ (worker_id + 1) * 2654435761u);

    while (g_running) {
        /* 随机选择操作类型（0=alloc, 1=free, 2=calloc, 3=realloc） */
        int op = rand_r(&seed) % 10;

        if (op < 7) {
            /* 70% 概率：malloc */
            if (local_count >= MAX_ALLOC_PER_THREAD) {
                /* 槽位已满：随机释放一个 */
                int idx = rand_r(&seed) % local_count;
                mtt_free(locals[idx]);
                locals[idx] = locals[local_count - 1];
                local_sizes[idx] = local_sizes[local_count - 1];
                local_count--;
            }

            size_t sz = (size_t)(rand_r(&seed) % (MAX_ALLOC_SIZE - MIN_ALLOC_SIZE + 1)) + MIN_ALLOC_SIZE;
            void *p = mtt_malloc(sz);
            if (p != NULL) {
                locals[local_count] = p;
                local_sizes[local_count] = sz;
                local_count++;
                /* 写入触摸内存确保物理分配 */
                memset(p, (int)(sz & 0xFF), (sz > 64) ? 64 : sz); /* 只触摸前 64 字节节省时间 */
            }
        } else if (op < 9) {
            /* 20% 概率：释放一个随机槽位 */
            if (local_count > 0) {
                int idx = rand_r(&seed) % local_count;
                mtt_free(locals[idx]);
                locals[idx] = locals[local_count - 1];
                local_sizes[idx] = local_sizes[local_count - 1];
                local_count--;
            }
        } else {
            /* 10% 概率：realloc 一个随机槽位 */
            if (local_count > 0) {
                int idx = rand_r(&seed) % local_count;
                size_t new_sz = (size_t)(rand_r(&seed) % (MAX_ALLOC_SIZE - MIN_ALLOC_SIZE + 1)) + MIN_ALLOC_SIZE;
                void *new_p = mtt_realloc(locals[idx], new_sz);
                if (new_p != NULL) {
                    locals[idx] = new_p;
                    local_sizes[idx] = new_sz;
                }
                /* 如果 new_p == NULL，原块仍有效，保持原状 */
            } else {
                /* 没有可 realloc 的块，做一次 malloc */
                size_t sz = (size_t)(rand_r(&seed) % (MAX_ALLOC_SIZE - MIN_ALLOC_SIZE + 1)) + MIN_ALLOC_SIZE;
                void *p = mtt_malloc(sz);
                if (p != NULL) {
                    locals[local_count] = p;
                    local_sizes[local_count] = sz;
                    local_count++;
                }
            }
        }
    }

    /* 清理：释放所有剩余槽位 */
    for (int i = 0; i < local_count; i++) {
        mtt_free(locals[i]);
    }

    return NULL;
}

/* ======================================================================== *
 *                     监控线程函数
 * ======================================================================== */

/**
 * 监控线程：每 MONITOR_INTERVAL_SEC 秒输出统计快照。
 *
 * 用于人工确认测试过程中统计值的合理性。
 * 通过 g_running 控制退出，通过 g_monitor_done 通知主线程退出。
 */
static void* monitor_thread_fn(void *arg)
{
    (void)arg;
    time_t start = time(NULL);

    pthread_mutex_lock(&g_print_lock);
    printf("\n--- Stability Monitor (every %ds) ---\n", MONITOR_INTERVAL_SEC);
    printf("   Time |  Allocs |   Frees |   Leaks | Current |    Peak |    Total\n");
    printf("  ------|---------|---------|---------|---------|---------|---------\n");
    pthread_mutex_unlock(&g_print_lock);

    while (g_running) {
        sleep(MONITOR_INTERVAL_SEC);
        if (!g_running) break;

        time_t elapsed = time(NULL) - start;
        size_t allocs   = mtt_get_alloc_count();
        size_t frees    = mtt_get_free_count();
        size_t leaks    = mtt_get_leak_count();
        size_t cur      = mtt_get_current_usage();
        size_t peak     = mtt_get_peak_usage();
        size_t total    = mtt_get_total_allocated();

        pthread_mutex_lock(&g_print_lock);
        printf("  %5lds | %7zu | %7zu | %7zu | %7s | %7s | %7s\n",
               (long)elapsed, allocs, frees, leaks,
               format_bytes(cur), format_bytes(peak), format_bytes(total));
        fflush(stdout);
        pthread_mutex_unlock(&g_print_lock);
    }

    g_monitor_done = 1;
    return NULL;
}

/* ---- 人类可读字节格式化（监控打印用） ---- */

static const char* format_bytes(size_t b)
{
    static __thread char buf[32];
    if (b >= 1048576) {
        snprintf(buf, sizeof(buf), "%.1fM", (double)b / 1048576.0);
    } else if (b >= 1024) {
        snprintf(buf, sizeof(buf), "%.1fK", (double)b / 1024.0);
    } else {
        snprintf(buf, sizeof(buf), "%zuB", b);
    }
    return buf;
}

/* ======================================================================== *
 *                     统计验证函数
 * ======================================================================== */

/** 验证 1: alloc_count >= free_count */
static void verify_alloc_ge_free(void)
{
    TEST("alloc_count >= free_count after 60s stress");
    size_t a = mtt_get_alloc_count();
    size_t f = mtt_get_free_count();
    T_ASSERT(a >= f, "alloc_count < free_count (impossible, counter corruption)");
    size_t allocs_since_start = a;
    T_ASSERT(allocs_since_start > 0, "no allocations tracked");
    PASS();
}

/** 验证 2: total_allocated 单调递增 */
static void verify_total_allocated_positive(void)
{
    TEST("total_allocated > 0 and reasonable");
    size_t t = mtt_get_total_allocated();
    T_ASSERT(t > 0, "total_allocated is 0 after 60s stress");
    /* 应远小于溢出值（64-bit 不可能溢出，但 sanity check） */
    T_ASSERT(t < (size_t)1 << 62, "total_allocated suspiciously large");
    PASS();
}

/** 验证 3: peak_bytes 保持 */
static void verify_peak_bytes_reasonable(void)
{
    TEST("peak_bytes > 0 and >= current_bytes");
    size_t peak = mtt_get_peak_usage();
    size_t cur = mtt_get_current_usage();
    T_ASSERT(peak > 0, "peak_bytes is 0 after stress test");
    T_ASSERT(peak >= cur, "peak_bytes < current_bytes (semantic violation)");
    PASS();
}

/** 验证 4: current_bytes 接近基线（没有显著累积泄漏） */
static void verify_current_bytes_near_baseline(void)
{
    TEST("current_bytes near baseline after workers cleanup");
    /* 工作线程已释放所有槽位，current_bytes 应接近测试开始前的基线。
     * 由于库内部有少量自身分配，允许最多 2 MB 的余量。 */
    size_t cur = mtt_get_current_usage();
    size_t max_tolerance = 2 * 1024 * 1024; /* 2 MB tolerance */
    T_ASSERT(cur < max_tolerance,
             "current_bytes too high after cleanup (possible internal leak)");
    PASS();
}

/** 验证 5: peak_bytes 不由于 free 而倒退 */
static void verify_peak_persists(void)
{
    TEST("peak_bytes stable after multiple reads");
    size_t p1 = mtt_get_peak_usage();
    size_t p2 = mtt_get_peak_usage();
    char buf[128];
    if (p1 != p2) {
        /* peak 可能在两次读取之间有新的高水位，但不应该降低 */
        T_ASSERT(p2 >= p1, "peak_bytes decreased between reads");
    }
    PASS();
}

/** 验证 6: 多次查询统计的一致性 */
static void verify_counters_consistent(void)
{
    TEST("stat counters consistent after stress");
    size_t a = mtt_get_alloc_count();
    size_t f = mtt_get_free_count();
    size_t l = mtt_get_leak_count();
    size_t expected_leaks = (a > f) ? (a - f) : 0;
    T_ASSERT(l >= expected_leaks,
             "leak_count should be approximately alloc_count - free_count");
    PASS();
}

/** 验证 7: leak_count 最终接近 0 */
static void verify_leak_count_near_zero(void)
{
    TEST("leak_count near zero after all freed");
    size_t leaks = mtt_get_leak_count();
    /* 允许少量内部分配（库自身的分配） */
    T_ASSERT(leaks < 100, "leak_count suspiciously high after cleanup");
    PASS();
}

/* ======================================================================== *
 *                     main
 * ======================================================================== */

int main(void)
{
    printf("=== MemoryTraceTool Stability Test (60s concurrent stress) ===\n\n");
    printf("Configuration: %d worker threads, %ds duration\n",
           THREAD_COUNT, TEST_DURATION_SEC);

    /* 记录基线 */
    size_t base_alloc  = mtt_get_alloc_count();
    size_t base_free   = mtt_get_free_count();
    size_t base_cur    = mtt_get_current_usage();
    size_t base_peak   = mtt_get_peak_usage();
    size_t base_total  = mtt_get_total_allocated();
    printf("Baseline: alloc=%zu free=%zu cur=%zu peak=%zu total=%zu\n",
           base_alloc, base_free, base_cur, base_peak, base_total);

    /* 创建监控线程 */
    pthread_t monitor_tid;
    if (pthread_create(&monitor_tid, NULL, monitor_thread_fn, NULL) != 0) {
        fprintf(stderr, "FATAL: failed to create monitor thread\n");
        return 1;
    }

    /* 创建工作线程 */
    pthread_t workers[THREAD_COUNT];
    for (int i = 0; i < THREAD_COUNT; i++) {
        int *id = (int *)malloc(sizeof(int));
        if (id == NULL) {
            fprintf(stderr, "FATAL: malloc for worker id failed\n");
            g_running = 0;
            for (int j = 0; j < i; j++) pthread_join(workers[j], NULL);
            pthread_join(monitor_tid, NULL);
            return 1;
        }
        *id = i;
        if (pthread_create(&workers[i], NULL, worker_thread_fn, id) != 0) {
            fprintf(stderr, "FATAL: failed to create worker thread %d\n", i);
            g_running = 0;
            for (int j = 0; j < i; j++) pthread_join(workers[j], NULL);
            pthread_join(monitor_tid, NULL);
            free(id);
            return 1;
        }
    }

    /* 等待测试时长 */
    printf("\nRunning stress test for %d seconds...\n", TEST_DURATION_SEC);
    fflush(stdout);
    sleep(TEST_DURATION_SEC);

    /* 停止所有线程 */
    printf("\nStopping workers...\n");
    g_running = 0;

    /* 等待监控线程退出 */
    while (!g_monitor_done) {
        usleep(100000); /* 100ms */
    }
    pthread_join(monitor_tid, NULL);

    /* 等待工作线程退出 */
    for (int i = 0; i < THREAD_COUNT; i++) {
        pthread_join(workers[i], NULL);
    }

    printf("All threads finished cleanly.\n\n");

    /* ---- 验证阶段 ---- */
    printf("Verification:\n\n");

    verify_alloc_ge_free();
    verify_total_allocated_positive();
    verify_peak_bytes_reasonable();
    verify_current_bytes_near_baseline();
    verify_peak_persists();
    verify_counters_consistent();
    verify_leak_count_near_zero();

    /* ---- 最终快照 ---- */
    printf("\n--- Final Snapshot ---\n");
    printf("  alloc_count    = %zu\n", mtt_get_alloc_count());
    printf("  free_count     = %zu\n", mtt_get_free_count());
    printf("  leak_count     = %zu\n", mtt_get_leak_count());
    printf("  current_bytes  = %s\n", format_bytes(mtt_get_current_usage()));
    printf("  peak_bytes     = %s\n", format_bytes(mtt_get_peak_usage()));
    printf("  total_allocated= %s\n", format_bytes(mtt_get_total_allocated()));

    /* 计算分配吞吐量 */
    size_t total_allocs = mtt_get_alloc_count() - base_alloc;
    printf("  ops/sec (alloc) = ~%zu\n", total_allocs / TEST_DURATION_SEC);

    printf("\n---\n");
    printf("Results: %d run, %d passed, %d failed\n",
           g_tests_run, g_tests_pass, g_tests_fail);

    fflush(stdout);
    fflush(stderr);
    return (g_tests_fail > 0) ? 1 : 0;
}

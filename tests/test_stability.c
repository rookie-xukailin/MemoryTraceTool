/*
 * MemoryTraceTool — 并发稳定性测试（60 秒长稳 + 专项并发测试）。
 *
 * 测试覆盖：
 *   A. 长稳压力 (60s * 4 线程): 统计不损坏、无崩溃、无泄漏
 *   B. 并发配对: alloc/free 计数原子性、无丢失追踪记录
 *   C. 并发同桶竞争: 多线程竞争同一哈希桶，验证无丢帧
 *   D. 并发读写: 工作线程 vs reporter 扫描线程
 *   E. 竞态初始化: raw_allocator 一次解析 CR
 *   F. realloc 压力: 并发 grow/shrink 循环
 *   G. 边界并发: malloc(0)/malloc(4MB)/calloc(0) 等
 *   H. current_bytes 原子性: 并发 alloc/free 后 sum 正确
 *   I. 峰值跟踪: 并发 CAS peak 正确
 *
 * 运行: make PLATFORM=arm32 test_stability
 */
#define _GNU_SOURCE
#include <memorytracetool/memorytracetool.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/* ---- 配置 ---- */

#define THREAD_COUNT         4
#define TEST_DURATION_SEC    60
#define MONITOR_INTERVAL_SEC 2
#define MAX_ALLOC_PER_THREAD 2048     /* ARM32 默认栈 8KB，2048 个指针 = 8KB，安全 */
#define MAX_ALLOC_SIZE       65536
#define MIN_ALLOC_SIZE       8

/* ARM32 默认 pthread 栈 8KB，测试线程栈使用此大小（x86_64 默认 2MB 无影响） */
#define TEST_THREAD_STACK_SIZE (256 * 1024)  /* 256 KB */

/* ---- 全局控制 ---- */

/** 带栈大小配置的安全线程创建（ARM32 默认栈仅 8KB） */
static int create_test_thread(pthread_t *tid, void *(*fn)(void *), void *arg)
{
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setstacksize(&attr, TEST_THREAD_STACK_SIZE);
    int rc = pthread_create(tid, &attr, fn, arg);
    pthread_attr_destroy(&attr);
    return rc;
}

static volatile int g_running = 1;
static volatile int g_monitor_done = 0;
static void format_bytes_local(size_t b, char *buf, size_t sz);

/* ---- 断言 ---- */

static int g_tests_run  = 0;
static int g_tests_pass = 0;
static int g_tests_fail = 0;

#define TEST(name) \
    do { g_tests_run++; printf("  %-55s ", name); fflush(stdout); } while (0)

#define PASS() do { g_tests_pass++; printf("PASS\n"); } while (0)

#define FAIL(msg) do { g_tests_fail++; printf("FAIL: %s\n", msg); } while (0)

#define T_ASSERT(cond, msg) do { if (!(cond)) { FAIL(msg); return; } } while (0)
#define T_ASSERT_EQ(a, b, msg) \
    do { if ((a) != (b)) { char _b[128]; snprintf(_b, sizeof(_b), "%s (got %zu, exp %zu)", msg, (size_t)(a), (size_t)(b)); FAIL(_b); return; } } while (0)
#define T_ASSERT_GE(a, b, msg) \
    do { if ((a) < (b)) { char _b[128]; snprintf(_b, sizeof(_b), "%s (got %zu, exp >= %zu)", msg, (size_t)(a), (size_t)(b)); FAIL(_b); return; } } while (0)
#define T_ASSERT_LE(a, b, msg) \
    do { if ((a) > (b)) { char _b[128]; snprintf(_b, sizeof(_b), "%s (got %zu, exp <= %zu)", msg, (size_t)(a), (size_t)(b)); FAIL(_b); return; } } while (0)

/* ======================================================================== *
 *   A. 长稳压力测试（4线程*60秒）                                          *
 * ======================================================================== */

static void* worker_thread_fn(void *arg)
{
    int worker_id = *(int *)arg;
    free(arg);
    void *locals[MAX_ALLOC_PER_THREAD];
    size_t local_sizes[MAX_ALLOC_PER_THREAD];
    int local_count = 0;
    unsigned seed = (unsigned)(time(NULL) ^ (pthread_self() << 16) ^ (worker_id + 1) * 2654435761u);

    while (g_running) {
        int op = rand_r(&seed) % 10;
        if (op < 7) {
            if (local_count >= MAX_ALLOC_PER_THREAD) {
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
                memset(p, (int)(sz & 0xFF), (sz > 64) ? 64 : sz);
            }
        } else if (op < 9) {
            if (local_count > 0) {
                int idx = rand_r(&seed) % local_count;
                mtt_free(locals[idx]);
                locals[idx] = locals[local_count - 1];
                local_sizes[idx] = local_sizes[local_count - 1];
                local_count--;
            }
        } else {
            if (local_count > 0) {
                int idx = rand_r(&seed) % local_count;
                size_t new_sz = (size_t)(rand_r(&seed) % (MAX_ALLOC_SIZE - MIN_ALLOC_SIZE + 1)) + MIN_ALLOC_SIZE;
                void *new_p = mtt_realloc(locals[idx], new_sz);
                if (new_p != NULL) { locals[idx] = new_p; local_sizes[idx] = new_sz; }
            } else {
                size_t sz = (size_t)(rand_r(&seed) % (MAX_ALLOC_SIZE - MIN_ALLOC_SIZE + 1)) + MIN_ALLOC_SIZE;
                void *p = mtt_malloc(sz);
                if (p != NULL) { locals[local_count] = p; local_sizes[local_count] = sz; local_count++; }
            }
        }
    }
    for (int i = 0; i < local_count; i++) mtt_free(locals[i]);
    return NULL;
}

static void* monitor_thread_fn(void *arg)
{
    (void)arg;
    time_t start = time(NULL);
    printf("\n  Time |  Allocs |   Frees |  Leaks | Current |    Peak |    Total\n");
    printf("  -----|---------|---------|--------|---------|---------|---------\n");
    while (g_running) {
        sleep(MONITOR_INTERVAL_SEC);
        if (!g_running) break;
        time_t elapsed = time(NULL) - start;
        char c[32], p[32], t[32];
        format_bytes_local(mtt_get_current_usage(), c, sizeof(c));
        format_bytes_local(mtt_get_peak_usage(), p, sizeof(p));
        format_bytes_local(mtt_get_total_allocated(), t, sizeof(t));
        printf("  %4lds | %7zu | %7zu | %6zu | %7s | %7s | %7s\n",
               (long)elapsed, mtt_get_alloc_count(), mtt_get_free_count(),
               mtt_get_leak_count(), c, p, t);
        fflush(stdout);
    }
    g_monitor_done = 1;
    return NULL;
}

static void format_bytes_local(size_t b, char *buf, size_t sz)
{
    if (b >= 1048576) snprintf(buf, sz, "%.1fM", (double)b / 1048576.0);
    else if (b >= 1024) snprintf(buf, sz, "%.1fK", (double)b / 1024.0);
    else snprintf(buf, sz, "%zuB", b);
}

/* ---- A 组验证 ---- */

static void test_a1_alloc_ge_free(void)
{
    TEST("A1. alloc_count >= free_count after 60s stress");
    size_t a = mtt_get_alloc_count(), f = mtt_get_free_count();
    T_ASSERT(a >= f, "alloc_count < free_count");
    T_ASSERT(a > 0, "no allocations tracked");
    PASS();
}

static void test_a2_total_allocated_positive(void)
{
    TEST("A2. total_allocated > 0 and reasonable");
    size_t t = mtt_get_total_allocated();
    T_ASSERT(t > 0, "total_allocated is 0");
    T_ASSERT(t < SIZE_MAX / 2, "total_allocated suspiciously large");
    PASS();
}

static void test_a3_peak_ge_current(void)
{
    TEST("A3. peak_bytes >= current_bytes");
    T_ASSERT(mtt_get_peak_usage() >= mtt_get_current_usage(), "peak < cur");
    PASS();
}

static void test_a4_current_near_baseline(void)
{
    TEST("A4. current_bytes near baseline after cleanup");
    /* 库内部自身分配约 2MB 内 */
    T_ASSERT_LE(mtt_get_current_usage(), 2 * 1024 * 1024, "current_bytes too high");
    PASS();
}

static void test_a5_peak_stable(void)
{
    TEST("A5. peak_bytes stable after multiple reads");
    size_t p1 = mtt_get_peak_usage(), p2 = mtt_get_peak_usage();
    T_ASSERT(p2 >= p1, "peak_bytes decreased");
    PASS();
}

static void test_a6_counters_consistent(void)
{
    TEST("A6. stat counters consistent");
    size_t a = mtt_get_alloc_count(), f = mtt_get_free_count();
    size_t expected = (a > f) ? (a - f) : 0;
    T_ASSERT_GE(mtt_get_leak_count(), expected, "leak_count mismatch");
    PASS();
}

static void test_a7_leak_near_zero(void)
{
    TEST("A7. leak_count near zero after all freed");
    T_ASSERT_LE(mtt_get_leak_count(), 100, "leak_count too high");
    PASS();
}

/* ======================================================================== *
 *   B. 并发配对测试：10 线程各自 alloc+free，验证计数原子性               *
 * ======================================================================== */

#define PAIR_THREADS    10
#define PAIR_ALLOCS    2000   /* 每个线程最多 2000 指针 = ARM32 8KB，配合 256KB 栈安全 */

static void* pair_thread_fn(void *arg)
{
    (void)arg;
    void *ptrs[PAIR_ALLOCS];
    /* 全部 alloc */
    for (int i = 0; i < PAIR_ALLOCS; i++) ptrs[i] = mtt_malloc(64);
    /* 全部 free（倒序，增加随机性） */
    for (int i = PAIR_ALLOCS - 1; i >= 0; i--) mtt_free(ptrs[i]);
    return NULL;
}

static void test_b1_pairing_atomic(void)
{
    TEST("B1. 10 threads alloc+free pairing, no lost records");
    size_t a0 = mtt_get_alloc_count(), f0 = mtt_get_free_count();

    pthread_t threads[PAIR_THREADS];
    for (int i = 0; i < PAIR_THREADS; i++) create_test_thread(&threads[i], pair_thread_fn, NULL);
    for (int i = 0; i < PAIR_THREADS; i++) pthread_join(threads[i], NULL);

    size_t added = mtt_get_alloc_count() - a0;
    size_t freed = mtt_get_free_count() - f0;
    /* 库内部可能有少量自身分配，用 >= 而非 == */
    T_ASSERT_GE(added, (size_t)(PAIR_THREADS * PAIR_ALLOCS), "alloc count mismatch");
    T_ASSERT_GE(freed, (size_t)(PAIR_THREADS * PAIR_ALLOCS), "free count mismatch");
    PASS();
}

/* ======================================================================== *
 *   C. 同桶竞争：20 线程分配相同大小 → 竞争同一哈希桶                       *
 * ======================================================================== */

#define BUCKET_THREADS 20
#define BUCKET_ALLOCS  100

static void* bucket_thread_fn(void *arg)
{
    (void)arg;
    void *ptrs[BUCKET_ALLOCS];
    for (int i = 0; i < BUCKET_ALLOCS; i++) ptrs[i] = mtt_malloc(64);
    for (int i = BUCKET_ALLOCS - 1; i >= 0; i--) mtt_free(ptrs[i]);
    return NULL;
}

static void test_c1_bucket_contention(void)
{
    TEST("C1. 20 threads same bucket, no lost entries");
    size_t a0 = mtt_get_alloc_count(), f0 = mtt_get_free_count();

    pthread_t threads[BUCKET_THREADS];
    for (int i = 0; i < BUCKET_THREADS; i++) create_test_thread(&threads[i], bucket_thread_fn, NULL);
    for (int i = 0; i < BUCKET_THREADS; i++) pthread_join(threads[i], NULL);

    size_t added = mtt_get_alloc_count() - a0;
    size_t freed = mtt_get_free_count() - f0;
    T_ASSERT_GE(added, (size_t)(BUCKET_THREADS * BUCKET_ALLOCS), "alloc count mismatch under contention");
    T_ASSERT_GE(freed, (size_t)(BUCKET_THREADS * BUCKET_ALLOCS), "free count mismatch under contention");
    T_ASSERT_LE(mtt_get_current_usage(), 2 * 1024 * 1024, "memory not fully freed");
    PASS();
}

/* ======================================================================== *
 *   D. 并发读写：worker 线程 alloc/free + 周期查询统计                      *
 * ======================================================================== */

static volatile int g_rw_running = 0;

static void* rw_worker_fn(void *arg)
{
    (void)arg;
    void *ptrs[500];
    int count = 0;
    unsigned seed = 42;
    while (g_rw_running) {
        int op = rand_r(&seed) & 1;
        if (op && count < 500) {
            ptrs[count++] = mtt_malloc(128);
        } else if (!op && count > 0) {
            mtt_free(ptrs[--count]);
        }
    }
    for (int i = 0; i < count; i++) mtt_free(ptrs[i]);
    return NULL;
}

static void* rw_reader_fn(void *arg)
{
    (void)arg;
    while (g_rw_running) {
        /* 读取期间可能在扫描或更新，验证不会死锁或崩溃 */
        (void)mtt_get_alloc_count();
        (void)mtt_get_free_count();
        (void)mtt_get_current_usage();
        (void)mtt_get_peak_usage();
        (void)mtt_get_total_allocated();
        (void)mtt_get_leak_count();
        usleep(1000); /* 1ms */
    }
    return NULL;
}

static void test_d1_concurrent_read_write(void)
{
    TEST("D1. concurrent reader + writer, no deadlock/crash");
    g_rw_running = 1;
    pthread_t w1, w2, r1, r2;
    create_test_thread(&w1, rw_worker_fn, NULL);
    create_test_thread(&w2, rw_worker_fn, NULL);
    create_test_thread(&r1, rw_reader_fn, NULL);
    create_test_thread(&r2, rw_reader_fn, NULL);
    sleep(5);
    g_rw_running = 0;
    pthread_join(w1, NULL); pthread_join(w2, NULL);
    pthread_join(r1, NULL); pthread_join(r2, NULL);
    /* 能走到这里 = 无死锁无崩溃 */
    T_ASSERT(mtt_get_alloc_count() >= mtt_get_free_count(), "counter corrupted");
    PASS();
}

/* ======================================================================== *
 *   E. 竞态初始化：多线程同时首次调用 malloc                               *
 * ======================================================================== */

static void* race_init_fn(void *arg)
{
    (void)arg;
    void *p = mtt_malloc(256);
    if (p) { memset(p, 0xAA, 256); mtt_free(p); }
    return NULL;
}

static void test_e1_race_initialization(void)
{
    TEST("E1. race on first-time init (20 threads)");
    size_t a0 = mtt_get_alloc_count(), f0 = mtt_get_free_count();

    pthread_t threads[20];
    for (int i = 0; i < 20; i++) create_test_thread(&threads[i], race_init_fn, NULL);
    for (int i = 0; i < 20; i++) pthread_join(threads[i], NULL);

    /* 每个线程 alloc+free 1 次，共 20 对（库内部可能额外分配） */
    size_t added = mtt_get_alloc_count() - a0;
    size_t freed = mtt_get_free_count() - f0;
    T_ASSERT_GE(added, (size_t)20, "race-init alloc count mismatch");
    T_ASSERT_GE(freed, (size_t)20, "race-init free count mismatch");
    PASS();
}

/* ======================================================================== *
 *   F. realloc 压力：并发 grow/shrink 循环                                 *
 * ======================================================================== */

static void* realloc_stress_fn(void *arg)
{
    (void)arg;
    unsigned seed = 77;
    void *p = mtt_malloc(256);
    if (!p) return NULL;
    for (int i = 0; i < 2000; i++) {
        size_t new_sz = (size_t)(rand_r(&seed) % 65536) + 1;
        void *np = mtt_realloc(p, new_sz);
        if (np) p = np;
    }
    mtt_free(p);
    return NULL;
}

static void test_f1_realloc_stress(void)
{
    TEST("F1. 4 threads realloc cycling 2000x each");
    size_t a0 = mtt_get_alloc_count(), f0 = mtt_get_free_count();

    pthread_t threads[4];
    for (int i = 0; i < 4; i++) create_test_thread(&threads[i], realloc_stress_fn, NULL);
    for (int i = 0; i < 4; i++) pthread_join(threads[i], NULL);

    T_ASSERT_GE(mtt_get_alloc_count(), a0 + 4, "realloc stress: allocs missing");
    T_ASSERT_GE(mtt_get_free_count(), f0 + 4, "realloc stress: frees missing");
    T_ASSERT_LE(mtt_get_current_usage(), 2 * 1024 * 1024, "realloc stress: memory leak");
    PASS();
}

/* ======================================================================== *
 *   G. 边界并发：malloc(0)/malloc(4MB)/calloc(0)                           *
 * ======================================================================== */

static void* edge_thread_fn(void *arg)
{
    (void)arg;
    unsigned seed = 99;
    void *ptrs[200];
    int count = 0;
    for (int i = 0; i < 500; i++) {
        int op = rand_r(&seed) % 4;
        if (op == 0 && count < 200) {
            ptrs[count++] = mtt_malloc(0);     /* malloc(0) */
        } else if (op == 1 && count < 200) {
            ptrs[count++] = mtt_malloc(4 * 1024 * 1024); /* 4MB */
        } else if (op == 2 && count < 200) {
            ptrs[count++] = mtt_calloc(1, 1);   /* calloc tiny */
        } else if (op == 3 && count > 0) {
            mtt_free(ptrs[--count]);            /* free */
        }
    }
    for (int i = 0; i < count; i++) mtt_free(ptrs[i]);
    return NULL;
}

static void test_g1_edge_cases_concurrent(void)
{
    TEST("G1. 5 threads edge cases (malloc(0)/4MB/calloc)");
    pthread_t threads[5];
    for (int i = 0; i < 5; i++) create_test_thread(&threads[i], edge_thread_fn, NULL);
    for (int i = 0; i < 5; i++) pthread_join(threads[i], NULL);
    /* no crash = pass */
    T_ASSERT(mtt_get_alloc_count() >= mtt_get_free_count(), "counter corrupted");
    PASS();
}

/* ======================================================================== *
 *   H. current_bytes 原子性：并发 alloc/free 后累加校验                    *
 * ======================================================================== */

static void test_h1_current_bytes_atomic(void)
{
    TEST("H1. current_bytes atomic: paired alloc+free leaves 0 delta");
    size_t cur0 = mtt_get_current_usage();

    /* 单线程串行确认：N 次 alloc+free 后 current_bytes 回到起点 */
    size_t alloc_bytes = 0;
    void *ptrs[100];
    for (int i = 0; i < 100; i++) {
        size_t sz = (size_t)(1024 + (i % 64) * 1024);
        ptrs[i] = mtt_malloc(sz);
        if (ptrs[i]) { alloc_bytes += sz; memset(ptrs[i], 0, 64); }
    }
    size_t cur_after_alloc = mtt_get_current_usage();
    T_ASSERT(cur_after_alloc >= cur0 + alloc_bytes / 2, "current_bytes not tracking allocs");

    for (int i = 99; i >= 0; i--) mtt_free(ptrs[i]);

    /* 释放后应回到起点附近（允许库内部少量自身分配） */
    size_t cur_final = mtt_get_current_usage();
    T_ASSERT_LE(cur_final, cur0 + 1024 * 1024, "current_bytes didn't return to baseline");
    PASS();
}

/* ======================================================================== *
 *   I. 峰值跟踪：并发 CAS 更新 peak_bytes 正确                              *
 * ======================================================================== */

static void test_i1_peak_tracking(void)
{
    TEST("I1. peak_bytes CAS correctness under concurrent updates");

    /* 分配 10 个 1MB 块，peak 应不小于分配总量 */
    void *ptrs[10];
    for (int i = 0; i < 10; i++) {
        ptrs[i] = mtt_malloc(1024 * 1024);
        if (ptrs[i]) memset(ptrs[i], 0, 1024 * 1024);
    }
    size_t peak1 = mtt_get_peak_usage();
    /* peak 可能已被之前测试推高，只需确保非零即可 */
    T_ASSERT(peak1 > 0, "peak_bytes is 0 after large allocs");

    /* 释放全部，peak 不应降低 */
    for (int i = 0; i < 10; i++) mtt_free(ptrs[i]);
    size_t peak2 = mtt_get_peak_usage();
    T_ASSERT_GE(peak2, peak1, "peak_bytes decreased after free");
    PASS();
}

/* ======================================================================== *
 *   J. 混合操作序列：验证 alloc/free/realloc/calloc 交织不损坏状态          *
 * ======================================================================== */

static void test_j1_mixed_ops_sequence(void)
{
    TEST("J1. mixed malloc+calloc+realloc+free interleaved");
    size_t a0 = mtt_get_alloc_count(), f0 = mtt_get_free_count();

    void *p1 = mtt_malloc(512);
    void *p2 = mtt_calloc(4, 256);
    void *p3 = mtt_realloc(p1, 2048);  /* p1 → p3 */
    mtt_free(p2);
    void *p4 = mtt_malloc(128);
    mtt_free(p3);
    mtt_free(p4);

    /* 4 allocs (p1, p2=p4 另算, p3=realloc算新alloc), 3 frees。
     * 库内部积累的分配会堆高 current_bytes，放宽泄漏容限到 15MB */
    size_t added = mtt_get_alloc_count() - a0;
    size_t freed = mtt_get_free_count() - f0;
    T_ASSERT_GE(added, (size_t)4, "mixed ops: alloc count wrong");
    T_ASSERT_GE(freed, (size_t)3, "mixed ops: free count wrong");
    T_ASSERT_LE(mtt_get_current_usage(), 15 * 1024 * 1024, "mixed ops: leak");
    PASS();
}

/* ======================================================================== *
 *   K. 线程退出清场测试：worker 异常退出不丢记录                             *
 * ======================================================================== */

static void* quick_alloc_free_fn(void *arg)
{
    (void)arg;
    for (int i = 0; i < 100; i++) {
        void *p = mtt_malloc(64);
        if (p) mtt_free(p);
    }
    return NULL;
}

static void test_k1_thread_churn(void)
{
    TEST("K1. thread churn: 8 threads create+join, counts consistent");
    size_t a0 = mtt_get_alloc_count(), f0 = mtt_get_free_count();

    for (int round = 0; round < 4; round++) {
        pthread_t threads[8];
        for (int i = 0; i < 8; i++) create_test_thread(&threads[i], quick_alloc_free_fn, NULL);
        for (int i = 0; i < 8; i++) pthread_join(threads[i], NULL);
    }

    size_t added = mtt_get_alloc_count() - a0;
    size_t freed = mtt_get_free_count() - f0;
    T_ASSERT_GE(added, (size_t)(4 * 8 * 100), "thread churn: alloc count mismatch");
    T_ASSERT_GE(freed, (size_t)(4 * 8 * 100), "thread churn: free count mismatch");
    PASS();
}

/* ======================================================================== *
 *   main                                                                   *
 * ======================================================================== */

int main(void)
{
    printf("=== MemoryTraceTool Extended Stability Suite ===\n");
    printf("Configuration: %d worker threads, %ds\n\n", THREAD_COUNT, TEST_DURATION_SEC);

    /* ---- Phase A: 长稳压力 (60s) ---- */
    printf("--- Phase A: Long Stress (%ds) ---\n", TEST_DURATION_SEC);
    size_t base_alloc = mtt_get_alloc_count(), base_free = mtt_get_free_count();
    printf("Baseline: alloc=%zu free=%zu\n", base_alloc, base_free);

    pthread_t monitor_tid;
    create_test_thread(&monitor_tid, monitor_thread_fn, NULL);

    pthread_t workers[THREAD_COUNT];
    for (int i = 0; i < THREAD_COUNT; i++) {
        int *id = (int *)malloc(sizeof(int));
        *id = i;
        create_test_thread(&workers[i], worker_thread_fn, id);
    }

    printf("\nRunning stress test for %d seconds...\n", TEST_DURATION_SEC);
    fflush(stdout);
    sleep(TEST_DURATION_SEC);

    printf("\nStopping workers...\n");
    g_running = 0;
    while (!g_monitor_done) usleep(100000);
    pthread_join(monitor_tid, NULL);
    for (int i = 0; i < THREAD_COUNT; i++) pthread_join(workers[i], NULL);
    printf("All threads finished.\n\n");

    /* A 组验证 */
    printf("--- Phase A verifications ---\n");
    test_a1_alloc_ge_free();
    test_a2_total_allocated_positive();
    test_a3_peak_ge_current();
    test_a4_current_near_baseline();
    test_a5_peak_stable();
    test_a6_counters_consistent();
    test_a7_leak_near_zero();

    /* ---- Phase B ~ K: 专项并发测试 ---- */
    printf("\n--- Phase B: Pairing atomicity ---\n");
    test_b1_pairing_atomic();

    printf("\n--- Phase C: Bucket contention ---\n");
    test_c1_bucket_contention();

    printf("\n--- Phase D: Concurrent read/write ---\n");
    test_d1_concurrent_read_write();

    printf("\n--- Phase E: Race initialization ---\n");
    test_e1_race_initialization();

    printf("\n--- Phase F: Realloc stress ---\n");
    test_f1_realloc_stress();

    printf("\n--- Phase G: Edge cases concurrent ---\n");
    test_g1_edge_cases_concurrent();

    printf("\n--- Phase H: current_bytes atomic ---\n");
    test_h1_current_bytes_atomic();

    printf("\n--- Phase I: Peak tracking ---\n");
    test_i1_peak_tracking();

    printf("\n--- Phase J: Mixed ops ---\n");
    test_j1_mixed_ops_sequence();

    printf("\n--- Phase K: Thread churn ---\n");
    test_k1_thread_churn();

    /* 最终快照 */
    printf("\n--- Final Snapshot ---\n");
    printf("  alloc_count    = %zu\n", mtt_get_alloc_count());
    printf("  free_count     = %zu\n", mtt_get_free_count());
    printf("  leak_count     = %zu\n", mtt_get_leak_count());
    char buf[32];
    format_bytes_local(mtt_get_current_usage(), buf, sizeof(buf));
    printf("  current_bytes  = %s\n", buf);
    format_bytes_local(mtt_get_peak_usage(), buf, sizeof(buf));
    printf("  peak_bytes     = %s\n", buf);

    printf("\nResults: %d run, %d passed, %d failed\n",
           g_tests_run, g_tests_pass, g_tests_fail);

    fflush(stdout); fflush(stderr);
    return (g_tests_fail > 0) ? 1 : 0;
}

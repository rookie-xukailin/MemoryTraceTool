/*
 * MemoryTraceTool -- 核心追踪逻辑扩展单元测试（30+ 用例）。
 *
 * 覆盖所有公共 API 函数：
 *   - mtt_malloc / mtt_free
 *   - mtt_calloc
 *   - mtt_realloc
 *   - mtt_get_alloc_count / mtt_get_free_count
 *   - mtt_get_leak_count
 *   - mtt_get_current_usage
 *   - mtt_get_peak_usage
 *   - mtt_get_total_allocated
 *
 * 测试维度：基本功能、边界条件、一致性、稳定性。
 */
#include <memorytracetool/memorytracetool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>

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

#define ASSERT(cond, msg) \
    do { \
        if (!(cond)) { FAIL(msg); return; } \
    } while (0)

#define ASSERT_EQ(a, b, msg) \
    do { \
        if ((a) != (b)) { \
            char _buf[128]; \
            snprintf(_buf, sizeof(_buf), "%s (got %zu, expected %zu)", \
                     msg, (size_t)(a), (size_t)(b)); \
            FAIL(_buf); return; \
        } \
    } while (0)

#define ASSERT_GE(a, b, msg) \
    do { \
        if ((a) < (b)) { \
            char _buf[128]; \
            snprintf(_buf, sizeof(_buf), "%s (got %zu, expected >= %zu)", \
                     msg, (size_t)(a), (size_t)(b)); \
            FAIL(_buf); return; \
        } \
    } while (0)

#define ASSERT_PTR_NOT_NULL(p, msg) \
    do { \
        if ((p) == NULL) { FAIL(msg); return; } \
    } while (0)

/* ======================================================================== *
 *                            Test Cases (30+)                                *
 * ======================================================================== */

/** 测试 1: 基本 malloc + free */
static void test_malloc_free(void)
{
    TEST("malloc + free basic");
    size_t before_alloc = mtt_get_alloc_count();
    size_t before_free  = mtt_get_free_count();

    void *p = mtt_malloc(128);
    ASSERT_PTR_NOT_NULL(p, "malloc(128) returned NULL");
    ASSERT_EQ(mtt_get_alloc_count(), before_alloc + 1, "alloc_count not incremented");

    mtt_free(p);
    ASSERT_EQ(mtt_get_free_count(), before_free + 1, "free_count not incremented");
    PASS();
}

/** 测试 2: calloc 零初始化 */
static void test_calloc_zero(void)
{
    TEST("calloc zero init");
    int *p = (int *)mtt_calloc(100, sizeof(int));
    ASSERT_PTR_NOT_NULL(p, "calloc(100,4) returned NULL");

    int all_zero = 1;
    for (int i = 0; i < 100; i++) {
        if (p[i] != 0) { all_zero = 0; break; }
    }
    ASSERT(all_zero, "calloc memory not zero-initialized");
    mtt_free(p);
    PASS();
}

/** 测试 3: calloc 溢出检查 */
static void test_calloc_overflow(void)
{
    TEST("calloc overflow check");
    void *p = mtt_calloc(SIZE_MAX, 2);
    ASSERT(p == NULL, "calloc(SIZE_MAX,2) should return NULL on overflow");
    PASS();
}

/** 测试 4: calloc count=0 边界 */
static void test_calloc_zero_count(void)
{
    TEST("calloc count=0");
    void *p = mtt_calloc(0, 100);
    /* 行为取决于实现：NULL 或有效指针都是合法的 */
    if (p != NULL) mtt_free(p);
    PASS();
}

/** 测试 5: calloc size=0 边界 */
static void test_calloc_zero_size(void)
{
    TEST("calloc size=0");
    void *p = mtt_calloc(100, 0);
    if (p != NULL) mtt_free(p);
    PASS();
}

/** 测试 6: realloc(NULL, N) -> 等同于 malloc */
static void test_realloc_null(void)
{
    TEST("realloc(NULL, N)");
    size_t before_alloc = mtt_get_alloc_count();
    void *p = mtt_realloc(NULL, 256);
    ASSERT_PTR_NOT_NULL(p, "realloc(NULL,256) returned NULL");
    ASSERT_EQ(mtt_get_alloc_count(), before_alloc + 1,
              "alloc_count not incremented for realloc(NULL)");
    mtt_free(p);
    PASS();
}

/** 测试 7: realloc(ptr, 0) -> 等同于 free */
static void test_realloc_zero(void)
{
    TEST("realloc(ptr, 0)");
    void *p = mtt_malloc(128);
    ASSERT_PTR_NOT_NULL(p, "malloc(128) returned NULL");

    size_t before_free = mtt_get_free_count();
    void *r = mtt_realloc(p, 0);
    ASSERT(r == NULL, "realloc(ptr,0) should return NULL");
    ASSERT_EQ(mtt_get_free_count(), before_free + 1,
              "free_count not incremented for realloc(ptr,0)");
    PASS();
}

/** 测试 8: realloc 扩大 + 数据保留 */
static void test_realloc_grow(void)
{
    TEST("realloc grow + data preserved");
    char *p = (char *)mtt_malloc(64);
    ASSERT_PTR_NOT_NULL(p, "malloc(64) returned NULL");
    memset(p, 0xAB, 64);

    char *new_p = (char *)mtt_realloc(p, 256);
    ASSERT_PTR_NOT_NULL(new_p, "realloc grow returned NULL");

    int preserved = 1;
    for (int i = 0; i < 64; i++) {
        if (new_p[i] != (char)0xAB) { preserved = 0; break; }
    }
    ASSERT(preserved, "realloc grow: original data not preserved");
    mtt_free(new_p);
    PASS();
}

/** 测试 9: realloc 缩小 + 数据保留 */
static void test_realloc_shrink(void)
{
    TEST("realloc shrink + data preserved");
    char *p = (char *)mtt_malloc(256);
    ASSERT_PTR_NOT_NULL(p, "malloc(256) returned NULL");
    memset(p, 0xCD, 256);

    char *new_p = (char *)mtt_realloc(p, 64);
    ASSERT_PTR_NOT_NULL(new_p, "realloc shrink returned NULL");

    /* 前 64 字节应保持 */
    int preserved = 1;
    for (int i = 0; i < 64; i++) {
        if (new_p[i] != (char)0xCD) { preserved = 0; break; }
    }
    ASSERT(preserved, "realloc shrink: data not preserved");
    mtt_free(new_p);
    PASS();
}

/** 测试 10: realloc 相同大小 */
static void test_realloc_same_size(void)
{
    TEST("realloc same size");
    void *p = mtt_malloc(512);
    ASSERT_PTR_NOT_NULL(p, "malloc(512) returned NULL");

    size_t before_alloc = mtt_get_alloc_count();
    void *r = mtt_realloc(p, 512);
    ASSERT_PTR_NOT_NULL(r, "realloc(512->512) returned NULL");
    /* realloc 相同大小可能导致 alloc+free 各+1，或指针直接返回 */
    size_t after_alloc = mtt_get_alloc_count();
    ASSERT(after_alloc >= before_alloc,
           "alloc_count should not decrease for same-size realloc");
    mtt_free(r);
    PASS();
}

/** 测试 11: 多次 realloc 循环 */
static void test_realloc_cycle(void)
{
    TEST("realloc cycle: 64->128->256->128->64");
    void *p = mtt_malloc(64);
    ASSERT_PTR_NOT_NULL(p, "initial malloc(64) failed");

    for (int i = 0; i < 3; i++) {
        void *r = mtt_realloc(p, 128);
        ASSERT_PTR_NOT_NULL(r, "realloc to 128 failed");
        p = r;

        r = mtt_realloc(p, 256);
        ASSERT_PTR_NOT_NULL(r, "realloc to 256 failed");
        p = r;

        r = mtt_realloc(p, 128);
        ASSERT_PTR_NOT_NULL(r, "realloc to 128 failed");
        p = r;

        r = mtt_realloc(p, 64);
        ASSERT_PTR_NOT_NULL(r, "realloc to 64 failed");
        p = r;
    }

    mtt_free(p);
    PASS();
}

/** 测试 12: 大块分配（多 MB，测试边界） */
static void test_malloc_large(void)
{
    TEST("malloc large block (4 MB)");
    void *p = mtt_malloc(4 * 1024 * 1024);
    ASSERT_PTR_NOT_NULL(p, "malloc(4MB) returned NULL");
    mtt_free(p);
    PASS();
}

/** 测试 13: 分配大小 1 字节 */
static void test_malloc_tiny(void)
{
    TEST("malloc tiny (1 byte)");
    void *p = mtt_malloc(1);
    ASSERT_PTR_NOT_NULL(p, "malloc(1) returned NULL");
    /* 写入不崩溃 */
    *(char *)p = 'X';
    mtt_free(p);
    PASS();
}

/** 测试 14: 分配大小 SIZE_MAX（预期失败） */
static void test_malloc_huge(void)
{
    TEST("malloc(SIZE_MAX) -> expect NULL or crash-safe");
    void *p = mtt_malloc(SIZE_MAX);
    if (p != NULL) {
        /* 虽然不太可能，但若成功则释放 */
        mtt_free(p);
    }
    PASS();
}

/** 测试 15: free(NULL) 不崩溃 */
static void test_free_null(void)
{
    TEST("free(NULL) twice");
    mtt_free(NULL);
    mtt_free(NULL);  /* 两次都不应崩溃 */
    PASS();
}

/** 测试 16: malloc(0) */
static void test_malloc_zero(void)
{
    TEST("malloc(0)");
    void *p = mtt_malloc(0);
    /* malloc(0) 返回非 NULL 是合法行为 */
    if (p != NULL) mtt_free(p);
    PASS();
}

/** 测试 17: 多块分配 + 部分释放（泄漏检测） */
static void test_leak_detection(void)
{
    TEST("leak detection (10 allocs, 3 leaks)");
    size_t before_alloc = mtt_get_alloc_count();
    size_t before_free  = mtt_get_free_count();

    void *ptrs[10];
    for (int i = 0; i < 10; i++) {
        ptrs[i] = mtt_malloc(256);
        ASSERT_PTR_NOT_NULL(ptrs[i], "malloc(256) failed");
    }
    ASSERT_EQ(mtt_get_alloc_count(), before_alloc + 10, "alloc_count should be +10");

    for (int i = 0; i < 7; i++) {
        mtt_free(ptrs[i]);
    }
    ASSERT_EQ(mtt_get_free_count(), before_free + 7, "free_count should be +7");
    ASSERT_GE(mtt_get_leak_count(), 3, "leak_count should be at least 3");

    for (int i = 7; i < 10; i++) {
        mtt_free(ptrs[i]);
    }
    ASSERT(mtt_get_leak_count() <= (size_t)2,
           "leak_count should be near 0 after all freed");
    PASS();
}

/** 测试 18: leak_count 在所有块释放后应接近 0 */
static void test_leak_zero_after_cleanup(void)
{
    TEST("leak_count zero after all freed (100 blocks)");
    size_t before_leak = mtt_get_leak_count();

    void *ptrs[100];
    for (int i = 0; i < 100; i++) {
        ptrs[i] = mtt_malloc(128);
        ASSERT_PTR_NOT_NULL(ptrs[i], "malloc(128) failed");
    }

    for (int i = 0; i < 100; i++) {
        mtt_free(ptrs[i]);
    }

    size_t after_leak = mtt_get_leak_count();
    /* 库内部可能有少量自身分配，允许 <=5 的余量 */
    ASSERT(after_leak <= before_leak + 5,
           "leak_count should return near baseline after 100 free");
    PASS();
}

/** 测试 19: current_bytes 跟踪 */
static void test_current_bytes(void)
{
    TEST("current_bytes tracking");
    size_t before = mtt_get_current_usage();

    void *p1 = mtt_malloc(512);
    void *p2 = mtt_malloc(1024);
    void *p3 = mtt_malloc(2048);
    ASSERT_PTR_NOT_NULL(p1, "malloc(512) failed");
    ASSERT_PTR_NOT_NULL(p2, "malloc(1024) failed");
    ASSERT_PTR_NOT_NULL(p3, "malloc(2048) failed");

    size_t cur = mtt_get_current_usage();
    ASSERT_GE(cur, before + 512 + 1024 + 2048,
              "current_bytes should reflect active allocations");

    mtt_free(p1);
    mtt_free(p2);
    mtt_free(p3);

    size_t after = mtt_get_current_usage();
    ASSERT(after <= before + 512,
           "current_bytes should return near baseline after all freed");
    PASS();
}

/** 测试 20: current_bytes 随 free 递减 */
static void test_current_bytes_decreases(void)
{
    TEST("current_bytes decreases after free");
    size_t before = mtt_get_current_usage();

    void *p = mtt_malloc(8192);
    ASSERT_PTR_NOT_NULL(p, "malloc(8192) failed");
    size_t after_alloc = mtt_get_current_usage();
    ASSERT_GE(after_alloc, before + 8192, "current_bytes should increase after alloc");

    mtt_free(p);
    size_t after_free = mtt_get_current_usage();
    ASSERT(after_free < after_alloc, "current_bytes should decrease after free");
    PASS();
}

/** 测试 21: peak_bytes 跟踪 */
static void test_peak_bytes(void)
{
    TEST("peak_bytes tracking");
    size_t before = mtt_get_peak_usage();

    void *p1 = mtt_malloc(4096);
    void *p2 = mtt_malloc(4096);
    void *p3 = mtt_malloc(4096);
    ASSERT_PTR_NOT_NULL(p1, "p1 failed");
    ASSERT_PTR_NOT_NULL(p2, "p2 failed");
    ASSERT_PTR_NOT_NULL(p3, "p3 failed");

    size_t peak = mtt_get_peak_usage();
    ASSERT_GE(peak, before + 3 * 4096, "peak_bytes should be >= before+12KB");

    mtt_free(p1);
    mtt_free(p2);
    mtt_free(p3);
    PASS();
}

/** 测试 22: peak_bytes 不因 free 而减少 */
static void test_peak_bytes_persists(void)
{
    TEST("peak_bytes persists after free");
    void *p1 = mtt_malloc(10000);
    void *p2 = mtt_malloc(20000);
    ASSERT_PTR_NOT_NULL(p1, "p1 failed");
    ASSERT_PTR_NOT_NULL(p2, "p2 failed");

    size_t peak_alloc = mtt_get_peak_usage();

    mtt_free(p1);
    mtt_free(p2);

    size_t peak_after_free = mtt_get_peak_usage();
    ASSERT_GE(peak_after_free, peak_alloc,
              "peak_bytes should not decrease after freeing");
    PASS();
}

/** 测试 23: total_allocated 累计 + 单调递增 */
static void test_total_allocated(void)
{
    TEST("total_allocated monotonic");
    size_t t1 = mtt_get_total_allocated();

    void *p = mtt_malloc(1024);
    ASSERT_PTR_NOT_NULL(p, "malloc(1024) failed");

    size_t t2 = mtt_get_total_allocated();
    ASSERT_GE(t2, t1 + 1024, "total_allocated should increase by at least 1024");

    mtt_free(p);

    /* total_allocated 不因 free 而减少（累计值） */
    size_t t3 = mtt_get_total_allocated();
    ASSERT_GE(t3, t2, "total_allocated should not decrease after free");
    PASS();
}

/** 测试 24: total_allocated 多轮累积 */
static void test_total_allocated_multi(void)
{
    TEST("total_allocated multi-round accumulation");
    size_t t1 = mtt_get_total_allocated();
    size_t expected = t1;

    for (int i = 0; i < 50; i++) {
        void *p = mtt_malloc(256);
        ASSERT_PTR_NOT_NULL(p, "malloc(256) failed");
        expected += 256;
        mtt_free(p);
    }

    size_t t2 = mtt_get_total_allocated();
    ASSERT_GE(t2, expected, "total_allocated should accumulate across rounds");
    PASS();
}

/** 测试 25: alloc_count == free_count 在平衡操作后 */
static void test_balanced_alloc_free(void)
{
    TEST("alloc_count == free_count after balanced ops");
    size_t start_alloc = mtt_get_alloc_count();
    size_t start_free  = mtt_get_free_count();
    size_t start_diff  = start_alloc - start_free;

    void *ptrs[20];
    for (int i = 0; i < 20; i++) {
        ptrs[i] = mtt_malloc(512);
        ASSERT_PTR_NOT_NULL(ptrs[i], "malloc(512) failed");
    }

    for (int i = 0; i < 20; i++) {
        mtt_free(ptrs[i]);
    }

    size_t end_diff = mtt_get_alloc_count() - mtt_get_free_count();
    ASSERT(end_diff <= start_diff + 2,
           "alloc-free diff should return near baseline after balanced ops");
    PASS();
}

/** 测试 26: 交替分配和释放的一致性 */
static void test_interleaved_alloc_free(void)
{
    TEST("interleaved alloc and free consistency");
    size_t start_alloc = mtt_get_alloc_count();
    size_t start_free  = mtt_get_free_count();

    for (int round = 0; round < 5; round++) {
        void *p1 = mtt_malloc(256);
        ASSERT_PTR_NOT_NULL(p1, "malloc(256) failed");

        void *p2 = mtt_malloc(512);
        ASSERT_PTR_NOT_NULL(p2, "malloc(512) failed");

        mtt_free(p1);

        void *p3 = mtt_malloc(128);
        ASSERT_PTR_NOT_NULL(p3, "malloc(128) failed");

        mtt_free(p2);
        mtt_free(p3);
    }

    size_t end_diff = mtt_get_alloc_count() - mtt_get_free_count();
    ASSERT_GE(end_diff, start_alloc - start_free,
              "alloc-free diff should be consistent after interleaved ops");
    PASS();
}

/** 测试 27: alloc_count 单调递增 */
static void test_alloc_count_monotonic(void)
{
    TEST("alloc_count monotonic increase");
    size_t a1 = mtt_get_alloc_count();
    void *p = mtt_malloc(100);
    ASSERT_PTR_NOT_NULL(p, "malloc(100) failed");
    size_t a2 = mtt_get_alloc_count();
    ASSERT(a2 > a1, "alloc_count should increase");
    mtt_free(p);
    PASS();
}

/** 测试 28: free_count 单调递增 */
static void test_free_count_monotonic(void)
{
    TEST("free_count monotonic increase");
    size_t f1 = mtt_get_free_count();
    void *p = mtt_malloc(100);
    ASSERT_PTR_NOT_NULL(p, "malloc(100) failed");
    mtt_free(p);
    size_t f2 = mtt_get_free_count();
    ASSERT(f2 > f1, "free_count should increase after free");
    PASS();
}

/** 测试 29: alloc_count >= free_count 恒成立 */
static void test_alloc_ge_free(void)
{
    TEST("alloc_count >= free_count always");
    size_t allocs = mtt_get_alloc_count();
    size_t frees  = mtt_get_free_count();
    ASSERT(allocs >= frees, "alloc_count should always be >= free_count");
    PASS();
}

/** 测试 30: 压力测试 -- 500 次分配/释放 */
static void test_stress_alloc_free(void)
{
    TEST("stress: 500 alloc+free in sequence");
    size_t before_leak = mtt_get_leak_count();

    for (int i = 0; i < 500; i++) {
        void *p = mtt_malloc((size_t)((i % 100) + 1) * 64);
        if (p == NULL) {
            /* 分配失败：停止但不算测试失败（资源压力下预期行为） */
            break;
        }
        mtt_free(p);
    }

    size_t after_leak = mtt_get_leak_count();
    ASSERT(after_leak <= before_leak + 10,
           "leak_count should stay near baseline after 500 alloc+free");
    PASS();
}

/** 测试 31: realloc 后原始指针可能变化 */
static void test_realloc_ptr_may_change(void)
{
    TEST("realloc may change pointer");
    void *p1 = mtt_malloc(32);
    ASSERT_PTR_NOT_NULL(p1, "malloc(32) failed");
    memset(p1, 0xEE, 32);

    size_t before = mtt_get_alloc_count();
    void *p2 = mtt_realloc(p1, 65536);
    ASSERT_PTR_NOT_NULL(p2, "realloc to 64K failed");
    /* p2 可能等于 p1 也可能不等，两种都合法 */
    /* 但成功 realloc 后 p1 不再有效 */
    (void)before;
    mtt_free(p2);
    PASS();
}

/** 测试 32: calloc 后 access 不崩溃 */
static void test_calloc_writable(void)
{
    TEST("calloc memory writable");
    size_t sz = 1024;
    char *p = (char *)mtt_calloc(1, sz);
    ASSERT_PTR_NOT_NULL(p, "calloc(1,1024) failed");
    memset(p, 0xAA, sz); /* 必须不崩溃 */
    for (size_t i = 0; i < sz; i++) {
        if ((unsigned char)p[i] != 0xAA) {
            FAIL("calloc memory not writable");
            mtt_free(p);
            return;
        }
    }
    mtt_free(p);
    PASS();
}

/** 测试 33: 多次 realloc 在不同大小之间切换 */
static void test_realloc_alternating(void)
{
    TEST("realloc alternating sizes");
    void *p = mtt_malloc(64);
    ASSERT_PTR_NOT_NULL(p, "initial malloc(64) failed");

    for (int i = 0; i < 10; i++) {
        void *r = mtt_realloc(p, (i % 2 == 0) ? 1024 : 512);
        ASSERT_PTR_NOT_NULL(r, "alternating realloc failed");
        p = r;
    }
    mtt_free(p);
    PASS();
}

/** 测试 34: 所有统计查询返回合理值 */
static void test_all_stats_queries(void)
{
    TEST("all stats queries return valid values");
    size_t a = mtt_get_alloc_count();
    size_t f = mtt_get_free_count();
    size_t l = mtt_get_leak_count();
    size_t c = mtt_get_current_usage();
    size_t p = mtt_get_peak_usage();
    size_t t = mtt_get_total_allocated();
    (void)a; (void)f; (void)l; (void)c; (void)p; (void)t;
    /* 所有查询都应返回而不崩溃 */
    PASS();
}

/** 测试 35: 混合 calloc + malloc + realloc */
static void test_mixed_allocators(void)
{
    TEST("mixed calloc+malloc+realloc sequence");
    void *p1 = mtt_calloc(10, sizeof(int));
    ASSERT_PTR_NOT_NULL(p1, "calloc(10, sizeof(int)) failed");
    ((int *)p1)[0] = 42;

    void *p2 = mtt_malloc(512);
    ASSERT_PTR_NOT_NULL(p2, "malloc(512) failed");
    memset(p2, 0, 512);

    void *p3 = mtt_realloc(p1, 2048);
    ASSERT_PTR_NOT_NULL(p3, "realloc(p1,2048) failed");
    /* calloc 初始化的数据应保留 */
    ASSERT(((int *)p3)[0] == 42, "realloc after calloc: data not preserved");

    mtt_free(p3);
    mtt_free(p2);
    PASS();
}

/** 测试 36: 统计一致性：leak_count = alloc_count - free_count（不考虑内部分配） */
static void test_leak_count_formula(void)
{
    TEST("leak_count formula consistency");
    size_t a = mtt_get_alloc_count();
    size_t f = mtt_get_free_count();
    size_t l = mtt_get_leak_count();
    ASSERT_GE(l, a - f, "leak_count should be approximately alloc_count - free_count");
    PASS();
}

/* ======================================================================== *
 *                            Test Runner                                      *
 * ======================================================================== */

int main(void)
{
    printf("=== MemoryTraceTool Extended Unit Tests (36 cases) ===\n\n");

    /* Phase 1: malloc/free 基本功能 */
    test_malloc_free();
    test_malloc_zero();
    test_malloc_tiny();
    test_malloc_large();
    test_malloc_huge();
    test_free_null();

    /* Phase 2: calloc 功能 */
    test_calloc_zero();
    test_calloc_overflow();
    test_calloc_zero_count();
    test_calloc_zero_size();
    test_calloc_writable();

    /* Phase 3: realloc 功能 */
    test_realloc_null();
    test_realloc_zero();
    test_realloc_grow();
    test_realloc_shrink();
    test_realloc_same_size();
    test_realloc_cycle();
    test_realloc_ptr_may_change();
    test_realloc_alternating();

    /* Phase 4: 泄漏检测 */
    test_leak_detection();
    test_leak_zero_after_cleanup();
    test_leak_count_formula();

    /* Phase 5: 统计计数器 */
    test_current_bytes();
    test_current_bytes_decreases();
    test_peak_bytes();
    test_peak_bytes_persists();
    test_total_allocated();
    test_total_allocated_multi();
    test_alloc_count_monotonic();
    test_free_count_monotonic();
    test_alloc_ge_free();

    /* Phase 6: 一致性 / 压力 / 混合 */
    test_balanced_alloc_free();
    test_interleaved_alloc_free();
    test_all_stats_queries();
    test_mixed_allocators();
    test_stress_alloc_free();

    printf("\n---\n");
    printf("Results: %d run, %d passed, %d failed\n",
           g_tests_run, g_tests_pass, g_tests_fail);

    fflush(stdout);
    fflush(stderr);
    return (g_tests_fail > 0) ? 1 : 0;
}

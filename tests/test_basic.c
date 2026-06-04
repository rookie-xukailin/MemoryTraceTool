/*
 * MemoryTraceTool — 核心追踪逻辑单元测试。
 *
 * 测试 mtt_malloc/mtt_free/mtt_calloc/mtt_realloc 及统计计数器。
 * 不依赖测试框架，使用断言宏，断言失败时输出行号并退出。
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

#define ASSERT_PTR_NOT_NULL(p, msg) \
    do { \
        if ((p) == NULL) { FAIL(msg); return; } \
    } while (0)

/* ---- 测试用例 ---- */

/** 测试 1: 基本 malloc + free */
static void test_malloc_free(void)
{
    TEST("malloc + free");
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

/** 测试 4: realloc(NULL) → malloc */
static void test_realloc_null(void)
{
    TEST("realloc(NULL, N)");

    size_t before_alloc = mtt_get_alloc_count();
    void *p = mtt_realloc(NULL, 256);
    ASSERT_PTR_NOT_NULL(p, "realloc(NULL,256) returned NULL");
    ASSERT_EQ(mtt_get_alloc_count(), before_alloc + 1, "alloc_count not incremented for realloc(NULL)");

    mtt_free(p);
    PASS();
}

/** 测试 5: realloc(ptr, 0) → free */
static void test_realloc_zero(void)
{
    TEST("realloc(ptr, 0)");

    void *p = mtt_malloc(128);
    ASSERT_PTR_NOT_NULL(p, "malloc(128) returned NULL");

    size_t before_free = mtt_get_free_count();
    void *r = mtt_realloc(p, 0);
    ASSERT(r == NULL, "realloc(ptr,0) should return NULL");
    ASSERT_EQ(mtt_get_free_count(), before_free + 1, "free_count not incremented for realloc(ptr,0)");
    PASS();
}

/** 测试 6: realloc 扩大 */
static void test_realloc_grow(void)
{
    TEST("realloc grow");

    char *p = (char *)mtt_malloc(64);
    ASSERT_PTR_NOT_NULL(p, "malloc(64) returned NULL");
    memset(p, 0xAB, 64);

    char *new_p = (char *)mtt_realloc(p, 256);
    ASSERT_PTR_NOT_NULL(new_p, "realloc grow returned NULL");

    /* 前 64 字节应保持不变 */
    int preserved = 1;
    for (int i = 0; i < 64; i++) {
        if (new_p[i] != (char)0xAB) { preserved = 0; break; }
    }
    ASSERT(preserved, "realloc grow: original data not preserved");

    mtt_free(new_p);
    PASS();
}

/** 测试 7: 多块分配 + 部分释放（泄漏计数） */
static void test_leak_detection(void)
{
    TEST("leak detection");

    size_t before_alloc = mtt_get_alloc_count();
    size_t before_free  = mtt_get_free_count();

    /* 分配 10 块 */
    void *ptrs[10];
    for (int i = 0; i < 10; i++) {
        ptrs[i] = mtt_malloc(256);
        ASSERT_PTR_NOT_NULL(ptrs[i], "malloc(256) failed");
    }
    ASSERT_EQ(mtt_get_alloc_count(), before_alloc + 10, "alloc_count should be +10");

    /* 释放前 7 块，泄漏 3 块 */
    for (int i = 0; i < 7; i++) {
        mtt_free(ptrs[i]);
    }
    ASSERT_EQ(mtt_get_free_count(), before_free + 7, "free_count should be +7");
    /* 库内部可能有少量自身分配，所以用 >= */
    ASSERT(mtt_get_leak_count() >= (size_t)3, "leak_count should be at least 3");

    /* 释放剩余 3 块 */
    for (int i = 7; i < 10; i++) {
        mtt_free(ptrs[i]);
    }
    /* 库内部有少量自身分配，允许 <= 2 的余量 */
    ASSERT(mtt_get_leak_count() <= (size_t)2, "leak_count should be near 0 after all freed");
    PASS();
}

/** 测试 8: current_bytes 跟踪 */
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

    /* 当前活跃应至少增加 512+1024+2048（不考虑内部开销） */
    size_t cur = mtt_get_current_usage();
    ASSERT(cur >= before + 512 + 1024 + 2048,
           "current_bytes should reflect active allocations");

    mtt_free(p1);
    mtt_free(p2);
    mtt_free(p3);

    size_t after = mtt_get_current_usage();
    ASSERT(after <= before + 256, /* 容忍内部追踪开销 */
           "current_bytes should return near baseline after all freed");
    PASS();
}

/** 测试 9: peak_bytes 更新 */
static void test_peak_bytes(void)
{
    TEST("peak_bytes tracking");

    size_t cur_before = mtt_get_current_usage();

    /* 分配 3 块，观察峰值 */
    void *p1 = mtt_malloc(4096);
    void *p2 = mtt_malloc(4096);
    void *p3 = mtt_malloc(4096);
    ASSERT_PTR_NOT_NULL(p1, "malloc(4096) p1 failed");
    ASSERT_PTR_NOT_NULL(p2, "malloc(4096) p2 failed");
    ASSERT_PTR_NOT_NULL(p3, "malloc(4096) p3 failed");

    size_t peak = mtt_get_peak_usage();
    ASSERT(peak >= cur_before + 3 * 4096,
           "peak_bytes should be at least cur+12KB");

    mtt_free(p1);
    mtt_free(p2);
    mtt_free(p3);
    PASS();
}

/** 测试 10: mtt_free(NULL) 不崩溃 */
static void test_free_null(void)
{
    TEST("free(NULL)");

    mtt_free(NULL);  /* 必须不崩溃 */
    PASS();
}

/** 测试 11: mtt_malloc(0) */
static void test_malloc_zero(void)
{
    TEST("malloc(0)");

    void *p = mtt_malloc(0);
    /* malloc(0) 返回非 NULL 是合法行为（实现定义） */
    if (p != NULL) mtt_free(p);
    PASS();
}

/** 测试 12: total_allocated 单调递增 */
static void test_total_allocated(void)
{
    TEST("total_allocated monotonic");

    size_t t1 = mtt_get_total_allocated();

    void *p = mtt_malloc(1024);
    ASSERT_PTR_NOT_NULL(p, "malloc(1024) failed");

    size_t t2 = mtt_get_total_allocated();
    ASSERT(t2 >= t1 + 1024, "total_allocated should increase by at least 1024");

    mtt_free(p);

    /* total_allocated 不因 free 而减少（累计值） */
    size_t t3 = mtt_get_total_allocated();
    ASSERT(t3 >= t2, "total_allocated should not decrease after free");
    PASS();
}

/* ---- 测试运行器 ---- */

int main(void)
{
    printf("=== MemoryTraceTool Unit Tests ===\n\n");

    test_malloc_free();
    test_calloc_zero();
    test_calloc_overflow();
    test_realloc_null();
    test_realloc_zero();
    test_realloc_grow();
    test_leak_detection();
    test_current_bytes();
    test_peak_bytes();
    test_free_null();
    test_malloc_zero();
    test_total_allocated();

    printf("\n---\n");
    printf("Results: %d run, %d passed, %d failed\n",
           g_tests_run, g_tests_pass, g_tests_fail);

    fflush(stdout);
    fflush(stderr);
    return (g_tests_fail > 0) ? 1 : 0;
}

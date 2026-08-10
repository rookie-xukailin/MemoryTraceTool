/*
 * MemoryTraceTool -- 库地址范围黑名单测试(MTT_LIB_BLACKLIST_FAST)
 *
 * 验证黑名单机制的正确性:
 *   T1: 默认未启用(g_blacklist_fast_enabled=0)
 *   T2: mtt_is_lr_in_blacklist 防御性测试
 *   T3: 环境变量已设时,g_blacklist_fast_enabled=1 + range_count > 0
 *   T4: 业务函数地址不在黑名单(即使在黑名单启用时)
 *
 * 启动方式:
 *   ./test_blacklist_fast                            # 默认(T1/T2/T4)
 *   MTT_LIB_BLACKLIST_FAST=libc ./test_blacklist_fast # 启用黑名单(T3)
 */
#include <memorytracetool/memorytracetool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>

#include "mtt_internal.h"

static int g_tests_run  = 0;
static int g_tests_pass = 0;
static int g_tests_fail = 0;

#define TEST(name) do { g_tests_run++; printf("  %-50s ", name); fflush(stdout); } while (0)
#define PASS()     do { g_tests_pass++; printf("PASS\n"); } while (0)
#define FAIL(msg)  do { g_tests_fail++; printf("FAIL: %s\n", msg); } while (0)
#define ASSERT(cond, msg) do { if (!(cond)) { FAIL(msg); return; } } while (0)
#define ASSERT_EQ(a, b, msg) \
    do { \
        if ((a) != (b)) { \
            char _buf[160]; \
            snprintf(_buf, sizeof(_buf), "%s (got %d, expected %d)", \
                     msg, (int)(a), (int)(b)); \
            FAIL(_buf); return; \
        } \
    } while (0)

/* T1: 默认未启用(测试启动时未设 MTT_LIB_BLACKLIST_FAST) */
static void test_blacklist_disabled_by_default(void) {
    TEST("T1 blacklist_disabled_by_default");
    if (getenv("MTT_LIB_BLACKLIST_FAST") == NULL) {
        ASSERT_EQ(g_blacklist_fast_enabled, 0, "default should be disabled");
    } else {
        printf("(env set, skip) ");
    }
    PASS();
}

/* T2: mtt_is_lr_in_blacklist 防御性测试 */
static void test_blacklist_null_lr(void) {
    TEST("T2 blacklist_null_lr_returns_0");
    int r = mtt_is_lr_in_blacklist(NULL);
    ASSERT_EQ(r, 0, "NULL lr should return 0");
    PASS();
}

/* T3: 环境变量已设时,验证解析成功(关键) */
static void test_blacklist_parse_libc(void) {
    TEST("T3 blacklist_parse_libc (env-driven)");
    const char *env = getenv("MTT_LIB_BLACKLIST_FAST");
    if (env == NULL) {
        printf("(no env, skip) ");
        PASS();
        return;
    }
    /* 环境变量已设,验证 g_blacklist_fast_enabled + range_count */
    ASSERT_EQ(g_blacklist_fast_enabled, 1, "should be enabled when env set");
    ASSERT(g_blacklist_range_count > 0, "should have ranges (libc loaded)");
    printf("(env=%s ranges=%d) ", env, g_blacklist_range_count);
    PASS();
}

/* T4: 业务函数地址不在黑名单 */
static void test_business_func_not_in_blacklist(void) {
    TEST("T4 business_func_not_in_blacklist");
    void *business_lr = (void*)&test_business_func_not_in_blacklist;
    int r = mtt_is_lr_in_blacklist(business_lr);
    ASSERT_EQ(r, 0, "business function should not be in blacklist");
    PASS();
}

int main(void) {
    printf("=== MemoryTraceTool MTT_LIB_BLACKLIST_FAST Tests ===\n\n");
    printf("  g_blacklist_fast_enabled = %d (start)\n", g_blacklist_fast_enabled);
    printf("  MTT_LIB_BLACKLIST_FAST   = %s\n\n",
           getenv("MTT_LIB_BLACKLIST_FAST") ? getenv("MTT_LIB_BLACKLIST_FAST") : "(not set)");

    test_blacklist_disabled_by_default();
    test_blacklist_null_lr();
    test_blacklist_parse_libc();
    test_business_func_not_in_blacklist();

    printf("\n--- Results: %d run, %d passed, %d failed ---\n",
           g_tests_run, g_tests_pass, g_tests_fail);

    return g_tests_fail == 0 ? 0 : 1;
}

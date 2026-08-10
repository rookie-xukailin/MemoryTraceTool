/*
 * MemoryTraceTool -- sigaction 一次性安装验证测试
 *
 * 验证方向 1(sigaction 一次性安装)的正确性:
 *   T1: init 后 SIGSEGV handler 已装好
 *   T2: SIGSEGV 在 unwind 范围内被拦截 + siglongjmp 跳回(commit 839821a 核心保护回归)
 *   T3: 多线程并发 capture 不互相干扰(mutex 串行化未破坏)
 *   T4: 正常栈抓取仍工作(libunwind_capture 返回 >= 1 帧)
 *
 * 设计要点:
 *   - 只测核心不变量(handler 装好、SIGSEGV 拦截、capture 正常)
 *   - 不动 TLS / 不动并发模型,行为应与改造前完全等价
 */
#include <memorytracetool/memorytracetool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>

#include "unwind_libunwind.h"

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
            snprintf(_buf, sizeof(_buf), "%s (got %zu, expected %zu)", \
                     msg, (size_t)(a), (size_t)(b)); \
            FAIL(_buf); return; \
        } \
    } while (0)
#define ASSERT_GE(a, b, msg) \
    do { \
        if ((a) < (b)) { \
            char _buf[160]; \
            snprintf(_buf, sizeof(_buf), "%s (got %zu, expected >= %zu)", \
                     msg, (size_t)(a), (size_t)(b)); \
            FAIL(_buf); return; \
        } \
    } while (0)

#ifndef SIGSEGV
#define SIGSEGV 11
#endif

/* ---- T1: init 后 SIGSEGV handler 已装 ---- */

static void test_handler_installed_at_init(void) {
    TEST("T1 handler_installed_at_init");
    ASSERT(mtt_test_segv_handler_is_mtt(), "SIGSEGV handler should be mtt's after init");
    PASS();
}

/* ---- T2: SIGSEGV 在 unwind 范围内被拦截 + siglongjmp 跳回 ---- */

static void test_sigsegv_in_unwind_intercepted(void) {
    TEST("T2 sigsegv_in_unwind_intercepted (commit 839821a)");
    int sig = mtt_test_trigger_sigsegv_in_unwind();
    ASSERT_EQ(sig, SIGSEGV, "should catch SIGSEGV and return signal number");
    PASS();
}

/* ---- T3: 多线程并发 capture 不互相干扰 ---- */

static void* concurrent_capture_thread(void *arg) {
    void **frames = (void**)arg;
    int local_count = 0;
    /* 每 100 次 capture 期间,可能其他线程也在 capture,
     * mutex 串行化保证全局 g_unwind_jmp 不会被覆盖 */
    for (int i = 0; i < 1000; i++) {
        int n = mtt_libunwind_capture(frames, 8);
        if (n >= 0) local_count++;
    }
    return (void*)(long)local_count;
}

static void test_multi_thread_capture_safe(void) {
    TEST("T3 multi_thread_capture_safe (4 threads x 1k)");
    const int N = 4;
    pthread_t threads[N];
    void *frames[N][8];
    for (int i = 0; i < N; i++)
        pthread_create(&threads[i], NULL, concurrent_capture_thread, frames[i]);
    int total_ok = 0;
    for (int i = 0; i < N; i++) {
        void *ret;
        pthread_join(threads[i], &ret);
        total_ok += (int)(long)ret;
    }
    /* 4 线程 × 1000 次 = 4000 次 capture,正常应全部成功 */
    ASSERT_GE(total_ok, (int)(N * 1000 * 0.9), "at least 90% captures should succeed");
    PASS();
}

/* ---- T4: 正常栈抓取仍工作 ---- */

static void test_unwind_capture_normal_works(void) {
    TEST("T4 unwind_capture_normal_works");
    void *frames[8] = {0};
    int n = mtt_libunwind_capture(frames, 8);
    ASSERT_GE(n, 1, "should capture at least 1 frame");
    PASS();
}

/* ---- 主入口 ---- */

int main(void) {
    printf("=== MemoryTraceTool sigaction-Install Tests (方向 1) ===\n\n");
    printf("  mtt handler installed = %d\n\n", mtt_test_segv_handler_is_mtt());

    test_handler_installed_at_init();
    test_sigsegv_in_unwind_intercepted();
    test_multi_thread_capture_safe();
    test_unwind_capture_normal_works();

    printf("\n--- Results: %d run, %d passed, %d failed ---\n",
           g_tests_run, g_tests_pass, g_tests_fail);

    return g_tests_fail == 0 ? 0 : 1;
}

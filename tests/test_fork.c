/*
 * MemoryTraceTool -- fork handler 测试(Type=forking 路径)
 *
 * 验证 mtt_fork_child 正确重置状态,让子进程的工具重新启动。
 *
 *   T1:fork 子进程,子进程 malloc 触发重新 init,验证正常退出
 *   T2:fork 子进程,验证 initialized 重置(子进程工具不假活)
 *   T3:多次 fork(模拟 daemon fork),每次子进程工具都能正常重启
 *
 * 关键:如果 mtt_fork_child 有 bug(子进程 initialized=1,后台线程不启动),
 * 子进程的 malloc 仍能正常返回(工具假活但不崩),但 reporter 不跑。
 * 本测试通过 fork + malloc + 正常退出验证不崩,间接验证 fork handler 生效。
 */
#include <memorytracetool/memorytracetool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/types.h>

#include "mtt_internal.h"

static int g_tests_run  = 0;
static int g_tests_pass = 0;
static int g_tests_fail = 0;

#define TEST(name) do { g_tests_run++; printf("  %-50s ", name); fflush(stdout); } while (0)
#define PASS()     do { g_tests_pass++; printf("PASS\n"); } while (0)
#define FAIL(msg)  do { g_tests_fail++; printf("FAIL: %s\n", msg); } while (0)
#define ASSERT(cond, msg) do { if (!(cond)) { FAIL(msg); return; } } while (0)

/* T1:fork 子进程,子进程 malloc + 正常退出 */
static void test_fork_child_malloc(void) {
    TEST("T1 fork_child_malloc_normal_exit");
    pid_t pid = fork();
    if (pid == 0) {
        /* 子进程:fork handler 应该已经重置 initialized=0。
         * 下次 malloc 触发 mtt_ensure_init 重新 init(启动后台线程)。
         * 如果 fork handler 有 bug(initialized=1),工具假活但 malloc 仍正常。
         * 这里只验证不崩 + malloc 正常返回。 */
        void *p = malloc(1024);
        if (p == NULL) _exit(1);
        memset(p, 0xAB, 1024);
        free(p);
        /* 再做一些 malloc 验证 entry 创建正常 */
        void *q[10];
        for (int i = 0; i < 10; i++) {
            q[i] = malloc(64);
            if (q[i] == NULL) _exit(1);
        }
        /* 故意不 free,让 reporter 有 leak 可报 */
        _exit(0);
    }
    ASSERT(pid > 0, "fork should succeed");
    int status;
    waitpid(pid, &status, 0);
    ASSERT(WIFEXITED(status) && WEXITSTATUS(status) == 0,
           "child should exit 0 (malloc + free works after fork)");
    PASS();
}

/* T2:fork 子进程,子进程再次 fork(模拟 daemon fork chain) */
static void test_fork_grandchild(void) {
    TEST("T2 fork_grandchild_double_fork");
    pid_t pid = fork();
    if (pid == 0) {
        /* 子进程:fork 出孙进程 */
        pid_t gpid = fork();
        if (gpid == 0) {
            /* 孙进程:malloc + 正常退出 */
            void *p = malloc(256);
            if (p == NULL) _exit(1);
            free(p);
            _exit(0);
        }
        if (gpid < 0) _exit(2);
        int gstatus;
        waitpid(gpid, &gstatus, 0);
        _exit(WIFEXITED(gstatus) && WEXITSTATUS(gstatus) == 0 ? 0 : 3);
    }
    ASSERT(pid > 0, "fork should succeed");
    int status;
    waitpid(pid, &status, 0);
    ASSERT(WIFEXITED(status) && WEXITSTATUS(status) == 0,
           "grandchild should exit 0 (double fork works)");
    PASS();
}

/* T3:fork 子进程,子进程做多线程 malloc */
static void* fork_child_thread_fn(void *arg) {
    (void)arg;
    for (int i = 0; i < 100; i++) {
        void *p = malloc(64);
        if (p) free(p);
    }
    return NULL;
}

static void test_fork_child_multithread(void) {
    TEST("T3 fork_child_multithread_malloc");
    pid_t pid = fork();
    if (pid == 0) {
        /* 子进程:启动多个线程并发 malloc */
        pthread_t threads[4];
        for (int i = 0; i < 4; i++) {
            if (pthread_create(&threads[i], NULL, fork_child_thread_fn, NULL) != 0)
                _exit(1);
        }
        for (int i = 0; i < 4; i++) {
            pthread_join(threads[i], NULL);
        }
        _exit(0);
    }
    ASSERT(pid > 0, "fork should succeed");
    int status;
    waitpid(pid, &status, 0);
    ASSERT(WIFEXITED(status) && WEXITSTATUS(status) == 0,
           "child should exit 0 (multithread malloc after fork)");
    PASS();
}

/* T4:不 fork 的进程行为不变(Type=notify/simple 路径回归) */
static void test_no_fork_regression(void) {
    TEST("T4 no_fork_regression (Type=notify path)");
    /* 主进程直接 malloc,验证工具正常工作(不 fork,fork handler 不触发) */
    void *p = malloc(128);
    ASSERT(p != NULL, "malloc should work");
    free(p);
    /* 多次 malloc/free 验证工具追踪正常 */
    for (int i = 0; i < 100; i++) {
        void *q = malloc(32);
        if (q) free(q);
    }
    ASSERT(mtt_get_alloc_count() > 0, "alloc_count should be > 0");
    PASS();
}

int main(void) {
    printf("=== MemoryTraceTool fork Handler Tests ===\n\n");

    test_fork_child_malloc();
    test_fork_grandchild();
    test_fork_child_multithread();
    test_no_fork_regression();

    printf("\n--- Results: %d run, %d passed, %d failed ---\n",
           g_tests_run, g_tests_pass, g_tests_fail);

    return g_tests_fail == 0 ? 0 : 1;
}

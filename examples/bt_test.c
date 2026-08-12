/*
 * bt_test v2 — 综合诊断:遍历所有可疑场景,一次定位 backtrace 失效根因
 *
 * 用法:
 *   挂工具:LD_PRELOAD=.../libmemorytracetool.so MTT_DEBUG=1 MTT_TRACE_SIZE=64 \
 *           MTT_HTTP_PORT=0 ./bt_test
 *   不挂(对照):./bt_test
 *
 * 7 个场景(纯单线程,不依赖 pthread):
 *   1. main 入口立即 backtrace(工具 init 可能还没跑)
 *   3. printf 后 backtrace(工具 init 应该完成)
 *   4. malloc(64) 后 backtrace(触发 hook 后)
 *   5. 连续 10 次 malloc(64) 后 backtrace
 *   6. sleep 1 秒(等 reporter 跑)后 backtrace
 *   7. sleep 3 秒(等信号线程就绪)后 backtrace
 *   foo(): 栈深度对照
 *
 * 关键判断:
 *   - 1/3/6/7 任一 n=0:工具加载/启动破坏了 backtrace
 *   - 1 n>0 但 3 n=0:printf/init 阶段破坏
 *   - 3 n>0 但 4 n=0:hook 拦截 malloc 破坏
 *   - 所有 n>0:工具不破坏 backtrace,问题在 storageManager 业务特殊
 */
#include <execinfo.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static void do_bt(const char *label) {
    void *f[64];
    int n = backtrace(f, 64);
    printf("BACKTRACE_TEST [%s] n=%d", label, n);
    if (n > 0) printf(" first=%p", f[0]);
    printf("\n");
    fflush(stdout);
}

void foo(void) { do_bt("foo_call"); }

int main(void) {
    do_bt("1_main_entry");              /* 1 */

    printf("=== bt_test v2 启动 ===\n");  /* 2:可能触发工具 init */
    fflush(stdout);

    do_bt("3_after_printf");            /* 3 */

    void *p1 = malloc(64);
    do_bt("4_after_malloc");            /* 4 */

    for (int i = 0; i < 10; i++) {
        void *p = malloc(64);
        (void)p;
    }
    do_bt("5_after_10_mallocs");        /* 5 */

    sleep(1);
    do_bt("6_after_1s_sleep");          /* 6 */

    sleep(2);
    do_bt("7_after_3s_total");          /* 7 */

    foo();                              /* foo 栈深度对照 */

    free(p1);
    do_bt("8_after_free");

    /* 等 reporter 首次扫描 */
    printf("\n等 60 秒让 reporter 扫描...\n");
    sleep(60);
    return 0;
}

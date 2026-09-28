/*
 * MemoryTraceTool -- 数据完整性计数测试（池耗尽可见性）。
 *
 * MTT_POOL_ENTRIES=1024（池最小值，Makefile 在 exec 前注入）下申请 5000
 * 个存活分配：池子在 1024 条后耗尽，剩余 ~3976 次分配应计入
 * skipped_overcap，并在报告头部输出 "Skipped (overflow): N"（N > 3000）。
 *
 * 修复前该路径完全漏计——池耗尽后工具静默降级，报告看似正常，
 * 实际数据已残缺。本测试是"数据不完整必须可见"的回归门禁。
 *
 * 注意：MTT_* 环境变量必须由 Makefile 在 exec 前注入（进程内 setenv
 * 自身会触发 libc malloc → hook → 懒初始化，环境变量将不生效）。
 */
#include <memorytracetool/memorytracetool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>

#define N_ALLOCS 5000
#define POOL_MIN 1024

static void *g_ptrs[N_ALLOCS];

static void alloc_many(void)
{
    for (int i = 0; i < N_ALLOCS; i++)
        g_ptrs[i] = mtt_malloc(16);
}

static void trigger_scan(void)
{
    kill(getpid(), SIGUSR1);
    struct timespec ts = {1, 200000000};
    nanosleep(&ts, NULL);
}

/* 在报告文本中解析 "Skipped (overflow): N" */
static long read_skipped_overflow(const char *path)
{
    FILE *fp = fopen(path, "r");
    if (fp == NULL) return -1;
    static char buf[131072];
    size_t n = fread(buf, 1, sizeof(buf) - 1, fp);
    fclose(fp);
    buf[n] = '\0';
    const char *p = strstr(buf, "Skipped (overflow):");
    if (p == NULL) return -1;
    return atol(p + strlen("Skipped (overflow):"));
}

static int g_fail = 0;

#define CHECK(cond, msg) \
    do { \
        printf("  %-58s %s\n", msg, (cond) ? "PASS" : "FAIL"); \
        if (!(cond)) g_fail++; \
    } while (0)

int main(void)
{
    printf("=== test_integrity (pool exhaustion accounting) ===\n");

    alloc_many();     /* 池 1024 条 → 预期 ~3976 次计入 skipped_overcap */
    trigger_scan();   /* SIGUSR1 即时扫描，写出报告 */

    /* 报告路径：/var/log/mtt/<pid>_test_integrity.log（不可写时回退 /tmp/mtt-logs） */
    char path[512];
    snprintf(path, sizeof(path), "/var/log/mtt/%d_test_integrity.log", (int)getpid());
    long skipped = read_skipped_overflow(path);
    if (skipped < 0) {
        snprintf(path, sizeof(path), "/tmp/mtt-logs/%d_test_integrity.log", (int)getpid());
        skipped = read_skipped_overflow(path);
    }

    printf("--- assertions ---\n");
    CHECK(skipped >= 0, "report file found and contains 'Skipped (overflow)'");
    CHECK(skipped > (long)(N_ALLOCS - POOL_MIN - 500),
          "pool exhaustion counted (skipped > ~3500)");
    printf("  (skipped_overcap = %ld)\n", skipped);

    /* 顺便释放，避免池模式回收路径警告 */
    for (int i = 0; i < N_ALLOCS; i++)
        mtt_free(g_ptrs[i]);

    printf("---\nResult: %s (%d failure%s)\n",
           g_fail == 0 ? "ALL TESTS PASSED" : "SOME TESTS FAILED",
           g_fail, g_fail == 1 ? "" : "s");
    return g_fail == 0 ? 0 : 1;
}

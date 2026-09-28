/*
 * MemoryTraceTool -- 扫描历史归档测试（JSONL 追加写）。
 *
 * 验证 /var/log/mtt/<pid>_test_archive.archive.jsonl（不可写时回退
 * /tmp/mtt-logs/）：
 *   1. 默认开启（无需设置 MTT_ARCHIVE）
 *   2. 每次扫描追加一行，行格式 {"scan":N,...,"sites":[...]}
 *   3. 站点条目包含 "conf" 分类字段
 *   4. 行数随扫描次数递增（与覆盖写的报告不同，归档保留历史）
 *
 * 注意：MTT_* 环境变量（阈值等）由 Makefile 在 exec 前注入。
 */
#include <memorytracetool/memorytracetool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>

static void *g_hold = NULL;

static void alloc_hold(void) { g_hold = mtt_malloc(33331); }

static void trigger_scan(void)
{
    kill(getpid(), SIGUSR1);
    struct timespec ts = {1, 200000000};
    nanosleep(&ts, NULL);
}

static int g_fail = 0;

#define CHECK(cond, msg) \
    do { \
        printf("  %-58s %s\n", msg, (cond) ? "PASS" : "FAIL"); \
        if (!(cond)) g_fail++; \
    } while (0)

int main(void)
{
    printf("=== test_archive (JSONL scan history) ===\n");

    alloc_hold();
    sleep(3);
    trigger_scan();  /* 第 1 行 */
    trigger_scan();  /* 第 2 行 */
    trigger_scan();  /* 第 3 行 */

    /* 归档路径（与 reporter.c 的命名规则一致） */
    char apath[512];
    FILE *fp = NULL;
    snprintf(apath, sizeof(apath), "/var/log/mtt/%d_test_archive.archive.jsonl", (int)getpid());
    fp = fopen(apath, "r");
    if (fp == NULL) {
        snprintf(apath, sizeof(apath), "/tmp/mtt-logs/%d_test_archive.archive.jsonl", (int)getpid());
        fp = fopen(apath, "r");
    }

    static char buf[262144];
    size_t n = 0;
    int lines = 0, has_scan_field = 0, has_conf = 0, has_sites = 0;
    if (fp != NULL) {
        n = fread(buf, 1, sizeof(buf) - 1, fp);
        fclose(fp);
        buf[n] = '\0';
        for (size_t i = 0; i < n; i++)
            if (buf[i] == '\n') lines++;
        if (strstr(buf, "\"scan\":") != NULL) has_scan_field = 1;
        if (strstr(buf, "\"conf\":") != NULL) has_conf = 1;
        if (strstr(buf, "\"sites\":") != NULL) has_sites = 1;
    }

    printf("--- assertions ---\n");
    CHECK(fp != NULL, "archive file exists (default enabled)");
    CHECK(lines >= 2, "at least 2 scan lines appended");
    CHECK(has_scan_field, "line contains \"scan\" sequence field");
    CHECK(has_conf, "site entries contain \"conf\" classification");
    CHECK(has_sites, "line contains \"sites\" array");
    printf("  (lines=%d path=%s)\n", lines, apath);

    mtt_free(g_hold);

    printf("---\nResult: %s (%d failure%s)\n",
           g_fail == 0 ? "ALL TESTS PASSED" : "SOME TESTS FAILED",
           g_fail, g_fail == 1 ? "" : "s");
    return g_fail == 0 ? 0 : 1;
}

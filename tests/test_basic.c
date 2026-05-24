/*
 * 核心追踪逻辑单元测试 — 覆盖 malloc/free/realloc/calloc/strdup 全部路径。
 *
 * 编译运行: make test
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>

#define MEMORYTRACETOOL_ENABLE
#include "memorytracetool/memorytracetool.h"

static int tests_run  = 0;
static int tests_pass = 0;

#define TEST(name)  do { tests_run++; printf("  %-40s ", name); } while(0)
#define OK()        do { tests_pass++; printf("PASS\n"); } while(0)
#define FAIL(msg)   do { printf("FAIL: %s\n", msg); } while(0)

int main(void)
{
    printf("=== MemoryTraceTool 核心追踪测试 ===\n\n");

    /* ---- 基础分配/释放 ---- */

    /* free(NULL) 是安全空操作 */
    TEST("free(NULL) is no-op");
    free(NULL);
    OK();

    /* 基础 malloc + free */
    TEST("malloc + free");
    char* p = malloc(100);
    assert(p != NULL);
    memset(p, 0xAB, 100);
    free(p);
    OK();

    /* calloc 零填充 */
    TEST("calloc zero-fill");
    int* arr = calloc(10, sizeof(int));
    assert(arr != NULL);
    int all_zero = 1;
    for (int i = 0; i < 10; i++)
        if (arr[i] != 0) all_zero = 0;
    assert(all_zero);
    free(arr);
    OK();

    /* realloc(NULL, n) 等价于 malloc(n) */
    TEST("realloc(NULL, n)");
    int* r1 = realloc(NULL, 40);
    assert(r1 != NULL);
    free(r1);
    OK();

    /* realloc 扩容，原数据保留 */
    TEST("realloc grow");
    int* r2 = malloc(4 * sizeof(int));
    r2[0] = 1; r2[1] = 2; r2[2] = 3; r2[3] = 4;
    r2 = realloc(r2, 8 * sizeof(int));
    assert(r2 != NULL);
    assert(r2[0] == 1 && r2[1] == 2 && r2[2] == 3 && r2[3] == 4);
    free(r2);
    OK();

    /* strdup 分配 + 释放 */
    TEST("strdup");
    char* s = strdup("test string");
    assert(s != NULL);
    assert(strcmp(s, "test string") == 0);
    free(s);
    OK();

    /* ---- 边界/特殊路径 ---- */

    /* malloc(0) 边界 — 返回非空或空均可，但必须可 free */
    TEST("malloc(0)");
    char* z = malloc(0);
    free(z);
    OK();

    /* realloc 缩容，数据保留前 N 字节 */
    TEST("realloc shrink");
    char* rs = malloc(64);
    memset(rs, 0xEF, 64);
    rs = realloc(rs, 32);
    assert(rs != NULL);
    int shrink_ok = 1;
    for (int i = 0; i < 32; i++)
        if (rs[i] != (char)0xEF) shrink_ok = 0;
    assert(shrink_ok);
    free(rs);
    OK();

    /* realloc(ptr, 0) 等价于 free(ptr) — ptr 句柄失效 */
    TEST("realloc(ptr, 0)");
    char* rz = malloc(50);
    rz = realloc(rz, 0);
    /* rz 现在是 NULL 或已释放的悬挂值，不应再使用 */
    OK();

    /* ---- 统计接口 ---- */

    /* 泄漏检测：故意泄漏 3 次，验证计数 */
    TEST("leak detection");
    size_t before_leak = mtt_get_leak_count();
    malloc(10);           /* 故意不释放 */
    malloc(20);           /* 故意不释放 */
    malloc(30);           /* 故意不释放 */
    size_t after_leak = mtt_get_leak_count();
    if (after_leak == before_leak + 3) OK();
    else FAIL("expected +3 leaks");

    /* current_usage 统计：分配上升，释放归零 */
    TEST("current_usage stat");
    size_t u1 = mtt_get_current_usage();
    char* cu = malloc(1024);
    size_t u2 = mtt_get_current_usage();
    free(cu);
    size_t u3 = mtt_get_current_usage();
    if (u2 > u1 && u3 < u2) OK();
    else FAIL("usage should rise then fall");

    /* peak_usage 统计：分配足够大内存后峰值应刷新，且 free 后不下降 */
    TEST("peak_usage stat");
    size_t pk_before = mtt_get_peak_usage();
    char* pk = malloc(4096);
    size_t pk_high = mtt_get_peak_usage();
    free(pk);
    size_t pk_after = mtt_get_peak_usage();
    if (pk_high > pk_before && pk_after == pk_high) OK();
    else FAIL("peak should rise on big alloc and stay after free");

    /* alloc_count / free_count 计数器 */
    TEST("alloc/free count sanity");
    size_t ac = mtt_get_alloc_count();
    size_t fc = mtt_get_free_count();
    size_t lk = mtt_get_leak_count();
    if (lk == ac - fc) OK();
    else FAIL("leak count != alloc - free");

    /* 交错 alloc/free：复杂顺序后泄漏计数正确 */
    TEST("interleaved alloc/free");
    size_t lk1 = mtt_get_leak_count();
    char* a1 = malloc(8);
    char* a2 = malloc(16);
    free(a1);
    char* a3 = malloc(32);
    free(a2);
    /* 此时仅 a3 未释放，净泄漏 +1 */
    size_t lk2 = mtt_get_leak_count();
    free(a3);
    if (lk2 == lk1 + 1) OK();
    else FAIL("interleaved leak count mismatch");

    /* 最终验证：仅有 leak_detection 留下的 3 个故意泄漏 */
    TEST("exactly 3 intentional leaks remain");
    size_t leaks = mtt_get_leak_count();
    if (leaks == 3) OK();
    else {
        char buf[64];
        snprintf(buf, sizeof(buf), "expected 3, got %zu", leaks);
        FAIL(buf);
    }

    /* Summary */
    printf("\n---\n");
    printf("Results: %d/%d tests passed\n", tests_pass, tests_run);

    return (tests_pass == tests_run) ? 0 : 1;
}

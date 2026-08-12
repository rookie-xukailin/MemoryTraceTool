/*
 * bt_test — backtrace + malloc hook 验证 demo
 *
 * 构造 10 次 malloc(64) 不释放,看工具是否抓到:
 *   - leak 报告 allocations=10 + 1 site (count=10, size=64B):工具正常追踪
 *   - allocations=0 / 1:工具跳过了大部分 malloc(depth 残留 / SKIP 路径)
 *
 * 同时测试 backtrace(不调 malloc,纯 backtrace):
 *   - 挂工具后 n>0:工具不破坏 backtrace
 */
#include <execinfo.h>
#include <stdio.h>
#include <stdlib.h>

void foo(void) {
    void *frames[64];
    int n = backtrace(frames, 64);
    printf("foo: n=%d\n", n);
}

int main(void) {
    /* 场景 A:backtrace(不调 malloc) */
    printf("=== 场景 A:纯 backtrace ===\n");
    foo();

    /* 场景 B:10 次 malloc(64) 不释放 */
    printf("\n=== 场景 B:10 次 malloc(64) 不释放 ===\n");
    char *leak[10];
    for (int i = 0; i < 10; i++) {
        leak[i] = malloc(64);
        if (leak[i] == NULL) { printf("malloc failed at i=%d\n", i); break; }
    }
    printf("分配完 10 个 64B,工具应追踪到 allocations>=10\n");

    /* 等 reporter 扫描(默认 60s 太久,sleep 70s 等首次扫描) */
    printf("\n等 70 秒让 reporter 扫描...\n");
    sleep(70);

    return 0;
}

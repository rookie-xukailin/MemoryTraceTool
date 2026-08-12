/*
 * bt_test — 最小 backtrace 验证 demo。
 *
 * 用途:确认 glibc backtrace 在目标平台(裸跑,不挂 LD_PRELOAD)能否拿到栈。
 *   - n=0:   glibc backtrace 在该平台/系统上不工作(系统/编译器问题)
 *   - n=4+:  backtrace 正常,工具影响时再查工具
 *   - n=1~3: 部分工作,可能业务二进制缺 unwind info
 *
 * 编译命令(Makefile 已配):
 *   make bt_test              # 本机
 *   ./scripts/compile-arm64.sh bt_test   # ARM64 docker
 *
 * 跑(在 BMC ARM64):
 *   ./bt_test                          # 不挂工具
 *   LD_PRELOAD=... ./bt_test           # 挂工具对比
 */
#include <execinfo.h>
#include <stdio.h>

void foo(void) {
    void *frames[64];
    int n = backtrace(frames, 64);
    printf("=== backtrace returned n=%d ===\n", n);
    for (int i = 0; i < n && i < 10; i++)
        printf("  [%d] %p\n", i, frames[i]);
    if (n == 0) {
        printf("ERROR: glibc backtrace failed on this platform.\n");
        printf("Likely causes: missing .eh_frame / broken unwind info / "
               "incompatible glibc + libgcc.\n");
    }
}

void bar(void) { foo(); }
void baz(void) { bar(); }

int main(void) {
    baz();
    return 0;
}

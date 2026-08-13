/*
 * bt_test v3 — backtrace vs FP chain 对比验证
 *
 * 核心问题:挂工具后 backtrace n=0,但 FP chain(帧指针遍历)可能不受影响。
 * 因为:
 *   - backtrace 依赖 libgcc 全局表(挂工具后被污染)
 *   - FP chain 只读寄存器(x29) + 栈内存,零全局依赖
 *
 * 用法:
 *   挂工具:LD_PRELOAD=.../libmemorytracetool.so MTT_HTTP_PORT=0 ./bt_test
 *   不挂:./bt_test
 */
#include <execinfo.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

/* 纯 FP chain 遍历(不加任何检查,最原始版本) */
static int fp_chain_raw(void **stack, int max) {
    int n = 0;
    void **fp = (void**)__builtin_frame_address(0);
    while (fp != NULL && n < max) {
        void *prev_fp = fp[0];
        void *lr      = fp[1];
        if (lr == NULL || prev_fp == NULL) break;
        stack[n++] = lr;
        if (prev_fp <= (void*)fp) break;
        fp = (void**)prev_fp;
    }
    return n;
}

/* 带"跨度检查"的 FP chain(模拟工具兜底,但不依赖 addr_validate) */
static int fp_chain_safe(void **stack, int max) {
    int n = 0;
    void **fp = (void**)__builtin_frame_address(0);
    while (fp != NULL && n < max) {
        void *prev_fp = fp[0];
        void *lr      = fp[1];
        if (lr == NULL || prev_fp == NULL) break;
        if ((char*)prev_fp - (char*)fp > 65536) break;
        if (prev_fp <= (void*)fp) break;
        stack[n++] = lr;
        fp = (void**)prev_fp;
    }
    return n;
}

static void test_at_level3(void) {
    void *bt_stack[64], *fp_raw[64], *fp_safe[64];
    int bt_n   = backtrace(bt_stack, 64);
    int raw_n  = fp_chain_raw(fp_raw, 64);
    int safe_n = fp_chain_safe(fp_safe, 64);

    printf("level3: backtrace=%d  fp_raw=%d  fp_safe=%d\n", bt_n, raw_n, safe_n);
    if (raw_n > 0) {
        printf("  fp_raw:");
        for (int i = 0; i < raw_n && i < 5; i++) printf(" %p", fp_raw[i]);
        printf("\n");
    }
}

static void test_at_level2(void) { test_at_level3(); }
static void test_at_level1(void) { test_at_level2(); }

int main(void) {
    printf("=== bt_test v3: backtrace vs FP chain ===\n");
    test_at_level1();
    sleep(1);
    return 0;
}

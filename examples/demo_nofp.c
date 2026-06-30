/*
 * 模拟 flasher 无帧指针二进制 + 多层调用栈的栈捕获验证 demo
 *
 * 关键:-O2 -fomit-frame-pointer 编译,模拟 release 二进制
 * 目的:验证 mtt_capture_stack 在无帧指针二进制上不再段错误,
 *      并能拿到合理的调用栈。
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* 多层调用栈:模拟 flasher 的 main → 业务 → ... → malloc */
__attribute__((noinline)) static void* alloc_inner(int idx)
{
    void *p = malloc(10 + idx);
    if (p) memset(p, 0xAB, 10 + idx);
    return p;
}

__attribute__((noinline)) static void* alloc_layer4(int idx)
{
    return alloc_inner(idx);
}

__attribute__((noinline)) static void* alloc_layer3(int idx)
{
    return alloc_layer4(idx);
}

__attribute__((noinline)) static void* alloc_layer2(int idx)
{
    return alloc_layer3(idx);
}

__attribute__((noinline)) static void* alloc_layer1(int idx)
{
    return alloc_layer2(idx);
}

int main(void)
{
    printf("=== No-FP Demo (simulating flasher) ===\n");
    printf("PID: %d\n", (int)getpid());

    /* 故意泄漏 5 次,让追踪系统拿到栈 */
    for (int i = 0; i < 5; i++) {
        void *p = alloc_layer1(i);
        printf("[leak %d] ptr=%p\n", i, p);
    }

    printf("\nWaiting 3s for hook init + first scan...\n");
    sleep(3);
    return 0;
}

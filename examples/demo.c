/*
 * MemoryTraceTool — 宏模式示例。
 *
 * 显式链接 libmemorytracetool.so，调用 mtt_malloc/mtt_free 系列函数。
 * 编译: make demo
 * 运行: LD_LIBRARY_PATH=build ./build/demo
 */
#include <memorytracetool/memorytracetool.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main(void)
{
    printf("=== MemoryTraceTool Macro Mode Demo ===\n");
    printf("PID: %d\n\n", (int)getpid());

    /* 分配若干内存（将被追踪） */
    char *p1 = (char *)mtt_malloc(1024);
    char *p2 = (char *)mtt_malloc(2048);
    char *p3 = (char *)mtt_calloc(10, 100);
    char *p4 = (char *)mtt_malloc(4096);

    if (p1 != NULL) strcpy(p1, "Hello from p1");
    if (p2 != NULL) strcpy(p2, "This p2 will leak");
    if (p3 != NULL) strcpy(p3, "p3 calloc'd block");
    if (p4 != NULL) strcpy(p4, "p4 allocation");

    printf("Allocated 4 blocks:\n");
    printf("  p1: 1024 B  (will be freed)\n");
    printf("  p2: 2048 B  (will LEAK)\n");
    printf("  p3: 1000 B  (will be freed)\n");
    printf("  p4: 4096 B  (will LEAK)\n\n");

    /* 释放部分（制造泄漏） */
    mtt_free(p1);  /* 正常释放 */
    mtt_free(p3);  /* 正常释放 */
    /* p2, p4 不释放 → 泄漏 */

    printf("Statistics:\n");
    printf("  Alloc count: %zu\n", mtt_get_alloc_count());
    printf("  Free count:  %zu\n", mtt_get_free_count());
    printf("  Leak count:  %zu\n", mtt_get_leak_count());
    printf("  Current:     %zu bytes\n", mtt_get_current_usage());
    printf("  Peak:        %zu bytes\n", mtt_get_peak_usage());
    printf("  Total:       %zu bytes\n", mtt_get_total_allocated());

    /* 等待报告线程执行首次扫描（约 60s） */
    printf("\nWaiting for reporter to scan (~65s, check the log file)...\n");
    printf("Log: /var/log/mtt/<pid>_demo.log\n\n");
    fflush(stdout);

    sleep(65);

    printf("Done.\n");
    return 0;
}

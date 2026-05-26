/*
 * MemoryTraceTool — LD_PRELOAD 模式示例。
 *
 * 使用标准 malloc/free，运行时通过 LD_PRELOAD 注入追踪。
 * 无需包含任何 MemoryTraceTool 头文件，无需修改源码。
 *
 * 编译: make demo_preload
 * 运行: LD_PRELOAD=build/libmemorytracetool.so ./build/demo_preload
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/** 模拟一个会泄漏内存的请求处理函数 */
static void handle_request(int id)
{
    /* 每 3 个请求中有一个泄漏 */
    char *buf = (char *)malloc(1024);
    if (buf == NULL) return;

    snprintf(buf, 1024, "Request #%d data", id);
    printf("  [req #%d] allocated 1024 B at %p\n", id, (void *)buf);

    if (id % 3 != 0) {
        /* 正常释放 */
        free(buf);
        printf("  [req #%d] freed\n", id);
    } else {
        /* 泄漏！ */
        printf("  [req #%d] LEAKED!\n", id);
    }
}

int main(void)
{
    printf("=== MemoryTraceTool LD_PRELOAD Demo ===\n");
    printf("PID: %d\n", (int)getpid());
    printf("Run with: LD_PRELOAD=build/libmemorytracetool.so ./build/demo_preload\n\n");

    /* 模拟 15 个请求，每第 3 个泄漏 */
    for (int i = 1; i <= 15; i++) {
        handle_request(i);
    }

    printf("\nProcessed 15 requests, 5 leaks (every 3rd).\n");
    printf("Waiting 65s for reporter scan...\n");
    printf("Check /var/log/mtt/<pid>_demo_preload.log\n");
    fflush(stdout);

    sleep(65);

    printf("Done.\n");
    return 0;
}

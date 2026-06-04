/*
 * MemoryTraceTool — 长期运行示例（LD_PRELOAD 模式）。
 *
 * 模拟一个长期运行的服务，持续分配内存并周期性泄漏。
 * 用于验证 48 小时监控的稳定性。
 *
 * 编译: make demo_long_running
 * 运行: LD_PRELOAD=build/libmemorytracetool.so ./build/demo_long_running
 *
 * 预期行为：
 *   - 每秒处理一个"请求"，每 5 个请求中有 1 个泄漏 4 KB
 *   - 约 20 分钟后泄漏 ~960 KB（1200 个请求，240 次泄漏）
 *   - 工具内存占用不超过 45 MB（追踪表 65536 条目 + 栈缓存 4096 + 泄漏去重 2048）
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#define LEAK_SIZE       4096      /* 每次泄漏 4 KB */
#define LEAK_EVERY_N    5         /* 每 N 个请求中泄漏 1 个 */

/** 模拟一个请求处理（可能泄漏） */
static void process_request(unsigned long seq)
{
    char *buf = (char *)malloc(LEAK_SIZE);
    if (buf == NULL) return;

    memset(buf, 0xAB, LEAK_SIZE);  /* 使用内存 */

    if (seq % LEAK_EVERY_N == 0) {
        /* 泄漏：不释放 */
    } else {
        free(buf);
    }
}

/** 格式化时长 "HH:MM:SS" */
static void print_elapsed(time_t elapsed)
{
    long h = (long)(elapsed / 3600);
    long m = (long)((elapsed % 3600) / 60);
    long s = (long)(elapsed % 60);
    printf("%02ld:%02ld:%02ld", h, m, s);
}

int main(void)
{
    printf("=== MemoryTraceTool Long-Running Demo ===\n");
    printf("PID: %d\n", (int)getpid());
    printf("Pattern: Leak %d KB every %d requests (1 req/sec)\n",
           LEAK_SIZE / 1024, LEAK_EVERY_N);
    printf("Log: /var/log/mtt/<pid>_demo_long_running.log\n\n");

    time_t start  = time(NULL);
    unsigned long seq = 0;

    printf("Running... Press Ctrl+C to stop.\n");
    printf("Elapsed    Requests   Leaks   Leak Total\n");
    printf("--------   --------   -----   ----------\n");
    fflush(stdout);

    while (1) {
        seq++;
        process_request(seq);

        /* 每 60s 输出进度 */
        if (seq % 60 == 0) {
            time_t elapsed = time(NULL) - start;
            unsigned long leaks = seq / LEAK_EVERY_N;
            size_t leak_kb = leaks * (LEAK_SIZE / 1024);

            printf("[");
            print_elapsed(elapsed);
            printf("]  %8lu   %5lu    %lu KB\n", seq, leaks, (unsigned long)leak_kb);
            fflush(stdout);
        }

        /* 1 req/sec */
        sleep(1);
    }

    return 0;
}

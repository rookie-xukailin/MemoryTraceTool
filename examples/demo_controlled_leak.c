/*
 * MemoryTraceTool — 可控泄漏演示（长期运行测试用）。
 *
 * 场景：模拟守护进程缓慢泄漏内存，20 分钟内共泄漏约 50MB。
 * 每次分配随机 4KB~64KB，每隔 1~30 秒泄漏一次（随机间隔）。
 * 达到 50MB 泄漏总量上限后停止泄漏，进程继续运行等待观察。
 *
 * 用法：
 *   LD_PRELOAD=./libmemorytracetool.so MTT_HTTP_PORT=8080 ./demo_controlled_leak
 *   浏览器打开 http://<ip>:8080 查看实时趋势图
 *
 * 编译：
 *   make demo_controlled_leak
 *   或 arm-linux-gnueabihf-gcc -o demo_controlled_leak examples/demo_controlled_leak.c -lpthread
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <signal.h>

/** 泄漏总量上限（字节） */
#define LEAK_LIMIT_BYTES  (50ULL * 1024 * 1024)  /* 50 MB */

/** 单次泄漏最小/最大字节数 */
#define LEAK_MIN_BYTES    (4 * 1024)              /* 4 KB */
#define LEAK_MAX_BYTES    (64 * 1024)             /* 64 KB */

/** 两次泄漏之间最小/最大间隔（秒） */
#define PAUSE_MIN_SEC     1
#define PAUSE_MAX_SEC     30

/** 状态打印间隔（秒） */
#define STATUS_INTERVAL   10

/** 简易随机数（避免 srand/rand 可能触发 malloc） */
static unsigned g_seed = 1;
static unsigned simple_rand(void)
{
    g_seed = g_seed * 1103515245 + 12345;
    return (g_seed >> 16) & 0x7FFFFFFF;
}

/** 随机范围 [min, max] */
static int rand_range(int min_val, int max_val)
{
    return min_val + (int)(simple_rand() % (unsigned)(max_val - min_val + 1));
}

/**
 * 格式化字节数为人类可读字符串。
 *
 * @param bytes  字节数
 * @param buf    输出缓冲区（至少 32 字节）
 * @return       buf
 */
static const char* fmt_size(size_t bytes, char *buf)
{
    if (bytes >= 1048576)
        snprintf(buf, 32, "%.2f MB", (double)bytes / 1048576.0);
    else if (bytes >= 1024)
        snprintf(buf, 32, "%.2f KB", (double)bytes / 1024.0);
    else
        snprintf(buf, 32, "%zu B", bytes);
    return buf;
}

/** 全局泄漏计数器 */
static volatile size_t  g_total_leaked = 0;    /* 累计泄漏字节数 */
static volatile size_t  g_leak_count    = 0;    /* 泄漏次数 */
static volatile int     g_stop_leaking  = 0;    /* 是否停止泄漏（达到上限） */
static volatile int     g_running       = 1;    /* 进程运行标志 */
static volatile time_t  g_start_time    = 0;

/** SIGINT 处理：优雅退出 */
static void sigint_handler(int sig)
{
    (void)sig;
    g_running = 0;
}

int main(void)
{
    char size_buf1[32] = {0};
    char size_buf2[32] = {0};
    time_t start = time(NULL);
    g_start_time = start;

    signal(SIGINT,  sigint_handler);
    signal(SIGTERM, sigint_handler);

    printf("=== MemoryTraceTool Controlled Leak Demo ===\n");
    printf("PID:        %d\n", (int)getpid());
    printf("Duration:   indefinite (runs until SIGINT/SIGTERM)\n");
    printf("Leak limit: %s\n", fmt_size(LEAK_LIMIT_BYTES, size_buf1));
    printf("Leak range: %s ~ %s per allocation\n",
           fmt_size(LEAK_MIN_BYTES, size_buf1),
           fmt_size(LEAK_MAX_BYTES, size_buf2));
    printf("Sleep range: %d ~ %d sec between leaks\n", PAUSE_MIN_SEC, PAUSE_MAX_SEC);
    printf("\nStart leaking... Press Ctrl+C to stop.\n\n");

    /* ---- 正常业务分配（会释放，不泄漏） ---- */
    {
        /* 模拟业务逻辑：定期分配+释放 */
        char *work_buf = (char *)malloc(65536);
        if (work_buf != NULL) {
            memset(work_buf, 0xCD, 65536);
            free(work_buf);
        }
    }

    /* ---- 主循环：缓慢泄漏 ---- */
    while (g_running) {
        time_t now = time(NULL);
        time_t elapsed = now - start;

        /* 检查是否达到泄漏上限 */
        if (g_total_leaked >= LEAK_LIMIT_BYTES && !g_stop_leaking) {
            g_stop_leaking = 1;
            printf("\n*** Leak limit (%s) reached! Stopping leaks, "
                   "process continues to run. ***\n",
                   fmt_size(LEAK_LIMIT_BYTES, size_buf1));
            printf("Keep the process alive to observe the leak report.\n\n");
        }

        /* 若未达到上限，执行一次泄漏 */
        if (!g_stop_leaking) {
            int leak_size = rand_range(LEAK_MIN_BYTES, LEAK_MAX_BYTES);

            /* 确保不超过总量上限 */
            if (g_total_leaked + (size_t)leak_size > LEAK_LIMIT_BYTES) {
                leak_size = (int)(LEAK_LIMIT_BYTES - g_total_leaked);
                if (leak_size <= 0) {
                    g_stop_leaking = 1;
                    continue;
                }
            }

            /* 分配并故意不释放（泄漏） */
            void *leaked = malloc((size_t)leak_size);
            if (leaked != NULL) {
                /* 写入已知模式（防止编译器优化掉分配） */
                memset(leaked, 0xDE, (size_t)leak_size);
                ((char*)leaked)[0]           = (char)(g_leak_count & 0xFF);
                ((char*)leaked)[leak_size-1] = 0xAD;
            }

            g_total_leaked += (size_t)leak_size;
            g_leak_count++;
        }

        /* 每 STATUS_INTERVAL 秒打印一次状态 */
        {
            static time_t last_report = 0;
            if (now - last_report >= STATUS_INTERVAL) {
                last_report = now;
                int pct = (int)((g_total_leaked * 100) / LEAK_LIMIT_BYTES);
                printf("[%5lds] leaks: %6zu | total: %9s | %3d%% | %s\n",
                       (long)elapsed, g_leak_count,
                       fmt_size(g_total_leaked, size_buf1),
                       pct,
                       g_stop_leaking ? "STOPPED" : "leaking");
                fflush(stdout);
            }
        }

        /* 随机间隔 */
        sleep((unsigned)rand_range(PAUSE_MIN_SEC, PAUSE_MAX_SEC));
    }

    /* ---- 最终报告 ---- */
    {
        time_t end = time(NULL);
        printf("\n=== Final Report ===\n");
        printf("Ran for:     %ld sec (~%.1f min)\n",
               (long)(end - start), (double)(end - start) / 60.0);
        printf("Total leaks: %zu allocations\n", g_leak_count);
        printf("Total bytes: %s\n", fmt_size(g_total_leaked, size_buf1));
        printf("Status:      %s\n", g_stop_leaking ? "Reached limit" : "Interrupted");

        /* 短暂等待 reporter 线程完成最后一次扫描 */
        printf("\nWaiting 3s for final report...\n");
        fflush(stdout);
        sleep(3);
    }

    return 0;
}

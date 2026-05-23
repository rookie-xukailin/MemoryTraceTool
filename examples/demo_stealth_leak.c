/*
 * demo_stealth_leak.c — 多线程慢性内存泄漏演示程序。
 *
 * 线程布局：
 *   - main:     监控协调线程，每 5 秒打印状态
 *   - 4 workers: 模拟正常业务（随机大小分配/释放）
 *   - 1 leaker:  每秒泄漏 16 字节，模拟慢性泄漏
 *   - 1 monitor: 每 5 秒检查累计泄漏量，超过 10MB 时触发退出
 *
 * 本程序不链接 MemoryTraceTool，可独立运行。
 * 通过守护进程 Web 界面选择进程并注入 .so 后，
 * 所有 malloc/free 调用将被自动拦截并报告。
 *
 * 用法：
 *   build/demo_stealth_leak              # 独立运行，每 5 秒打印状态
 *
 * 配合注入测试：
 *   1. build/mttd 8080 &
 *   2. build/demo_stealth_leak &
 *   3. 浏览器打开 http://localhost:8080
 *   4. 在进程列表中找到 demo_stealth_leak，点击 Inject
 *   5. 观察看板上逐渐增长的泄漏数据
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <time.h>
#include <stdatomic.h>

/* ---- 全局状态 ---- */

static atomic_int g_running = 1;        /* 程序运行标志，monitor 发现 >10M 时设 0 */
static _Atomic size_t g_leaked_total = 0; /* 累计泄漏字节数（仅 leaker 线程写入） */
static _Atomic size_t g_worker_ops = 0;   /* worker 线程完成的分配/释放操作次数 */

#define LEAK_BYTES_PER_SEC  16            /* 每秒泄漏字节数 */
#define MAX_LEAK_BYTES      (10 * 1024 * 1024)  /* 泄漏上限 10MB */
#define WORKER_THREADS      4              /* 正常工作线程数 */

/* ---- 辅助: 毫秒级休眠 ---- */

static void ms_sleep(int ms)
{
    struct timespec ts;
    ts.tv_sec = ms / 1000;
    ts.tv_nsec = (long)(ms % 1000) * 1000000L;
    nanosleep(&ts, NULL);
}

/* ---- Worker 线程: 模拟正常业务 ---- */

/** 正常业务线程: 随机大小分配，持有随机时间后释放 */
static void* worker_thread(void* arg)
{
    int id = (int)(long)arg;
    unsigned seed = (unsigned)(time(NULL) ^ (id * 0x9e3779b9));

    while (atomic_load(&g_running)) {
        /* 随机分配 1KB - 64KB */
        size_t sz = 1024 + (rand_r(&seed) % 64512);
        void* p = malloc(sz);
        if (!p) { ms_sleep(100); continue; }

        /* 填充数据模拟真实使用 */
        memset(p, (int)(sz & 0xFF), sz);

        /* 持有 100ms - 2s */
        ms_sleep(100 + (int)(rand_r(&seed) % 1900));

        free(p);
        atomic_fetch_add(&g_worker_ops, 1);
    }
    return NULL;
}

/* ---- Leaker 线程: 慢性泄漏 ---- */

/** 每秒泄漏 16 字节的线程 */
static void* leaker_thread(void* arg)
{
    (void)arg;

    while (atomic_load(&g_running)) {
        /* 分配 16 字节并故意不释放 */
        void* p = malloc(16);
        if (p) {
            memset(p, 0xEF, 16); /* 填充可识别模式 */
            size_t total = atomic_fetch_add(&g_leaked_total, 16) + 16;

            /* 提前退出: 本线程也检查上限 */
            if (total >= MAX_LEAK_BYTES) {
                atomic_store(&g_running, 0);
                break;
            }
        }
        sleep(1);
    }
    return NULL;
}

/* ---- Monitor 线程: 检查上限 ---- */

/** 每 5 秒检查累计泄漏量 */
static void* monitor_thread(void* arg)
{
    (void)arg;

    while (atomic_load(&g_running)) {
        sleep(5);
        size_t leaked = atomic_load(&g_leaked_total);
        if (leaked >= MAX_LEAK_BYTES) {
            printf("[monitor] Leaked %zu bytes (%.2f MB) >= 10MB limit, "
                   "shutting down...\n",
                   leaked, (double)leaked / (1024.0 * 1024.0));
            atomic_store(&g_running, 0);
            break;
        }
    }
    return NULL;
}

/* ---- main ---- */

int main(void)
{
    printf("=== demo_stealth_leak ===\n");
    printf("Threads: %d workers + 1 leaker (16 B/s) + 1 monitor\n", WORKER_THREADS);
    printf("Leak limit: 10 MB (will auto-stop after ~%.0f hours)\n",
           (double)MAX_LEAK_BYTES / (LEAK_BYTES_PER_SEC * 3600.0));
    printf("PID: %d\n", getpid());
    printf("\nTo inject memory tracer:\n");
    printf("  1. Start daemon: build/mttd 8080 &\n");
    printf("  2. Open http://localhost:8080\n");
    printf("  3. Find PID %d and click 'Inject'\n", getpid());
    printf("  4. Watch leaks accumulate on dashboard\n\n");

    pthread_t workers[WORKER_THREADS];
    pthread_t leaker;
    pthread_t monitor;

    /* 启动所有线程 */
    for (int i = 0; i < WORKER_THREADS; i++) {
        pthread_create(&workers[i], NULL, worker_thread, (void*)(long)i);
    }
    pthread_create(&leaker, NULL, leaker_thread, NULL);
    pthread_create(&monitor, NULL, monitor_thread, NULL);

    /* 主循环: 每 5 秒打印状态 */
    time_t start = time(NULL);
    while (atomic_load(&g_running)) {
        sleep(5);
        size_t leaked = atomic_load(&g_leaked_total);
        size_t ops = atomic_load(&g_worker_ops);
        time_t elapsed = time(NULL) - start;
        printf("[%5lds] Leaked: %7.2f KB | Workers: %6zu ops | Running...\n",
               (long)elapsed, (double)leaked / 1024.0, ops);
    }

    /* 等待所有线程退出 */
    pthread_join(monitor, NULL);
    pthread_join(leaker, NULL);
    for (int i = 0; i < WORKER_THREADS; i++) {
        pthread_cancel(workers[i]);
        pthread_join(workers[i], NULL);
    }

    size_t final_leaked = atomic_load(&g_leaked_total);
    printf("\n=== Demo stopped ===\n");
    printf("Total leaked: %.2f MB\n",
           (double)final_leaked / (1024.0 * 1024.0));
    printf("Worker ops: %zu\n", atomic_load(&g_worker_ops));

    /* 注意: 泄漏的内存(malloc(16) 未 free)会在进程退出时由 OS 回收 */
    return 0;
}

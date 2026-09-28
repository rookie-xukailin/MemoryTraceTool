/*
 * MemoryTraceTool -- addr2line 全链路验收测试（跨平台门禁）。
 *
 * 用户验收标准（2026-09 约定）：不能通过 addr2line 找回原文就是失败，
 * 适用于所有平台（本机/arm32/arm64/riscv64）。
 *
 * 流程：
 *   1. 已知泄漏点函数 leak_site_alloc()（noinline，调用点唯一）分配并不释放；
 *   2. SIGUSR1 触发扫描，读 MTT_REPORT_FILE JSON 拿到该站点的栈帧；
 *   3. 把帧写入 <binary>.mtt_frames（供 test_addr2line.sh 逐帧 addr2line）；
 *   4. 自校验：泄漏帧的 (binary+0xFILEOFF) 偏移，进程内读 /proc/self/exe
 *      对应 ELF 的符号表做交叉验证不可行时，直接依赖 shell 端 addr2line。
 *
 * 编译参数按目标工程参数表（sensorhub 同款：-O2 -g --export-dynamic）。
 */
#include <memorytracetool/memorytracetool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <limits.h>

#define LEAK_SIZE 33331

static void *g_leak = NULL;

/* 泄漏点函数（noinline 保证调用点 PC 唯一，addr2line 应解析到本函数） */
__attribute__((noinline)) static void leak_site_alloc(void)
{
    g_leak = mtt_malloc(LEAK_SIZE);
}

static void trigger_scan(void)
{
    kill(getpid(), SIGUSR1);
    /* 轮询等待扫描完成：JSON ts 变化或 10s 超时（不依赖固定 sleep，
     * 兼容 QEMU 慢机 —— 走读 P2-1 修复模式） */
    char path[PATH_MAX];
    const char *rpt = getenv("MTT_REPORT_FILE");
    if (rpt == NULL) return;
    snprintf(path, sizeof(path), "%s", rpt);
    long old_ts = 0;
    for (int i = 0; i < 50; i++) {
        struct timespec ts = {0, 200 * 1000 * 1000};
        nanosleep(&ts, NULL);
        FILE *fp = fopen(path, "r");
        if (!fp) continue;
        char buf[512] = {0};
        size_t n = fread(buf, 1, sizeof(buf) - 1, fp);
        fclose(fp);
        buf[n] = '\0';
        char *tsp = strstr(buf, "\"ts\":");
        if (tsp) {
            long cur = atol(tsp + 5);
            if (old_ts != 0 && cur != old_ts) return; /* 新扫描完成 */
            old_ts = cur;
        }
    }
}

/* 极简 JSON 提取：找 "size":LEAK_SIZE 站点的 "stack":[...] 数组 */
static int dump_frames(const char *json_path, const char *out_path)
{
    FILE *fp = fopen(json_path, "r");
    if (!fp) return -1;
    static char buf[262144];
    size_t n = fread(buf, 1, sizeof(buf) - 1, fp);
    fclose(fp);
    buf[n] = '\0';

    char needle[64];
    snprintf(needle, sizeof(needle), "\"size\":%zu,", (size_t)LEAK_SIZE);
    char *site = strstr(buf, needle);
    if (!site) return -1;
    char *stack = strstr(site, "\"stack\":[");
    if (!stack) return -1;
    stack += strlen("\"stack\":[");

    FILE *out = fopen(out_path, "w");
    if (!out) return -1;
    int frames = 0;
    char *p = stack;
    while (*p && *p != ']') {
        if (*p == '"') {
            char *e = strchr(p + 1, '"');
            if (!e) break;
            *e = '\0';
            fprintf(out, "%s\n", p + 1);
            frames++;
            p = e + 1;
        } else {
            p++;
        }
    }
    fclose(out);
    return frames;
}

int main(void)
{
    /* 二进制路径：/proc/self/exe（用于 frames 文件命名与 addr2line） */
    char exe[PATH_MAX] = {0};
    ssize_t elen = readlink("/proc/self/exe", exe, sizeof(exe) - 1);
    if (elen <= 0) { printf("FAIL: readlink exe\n"); return 1; }
    exe[elen] = '\0';

    char frames_path[PATH_MAX + 16];
    snprintf(frames_path, sizeof(frames_path), "%s.mtt_frames", exe);
    unlink(frames_path);

    printf("=== test_addr2line (leak site -> stack -> addr2line) ===\n");
    printf("  binary: %s\n", exe);

    leak_site_alloc();
    sleep(3);          /* 老化（MTT_LEAK_THRESHOLD_SEC=2 由 Makefile 注入） */
    trigger_scan();

    const char *rpt = getenv("MTT_REPORT_FILE");
    if (!rpt) { printf("FAIL: MTT_REPORT_FILE not set\n"); return 1; }

    int frames = dump_frames(rpt, frames_path);
    if (frames <= 0) {
        printf("FAIL: leak site (size=%d) not found in JSON or has no stack\n"
               "  dump_frames ret=%d (json_path=%s)\n",
               LEAK_SIZE, frames, rpt);
        /* 诊断：打印 JSON 前 200 字节 */
        FILE *fp = fopen(rpt, "r");
        if (fp) {
            char buf[201] = {0};
            size_t n = fread(buf, 1, 200, fp);
            fclose(fp);
            buf[n] = 0;
            printf("  json head: %s\n", buf);
        }
        return 1;
    }
    printf("  frames dumped: %d -> %s\n", frames, frames_path);
    printf("  (shell 端执行 tests/test_addr2line.sh 完成逐帧 addr2line 断言)\n");

    /* 保持存活直到 shell 端读取（atexit final scan 会释放？不会——泄漏不释放） */
    return 0;
}

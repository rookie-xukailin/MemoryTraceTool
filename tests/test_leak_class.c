/*
 * MemoryTraceTool -- 泄漏四级分类测试。
 *
 * 验证场景（默认智能分类模式）：
 *   A. 启动申请、进程存活期内永不释放      → long_lived（不再误报 probable）
 *   B. 超阈值后释放、随后同栈再申请        → session_scoped（周期作用域，
 *      模拟"收到主机重启 RPC 信号后释放"的内存）
 *   C. 同一调用栈持续增长、从不释放        → probable（真泄漏特征）
 *
 * classic 模式（Makefile 以 MTT_CLASSIC_LEAK=1 运行，argv[1] 仅作标签）：
 *   A/B/C 全部退回旧的纯时间判定 → probable（旧行为回归验证）
 *
 * 机制：MTT_LEAK_THRESHOLD_SEC=2 缩短老化阈值，
 *       kill(SIGUSR1) 触发即时扫描（不等 60s 周期），
 *       断言读 MTT_REPORT_FILE JSON 输出的 conf 字段。
 *
 * 注意：所有 MTT_* 环境变量必须由 Makefile 在 exec 前注入 ——
 *       进程内 setenv() 自身会触发 libc malloc → hook → 懒初始化，
 *       此时环境变量尚未生效（会按默认值解析）。
 *       报告路径从 MTT_REPORT_FILE 环境变量读取（getenv 不分配内存）。
 *       场景尺寸选用奇数值，避免与 stdio 缓冲区(4096/8192)等
 *       libc 内部分配的站点在按 size 匹配时混淆。
 */
#include <memorytracetool/memorytracetool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>

#define SIZE_A 33331   /* 场景 A 单次分配 */
#define SIZE_B 55557   /* 场景 B 单次分配 */
#define SIZE_C 7777    /* 场景 C 单次分配（× 20 次增长） */

static void *g_keep_a = NULL;
static void *g_keep_b = NULL;

/* 三个场景各自独立函数：保证栈回溯（站点 hash）互不相同。
 * noinline 必须加：编译器(-O1)会把小循环完全展开内联，
 * 同一 mtt_malloc 调用点被复制成多个 PC → 多轮分配被拆成不同站点。 */
__attribute__((noinline)) static void scenario_long_lived(void)
{
    g_keep_a = mtt_malloc(SIZE_A);
}

__attribute__((noinline)) static void scenario_cycle(void)
{
    g_keep_b = mtt_malloc(SIZE_B);
}

__attribute__((noinline)) static void scenario_grow(int n)
{
    for (int i = 0; i < n; i++) {
        void *p = mtt_malloc(SIZE_C);
        (void)p; /* 故意不释放：增长型泄漏 */
    }
}

static void trigger_scan(void)
{
    kill(getpid(), SIGUSR1);
    struct timespec ts = {1, 200000000}; /* 1.2s：等信号线程完成扫描 */
    nanosleep(&ts, NULL);
}

/* 在 MTT_REPORT_FILE JSON 中查找 total_size==want_size 的站点，
 * 判断其 "conf":"xxx" 是否等于 want_conf。
 * JSON 站点格式（reporter.c 固定输出）：
 *   {"count":c,"size":s,"hash":"h","conf":"x","late_free":n,"is_expired":b} */
static int find_conf(const char *path, size_t want_size, const char *want_conf)
{
    if (path == NULL || path[0] == '\0') return 0;
    FILE *fp = fopen(path, "r");
    if (fp == NULL) return 0;
    static char buf[131072];
    size_t n = fread(buf, 1, sizeof(buf) - 1, fp);
    fclose(fp);
    buf[n] = '\0';

    char needle[64];
    snprintf(needle, sizeof(needle), "\"size\":%zu,", want_size);
    const char *p = strstr(buf, needle);
    if (p == NULL) return 0;
    const char *c = strstr(p, "\"conf\":\"");
    if (c == NULL) return 0;
    c += strlen("\"conf\":\"");
    return strncmp(c, want_conf, strlen(want_conf)) == 0;
}

static int g_fail = 0;

#define CHECK(cond, msg) \
    do { \
        printf("  %-58s %s\n", msg, (cond) ? "PASS" : "FAIL"); \
        if (!(cond)) g_fail++; \
    } while (0)

int main(int argc, char **argv)
{
    int classic = (argc > 1 && strcmp(argv[1], "classic") == 0);
    const char *rpt = getenv("MTT_REPORT_FILE"); /* Makefile 注入，含完整 env */

    printf("=== test_leak_class (%s mode) ===\n", classic ? "classic" : "smart");
    printf("  report file: %s\n", rpt ? rpt : "(MTT_REPORT_FILE not set)");

    /* 预先抬高 peak_bytes：后续场景的内存增长(总计 <200KB)不会刷新
     * 峰值,避免 peak_updated 触发 reporter 提前扫描(增长后 1s 内抢先
     * 扫描会把站点峰值棘轮到位,导致手动扫描时看不到"超过峰值"状态)。
     * 扫描时机由此完全由本测试的 SIGUSR1 掌控。 */
    void *pre_peak = mtt_malloc(4 * 1024 * 1024);
    mtt_free(pre_peak); /* 年轻释放:不产生 late-free 证据,无副作用 */

    /* 场景 A：启动申请，永不释放 */
    scenario_long_lived();

    /* 场景 B：周期作用域（申请 → 老化 → 释放 → 再申请）。
     * 多轮调用必须在循环体内的同一行 —— 栈回溯包含 main 中的返回地址，
     * 两个不同调用点的栈 hash 不同，会被当成两个站点。
     * round0: 首次观测(possible) → 老化释放 → 站点消失(late-free 证据入历史表)
     * round1: 重新申请 → 同 hash 复现 → count≤peak 且 late_free>0 → session_scoped
     * round2: 再确认一轮 */
    /* volatile 循环变量：阻止编译器把常量次数循环"迭代剥离"成多个
     * 调用点（不同 PC → 不同栈 hash → 同一场景被拆成多个站点） */
    int first_no_probable = 1;
    for (volatile int round = 0; round < 3; round++) {
        scenario_cycle();
        sleep(3);        /* 超过 2s 阈值 → 老化 */
        trigger_scan();  /* 观测 */
        if (round == 0 && rpt != NULL) {
            first_no_probable = (!find_conf(rpt, SIZE_A, "probable"))
                             && (!find_conf(rpt, SIZE_B, "probable"));
        }
        if (round < 2) {
            mtt_free(g_keep_b); /* 老化释放：模拟收到重启 RPC 信号 */
            g_keep_b = NULL;
            trigger_scan();     /* 本轮消失，证据保留 */
        }
    }

    /* 场景 C：增长型泄漏 —— 每轮观测存活数都在涨(7×3=21)。
     * 不能只涨一轮：peak_updated 会触发 reporter 提前扫描把峰值
     * 棘轮到位，之后的稳定扫描会降级 long_lived。持续增长才能
     * 在任意扫描时刻保持 probable —— 这也是真泄漏的实际特征。 */
    for (volatile int r = 0; r < 3; r++) {
        scenario_grow(7);
        sleep(3);
        trigger_scan();
    }

    printf("--- assertions ---\n");
    if (!classic)
        CHECK(first_no_probable, "first scan: no site jumps to probable");
    else
        printf("  %-58s SKIP (classic mode marks aged sites probable)\n",
               "first scan: no site jumps to probable");
    CHECK(find_conf(rpt, SIZE_A, classic ? "probable" : "long_lived"),
          classic ? "scenario A (held forever) -> probable (classic)"
                  : "scenario A (held forever) -> long_lived");
    CHECK(find_conf(rpt, SIZE_B, classic ? "probable" : "session_scoped"),
          classic ? "scenario B (freed on signal, re-alloc) -> probable (classic)"
                  : "scenario B (freed on signal, re-alloc) -> session_scoped");
    CHECK(find_conf(rpt, 21 * SIZE_C, "probable"),
          "scenario C (growing leak) -> probable");

    printf("---\nResult: %s (%d failure%s)\n",
           g_fail == 0 ? "ALL TESTS PASSED" : "SOME TESTS FAILED",
           g_fail, g_fail == 1 ? "" : "s");
    return g_fail == 0 ? 0 : 1;
}

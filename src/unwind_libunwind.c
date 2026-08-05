/*
 * MemoryTraceTool — libunwind 栈回溯实现(静态链接 + dlopen 软依赖双模式)。
 *
 * 详见 unwind_libunwind.h 头部说明。
 *
 * 静态模式(MTT_STATIC_LIBUNWIND):
 *   - unw_backtrace 在链接期解析到静态库符号,无 dlopen/dlsym/pthread_once 开销
 *   - mtt_libunwind_available() 恒为 1(除非运行时崩溃被永久禁用)
 *
 * dlopen 模式(默认):
 *   - pthread_once 串行化首次加载,dlsym 解析 unw_backtrace
 *   - 失败时永久标记不可用,后续调用零开销短路(atomic load)
 *   - dlsym/dlopen 本身线程安全(POSIX 保证)
 *
 * SIGSEGV/SIGBUS 信号保护(双模式共有):
 *   背景:libunwind 1.8.2 在 ARM32 上走到某些缺 .ARM.exidx 的 .so 内部
 *   时,unw_step 可能解引用无效指针触发 SIGSEGV,整个被监控进程崩溃。
 *   典型场景:HDM3 storageManager 进程加载闭源厂商库,libunwind 走进去就崩。
 *
 *   方案:
 *   - 全局 mutex 串行化 capture 调用
 *   - sigaction 临时注册 SIGSEGV/SIGBUS handler
 *   - sigsetjmp 保存上下文,handler 用 siglongjmp 跳回
 *   - 崩过一次永久标记 libunwind 不可用,后续零开销走 backtrace fallback
 *
 * ARM32 Thumb bit 处理(两种模式一致):
 *   libunwind 返回的地址在 Thumb 模式下 LSB=1,统一清除。
 *   复用 MTT_FIX_THUMB_ADDR 宏(mtt_internal.h)。
 */
#define _GNU_SOURCE
#include "unwind_libunwind.h"

#include <stddef.h>
#include <stdatomic.h>
#include <pthread.h>
#include <setjmp.h>
#include <signal.h>
#include <unistd.h>

#include "mtt_internal.h"   /* MTT_FIX_THUMB_ADDR, mtt_log_stage */

/* ======================================================================== *
 *                  共享:SIGSEGV/SIGBUS 信号保护                             *
 * ======================================================================== */

/* 永久禁用标志:运行时崩溃后置 1,后续所有 capture 走 backtrace fallback。
 * 用 atomic 保证多线程可见性,崩溃后所有线程立即停止使用 libunwind */
static _Atomic int g_libunwind_disabled = 0;

/* 串行化 mutex:同一时刻只有一个线程在 unw_backtrace 调用中,
 * 防止多线程同时触发 handler 时跳错 sigjmp_buf */
static pthread_mutex_t g_unwind_mutex = PTHREAD_MUTEX_INITIALIZER;

/* sigsetjmp 缓冲区 + 进入标志。
 * mutex 保证单线程独占,这两个变量无需 thread_local */
static sigjmp_buf          g_unwind_jmp;
static volatile sig_atomic_t g_in_unwind_call = 0;

/**
 * SIGSEGV/SIGBUS 临时 handler:libunwind 崩溃时跳回 capture 调用点。
 *
 * 设计要点:
 *   - 仅在 g_in_unwind_call=1 时拦截,其余场景恢复 SIG_DFL 并 raise,
 *     不影响进程原有信号处理(被监控业务可能依赖 SIGSEGV 跑 core dump)
 *   - siglongjmp 是 async-signal-safe(POSIX 明确保证)
 *   - 不持有任何锁,跳回后由 mtt_safe_unw_backtrace 继续清理 */
static void mtt_unwind_crash_handler(int sig, siginfo_t *info, void *uctx)
{
    (void)info; (void)uctx;
    if (g_in_unwind_call) {
        /* 在 libunwind 调用中触发信号:跳回 sigsetjmp 调用点,
         * siglongjmp 第二参数传 sig(非零),sigsetjmp 返回 sig */
        g_in_unwind_call = 0;
        siglongjmp(g_unwind_jmp, sig);
    }
    /* 不在 libunwind 调用中:恢复默认处理,重新 raise 让进程走原 core dump 流程 */
    struct sigaction dfl;
    dfl.sa_handler = SIG_DFL;
    dfl.sa_flags = 0;
    sigemptyset(&dfl.sa_mask);
    sigaction(sig, &dfl, NULL);
    raise(sig);
}

/**
 * 调用 unw_backtrace,带 SIGSEGV/SIGBUS 信号保护。
 *
 * 流程:
 *   1. 加锁串行化
 *   2. 临时安装 SIGSEGV/SIGBUS handler
 *   3. sigsetjmp 保存上下文
 *   4. 调用 unw_backtrace
 *   5. 恢复原 handler,解锁
 *   6. 若崩溃:永久禁用 libunwind,返回 -1
 *
 * @param fn         unw_backtrace 函数指针(静态模式直接取 &unw_backtrace)
 * @param frames     输出帧数组
 * @param max_frames 数组容量
 * @return           ≥0=帧数,-1=libunwind 崩溃或调用失败 */
static int mtt_safe_unw_backtrace(int (*fn)(void **, int),
                                  void **frames, int max_frames)
{
    struct sigaction old_segv, old_bus;
    struct sigaction sa;
    sa.sa_sigaction = mtt_unwind_crash_handler;
    sa.sa_flags = SA_SIGINFO | SA_NODEFER;
    sigemptyset(&sa.sa_mask);

    pthread_mutex_lock(&g_unwind_mutex);

    sigaction(SIGSEGV, &sa, &old_segv);
    sigaction(SIGBUS,  &sa, &old_bus);

    g_in_unwind_call = 1;
    int sig = sigsetjmp(g_unwind_jmp, 1);

    int n = 0;
    int crashed = (sig != 0);
    if (!crashed) {
        n = fn(frames, max_frames);
        if (n < 0) n = 0;
    }
    g_in_unwind_call = 0;

    sigaction(SIGSEGV, &old_segv, NULL);
    sigaction(SIGBUS,  &old_bus, NULL);

    pthread_mutex_unlock(&g_unwind_mutex);

    if (crashed) {
        /* 永久禁用 libunwind:所有线程后续直接走 backtrace fallback,
         * atomic_store 保证其他线程立即可见 */
        atomic_store_explicit(&g_libunwind_disabled, 1, memory_order_release);
        mtt_log_stage(31, "unw_backtrace crashed (signal %d), libunwind disabled permanently", sig);
        return -1;
    }
    return n;
}

/* ======================================================================== *
 *                  模式 1: 静态链接(MTT_STATIC_LIBUNWIND)                    *
 * ======================================================================== */

#ifdef MTT_STATIC_LIBUNWIND

#include <libunwind.h>   /* unw_backtrace 声明 */

int mtt_libunwind_available(void)
{
    /* 静态链接:符号已链入,但运行时崩溃后被永久禁用则返回 0 */
    if (atomic_load_explicit(&g_libunwind_disabled, memory_order_acquire))
        return 0;
    return 1;
}

int mtt_libunwind_capture(void **frames, int max_frames)
{
    if (frames == NULL || max_frames <= 0) return -1;

    /* 运行时崩溃后永久短路,零开销 */
    if (atomic_load_explicit(&g_libunwind_disabled, memory_order_acquire))
        return -1;

    /* 第一次调用时输出阶段日志,定位 libunwind 是否触发 */
    static _Atomic int g_first_capture = 1;
    int is_first = atomic_compare_exchange_strong(&g_first_capture,
                                                  &(int){1}, 0);

    int n = mtt_safe_unw_backtrace(unw_backtrace, frames, max_frames);
    if (n < 0) {
        /* 崩溃或失败,返回 -1,让上层 fallback 到 backtrace */
        if (is_first) {
            mtt_log_stage(30, "first unw_backtrace failed/crashed");
        }
        return -1;
    }

    if (is_first) {
        mtt_log_stage(30, "first unw_backtrace done frames=%d", n);
    }

    /* 清除 ARM32 Thumb bit(LSB=1),与 dlopen 路径后处理保持一致,
     * 让下游 hash/dladdr 不受 Thumb 状态干扰 */
    for (int i = 0; i < n; i++)
        frames[i] = MTT_FIX_THUMB_ADDR(frames[i]);

    return n;
}

#else
/* ======================================================================== *
 *                  模式 2: dlopen 软依赖(开发/CI 默认)                       *
 * ======================================================================== */

#include <dlfcn.h>

/* libunwind unw_backtrace 函数指针类型
 * 原型: int unw_backtrace(void **buffer, int size);
 * 行为与 glibc backtrace() 相同,内部走 libunwind 多策略 unwind */
typedef int (*mtt_unw_backtrace_fn)(void **, int);

/* ---- 全局状态 ---- */

typedef struct {
    void                *handle;       /* dlopen 句柄,NULL=未加载 */
    mtt_unw_backtrace_fn backtrace;    /* unw_backtrace 函数指针 */
    atomic_int           available;    /* 0=未探测, 1=可用, -1=不可用 */
    pthread_once_t       once;         /* 串行化首次加载 */
} libunwind_state_t;

static libunwind_state_t g_libunwind = {
    .handle    = NULL,
    .backtrace = NULL,
    .available = 0,
    .once      = PTHREAD_ONCE_INIT,
};

/* ---- 内部加载函数 ---- */

/**
 * dlopen 加载 libunwind 并解析 unw_backtrace 符号。
 *
 * 尝试顺序(覆盖常见发行版):
 *   1. libunwind.so.8       — Debian/Ubuntu 标准名
 *   2. libunwind.so.7       — 较旧发行版
 *   3. libunwind.so         — 开发机或自定义构建
 *   4. libunwind-aarch64.so.8 / libunwind-arm.so.8 — 架构特定(少见)
 *
 * 符号解析:
 *   优先 unw_backtrace(对外公共符号),
 *   兜底 _UL_backtrace / _U_backtrace(libunwind 内部命名)。
 */
static void try_load_libunwind(void)
{
    /* 候选 soname:从最常见到兜底 */
    static const char *const sonames[] = {
        "libunwind.so.8",
        "libunwind.so.7",
        "libunwind.so",
        "libunwind-aarch64.so.8",
        "libunwind-arm.so.8",
        NULL,
    };

    for (int i = 0; sonames[i] != NULL; i++) {
        g_libunwind.handle = dlopen(sonames[i], RTLD_LAZY | RTLD_LOCAL);
        if (g_libunwind.handle != NULL) break;
    }

    if (g_libunwind.handle == NULL) {
        atomic_store_explicit(&g_libunwind.available, -1, memory_order_release);
        return;
    }

    /* 解析 unw_backtrace 函数指针:尝试多个可能的符号名 */
    static const char *const symbols[] = {
        "unw_backtrace",     /* 公共 API (libunwind.h 声明) */
        "_UL_backtrace",     /* 本地 unwind 命名 */
        "_U_backtrace",      /* 通用命名 */
        NULL,
    };
    for (int i = 0; symbols[i] != NULL; i++) {
        g_libunwind.backtrace =
            (mtt_unw_backtrace_fn)dlsym(g_libunwind.handle, symbols[i]);
        if (g_libunwind.backtrace != NULL) break;
    }

    if (g_libunwind.backtrace != NULL) {
        atomic_store_explicit(&g_libunwind.available, 1, memory_order_release);
    } else {
        /* 库加载了但没有 backtrace 符号(罕见):关闭并永久标记不可用 */
        dlclose(g_libunwind.handle);
        g_libunwind.handle = NULL;
        atomic_store_explicit(&g_libunwind.available, -1, memory_order_release);
    }
}

/* ---- 公共 API ---- */

int mtt_libunwind_available(void)
{
    /* 运行时崩溃后永久禁用 */
    if (atomic_load_explicit(&g_libunwind_disabled, memory_order_acquire))
        return 0;
    pthread_once(&g_libunwind.once, try_load_libunwind);
    return atomic_load_explicit(&g_libunwind.available, memory_order_acquire) == 1;
}

int mtt_libunwind_capture(void **frames, int max_frames)
{
    if (frames == NULL || max_frames <= 0) return -1;

    /* 运行时崩溃后永久短路 */
    if (atomic_load_explicit(&g_libunwind_disabled, memory_order_acquire))
        return -1;

    pthread_once(&g_libunwind.once, try_load_libunwind);
    if (atomic_load_explicit(&g_libunwind.available, memory_order_acquire) != 1)
        return -1;

    int n = mtt_safe_unw_backtrace(g_libunwind.backtrace, frames, max_frames);
    if (n < 0) return -1;

    /* 清除 ARM32 Thumb bit(LSB=1),与 backtrace() 后处理保持一致,
     * 让下游 hash/dladdr 不受 Thumb 状态干扰 */
    for (int i = 0; i < n; i++)
        frames[i] = MTT_FIX_THUMB_ADDR(frames[i]);

    return n;
}

#endif /* MTT_STATIC_LIBUNWIND */

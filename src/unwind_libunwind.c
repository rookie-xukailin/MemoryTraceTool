/*
 * MemoryTraceTool — libunwind 栈回溯实现(静态链接 + dlopen 软依赖双模式)。
 *
 * 详见 unwind_libunwind.h 头部说明。
 *
 * 静态模式(MTT_STATIC_LIBUNWIND):
 *   - 直接链入 unw_getcontext / unw_init_local / unw_step / unw_get_reg
 *   - 用细粒度 step 循环替代高层 unw_backtrace,崩溃时保留已回溯帧
 *   - mtt_libunwind_available() 恒为 1(除非该线程被运行时崩溃永久禁用)
 *
 * dlopen 模式(默认):
 *   - pthread_once 串行化首次加载,dlsym 解析 unw_backtrace
 *   - 失败时永久标记不可用,后续调用零开销短路(atomic load)
 *   - dlsym/dlopen 本身线程安全(POSIX 保证)
 *   - 注意:dlopen 模式下用高层 unw_backtrace,崩溃只能返回 -1
 *     (libunwind 的 unw_* 都是宏,没法 dlsym 细粒度 API)
 *
 * SIGSEGV/SIGBUS 信号保护 + per-thread 降级 + 部分帧保留(双模式共有):
 *   背景:libunwind 1.8.2 在 ARM32 上走到某些缺 .ARM.exidx 的 .so 内部
 *   时,unw_step 可能解引用无效指针触发 SIGSEGV,整个被监控进程崩溃。
 *   典型场景:HDM3 storageManager 进程加载闭源厂商库,libunwind 走进去就崩。
 *
 *   方案(per-thread 粒度 + 部分帧保留):
 *   - 全局 mutex 串行化 capture 调用,保证 handler 不跨线程干扰
 *   - sigaction 临时注册 SIGSEGV/SIGBUS handler
 *   - sigsetjmp 保存上下文,handler 用 siglongjmp 跳回
 *   - 静态模式:手动 unw_step 循环,每步成功后更新 g_unwind_safe_frames
 *     崩溃时返回 g_unwind_safe_frames(崩溃前的所有帧都保留)
 *   - 跳回后用 pthread_setspecific 标记**当前线程** libunwind 已禁用
 *   - 该线程后续 capture 直接走 FP chain 兜底,零开销
 *   - 其他线程未触发崩溃,继续用 libunwind 拿深栈
 *
 *   为什么不用全局降级:
 *   多线程进程里,线程 A 调用闭源库可能崩,线程 B 调用开源库完全 OK。
 *   全局禁用会让线程 B 也丢失深栈,降低监控价值。per-thread 粒度更合理。
 *
 * ARM32 Thumb bit 处理(两种模式一致):
 *   libunwind 返回的地址在 Thumb 模式下 LSB=1,统一清除。
 *   复用 MTT_FIX_THUMB_ADDR 宏(mtt_internal.h)。
 */
#define _GNU_SOURCE
#include "unwind_libunwind.h"

#include <stddef.h>
#include <stdio.h>
#include <stdatomic.h>
#include <pthread.h>
#include <setjmp.h>
#include <signal.h>
#include <unistd.h>

#include "mtt_internal.h"   /* MTT_FIX_THUMB_ADDR, mtt_log_stage */

/* ======================================================================== *
 *           模式 0: 无 libunwind 集成(MTT_NO_LIBUNWIND)                       *
 * ======================================================================== *
 * ARM64 / 本机默认走此路径(由 Makefile MTT_LIBUNWIND_STATIC 控制)。
 *
 * 原因:libunwind 静态链接进 .so(dd1145f)会破坏 glibc backtrace — bt_test
 * 实测铁证,挂工具后 n=0(原本 n=6)。ARM64 + 业务二进制 .eh_frame 完整时,
 * glibc backtrace 工作正常,不需要 libunwind。
 *
 * 此模式下:
 *   - mtt_libunwind_available() 恒返回 0 → mtt_capture_stack 自然走 backtrace
 *   - mtt_libunwind_capture() 永不被调
 *   - SIGSEGV handler / per-thread 降级 / mutex 等机制不编译(零开销)
 *
 * ARM32 仍走 libunwind 集成路径(compile-arm32.sh 传 MTT_LIBUNWIND_STATIC=1),
 * 因为 ARM32 -fomit-frame-pointer 业务上 glibc backtrace 拿不到深栈。 */
#ifdef MTT_NO_LIBUNWIND

int mtt_libunwind_available(void) { return 0; }

int mtt_libunwind_capture(void **frames, int max_frames)
{
    (void)frames; (void)max_frames;
    return -1;
}

int mtt_libunwind_thread_disabled(void) { return 0; }

/* 简单 backtrace 包装(无信号保护,因为无 libunwind 不会触发 SIGSEGV handler)。
 * MTT_NO_LIBUNWIND 模式下,thread_disabled 恒返回 0,capture_stack 永不调用
 * 本函数(disabled 路径)。保留实现仅为链接通过。 */
#if MTT_HAS_BACKTRACE
#include <execinfo.h>
int mtt_safe_backtrace(void **frames, int max_frames)
{
    if (frames == NULL || max_frames <= 0) return 0;
    return backtrace(frames, max_frames);
}
#else
int mtt_safe_backtrace(void **frames, int max_frames)
{
    (void)frames; (void)max_frames;
    return 0;
}
#endif

#else  /* !MTT_NO_LIBUNWIND — 以下代码仅在 libunwind 集成时编译 */

/* ======================================================================== *
 *        共享:SIGSEGV/SIGBUS 信号保护 + per-thread 降级                     *
 * ======================================================================== */

/* per-thread 降级标志。
 * pthread_key_create 用 pthread_once 懒初始化,首次访问时建立。
 * pthread_setspecific/pthread_getspecific 不能在 signal handler 里调用
 * (非 async-signal-safe),所以 mark 必须在 siglongjmp 跳回后做。 */
static pthread_key_t  g_disabled_key;
static pthread_once_t g_key_once = PTHREAD_ONCE_INIT;

static void mtt_make_disabled_key(void)
{
    (void)pthread_key_create(&g_disabled_key, NULL);
}

int mtt_libunwind_thread_disabled(void)
{
    (void)pthread_once(&g_key_once, mtt_make_disabled_key);
    return pthread_getspecific(g_disabled_key) != NULL;
}

static inline void mtt_libunwind_disable_this_thread(void)
{
    (void)pthread_once(&g_key_once, mtt_make_disabled_key);
    (void)pthread_setspecific(g_disabled_key, (void *)(intptr_t)1);
}

/* 串行化 mutex:同一时刻只有一个线程在 unw_backtrace 调用中,
 * 防止多线程同时触发 handler 时跳错 sigjmp_buf */
static pthread_mutex_t g_unwind_mutex = PTHREAD_MUTEX_INITIALIZER;

/* sigsetjmp 缓冲区 + 进入标志 + 已成功回溯帧数。
 * mutex 保证单线程独占,这三个变量无需 thread_local。
 * g_unwind_safe_frames 在每次 capture 入口清零,每步 unw_step 成功后更新,
 * 崩溃时由 mtt_safe_unw_backtrace 读取作为返回值 */
static sigjmp_buf          g_unwind_jmp;
static volatile sig_atomic_t g_in_unwind_call = 0;
static volatile sig_atomic_t g_unwind_safe_frames = 0;
/* 崩溃访问的无效地址(si_addr),定位崩在哪个 .so 用。每次 capture 入口清零。 */
static volatile uintptr_t  g_crash_addr = 0;

/**
 * SIGSEGV/SIGBUS 临时 handler:libunwind 崩溃时跳回 capture 调用点。
 *
 * 设计要点:
 *   - 仅在 g_in_unwind_call=1 时拦截,其余场景恢复 SIG_DFL 并 raise,
 *     不影响进程原有信号处理(被监控业务可能依赖 SIGSEGV 跑 core dump)
 *   - siglongjmp 是 async-signal-safe(POSIX 明确保证)
 *   - 不持有任何锁,跳回后由 mtt_safe_unw_backtrace 继续清理
 *   - 不调用 pthread_setspecific(非 async-signal-safe),mark 留给上层 */
static void mtt_unwind_crash_handler(int sig, siginfo_t *info, void *uctx)
{
    (void)uctx;
    if (g_in_unwind_call) {
        /* 记录崩溃访问的无效地址(si_addr),供日志定位崩在哪个 .so */
        if (info != NULL)
            g_crash_addr = (uintptr_t)info->si_addr;
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

/* ======================================================================== *
 *                  模式 1: 静态链接(MTT_STATIC_LIBUNWIND)                    *
 * ======================================================================== */

#ifdef MTT_STATIC_LIBUNWIND

#include <libunwind.h>   /* unw_* API */

/**
 * 细粒度 unwind:用 unw_init_local + unw_step + unw_get_reg 循环。
 *
 * 与高层 unw_backtrace 区别:
 *   - unw_backtrace 是黑盒,崩了之后无法知道已回溯多少帧
 *   - 细粒度循环每步更新 g_unwind_safe_frames,崩溃时该值就是有效帧数
 *
 * 行为:
 *   - 跳过当前帧(unw_getcontext 那帧,即 mtt_unwind_step_loop 自身)
 *     与 unw_backtrace 行为一致
 *   - 每步 unw_step 成功后 unw_get_reg 取 IP 写入 frames[n]
 *   - g_unwind_safe_frames 在每次写入后更新(确保 frames[n-1] 已就绪)
 *
 * 注意:本函数运行在信号保护上下文内(mtt_safe_unw_backtrace 已注册 handler),
 *       如果 unw_step 触发 SIGSEGV/SIGBUS,handler 用 siglongjmp 跳回,
 *       本函数不会返回,函数剩余代码不会执行。 */
static int mtt_unwind_step_loop(void **frames, int max_frames)
{
    unw_context_t ctx;
    unw_cursor_t  cursor;

    if (unw_getcontext(&ctx) < 0) return 0;
    if (unw_init_local(&cursor, &ctx) < 0) return 0;

    int n = 0;
    while (n < max_frames) {
        /* 移动到下一帧。崩溃通常发生在这里:unw_step 内部访问 .ARM.exidx
         * 表 + 栈帧,缺表或栈被破坏时解引用无效指针 */
        int ret = unw_step(&cursor);
        if (ret <= 0) break;

        unw_word_t pc;
        if (unw_get_reg(&cursor, UNW_REG_IP, &pc) != UNW_ESUCCESS) break;

        frames[n++] = (void *)pc;
        /* 关键:每步成功后立即更新 g_unwind_safe_frames。
         * 若下一步 unw_step 崩了,handler 跳回,本函数不返回,
         * 调用方通过 g_unwind_safe_frames 拿到本次循环已写入的帧数 */
        g_unwind_safe_frames = n;
    }

    return n;
}

int mtt_libunwind_available(void)
{
    /* 静态链接:符号已链入。但当前线程若被 per-thread 降级,返回 0 */
    if (mtt_libunwind_thread_disabled())
        return 0;
    return 1;
}

int mtt_libunwind_capture(void **frames, int max_frames)
{
    if (frames == NULL || max_frames <= 0) return -1;

    /* 当前线程已崩过 libunwind,永久短路 */
    if (mtt_libunwind_thread_disabled())
        return -1;

    /* 第一次调用时输出阶段日志,定位 libunwind 是否触发 */
    static _Atomic int g_first_capture = 1;
    int is_first = atomic_compare_exchange_strong(&g_first_capture,
                                                  &(int){1}, 0);

    /* 信号保护上下文 */
    struct sigaction old_segv, old_bus;
    struct sigaction sa;
    sa.sa_sigaction = mtt_unwind_crash_handler;
    sa.sa_flags = SA_SIGINFO | SA_NODEFER;
    sigemptyset(&sa.sa_mask);

    pthread_mutex_lock(&g_unwind_mutex);

    sigaction(SIGSEGV, &sa, &old_segv);
    sigaction(SIGBUS,  &sa, &old_bus);

    g_unwind_safe_frames = 0;
    g_crash_addr = 0;
    g_in_unwind_call = 1;
    int sig = sigsetjmp(g_unwind_jmp, 1);

    int n = 0;
    int crashed = (sig != 0);
    if (!crashed) {
        n = mtt_unwind_step_loop(frames, max_frames);
        if (n < 0) n = 0;
    } else {
        /* 崩了:取已成功回溯的帧数(可能 0..N-1)
         * frames[0..n-1] 都已被 mtt_unwind_step_loop 写入有效 IP */
        n = (int)g_unwind_safe_frames;
    }
    g_in_unwind_call = 0;

    sigaction(SIGSEGV, &old_segv, NULL);
    sigaction(SIGBUS,  &old_bus, NULL);

    pthread_mutex_unlock(&g_unwind_mutex);

    if (crashed) {
        /* per-thread 降级:本线程后续 capture 直接返回 -1,
         * 其他线程不受影响 */
        mtt_libunwind_disable_this_thread();
        /* 崩溃属关键事件:用 MTT_LOG_INFO(等级 >= 1 输出),不走 stage(等级 2)
         * 用户在 MTT_DEBUG=1 默认模式下也能看到 libunwind 降级提示 */
        {
            char cbuf[192];
            int clen = snprintf(cbuf, sizeof(cbuf),
                "[MTT] libunwind crashed (signal %d) at frame %d, kept %d partial frames, "
                "crash_addr=0x%lx, this thread falls back to FP chain\n",
                sig, n + 1, n, (unsigned long)g_crash_addr);
            if (clen > 0 && clen < (int)sizeof(cbuf))
                MTT_LOG_INFO(cbuf, (size_t)clen);
            /* 崩溃时把已回溯的部分帧打出来,定位崩在哪个 .so(仅崩溃一次,非热路径) */
            for (int i = 0; i < n && i < MTT_STACK_DEPTH; i++) {
                char fbuf[96];
                int flen = snprintf(fbuf, sizeof(fbuf),
                    "[MTT]   frame %d: 0x%lx\n",
                    i, (unsigned long)frames[i]);
                if (flen > 0 && flen < (int)sizeof(fbuf))
                    MTT_LOG_INFO(fbuf, (size_t)flen);
            }
        }
        mtt_log_stage(31, "unw_step crashed (signal %d) at frame %d, kept %d partial frames",
                      sig, n + 1, n);
        /* 关键:返回 n 而非 -1,把崩溃前的部分帧交给上层使用 */
        if (n >= 1) {
            /* 有部分帧,清除 Thumb bit 后返回 */
            for (int i = 0; i < n; i++)
                frames[i] = MTT_FIX_THUMB_ADDR(frames[i]);
            return n;
        }
        /* n == 0:第一帧就崩了,完全没拿到栈,返回 -1 让上层 fallback */
        if (is_first) {
            mtt_log_stage(30, "first unw_step crashed at frame 1");
        }
        return -1;
    }

    if (is_first) {
        mtt_log_stage(30, "first unw_step loop done frames=%d", n);
    }

    /* 清除 ARM32 Thumb bit(LSB=1),让下游 hash/dladdr 不受 Thumb 状态干扰 */
    for (int i = 0; i < n; i++)
        frames[i] = MTT_FIX_THUMB_ADDR(frames[i]);

    return n;
}

#else
/* ======================================================================== *
 *                  模式 2: dlopen 软依赖(开发/CI 默认)                       *
 * ======================================================================== */

#include <dlfcn.h>

/* libunwind unw_backtrace 函数指针类型 */
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
    /* 当前线程已被 per-thread 降级 */
    if (mtt_libunwind_thread_disabled())
        return 0;
    pthread_once(&g_libunwind.once, try_load_libunwind);
    return atomic_load_explicit(&g_libunwind.available, memory_order_acquire) == 1;
}

int mtt_libunwind_capture(void **frames, int max_frames)
{
    if (frames == NULL || max_frames <= 0) return -1;

    /* 当前线程已崩过 libunwind,永久短路 */
    if (mtt_libunwind_thread_disabled())
        return -1;

    pthread_once(&g_libunwind.once, try_load_libunwind);
    if (atomic_load_explicit(&g_libunwind.available, memory_order_acquire) != 1)
        return -1;

    /* dlopen 模式:用高层 unw_backtrace + 信号保护。
     * 与静态模式不同,这里没法做细粒度 step(libunwind 的 unw_* 是宏,
     * 无法 dlsym),崩了只能返回 -1,部分帧全部丢失 */
    struct sigaction old_segv, old_bus;
    struct sigaction sa;
    sa.sa_sigaction = mtt_unwind_crash_handler;
    sa.sa_flags = SA_SIGINFO | SA_NODEFER;
    sigemptyset(&sa.sa_mask);

    pthread_mutex_lock(&g_unwind_mutex);

    sigaction(SIGSEGV, &sa, &old_segv);
    sigaction(SIGBUS,  &sa, &old_bus);

    g_crash_addr = 0;
    g_in_unwind_call = 1;
    int sig = sigsetjmp(g_unwind_jmp, 1);

    int n = 0;
    int crashed = (sig != 0);
    if (!crashed) {
        n = g_libunwind.backtrace(frames, max_frames);
        if (n < 0) n = 0;
    }
    g_in_unwind_call = 0;

    sigaction(SIGSEGV, &old_segv, NULL);
    sigaction(SIGBUS,  &old_bus, NULL);

    pthread_mutex_unlock(&g_unwind_mutex);

    if (crashed) {
        /* dlopen 模式下没法拿到部分帧,只能放弃 */
        mtt_libunwind_disable_this_thread();
        /* 关键事件:等级 >= 1 输出 */
        {
            char cbuf[160];
            int clen = snprintf(cbuf, sizeof(cbuf),
                "[MTT] libunwind crashed (signal %d), crash_addr=0x%lx, this thread falls back to backtrace/FP chain\n",
                sig, (unsigned long)g_crash_addr);
            if (clen > 0 && clen < (int)sizeof(cbuf))
                MTT_LOG_INFO(cbuf, (size_t)clen);
        }
        mtt_log_stage(31, "unw_backtrace crashed (signal %d), no partial frames (dlopen mode)", sig);
        return -1;
    }

    /* 清除 ARM32 Thumb bit(LSB=1),与静态模式后处理保持一致 */
    for (int i = 0; i < n; i++)
        frames[i] = MTT_FIX_THUMB_ADDR(frames[i]);

    return n;
}

#endif /* MTT_STATIC_LIBUNWIND */

/* ======================================================================== *
 *        共享:glibc backtrace 信号保护(thread_disabled 后兜底)              *
 * ======================================================================== */

#if MTT_HAS_BACKTRACE
#include <execinfo.h>

/**
 * 调用 glibc backtrace(),复用 libunwind 路径已有的 SIGSEGV/SIGBUS 保护框架。
 *
 * 设计:与 mtt_libunwind_capture 共享 g_unwind_mutex / g_unwind_jmp / handler。
 * backtrace 内部走 libgcc _Unwind_Backtrace,在缺 .ARM.exidx 的栈上会崩,
 * 信号保护让它跳回返回 0,让上层走 FP chain 兜底,不 core dump。
 *
 * 何时用:libunwind 本线程被降级后(thread_disabled),仍需尝试 backtrace
 * 拿浅栈——后续 capture 栈不同(不同 malloc 调用点),backtrace 大概率正常。
 * 直接跳过 backtrace 会让长期持有的内存全无栈信息(leak 表全是空栈)。
 */
int mtt_safe_backtrace(void **frames, int max_frames)
{
    if (frames == NULL || max_frames <= 0) return 0;

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
        n = backtrace(frames, max_frames);
        if (n < 0) n = 0;
    }
    g_in_unwind_call = 0;

    sigaction(SIGSEGV, &old_segv, NULL);
    sigaction(SIGBUS,  &old_bus, NULL);

    pthread_mutex_unlock(&g_unwind_mutex);

    if (crashed) {
        /* backtrace 踩雷(同一栈上 _Unwind_Backtrace 也踩):返回 0,
         * 上层走 FP chain 兜底。不 mark thread_disabled——下次 capture
         * 栈不同,backtrace 大概率正常 */
        mtt_log_stage(35, "backtrace crashed (signal %d), skip to FP chain", sig);
        return 0;
    }
    return n;
}

#else /* !MTT_HAS_BACKTRACE */

/* 非 glibc 平台(musl/bionic):backtrace 不存在,直接返回 0 */
int mtt_safe_backtrace(void **frames, int max_frames)
{
    (void)frames; (void)max_frames;
    return 0;
}

#endif /* MTT_HAS_BACKTRACE */

#endif /* !MTT_NO_LIBUNWIND */

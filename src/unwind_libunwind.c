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
 *   - **并行模式(默认)**:sigjmp 上下文用 __thread TLS,每线程独立,
 *     无 mutex,sigaction 一次性安装 + chain 到业务原 handler
 *   - **串行 fallback 模式(MTT_UNWIND_PARALLEL=0 或 TLS 不可靠)**:
 *     沿用全局 mutex + sigjmp_buf,行为等价于改造前
 *   - 静态模式:手动 unw_step 循环,每步成功后更新 safe_frames
 *     崩溃时返回 safe_frames(崩溃前的所有帧都保留)
 *   - 跳回后用 pthread_setspecific 标记**当前线程** libunwind 已禁用
 *   - 该线程后续 capture 直接走 FP chain 兜底,零开销
 *   - 其他线程未触发崩溃,继续用 libunwind 拿深栈
 *
 *   为什么不用全局降级:
 *   多线程进程里,线程 A 调用闭源库可能崩,线程 B 调用开源库完全 OK。
 *   全局禁用会让线程 B 也丢失深栈,降低监控价值。per-thread 粒度更合理。
 *
 * 并行模式设计(unwind-parallel 改造,2026-08):
 *   背景:原串行模式下,8 线程并发 malloc 时 g_unwind_mutex 成为瓶颈,
 *   多核 CPU 失效,RPC P99 长尾。BMC storageManager 加载工具后 CPU +30%。
 *
 *   关键洞察:mutex 当初(commit 839821a)是为防 siglongjmp 跳错全局 jmp_buf,
 *   不是为防并发数据竞争。把全局 jmp_buf 改 __thread TLS 后,handler 通过
 *   TLS 自动识别当前线程,可消除 mutex。__thread 在 signal handler 里访问
 *   是 async-signal-safe(底层 TCB 寄存器读),项目已在 commit fa87bb8 验证
 *   __thread + TID 核对模式可用。
 *
 *   配套改造:sigaction 一次性安装(init 时单线程,无 race),handler 内
 *   chain 到业务原 handler(SIG_DFL/SIG_IGN/sa_handler/SA_SIGINFO 全覆盖),
 *   reporter 60s 心跳监控业务是否覆盖 mtt handler 并自动重装。
 *
 *   兜底:MTT_UNWIND_PARALLEL=0 一键回退到串行模式;TLS 可靠性自检失败
 *   也自动降级。详见 plan: bmc-cpu-rpc-4-8-malloc-inherited-meerkat.md。
 *
 * ARM32 Thumb bit 处理(两种模式一致):
 *   libunwind 返回的地址在 Thumb 模式下 LSB=1,统一清除。
 *   复用 MTT_FIX_THUMB_ADDR 宏(mtt_internal.h)。
 */
#define _GNU_SOURCE
#include "unwind_libunwind.h"

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdatomic.h>
#include <pthread.h>
#include <setjmp.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <sys/syscall.h>
#include <errno.h>

#include "mtt_internal.h"   /* MTT_FIX_THUMB_ADDR, mtt_log_stage */

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

/* ======================================================================== *
 *        并行 vs 串行 模式控制(unwind-parallel 改造)                       *
 * ======================================================================== *
 *   g_use_parallel_unwind=1(默认):走 TLS 路径,无 mutex,多核并行
 *   g_use_parallel_unwind=0:        走全局 mutex fallback(TLS 不可靠设备兜底)
 *
 *   决策来源:
 *     1. 环境变量 MTT_UNWIND_PARALLEL=0 强制串行
 *     2. mtt_init 阶段 TLS 可靠性自检失败自动降级
 *
 *   关键不变量:并行模式下,handler 通过 TLS 字段识别当前线程,
 *   siglongjmp 永远跳回当前线程的 tls_unwind_jmp,绝不会跨线程跳错。
 */
int g_use_parallel_unwind = 1;

/* ---- TLS 上下文(并行模式专用)---- */
static __thread sigjmp_buf          tls_unwind_jmp;
static __thread volatile sig_atomic_t tls_in_unwind_call = 0;
static __thread volatile sig_atomic_t tls_unwind_safe_frames = 0;
static __thread volatile uintptr_t  tls_crash_addr = 0;

/* ---- 全局 fallback 上下文(串行模式专用,沿用原 mutex 模式)---- */
static pthread_mutex_t g_unwind_mutex = PTHREAD_MUTEX_INITIALIZER;
static sigjmp_buf          g_unwind_jmp_fallback;
static volatile sig_atomic_t g_in_unwind_call_fallback = 0;
static volatile sig_atomic_t g_unwind_safe_frames_fallback = 0;
static volatile uintptr_t  g_crash_addr_fallback = 0;

/* ---- sigaction 一次性安装状态(并行模式专用)---- */
static struct sigaction g_saved_segv_handler;
static struct sigaction g_saved_bus_handler;
static int              g_handler_installed = 0;
/* handler 安装锁(init 阶段单线程,但 reporter 重装时多线程可能并发) */
static pthread_mutex_t  g_install_lock = PTHREAD_MUTEX_INITIALIZER;

/* 前向声明 */
static void mtt_unwind_crash_handler(int sig, siginfo_t *info, void *uctx);

/* ======================================================================== *
 *        sigaction 一次性安装 + handler chain(unwind-parallel 改造)        *
 * ======================================================================== */

/**
 * 安装 SIGSEGV/SIGBUS handler(并行模式专用)。
 *
 * 在 mtt_init 阶段(单线程)和 reporter 心跳检测到业务覆盖时(多线程,
 * 通过 g_install_lock 串行化)调用。保存业务原 handler 到 g_saved_*,
 * 后续 mtt_unwind_crash_handler 不在 unwind 调用中时 chain 调用业务 handler。
 *
 * 设计要点:
 *   - SA_SIGINFO:handler 用三参数签名(拿 si_addr 定位崩在哪个 .so)
 *   - SA_NODEFER:允许 handler 内再触发同信号(chain 业务 handler 时用)
 *   - sa_mask 空:不屏蔽其他信号,降低延迟
 *   - 业务原 handler 可能是 SIG_DFL/SIG_IGN/sa_handler/SA_SIGINFO 四种之一,
 *     handler 内 chain 时分别处理
 *
 * 线程安全:init 阶段单线程无 race;reporter 重装时持 g_install_lock。
 */
void mtt_install_unwind_handler(void)
{
    pthread_mutex_lock(&g_install_lock);

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = mtt_unwind_crash_handler;
    sa.sa_flags = SA_SIGINFO | SA_NODEFER;
    sigemptyset(&sa.sa_mask);

    /* 保存业务原 handler(可能是 SIG_DFL/SIG_IGN/自定义),用于 chain */
    sigaction(SIGSEGV, &sa, &g_saved_segv_handler);
    sigaction(SIGBUS,  &sa, &g_saved_bus_handler);
    g_handler_installed = 1;

    pthread_mutex_unlock(&g_install_lock);
}

/**
 * 检查 SIGSEGV/SIGBUS handler 是否被业务覆盖,若覆盖则重装。
 *
 * 由 reporter 60s 心跳调用。如果业务在 mtt_init 后 dlopen JVM/Go runtime/
 * libasan 等装了自己的 SIGSEGV handler,会覆盖 mtt 的,导致 libunwind 崩溃
 * 保护失效。本函数检测到覆盖后,重装 mtt handler 并保存新的业务 handler
 * 用于 chain。
 *
 * 线程安全:reporter 单线程调用,但内部仍持 g_install_lock 防御性。
 */
void mtt_check_handler_overridden(void)
{
    if (!g_handler_installed || !g_use_parallel_unwind) return;

    struct sigaction cur_segv, cur_bus;
    sigaction(SIGSEGV, NULL, &cur_segv);
    sigaction(SIGBUS,  NULL, &cur_bus);

    int overridden = 0;
    if (cur_segv.sa_sigaction != mtt_unwind_crash_handler ||
        cur_bus.sa_sigaction  != mtt_unwind_crash_handler) {
        overridden = 1;
    }

    if (overridden) {
        char buf[160];
        int len = snprintf(buf, sizeof(buf),
            "[MTT] WARNING: SIGSEGV/SIGBUS handler overridden by business code, "
            "reinstalling mtt handler (chain preserved)\n");
        if (len > 0 && len < (int)sizeof(buf))
            MTT_LOG_INFO(buf, (size_t)len);
        mtt_install_unwind_handler();
    }
}

/**
 * TLS 可靠性自检:验证 __thread 变量在多线程下不互相污染。
 *
 * 背景(commit 55cce13):某些 ARM64 BMC 设备 TLS 不可靠,__thread 跨线程
 * 共享。本次并行模式依赖 TLS,启动时自检失败则降级到串行模式。
 *
 * 测试方法:主线程设值 → 创建子线程设不同值 → join → 检查主线程值不变。
 *
 * @return 1=TLS 可靠,可走并行模式;0=不可靠,需走串行 fallback
 */
static __thread int tls_self_test_value = 0;

static void* mtt_tls_self_test_thread(void *arg)
{
    tls_self_test_value = 0xABCD;
    usleep(5000);  /* 5ms,等主线程也设值,放大跨线程污染概率 */
    *(int*)arg = tls_self_test_value;
    return NULL;
}

int mtt_check_tls_reliability(void)
{
    tls_self_test_value = 0x1234;
    int child_value = 0;

    pthread_t t;
    if (pthread_create(&t, NULL, mtt_tls_self_test_thread, &child_value) != 0)
        return 0;  /* 连线程都创建不了,保守返回不可靠 */
    pthread_join(t, NULL);

    /* 主线程的值应该始终是 0x1234(不被子线程污染) */
    if (tls_self_test_value != 0x1234) return 0;
    /* 子线程的值应该是它自己设的 0xABCD(不被主线程污染) */
    if (child_value != 0xABCD) return 0;
    return 1;
}

/* 获取当前线程 TID(用于 TLS 字段核对,防 TLS 不可靠场景)。
 * 若 syscall 失败返回 -1。 */
static inline pid_t mtt_gettid_fast(void)
{
    return (pid_t)syscall(SYS_gettid);
}

/**
 * SIGSEGV/SIGBUS handler:libunwind 崩溃时跳回,或 chain 到业务原 handler。
 *
 * 设计要点(unwind-parallel 改造):
 *   - **优先**检查 tls_in_unwind_call(TLS 读,自动识别当前线程):
 *       是 → siglongjmp 到当前线程的 tls_unwind_jmp
 *   - **其次**检查 g_in_unwind_call_fallback(串行模式全局标志):
 *       是 → siglongjmp 到 g_unwind_jmp_fallback
 *   - **都不在** unwind 调用中:chain 到业务原 handler
 *       (SIG_DFL/SIG_IGN/sa_handler/SA_SIGINFO 四种分别处理)
 *
 * async-signal-safe 保证:
 *   - siglongjmp / sigaction / raise / pthread_sigmask / signal 均为
 *     POSIX 明确 async-signal-safe
 *   - __thread 访问底层是 TCB 寄存器读 + 固定 offset,无函数调用,安全
 *   - 不调用 pthread_setspecific(留给上层 siglongjmp 跳回后做)
 */
static void mtt_unwind_crash_handler(int sig, siginfo_t *info, void *uctx)
{
    /* 1. 优先检查并行模式 TLS 标志 */
    if (tls_in_unwind_call) {
        if (info != NULL)
            tls_crash_addr = (uintptr_t)info->si_addr;
        tls_in_unwind_call = 0;
        siglongjmp(tls_unwind_jmp, sig);
    }

    /* 2. 串行 fallback 模式全局标志 */
    if (g_in_unwind_call_fallback) {
        if (info != NULL)
            g_crash_addr_fallback = (uintptr_t)info->si_addr;
        g_in_unwind_call_fallback = 0;
        siglongjmp(g_unwind_jmp_fallback, sig);
    }

    /* 3. 都不在 unwind 中,chain 到业务原 handler */
    struct sigaction *saved = (sig == SIGSEGV)
        ? &g_saved_segv_handler : &g_saved_bus_handler;

    /* 临时屏蔽本信号,防业务 handler 内再次触发导致栈嵌套溢出 */
    sigset_t mask, oldmask;
    sigemptyset(&mask);
    sigaddset(&mask, sig);
    pthread_sigmask(SIG_BLOCK, &mask, &oldmask);

    if (saved->sa_flags & SA_SIGINFO) {
        /* 业务用 sa_sigaction 三参数 handler。
         * sa_sigaction 与 sa_handler 在 struct sigaction 里是 union 共享内存,
         * 业务若装的是 SIG_IGN/SIG_DFL,sa_sigaction 字段也会是这两个值。
         * 用强制类型转换消除 GCC -Wcompare-distinct-pointer-types 警告。 */
        void (*h)(int, siginfo_t *, void *) = saved->sa_sigaction;
        if (h != NULL && h != (void (*)(int, siginfo_t *, void *))SIG_IGN
            && h != (void (*)(int, siginfo_t *, void *))SIG_DFL) {
            h(sig, info, uctx);
        } else if (h == (void (*)(int, siginfo_t *, void *))SIG_IGN) {
            /* 业务明确忽略,尊重 */
        } else {
            /* SIG_DFL 或异常:恢复默认行为(通常 core dump) */
            struct sigaction dfl;
            memset(&dfl, 0, sizeof(dfl));
            dfl.sa_handler = SIG_DFL;
            sigemptyset(&dfl.sa_mask);
            sigaction(sig, &dfl, NULL);
            raise(sig);
        }
    } else {
        /* 业务用 sa_handler 单参数 handler */
        void (*h)(int) = saved->sa_handler;
        if (h == SIG_IGN) {
            /* 忽略 */
        } else if (h == SIG_DFL || h == NULL) {
            struct sigaction dfl;
            memset(&dfl, 0, sizeof(dfl));
            dfl.sa_handler = SIG_DFL;
            sigemptyset(&dfl.sa_mask);
            sigaction(sig, &dfl, NULL);
            raise(sig);
        } else {
            h(sig);
        }
    }

    pthread_sigmask(SIG_SETMASK, &oldmask, NULL);
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
 *   - 细粒度循环每步更新 *safe_frames,崩溃时该值就是有效帧数
 *
 * 行为:
 *   - 跳过当前帧(unw_getcontext 那帧,即 mtt_unwind_step_loop 自身)
 *     与 unw_backtrace 行为一致
 *   - 每步 unw_step 成功后 unw_get_reg 取 IP 写入 frames[n]
 *   - *safe_frames 在每次写入后更新(确保 frames[n-1] 已就绪)
 *
 * 参数:
 *   - safe_frames:调用方提供的"已成功帧数"指示器(并行模式指向 TLS,
 *     串行模式指向全局 fallback)。崩溃时 handler 跳回后,调用方读此值。
 *
 * 注意:本函数运行在信号保护上下文内(mtt_safe_unw_backtrace 已注册 handler),
 *       如果 unw_step 触发 SIGSEGV/SIGBUS,handler 用 siglongjmp 跳回,
 *       本函数不会返回,函数剩余代码不会执行。 */
static int mtt_unwind_step_loop(void **frames, int max_frames,
                                volatile sig_atomic_t *safe_frames)
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
        /* 关键:每步成功后立即更新 *safe_frames。
         * 若下一步 unw_step 崩了,handler 跳回,本函数不返回,
         * 调用方通过 *safe_frames 拿到本次循环已写入的帧数 */
        *safe_frames = n;
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

    if (g_use_parallel_unwind) {
        /* ---- 并行路径:TLS 上下文,无 mutex,sigaction 已在 init 时装好 ---- */
        tls_unwind_safe_frames = 0;
        tls_crash_addr = 0;
        tls_in_unwind_call = 1;
        int sig = sigsetjmp(tls_unwind_jmp, 1);

        int n = 0;
        int crashed = (sig != 0);
        if (!crashed) {
            n = mtt_unwind_step_loop(frames, max_frames, &tls_unwind_safe_frames);
            if (n < 0) n = 0;
        } else {
            n = (int)tls_unwind_safe_frames;
        }
        tls_in_unwind_call = 0;

        if (crashed) {
            mtt_libunwind_disable_this_thread();
            {
                char cbuf[192];
                int clen = snprintf(cbuf, sizeof(cbuf),
                    "[MTT] libunwind crashed (signal %d) at frame %d, kept %d partial frames, "
                    "crash_addr=0x%lx, this thread falls back to FP chain (parallel mode)\n",
                    sig, n + 1, n, (unsigned long)tls_crash_addr);
                if (clen > 0 && clen < (int)sizeof(cbuf))
                    MTT_LOG_INFO(cbuf, (size_t)clen);
                for (int i = 0; i < n && i < MTT_STACK_DEPTH; i++) {
                    char fbuf[96];
                    int flen = snprintf(fbuf, sizeof(fbuf),
                        "[MTT]   frame %d: 0x%lx\n",
                        i, (unsigned long)frames[i]);
                    if (flen > 0 && flen < (int)sizeof(fbuf))
                        MTT_LOG_INFO(fbuf, (size_t)flen);
                }
            }
            mtt_log_stage(31, "unw_step crashed (signal %d) at frame %d, kept %d partial frames (parallel)",
                          sig, n + 1, n);
            if (n >= 1) {
                for (int i = 0; i < n; i++)
                    frames[i] = MTT_FIX_THUMB_ADDR(frames[i]);
                return n;
            }
            if (is_first) mtt_log_stage(30, "first unw_step crashed at frame 1 (parallel)");
            return -1;
        }

        if (is_first) mtt_log_stage(30, "first unw_step loop done frames=%d (parallel)", n);

        for (int i = 0; i < n; i++)
            frames[i] = MTT_FIX_THUMB_ADDR(frames[i]);
        return n;
    }

    /* ---- 串行 fallback 路径:沿用全局 mutex + 每 capture 装/恢复 sigaction ----
     * 行为完全等价于改造前(commit 839821a 原版),用于 TLS 不可靠设备兜底 */
    struct sigaction old_segv, old_bus;
    struct sigaction sa;
    sa.sa_sigaction = mtt_unwind_crash_handler;
    sa.sa_flags = SA_SIGINFO | SA_NODEFER;
    sigemptyset(&sa.sa_mask);

    pthread_mutex_lock(&g_unwind_mutex);

    sigaction(SIGSEGV, &sa, &old_segv);
    sigaction(SIGBUS,  &sa, &old_bus);

    g_unwind_safe_frames_fallback = 0;
    g_crash_addr_fallback = 0;
    g_in_unwind_call_fallback = 1;
    int sig = sigsetjmp(g_unwind_jmp_fallback, 1);

    int n = 0;
    int crashed = (sig != 0);
    if (!crashed) {
        n = mtt_unwind_step_loop(frames, max_frames, &g_unwind_safe_frames_fallback);
        if (n < 0) n = 0;
    } else {
        n = (int)g_unwind_safe_frames_fallback;
    }
    g_in_unwind_call_fallback = 0;

    sigaction(SIGSEGV, &old_segv, NULL);
    sigaction(SIGBUS,  &old_bus, NULL);

    pthread_mutex_unlock(&g_unwind_mutex);

    if (crashed) {
        /* per-thread 降级:本线程后续 capture 直接返回 -1,
         * 其他线程不受影响 */
        mtt_libunwind_disable_this_thread();
        {
            char cbuf[192];
            int clen = snprintf(cbuf, sizeof(cbuf),
                "[MTT] libunwind crashed (signal %d) at frame %d, kept %d partial frames, "
                "crash_addr=0x%lx, this thread falls back to FP chain (serial mode)\n",
                sig, n + 1, n, (unsigned long)g_crash_addr_fallback);
            if (clen > 0 && clen < (int)sizeof(cbuf))
                MTT_LOG_INFO(cbuf, (size_t)clen);
            for (int i = 0; i < n && i < MTT_STACK_DEPTH; i++) {
                char fbuf[96];
                int flen = snprintf(fbuf, sizeof(fbuf),
                    "[MTT]   frame %d: 0x%lx\n",
                    i, (unsigned long)frames[i]);
                if (flen > 0 && flen < (int)sizeof(fbuf))
                    MTT_LOG_INFO(fbuf, (size_t)flen);
            }
        }
        mtt_log_stage(31, "unw_step crashed (signal %d) at frame %d, kept %d partial frames (serial)",
                      sig, n + 1, n);
        if (n >= 1) {
            for (int i = 0; i < n; i++)
                frames[i] = MTT_FIX_THUMB_ADDR(frames[i]);
            return n;
        }
        if (is_first) mtt_log_stage(30, "first unw_step crashed at frame 1 (serial)");
        return -1;
    }

    if (is_first) mtt_log_stage(30, "first unw_step loop done frames=%d (serial)", n);

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

    if (g_use_parallel_unwind) {
        /* ---- 并行路径:TLS 上下文,无 mutex ---- */
        tls_crash_addr = 0;
        tls_in_unwind_call = 1;
        int sig = sigsetjmp(tls_unwind_jmp, 1);

        int n = 0;
        int crashed = (sig != 0);
        if (!crashed) {
            n = g_libunwind.backtrace(frames, max_frames);
            if (n < 0) n = 0;
        }
        tls_in_unwind_call = 0;

        if (crashed) {
            mtt_libunwind_disable_this_thread();
            {
                char cbuf[160];
                int clen = snprintf(cbuf, sizeof(cbuf),
                    "[MTT] libunwind crashed (signal %d), crash_addr=0x%lx, "
                    "this thread falls back to backtrace/FP chain (parallel dlopen)\n",
                    sig, (unsigned long)tls_crash_addr);
                if (clen > 0 && clen < (int)sizeof(cbuf))
                    MTT_LOG_INFO(cbuf, (size_t)clen);
            }
            mtt_log_stage(31, "unw_backtrace crashed (signal %d), no partial frames (parallel dlopen)", sig);
            return -1;
        }

        for (int i = 0; i < n; i++)
            frames[i] = MTT_FIX_THUMB_ADDR(frames[i]);
        return n;
    }

    /* ---- 串行 fallback 路径 ---- */
    struct sigaction old_segv, old_bus;
    struct sigaction sa;
    sa.sa_sigaction = mtt_unwind_crash_handler;
    sa.sa_flags = SA_SIGINFO | SA_NODEFER;
    sigemptyset(&sa.sa_mask);

    pthread_mutex_lock(&g_unwind_mutex);

    sigaction(SIGSEGV, &sa, &old_segv);
    sigaction(SIGBUS,  &sa, &old_bus);

    g_crash_addr_fallback = 0;
    g_in_unwind_call_fallback = 1;
    int sig = sigsetjmp(g_unwind_jmp_fallback, 1);

    int n = 0;
    int crashed = (sig != 0);
    if (!crashed) {
        n = g_libunwind.backtrace(frames, max_frames);
        if (n < 0) n = 0;
    }
    g_in_unwind_call_fallback = 0;

    sigaction(SIGSEGV, &old_segv, NULL);
    sigaction(SIGBUS,  &old_bus, NULL);

    pthread_mutex_unlock(&g_unwind_mutex);

    if (crashed) {
        /* dlopen 模式下没法拿到部分帧,只能放弃 */
        mtt_libunwind_disable_this_thread();
        {
            char cbuf[160];
            int clen = snprintf(cbuf, sizeof(cbuf),
                "[MTT] libunwind crashed (signal %d), crash_addr=0x%lx, "
                "this thread falls back to backtrace/FP chain (serial dlopen)\n",
                sig, (unsigned long)g_crash_addr_fallback);
            if (clen > 0 && clen < (int)sizeof(cbuf))
                MTT_LOG_INFO(cbuf, (size_t)clen);
        }
        mtt_log_stage(31, "unw_backtrace crashed (signal %d), no partial frames (serial dlopen)", sig);
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

    if (g_use_parallel_unwind) {
        /* ---- 并行路径:TLS 上下文,无 mutex ---- */
        tls_in_unwind_call = 1;
        int sig = sigsetjmp(tls_unwind_jmp, 1);

        int n = 0;
        int crashed = (sig != 0);
        if (!crashed) {
            n = backtrace(frames, max_frames);
            if (n < 0) n = 0;
        }
        tls_in_unwind_call = 0;

        if (crashed) {
            mtt_log_stage(35, "backtrace crashed (signal %d), skip to FP chain (parallel)", sig);
            return 0;
        }
        return n;
    }

    /* ---- 串行 fallback 路径 ---- */
    struct sigaction old_segv, old_bus;
    struct sigaction sa;
    sa.sa_sigaction = mtt_unwind_crash_handler;
    sa.sa_flags = SA_SIGINFO | SA_NODEFER;
    sigemptyset(&sa.sa_mask);

    pthread_mutex_lock(&g_unwind_mutex);

    sigaction(SIGSEGV, &sa, &old_segv);
    sigaction(SIGBUS,  &sa, &old_bus);

    g_in_unwind_call_fallback = 1;
    int sig = sigsetjmp(g_unwind_jmp_fallback, 1);

    int n = 0;
    int crashed = (sig != 0);
    if (!crashed) {
        n = backtrace(frames, max_frames);
        if (n < 0) n = 0;
    }
    g_in_unwind_call_fallback = 0;

    sigaction(SIGSEGV, &old_segv, NULL);
    sigaction(SIGBUS,  &old_bus, NULL);

    pthread_mutex_unlock(&g_unwind_mutex);

    if (crashed) {
        /* backtrace 踩雷(同一栈上 _Unwind_Backtrace 也踩):返回 0,
         * 上层走 FP chain 兜底。不 mark thread_disabled——下次 capture
         * 栈不同,backtrace 大概率正常 */
        mtt_log_stage(35, "backtrace crashed (signal %d), skip to FP chain (serial)", sig);
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

/* ======================================================================== *
 *        Test-only helpers(仅测试代码调用,生产代码不引用)                 *
 * ======================================================================== *
 *  暴露给 tests/test_signal.c / test_concurrent.c 用于验证 SIGSEGV 拦截
 *  跳回机制。生产 .so 会包含这些符号但不会被业务调用。
 */

/**
 * 在 unwind 上下文中触发 SIGSEGV,验证 handler 拦截 + siglongjmp 跳回。
 *
 * 流程:
 *   1. 设置 tls_in_unwind_call=1(模拟在 libunwind 调用中)
 *   2. sigsetjmp 保存上下文到 tls_unwind_jmp
 *   3. 第一次调用(sig==0):解引用无效地址 0xdeadbeef 触发 SIGSEGV
 *   4. handler 拦截 → siglongjmp 跳回 → sigsetjmp 返回 SIGSEGV(11)
 *   5. 第二次调用(sig!=0):返回 sig 值,调用方验证跳回成功
 *
 * @param use_parallel 1=走并行 TLS 路径,0=走串行 fallback 路径
 * @return 0=未触发(异常),>0=收到的信号编号(SIGSEGV=11)
 */
int mtt_test_trigger_sigsegv_in_unwind(int use_parallel)
{
    if (use_parallel) {
        tls_in_unwind_call = 1;
        int sig = sigsetjmp(tls_unwind_jmp, 1);
        if (sig == 0) {
            /* 触发 SIGSEGV:解引用无效地址。
             * volatile 防止编译器优化掉 */
            volatile int *bad = (volatile int*)0xdeadbeef;
            *bad = 42;
            /* 不应该到这里,handler 应该跳回来 */
            tls_in_unwind_call = 0;
            return 0;
        }
        tls_in_unwind_call = 0;
        return sig;
    } else {
        g_in_unwind_call_fallback = 1;
        int sig = sigsetjmp(g_unwind_jmp_fallback, 1);
        if (sig == 0) {
            volatile int *bad = (volatile int*)0xdeadbeef;
            *bad = 42;
            g_in_unwind_call_fallback = 0;
            return 0;
        }
        g_in_unwind_call_fallback = 0;
        return sig;
    }
}

/**
 * 查询当前 SIGSEGV handler 是否是 mtt 的(用于验证 mtt_install_unwind_handler)。
 * @return 1=是 mtt handler,0=不是
 */
int mtt_test_segv_handler_is_mtt(void)
{
    struct sigaction cur;
    memset(&cur, 0, sizeof(cur));
    sigaction(SIGSEGV, NULL, &cur);
    return cur.sa_sigaction == mtt_unwind_crash_handler;
}

/**
 * 获取保存的业务原 SIGSEGV handler 的 sa_sigaction(用于验证 chain)。
 * @param out_idx 0=SIGSEGV,1=SIGBUS
 * @return 业务原 handler 的 sa_sigaction 值(可能是 SIG_DFL/SIG_IGN/函数指针)
 */
void mtt_test_get_saved_handler(int idx, void (**out)(int, siginfo_t*, void*))
{
    if (out == NULL) return;
    if (idx == 0) *out = g_saved_segv_handler.sa_sigaction;
    else          *out = g_saved_bus_handler.sa_sigaction;
}

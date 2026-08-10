/*
 * MemoryTraceTool — libunwind 栈回溯(静态链接 + dlopen 软依赖双模式)。
 *
 * 两种集成模式:
 *
 * 1. MTT_STATIC_LIBUNWIND (推荐,生产部署):
 *    libunwind 源码作为 git submodule 编译进我们的 .so,-l:libunwind.a 静态链接。
 *    优势:目标机零依赖,unw_backtrace 符号在链接期解析,运行时无 dlopen 开销。
 *    详见 Makefile vendor/libunwind 构建目标。
 *
 * 2. dlopen 软依赖 (开发/CI 默认):
 *    运行时 dlopen libunwind.so.8,缺失时自动回退到 glibc backtrace()。
 *    适合开发机/CI 不愿引入 libunwind 源码的场景。
 *
 * 公共 API (mtt_libunwind_available / mtt_libunwind_capture) 两种模式下行为一致。
 *
 * 为什么选 unw_backtrace 而非 unw_init_local+step:
 *   - unw_backtrace 是 libunwind 提供的高层 API,内部自管理 cursor(可达 4KB)
 *   - 调用方无需关心 unw_cursor_t 的平台相关大小
 *   - 行为与 glibc backtrace() 接近,无缝替换
 *
 * 性能:
 *   - libunwind 在 ARM32 上比 glibc backtrace 慢 5-20 倍(多策略 unwind 开销)
 *   - 现有采样机制(MTT_SAMPLE_RATE)可控制总开销
 *   - 单次捕获典型 < 100us,对热路径可接受
 */
#ifndef MTT_UNWIND_LIBUNWIND_H
#define MTT_UNWIND_LIBUNWIND_H

#include <signal.h>   /* siginfo_t, sigaction(test-only API 用) */

/**
 * 探测 libunwind 是否可用。
 *
 * 静态链接模式(MTT_STATIC_LIBUNWIND):始终返回 1(编译期已链入)。
 * dlopen 模式:懒加载 + 缓存结果,首次调用触发探测。
 *
 * @return 1=可用,0=不可用
 */
int mtt_libunwind_available(void);

/**
 * 用 libunwind 捕获当前调用栈。
 *
 * @param frames      输出帧数组
 * @param max_frames  数组容量
 * @return            实际帧数(≥0),-1=libunwind 不可用或捕获失败
 *
 * 注意:本函数会清除 ARM32 Thumb bit(返回地址 LSB),与 backtrace() 后处理一致,
 *       调用方拿到即可直接用于 hash/dladdr。
 */
int mtt_libunwind_capture(void **frames, int max_frames);

/**
 * 当前线程是否已被 per-thread 降级(libunwind 崩过)。
 *
 * 调用方(如 mtt_capture_stack)应在调用 backtrace 前检查:
 * 已降级线程的栈上存在缺 .ARM.exidx 的坏 .so,libunwind 走进去会崩,
 * glibc backtrace 内部用 _Unwind_Backtrace 同样会崩。
 *
 * @return 1=本线程 libunwind 已禁用,应跳过 backtrace 走 FP chain 兜底
 *         0=本线程 libunwind 正常
 */
int mtt_libunwind_thread_disabled(void);

/**
 * 调用 glibc backtrace(),带 SIGSEGV/SIGBUS 信号保护。
 *
 * 用途:libunwind 被本线程降级(thread_disabled)后的兜底栈回溯。
 * glibc backtrace 内部走 libgcc _Unwind_Backtrace,在缺 .ARM.exidx
 * 的栈上同样会崩。本函数包信号保护,崩了 siglongjmp 跳回,返回 0,
 * 让上层走 FP chain 兜底,不 core dump。
 *
 * 注意:per-thread 降级后**不应完全跳过 backtrace**——只有 libunwind
 * 踩雷的那次 capture 的栈是坏栈,后续 capture 栈不同(不同 malloc
 * 调用点),backtrace 大概率正常。直接跳过会让长期持有的内存全部
 * 丢失栈信息(leak 表全是空栈)。
 *
 * @param frames      输出帧数组
 * @param max_frames  数组容量
 * @return            ≥0=帧数,踩雷或调用失败返回 0
 */
int mtt_safe_backtrace(void **frames, int max_frames);

/* ======================================================================== *
 *        unwind-parallel 改造:并行 vs 串行模式控制 + 监控补偿              *
 * ======================================================================== *
 *  详见 unwind_libunwind.c 头部说明和 plan:
 *  bmc-cpu-rpc-4-8-malloc-inherited-meerkat.md
 *
 *  改造目标:消除 mtt_libunwind_capture 内 g_unwind_mutex 全局串行化,
 *  让栈回溯多核并行,缓解 BMC 多线程业务 CPU 飙升 + RPC P99 长尾超时。
 *
 *  核心思路:全局 sigjmp_buf 改 __thread TLS,handler 通过 TLS 自动识别
 *  当前线程,siglongjmp 永远跳回当前线程的 buf,无需 mutex 串行化。
 *
 *  关键不变量:
 *    - libunwind 触发 SIGSEGV/SIGBUS 时 handler 必须拦截跳回(commit 839821a)
 *    - per-thread 降级机制(commit 8129a5c)不变
 *    - MTT_UNWIND_PARALLEL=0 一键回退到串行 fallback
 *    - TLS 可靠性自检失败自动降级
 */

/* 并行模式开关。
 *   1 = 并行(默认):TLS 上下文,无 mutex,多核并行
 *   0 = 串行 fallback:全局 mutex + 每 capture 装/恢复 sigaction
 *
 * 由 mtt_ensure_init 解析 MTT_UNWIND_PARALLEL 设置,
 * TLS 自检失败也会自动改为 0。 */
extern int g_use_parallel_unwind;

/**
 * 安装 SIGSEGV/SIGBUS handler(并行模式专用)。
 *
 * 在 mtt_init 阶段(单线程)和 reporter 心跳检测到业务覆盖时(多线程,
 * 通过 g_install_lock 串行化)调用。保存业务原 handler 用于 chain。
 *
 * 线程安全:init 阶段单线程无 race;reporter 重装时持 g_install_lock。
 */
void mtt_install_unwind_handler(void);

/**
 * 检查 SIGSEGV/SIGBUS handler 是否被业务覆盖,若覆盖则重装。
 *
 * 由 reporter 60s 心跳调用。如果业务在 mtt_init 后 dlopen JVM/Go runtime/
 * libasan 等装了自己的 SIGSEGV handler,会覆盖 mtt 的,导致 libunwind 崩溃
 * 保护失效。本函数检测到覆盖后,重装 mtt handler 并保存新的业务 handler
 * 用于 chain。
 */
void mtt_check_handler_overridden(void);

/**
 * TLS 可靠性自检:验证 __thread 变量在多线程下不互相污染。
 *
 * 背景(commit 55cce13):某些 ARM64 BMC 设备 TLS 不可靠。本次并行模式
 * 依赖 TLS,启动时自检失败则降级到串行模式。
 *
 * @return 1=TLS 可靠,可走并行模式;0=不可靠,需走串行 fallback
 */
int mtt_check_tls_reliability(void);

/* ======================================================================== *
 *        Test-only helpers(仅测试代码调用,生产代码不引用)                 *
 * ======================================================================== */

/**
 * 在 unwind 上下文中触发 SIGSEGV,验证 handler 拦截 + siglongjmp 跳回。
 * 仅 tests/test_signal.c 等测试代码调用。
 *
 * @param use_parallel 1=走并行 TLS 路径,0=走串行 fallback 路径
 * @return 0=未触发(异常),>0=收到的信号编号(SIGSEGV=11)
 */
int mtt_test_trigger_sigsegv_in_unwind(int use_parallel);

/**
 * 查询当前 SIGSEGV handler 是否是 mtt 的(测试用)。
 * @return 1=是 mtt handler,0=不是
 */
int mtt_test_segv_handler_is_mtt(void);

/**
 * 获取保存的业务原 handler 的 sa_sigaction(测试用,验证 chain)。
 * @param idx 0=SIGSEGV,1=SIGBUS
 * @param out 输出业务原 handler 的函数指针
 */
void mtt_test_get_saved_handler(int idx, void (**out)(int, siginfo_t*, void*));

#endif /* MTT_UNWIND_LIBUNWIND_H */

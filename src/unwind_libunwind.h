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
 *     sigaction 一次性安装(优化:省每次 capture 的 4 次 sigaction syscall)  *
 * ======================================================================== *
 *  原实现每次 mtt_libunwind_capture / mtt_safe_backtrace 都要装/恢复
 *  sigaction 共 4 次 syscall(~4μs/次),是单次 capture 的 fixed cost 大头。
 *  本函数把 sigaction 安装移到 mtt_init 阶段一次性完成。
 *
 *  关键约束(避免 unwind-parallel 失败教训):
 *    - 不动 g_unwind_mutex(串行化保留)
 *    - 不动 g_in_unwind_call / g_unwind_jmp(全局变量保留)
 *    - 不动 mtt_unwind_crash_handler(handler 行为完全不变)
 *    - 不做 handler chain(简化,BMC 业务不装 SIGSEGV)
 *
 *  兼容性兜底:如果业务真的装了 SIGSEGV handler 覆盖 mtt 的,
 *  libunwind 崩溃保护失效,可用 MTT_UNWINDER=backtrace 绕过。
 */

/**
 * 一次性安装 SIGSEGV/SIGBUS handler(sigaction 优化)。
 *
 * 在 mtt_init 阶段(init_lock 内)调用,后续 capture 不再装/恢复 sigaction。
 * 幂等:多次调用通过 g_handler_installed 标志保证只装一次。
 */
void mtt_install_unwind_handler(void);

/* ======================================================================== *
 *        Test-only helpers(仅测试代码调用,生产代码不引用)                 *
 * ======================================================================== */

/**
 * 在 unwind 上下文触发 SIGSEGV,验证 handler 拦截 + siglongjmp 跳回。
 * 仅 tests/test_sigaction_install.c 等测试代码调用。
 * @return 0=未触发(异常),>0=收到的信号编号(SIGSEGV=11)
 */
int mtt_test_trigger_sigsegv_in_unwind(void);

/**
 * 查询当前 SIGSEGV handler 是否是 mtt 的(测试用)。
 * @return 1=是 mtt handler,0=不是
 */
int mtt_test_segv_handler_is_mtt(void);

#endif /* MTT_UNWIND_LIBUNWIND_H */

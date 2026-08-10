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

#endif /* MTT_UNWIND_LIBUNWIND_H */

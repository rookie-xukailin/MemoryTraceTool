/*
 * MemoryTraceTool — libunwind 软依赖栈回溯。
 *
 * 通过 dlopen 运行时加载 libunwind.so.8,失败时自动回退到 glibc backtrace()。
 * 避免对目标设备/构建工具链的硬依赖:libunwind 缺失不影响工具运行。
 *
 * 工作原理:
 *   1. 首次 mtt_libunwind_capture() 触发 pthread_once → try_load_libunwind()
 *   2. dlopen 尝试多个 soname(libunwind.so.8 / libunwind-aarch64.so.8 等)
 *   3. dlsym 解析 unw_backtrace 符号(可能名为 unw_backtrace 或 _UL_backtrace)
 *   4. 成功 → 后续调用直接走函数指针;失败 → 永久标记不可用,零开销短路
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
 * 探测 libunwind 是否可用(懒加载 + 缓存结果)。
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

#endif /* MTT_UNWIND_LIBUNWIND_H */

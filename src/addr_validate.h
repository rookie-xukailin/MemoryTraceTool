/*
 * MemoryTraceTool — 可执行地址区间校验模块。
 *
 * 通过解析 /proc/self/maps 缓存所有可执行（r-xp）映射段，
 * 供栈回溯（FP chain、stack scan）验证候选返回地址是否合法。
 *
 * 设计：
 *   - 启动时一次性读取 /proc/self/maps，缓存到静态数组
 *   - 二分查找 O(log N)，N ≤ 256
 *   - pthread_once 保证只解析一次，无锁热路径
 *   - 提供 mtt_addr_validate_refresh() 在 dlopen 后刷新
 *
 * 线程安全：
 *   - init 阶段：pthread_once 串行化
 *   - 读路径：atomic load g_range_count + 静态数组只读，无竞争
 *
 * 降级：
 *   - /proc 不可用时 g_range_count 恒为 0，所有校验返回 0（deny），
 *     FP chain/stack scan 由此自动失效，不影响 backtrace 主路径
 */
#ifndef MTT_ADDR_VALIDATE_H
#define MTT_ADDR_VALIDATE_H

#include <stddef.h>

/**
 * 初始化可执行段缓存（懒加载，pthread_once 保证只解析一次）。
 *
 * 首次调用阻塞读取 /proc/self/maps；后续调用立即返回。
 * 失败时不抛错，仅令 g_range_count 保持 0。
 */
void mtt_addr_validate_init(void);

/**
 * 强制重新解析 /proc/self/maps。
 *
 * 适用场景：目标进程 dlopen 加载新 .so 后，新映射的可执行段
 * 需要进入缓存才能通过校验。reporter 周期扫描时调用一次即可。
 */
void mtt_addr_validate_refresh(void);

/**
 * 判断地址是否落在某个可执行映射内。
 *
 * @param addr  待校验地址（任意，含或不含 Thumb bit）
 * @return      1=落在 r-xp 段内，0=不在或缓存为空
 *
 * 注意：本函数会自动清除 Thumb bit（ARM32 兼容），调用者无需预处理。
 */
int mtt_addr_is_executable(void *addr);

/**
 * 查询地址所属的可执行映像短名（basename）。
 *
 * @param addr  待查询地址
 * @return      短名指针（如 "libc-2.31.so"），未命中返回 NULL
 *              返回的指针指向静态缓冲区，无需释放，下一次 refresh 前一直有效
 */
const char* mtt_addr_libname(void *addr);

#endif /* MTT_ADDR_VALIDATE_H */

/*
 * MemoryTraceTool — 公共 API。
 *
 * 本头文件提供两种使用模式：
 *
 *   模式 1: LD_PRELOAD（推荐，零配置）
 *     LD_PRELOAD=libmemorytracetool.so ./target_app
 *     无需包含任何头文件，无需修改源码。库自动拦截 malloc/free，
 *     每 60s 输出泄漏报告到 /var/log/mtt/<pid>_<process_name>.log。
 *
 *   模式 2: 显式链接（开发调试）
 *     链接 libmemorytracetool.so，调用 mtt_malloc/mtt_free 系列函数，
 *     或定义 MTT_MACRO_MODE 宏重定向标准 malloc 到追踪版本。
 *     通过 mtt_get_* 统计函数查询运行时状态。
 */

#ifndef MEMORYTRACETOOL_H
#define MEMORYTRACETOOL_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ======================================================================== *
 *                    宏模式：重定向标准 malloc 系列                              *
 * ======================================================================== */

#ifdef MTT_MACRO_MODE
#undef  malloc
#undef  free
#undef  calloc
#undef  realloc
#define malloc(s)       mtt_malloc(s)
#define free(p)         mtt_free(p)
#define calloc(c,s)     mtt_calloc(c,s)
#define realloc(p,s)    mtt_realloc(p,s)
#endif

/* ======================================================================== *
 *                   追踪分配函数（显式调用）                                     *
 * ======================================================================== */

/** 分配 size 字节内存并记录追踪信息 */
void* mtt_malloc(size_t size);

/** 释放内存并从追踪表删除 */
void  mtt_free(void *ptr);

/** 分配并零初始化内存 */
void* mtt_calloc(size_t count, size_t size);

/** 重新分配内存 */
void* mtt_realloc(void *ptr, size_t size);

/* ======================================================================== *
 *                   统计查询函数（原子读取，无需持锁）                              *
 * ======================================================================== */

/** 累计分配次数 */
size_t mtt_get_alloc_count(void);

/** 累计释放次数 */
size_t mtt_get_free_count(void);

/** 当前未释放的分配次数（alloc_count - free_count） */
size_t mtt_get_leak_count(void);

/** 当前仍未释放的字节数 */
size_t mtt_get_current_usage(void);

/** 历史峰值 current_bytes */
size_t mtt_get_peak_usage(void);

/** 累计分配字节总数 */
size_t mtt_get_total_allocated(void);

#ifdef __cplusplus
}
#endif

#endif /* MEMORYTRACETOOL_H */

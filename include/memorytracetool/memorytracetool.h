/*
 * MemoryTraceTool — C/C++ 内存泄漏检测工具，公共 API 头文件。
 *
 * 集成方式：
 *   Macro 模式:  在包含本头文件之前 #define MEMORYTRACETOOL_ENABLE，
 *               然后链接 -lmemorytracetool。
 *               所有 malloc/free 调用自动带上 __FILE__ 和 __LINE__。
 *   Preload 模式: LD_PRELOAD=libmemorytracetool.so ./your_program
 *                无需修改源码，但无文件:行号信息。
 *
 * 环境变量控制（不影响代码，仅需设置环境变量）：
 *   MTT_SAMPLE=N    — 每 N 次分配记录 1 次，N>=1 时启用采样，默认 0（全量）
 *   MTT_DISABLE=1   — 完全禁用追踪（紧急开关，降低开销为零）
 *   MTT_MAX_ENTRIES=N — 哈希表最大条目数，默认 65536
 *
 * 重要：Macro 模式下，系统头文件（stdlib.h、string.h 等）必须
 * 放在 #define MEMORYTRACETOOL_ENABLE 之前，否则会导致语法错误。
 */

#ifndef MEMORYTRACETOOL_H
#define MEMORYTRACETOOL_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * ============================================================
 *  运行时 API — 生命周期管理
 * ============================================================
 */

/** 显式初始化追踪系统（通常在首次分配时自动调用，无需手动调用） */
void  mtt_init(void);

/** 将当前泄漏报告输出到 stderr */
void  mtt_report(void);

/** 将当前泄漏报告输出到指定文件描述符 */
void  mtt_report_to_fd(int fd);

/** 将在线泄漏报告发送到守护进程（如果未连接守护进程则静默降级为 stderr） */
void  mtt_report_to_daemon(void);

/**
 * 安装 SIGUSR1 信号处理器。
 *
 * 安装后，进程在收到 `kill -USR1 <pid>` 时会自动生成泄漏报告并发送给守护进程
 *（若守护进程不可用则输出到 stderr）。可多次安全调用（幂等操作）。
 * 专为不会主动退出的常驻进程（服务器、嵌入式设备）设计。
 */
void  mtt_install_signal_handler(void);

/**
 * 主动发送中间报告到守护进程（不含 BYE 消息，进程继续运行）。
 *
 * 与 mtt_report_to_daemon 不同，本函数仅发送 HELLO + LEAK/FRAME 数据，
 * 关闭连接时不发送 BYE，守护进程不会将该进程标记为 DONE。
 * 适用于在程序逻辑中主动触发的周期性报告。
 */
void  mtt_client_report(void);

/** 设置采样周期（0=全量追踪，N>0=每N次分配记录1次），线程安全 */
void  mtt_set_sample_period(unsigned period);

/** 获取当前采样周期 */
unsigned mtt_get_sample_period(void);

/** 设置哈希表最大条目数，超过后新分配不再记录 */
void  mtt_set_max_entries(unsigned limit);

/** 获取跳过的采样统计 */
size_t mtt_get_skipped_sampled(void);

/** 获取因超容量跳过的统计 */
size_t mtt_get_skipped_overcap(void);

/*
 * ============================================================
 *  带追踪的分配函数（替代 malloc / free / ...）
 * ============================================================
 */

/** 分配 size 字节，记录分配点的文件和行号 */
void* mtt_malloc(size_t size, const char* file, int line);
/** 分配 count*size 字节并零初始化 */
void* mtt_calloc(size_t count, size_t size, const char* file, int line);
/** 重新分配内存，保留旧数据并记录新分配点 */
void* mtt_realloc(void* ptr, size_t size, const char* file, int line);
/** 释放内存并从追踪表中删除 */
void  mtt_free(void* ptr);
/** strdup 的追踪版本 */
char* mtt_strdup(const char* s, const char* file, int line);

/*
 * ============================================================
 *  统计查询
 * ============================================================
 */

size_t mtt_get_alloc_count(void);     /* 累计分配次数（含已释放的） */
size_t mtt_get_free_count(void);      /* 累计释放次数 */
size_t mtt_get_leak_count(void);      /* 当前未释放的分配次数 = alloc - free */
size_t mtt_get_current_usage(void);   /* 当前未释放的字节数 */
size_t mtt_get_peak_usage(void);      /* 历史峰值字节占用 */
size_t mtt_get_total_allocated(void); /* 累计分配字节总数（不减释放） */

#ifdef __cplusplus
}
#endif

/*
 * 宏替换开关。
 *
 * 当定义了 MEMORYTRACETOOL_ENABLE 时，标准 malloc/free 等函数会被替换为
 * 带追踪的版本，自动传入 __FILE__ 和 __LINE__。
 *
 * 注意：glibc 可能已经将 malloc 定义为宏（如 __attribute__(__malloc__)），
 * 因此需要先 #undef 再重新 #define。
 */
#ifdef MEMORYTRACETOOL_ENABLE
  #ifdef malloc
    #undef malloc
  #endif
  #ifdef calloc
    #undef calloc
  #endif
  #ifdef realloc
    #undef realloc
  #endif
  #ifdef free
    #undef free
  #endif
  #ifdef strdup
    #undef strdup
  #endif
  #define malloc(size)        mtt_malloc(size, __FILE__, __LINE__)
  #define calloc(cnt, sz)     mtt_calloc(cnt, sz, __FILE__, __LINE__)
  #define realloc(ptr, sz)    mtt_realloc(ptr, sz, __FILE__, __LINE__)
  #define free(ptr)           mtt_free(ptr)
  #define strdup(s)           mtt_strdup(s, __FILE__, __LINE__)
#endif

#endif /* MEMORYTRACETOOL_H */

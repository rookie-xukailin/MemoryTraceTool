/*
 * per_thread.h — 不依赖 TLS 的线程上下文管理
 *
 * 某些 ARM64 设备上，LD_PRELOAD 加载的共享库中 __thread 和
 * pthread_getspecific 均不可靠（可能跨线程共享或返回脏值）。
 * 本模块通过 syscall(SYS_gettid) 获取内核线程 ID，
 * 在全局槽位数组中用 CAS 分配每线程上下文，完全避免 TLS。
 *
 * 同类参考: libleak 同样不使用 TLS，改用 mutex 保护全局状态。
 */

#ifndef MTT_PER_THREAD_H
#define MTT_PER_THREAD_H

#include <unistd.h>
#include <sys/syscall.h>
#include <stdatomic.h>

#define MTT_MAX_THREADS 64

typedef struct {
    _Atomic pid_t tid;       /* 0=空闲槽位，否则为所属线程 TID */
    int  hook_depth;          /* 递归深度计数 (原 __thread g_hook_depth) */
    int  depth_inited;        /* 哨兵: 首次访问时设为 0x2A (原 __thread g_depth_inited) */
    int  in_hook;             /* 钩子中进行中 (原 __thread g_in_hook) */
    int  tool_internal;       /* 工具内部线程标记 (原 __thread g_tool_internal) */
    int  raw_resolving;       /* dlsym 重入保护 (原 __thread g_raw_resolving) */
    int  in_capture;          /* backtrace 重入保护 (原 __thread g_in_capture) */
} mtt_per_thread_t;

/* 全局槽位数组 — BSS 零初始化。
 * 64 槽位远超过实际需求（通常 <10 线程），每个槽位约 32 字节 */
extern mtt_per_thread_t g_threads[MTT_MAX_THREADS];

/**
 * 获取当前线程的上下文指针。
 *
 * 首次调用时通过 CAS 分配空闲槽位并初始化哨兵值。
 * 后续调用通过 TID 匹配直接命中（线性探测，O(N)但 N≤64）。
 * 若槽位满返回 NULL——调用者应安全降级（直接透传 raw_*）。
 */
static inline mtt_per_thread_t* mtt_thread_get(void)
{
    pid_t tid = (pid_t)syscall(SYS_gettid);

    /* 第一阶段: 查找已有槽位（常见路径） */
    for (int i = 0; i < MTT_MAX_THREADS; i++) {
        if (atomic_load_explicit(&g_threads[i].tid, memory_order_acquire) == tid)
            return &g_threads[i];
    }

    /* 第二阶段: CAS 分配新槽位 */
    for (int i = 0; i < MTT_MAX_THREADS; i++) {
        pid_t zero = 0;
        if (atomic_compare_exchange_strong_explicit(
                &g_threads[i].tid, &zero, tid,
                memory_order_acq_rel, memory_order_acquire)) {
            /* 新槽位: 初始化哨兵值（其他字段 BSS 已为 0） */
            g_threads[i].hook_depth  = -1;
            g_threads[i].depth_inited = -1;
            return &g_threads[i];
        }
    }

    return NULL; /* 槽位满 — 极为罕见，调用者降级处理 */
}

#endif /* MTT_PER_THREAD_H */

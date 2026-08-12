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
#include <signal.h>
#include <errno.h>
#include <stdatomic.h>

/* 槽位上限:从 64 扩到 512。
 * 背景:storageManager 等大型 BMC 进程线程数易超 64,晚创建的线程
 * (如分类线程池动态派生的业务线程)拿不到槽位 → ctx==NULL → malloc
 * 透传不追踪 → 该线程所有泄漏完全丢失。
 * 内存成本:512 × sizeof(mtt_per_thread_t) ≈ 32KB,嵌入式可接受。 */
#define MTT_MAX_THREADS 512

/* hook 深度异常上限:超过视为 TID 复用残留的脏值。
 * 正常 hook 深度:业务 malloc → raw_*(函数指针直调) → 通常 ≤ 3。 */
#define MTT_HOOK_DEPTH_MAX 8

typedef struct {
    _Atomic pid_t tid;       /* 0=空闲槽位，否则为所属线程 TID */
    int  hook_depth;          /* 递归深度计数 (原 __thread g_hook_depth) */
    int  depth_inited;        /* 哨兵: 首次访问时设为 0x2A (原 __thread g_depth_inited) */
    int  in_hook;             /* 钩子中进行中 (原 __thread g_in_hook) */
    int  tool_internal;       /* 工具内部线程标记 (原 __thread g_tool_internal) */
    int  raw_resolving;       /* dlsym 重入保护 (原 __thread g_raw_resolving) */
    int  in_capture;          /* backtrace 重入保护 (原 __thread g_in_capture) */
    /* 缓存行填充:多核 ARM 上避免相邻槽位 tid 字段落在同一缓存行造成伪共享。
     * 与 mtt_aligned_mutex_t 设计保持一致。 */
    char __padding[36];
} mtt_per_thread_t;

/* 全局槽位数组 — BSS 零初始化。
 * 512 槽位覆盖大型 BMC 进程(通常 <100 线程),每个槽位约 64 字节 */
extern mtt_per_thread_t g_threads[MTT_MAX_THREADS];

/**
 * 获取当前线程的上下文指针。
 *
 * 首次调用时通过 CAS 分配空闲槽位并初始化哨兵值。
 * 后续调用通过 TID 匹配直接命中（线性探测，O(N)但 N≤512）。
 *
 * 槽位满时的兜底回收:线程池场景线程动态创建/销毁,已退出线程的槽位
 * tid 残留。kill(tid,0)==ESRCH 表示该线程已不存在,可安全复用其槽位。
 * 当前线程必然存活(正在执行本函数),不会被误清。
 *
 * @return 槽位指针,全满且无可回收时返回 NULL(调用者应安全降级)
 */
static inline mtt_per_thread_t* mtt_thread_get(void)
{
    pid_t tid = (pid_t)syscall(SYS_gettid);

    /* 第一阶段: 查找已有槽位（常见路径） */
    for (int i = 0; i < MTT_MAX_THREADS; i++) {
        if (atomic_load_explicit(&g_threads[i].tid, memory_order_acquire) == tid)
            return &g_threads[i];
    }

    /* 第二阶段: CAS 分配新槽位。
     * 初始化必须在 CAS 成功之后，否则 CAS 失败会破坏其他线程的数据。
     * 槽位 tid 为 0 期间其他线程不可见（TID 不匹配），无需担心 TOCTOU。 */
    for (int i = 0; i < MTT_MAX_THREADS; i++) {
        pid_t zero = 0;
        if (atomic_compare_exchange_strong_explicit(
                &g_threads[i].tid, &zero, tid,
                memory_order_acq_rel, memory_order_acquire)) {
            /* CAS 成功：显式初始化全部字段。
             * BSS 零初始化虽已兜底,但显式赋值防御未来引入槽位回收时的脏值问题。 */
            g_threads[i].hook_depth    = -1;
            g_threads[i].depth_inited  = -1;
            g_threads[i].in_hook       = 0;
            g_threads[i].tool_internal = 0;
            g_threads[i].raw_resolving = 0;
            g_threads[i].in_capture    = 0;
            return &g_threads[i];
        }
    }

    /* 第三阶段: 槽位全满 — 回收已退出线程的槽位后再试。
     * kill(tid,0) 成功(0)说明线程存活,保留;ESRCH 说明已退出,复用。 */
    for (int i = 0; i < MTT_MAX_THREADS; i++) {
        pid_t owner = atomic_load_explicit(&g_threads[i].tid, memory_order_acquire);
        if (owner != 0 && owner != tid && kill(owner, 0) != 0 && errno == ESRCH) {
            if (atomic_compare_exchange_strong_explicit(
                    &g_threads[i].tid, &owner, tid,
                    memory_order_acq_rel, memory_order_acquire)) {
                g_threads[i].hook_depth    = -1;
                g_threads[i].depth_inited  = -1;
                g_threads[i].in_hook       = 0;
                g_threads[i].tool_internal = 0;
                g_threads[i].raw_resolving = 0;
                g_threads[i].in_capture    = 0;
                return &g_threads[i];
            }
        }
    }

    return NULL; /* 槽位全满且无已死线程 — 调用者降级处理 */
}

/* ======================================================================== *
 *      1.1 热路径加速:TLS 缓存线程上下文(免每次 syscall + 扫 512 槽)        *
 * ======================================================================== */

/* TLS 缓存指针:命中免 syscall(SYS_gettid) + 线性扫 512 槽。
 * 历史问题(某些 ARM64 设备 __thread 不可靠)用"tid 核对"兜底:
 * 命中后原子核对槽位 tid == 当前 tid,不匹配则回退慢路径重扫。 */
static __thread mtt_per_thread_t *mtt_tls_ctx = NULL;

/**
 * 获取当前线程上下文(热路径加速版)。
 *
 * 快路径:纯 TLS 读(cache + cached_tid 都在 TLS),零 syscall 零扫描。
 * 慢路径:TLS 为空 或 缓存 tid 与槽位不一致(线程迁移/槽位回收)时
 * 回退 mtt_thread_get() 重扫,并刷新 TLS 缓存。
 *
 * 注意:快路径不做 syscall 校验(会抵消缓存收益)。用 TLS 存 cached_tid,
 * 与槽位 tid 比较纯 TLS 读;线程池场景 TID 复用导致槽位被新线程占用时,
 * cached_tid 仍是旧值,比较失败 → 回退慢路径,正确。
 *
 * @return 槽位指针(可能 NULL,调用者应安全降级)
 */
static __thread pid_t mtt_tls_cached_tid = 0;

static inline mtt_per_thread_t* mtt_thread_get_cached(void)
{
#if defined(__aarch64__)
    /* ARM64:__thread 在 LD_PRELOAD 场景下不可靠(可能跨线程共享返回脏值)。
     * 现象:线程 B 读到线程 A 的 TLS 缓存,三重校验(c != NULL + cached_tid
     * == slot->tid + 槽位 tid 匹配)全部通过,但 B 实际拿到 A 的 ctx,
     * 误读 A 的 hook_depth 残留 → B 的所有 malloc 被递归保护吞掉,
     * 表现为 site 数暴跌、看不到 main、TRACE64 显示 SKIP reason=recursion。
     *
     * 修复:不信任 TLS 缓存的 tid,用 syscall(SYS_gettid) 拿内核真实 tid,
     * 与 TLS 缓存 + 槽位 tid 三方比对。TLS 不一致时回退慢路径重扫。
     *
     * 开销:每次 hook_enter 加 1 次 syscall(~100ns ARM64),正确性必需。
     * 详见 commits fa87bb8(引入 TLS 缓存) + 9c607ab/storageManager 实测现象。 */
    mtt_per_thread_t *c = mtt_tls_ctx;
    pid_t my_real_tid = (pid_t)syscall(SYS_gettid);
    if (c != NULL && mtt_tls_cached_tid == my_real_tid &&
            atomic_load_explicit(&c->tid, memory_order_relaxed) == my_real_tid)
        return c;
    mtt_tls_ctx = mtt_thread_get();
    mtt_tls_cached_tid = my_real_tid;
    return mtt_tls_ctx;
#else
    /* ARM32 / x86_64: __thread 可靠,保留 fa87bb8 的 fast path(无 syscall)。
     * ARM32 实测 storageManager 表现正常,无需此修复。 */
    mtt_per_thread_t *c = mtt_tls_ctx;
    if (c != NULL && mtt_tls_cached_tid ==
            atomic_load_explicit(&c->tid, memory_order_relaxed))
        return c;   /* 快路径:纯 TLS 读,零 syscall */
    mtt_tls_ctx = mtt_thread_get();       /* 慢路径:syscall + 扫槽 */
    mtt_tls_cached_tid = (mtt_tls_ctx != NULL)
        ? atomic_load_explicit(&mtt_tls_ctx->tid, memory_order_relaxed) : 0;
    return mtt_tls_ctx;
#endif
}

#endif /* MTT_PER_THREAD_H */

/*
 * MemoryTraceTool — LD_PRELOAD 拦截钩子。
 *
 * 本文件重写了 libc 的 malloc / calloc / realloc / free 符号，
 * 编译进动态库（libmemorytracetool.so）中。
 * 通过 LD_PRELOAD 加载后，无需修改任何源码即可拦截目标进程中
 * 所有的堆内存分配和释放操作。
 *
 * 防递归策略：
 *   - g_in_hook (__thread): 置位时直接透传到 raw_*，不做任何追踪
 *   - save/restore 模式支持嵌套调用
 *   - 所有内部分配使用 raw_malloc/raw_free（直接调用 libc）
 *   - bootstrap 缓冲区在 raw_* 未就绪时兜底
 *   - 不在 hook 路径中使用 fprintf/printf（内部触发 malloc）
 *   - 错误诊断使用 write() 系统调用（无 malloc）
 *
 * 线程安全：64 分段锁保护全局状态。
 *
 * 原子操作内存序：统计计数器用 relaxed，控制标志用 acquire/release。
 */

#define _GNU_SOURCE
#include "mtt_internal.h"
#include "per_thread.h"
#include <dlfcn.h>

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <stdarg.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <errno.h>

/*
 * 所有诊断输出使用 write() 系统调用（无 malloc）。
 * 注意：snprintf 仅格式化到栈缓冲区，不触发堆分配。 */

/* ---- 库地址范围黑名单快速检查宏(MTT_LIB_BLACKLIST_FAST) ----
 * 在 hook 函数体内调用,__builtin_return_address(0) 取的是 hook 函数的
 * 直接 caller(业务调用点或库内调用点)。命中返回 1,跳过追踪。
 *
 * 必须在 mtt_resolve_raw_allocators() 之后调用(需要 raw_* 函数指针)。
 * g_blacklist_fast_enabled 全局变量,用户未设环境变量时为 0,
 * mtt_is_lr_in_blacklist 第一行就 return 0,几乎零开销。 */
#define MTT_LR_IN_BLACKLIST() \
    (g_blacklist_fast_enabled && \
     mtt_is_lr_in_blacklist(__builtin_return_address(0)))

/* ---- hook 诊断计数器（仅首次记录，避免高频 IO） ---- */

static _Atomic int g_first_malloc_diag  = 1;
static _Atomic int g_first_free_diag    = 1;
static _Atomic int g_first_calloc_diag  = 1;
static _Atomic int g_first_realloc_diag = 1;

/* ---- 全流程跟踪(定位"特定 size 的 malloc 被吞"问题) ----
 * MTT_TRACE_SIZE 环境变量指定要跟踪的 size(默认 0=不跟踪)。
 * 等级 1 输出,业务每次该 size 的 malloc 都打印一行流程日志:
 *   [MTT] TRACE64 enter LR=0xAAA
 *   [MTT] TRACE64 SKIP reason=recursion depth=N
 *   [MTT] TRACE64 ptr=0xBBB entry=0xCCC frames=N
 *   [MTT] TRACE64 added bucket=N entry_count=M
 */
static size_t g_trace_size = 0;
static _Atomic int g_trace_resolved = 0;

/* 首次调用时解析 MTT_TRACE_SIZE 环境变量(默认 0=不跟踪) */
static inline void mtt_resolve_trace_size(void)
{
    int expected = 0;
    if (atomic_compare_exchange_strong(&g_trace_resolved, &expected, 1)) {
        const char *env = getenv("MTT_TRACE_SIZE");
        if (env != NULL) {
            int ts = atoi(env);
            if (ts > 0) g_trace_size = (size_t)ts;
        }
    }
}

#define MTT_TRACE_TARGET(size) \
    ((size) == g_trace_size && g_trace_size > 0 && \
     atomic_load_explicit(&mtt_debug_level, memory_order_relaxed) >= 1)

#define MTT_TRACE(size, fmt, ...) \
    do { \
        if (MTT_TRACE_TARGET(size)) { \
            char __buf[256]; \
            int __n = snprintf(__buf, sizeof(__buf), \
                "[MTT] TRACE%zu " fmt "\n", \
                (size_t)(size), ##__VA_ARGS__); \
            if (__n > 0) { \
                if (__n >= (int)sizeof(__buf)) __n = (int)sizeof(__buf) - 1; \
                MTT_DIAG_WRITE(STDERR_FILENO, __buf, (size_t)__n); \
            } \
        } \
    } while (0)

/** 仅在首次调用时输出诊断（确认 hook 被调用，受 MTT_DEBUG 控制）。
 * 直接读环境变量,不依赖 mtt_debug_level(后者在 init 阶段2 才设置,
 * 而 first_call 通常在 init 之前触发)。
 * MTT_DEBUG 等级语义:0 静默,1 关键事件(默认输出 first call),2 全量 */
static void first_call_diag(const char *func_name, _Atomic int *flag, int stage_id)
{
    int expected = 1;
    if (atomic_compare_exchange_strong(flag, &expected, 0)) {
        const char *env_debug = getenv("MTT_DEBUG");
        int level = MTT_DEBUG_DEFAULT;
        if (env_debug != NULL) {
            int lv = atoi(env_debug);
            if (lv < 0) lv = 0;
            if (lv > 2) lv = 2;
            level = lv;
        }
        if (level < 1)
            return;  /* MTT_DEBUG=0:静默,不输出 first call 诊断 */
        char buf[128] = {0};
        int len = snprintf(buf, sizeof(buf),
            "[MTT] hook: %s first call (pid=%d)\n", func_name, (int)getpid());
        if (len > 0 && len < (int)sizeof(buf))
            MTT_DIAG_WRITE(STDERR_FILENO, buf, (size_t)len);
        /* 加阶段编号,跟 init 阶段串起来定位崩溃点 */
        mtt_log_stage(stage_id, "first %s done", func_name);
    }
}

/* ======================================================================== *
 *                     LD_PRELOAD 拦截入口                                     *
 * ======================================================================== */

/* 深度计数器已迁移至 per_thread.h 槽位数组。
 * mtt_hook_enter/inc/dec 内部通过 mtt_thread_get() 访问。 */

#if defined(__aarch64__)
/* ARM64: 工具 .so 地址范围(init 阶段填充,hook_enter 纯指针比较)。
 * 用于区分"业务直接调"(LR 在业务代码 → depth 残留 → 重置)
 * vs "工具内部嵌套"(LR 在工具 .so → 保留 SKIP)。
 * init 前 lo=0,hook_enter 不检测(保守,不重置)。 */
static _Atomic uintptr_t g_tool_lo = 0;
static _Atomic uintptr_t g_tool_hi = 0;

/* 由 mtt_ensure_init 末尾调用(不在 hook 上下文,dladdr 安全) */
void mtt_init_tool_range(void)
{
    Dl_info info;
    if (dladdr((void*)&mtt_init_tool_range, &info) && info.dli_fbase) {
        uintptr_t base = (uintptr_t)info.dli_fbase;
        atomic_store_explicit(&g_tool_lo, base, memory_order_relaxed);
        atomic_store_explicit(&g_tool_hi, base + (1 << 20), memory_order_relaxed);
    }
}
#endif
/** 获取当前 hook 调用深度，首次调用时自动修正脏值。
 * 若槽位满返回 -1（降级：视为递归，直接透传 raw_*）。
 *
 * 残留检测(三重防御,覆盖所有已知残留来源):
 *   1. depth_inited != 0x2A:首次访问,初始化为 0
 *   2. hook_depth > MTT_HOOK_DEPTH_MAX(8):明显脏值,重置(e1ce48d 原逻辑)
 *   3. hook_depth > 0 && in_hook == 0:不可能的正常状态,必为残留
 *      正常路径:inc_depth 后立刻设 in_hook=1,dec_depth 时同时恢复 in_hook=0。
 *      所以 hook_depth > 0 时 in_hook 必为 1。否则:
 *        - TID 复用残留(线程 A 退出后 hook_depth=1 残留,B 复用 A 的 TID)
 *        - TLS 缓存跨线程污染(ARM64 __thread 不可靠,B 拿到 A 的 ctx)
 *        - 上次 hook 异常退出(inc 后线程被 cancel)
 *      全部重置为 0,恢复追踪。 */
static inline int mtt_hook_enter(void)
{
    mtt_per_thread_t * __restrict__ ctx = mtt_thread_get_cached();
    if (ctx == NULL) return -1; /* 降级：无槽位时保守视为递归 */
    if (ctx->depth_inited != 0x2A) {
        ctx->hook_depth = 0;
        ctx->depth_inited = 0x2A;
    } else if (ctx->hook_depth > MTT_HOOK_DEPTH_MAX) {
        ctx->hook_depth = 0;
    } else if (ctx->hook_depth > 0 && !ctx->in_hook) {
        ctx->hook_depth = 0;
    }
#if defined(__aarch64__)
    else if (ctx->hook_depth > 0) {
        /* ARM64:depth>0 + 三标志全=0 时,用 LR 区分残留 vs 嵌套。
         * LR 在工具 .so → 工具内部嵌套 → 保留 SKIP。
         * LR 不在工具 .so(业务代码/libc)→ depth 残留 → 重置 depth=0。
         *   - 业务直接调 malloc(LR 在业务代码):重置 → 追踪 ✓
         *   - libc 嵌套(dlsym/backtrace 之外,LR 在 libc):重置 →
         *     追踪但 entry 会被 free 移除(临时分配,不是泄漏)。
         * init 前(g_tool_lo=0)不检测,保守 SKIP。
         * 只重置 depth,不动 in_hook(避免破坏外层 hook 状态)。 */
        if (!ctx->raw_resolving && !ctx->in_capture && !ctx->tool_internal) {
            void *lr = __builtin_return_address(0);
            uintptr_t lo = atomic_load_explicit(&g_tool_lo, memory_order_relaxed);
            uintptr_t hi = atomic_load_explicit(&g_tool_hi, memory_order_relaxed);
            if (lo != 0 && !((uintptr_t)lr >= lo && (uintptr_t)lr < hi)) {
                ctx->hook_depth = 0;
            }
        }
    }
#endif
    return ctx->hook_depth;
}

static inline void mtt_hook_inc_depth(void)
{
    mtt_per_thread_t * __restrict__ ctx = mtt_thread_get_cached();
    if (ctx == NULL) return; /* 降级：无槽位时跳过 */
    int init_ok = (ctx->depth_inited == 0x2A);
    if (!init_ok) { ctx->hook_depth = 0; ctx->depth_inited = 0x2A; }
    if (ctx->hook_depth >= MTT_HOOK_DEPTH_MAX) return; /* 防溢出 + 防残留累积 */
    ctx->hook_depth++;
}

static inline void mtt_hook_dec_depth(void)
{
    mtt_per_thread_t * __restrict__ ctx = mtt_thread_get_cached();
    if (ctx == NULL) return; /* 降级：无槽位时跳过 */
    if (ctx->hook_depth > 0)
        ctx->hook_depth--;
    else
        ctx->hook_depth = 0;
}

/**
 * LD_PRELOAD 拦截的 malloc。
 *
 * 执行流程：
 *   1. g_in_hook 递归保护（save/restore）
 *   2. 解析 raw_* 分配器
 *   3. g_in_hook 置位 → 直接透传
 *   4. 懒初始化全局状态
 *   5. disabled/采样/容量检查
 *   6. raw_malloc 分配用户内存
 *   7. 创建追踪记录 → 插入哈希表 → 更新统计
 */
void* malloc(size_t size)
{
    /* 首次调用诊断 */
    first_call_diag("malloc", &g_first_malloc_diag, 20);
    mtt_resolve_trace_size();
    MTT_TRACE(size, "enter LR=%p", __builtin_return_address(0));

    /* 递归保护：__thread 深度计数器（哨兵自动修正脏值） */
    {
        int depth = mtt_hook_enter();
        if (depth > 0) {
            /* 诊断:depth > 0 时输出完整上下文(等级 1),定位 depth 残留源头。
             * 只在 TRACE 跟踪 size 时输出,避免污染日志。 */
            if (MTT_TRACE_TARGET(size)) {
                mtt_per_thread_t *__diag_ctx = mtt_thread_get_cached();
                pid_t __real_tid = (__diag_ctx != NULL) ?
                    (pid_t)syscall(SYS_gettid) : 0;
                int __slot_tid = (__diag_ctx != NULL) ?
                    (int)atomic_load_explicit(&__diag_ctx->tid, memory_order_relaxed) : 0;
                int __in_hook = (__diag_ctx != NULL) ? __diag_ctx->in_hook : -1;
                int __tool = (__diag_ctx != NULL) ? __diag_ctx->tool_internal : -1;
                int __in_cap = (__diag_ctx != NULL) ? __diag_ctx->in_capture : -1;
                int __raw_res = (__diag_ctx != NULL) ? __diag_ctx->raw_resolving : -1;
                char __buf[256];
                int __n = snprintf(__buf, sizeof(__buf),
                    "[MTT] TRACE%zu SKIP recursion depth=%d real_tid=%d slot_tid=%d "
                    "in_hook=%d tool_internal=%d in_capture=%d raw_resolving=%d "
                    "depth_inited=%d\n",
                    (size_t)size, depth, (int)__real_tid, __slot_tid,
                    __in_hook, __tool, __in_cap, __raw_res,
                    __diag_ctx ? __diag_ctx->depth_inited : -1);
                if (__n > 0) {
                    if (__n >= (int)sizeof(__buf)) __n = (int)sizeof(__buf) - 1;
                    MTT_DIAG_WRITE(STDERR_FILENO, __buf, (size_t)__n);
                }
            }
            MTT_TRACE(size, "SKIP reason=recursion depth=%d", depth);
            mtt_resolve_raw_allocators();
            return (raw_malloc != NULL) ? raw_malloc(size) : NULL;
        }
    }
    mtt_per_thread_t *ctx = mtt_thread_get_cached();
    if (ctx == NULL) {
        /* 槽位满(512 上限):降级透传,不追踪。
         * MTT_DEBUG=2 时输出 S25,定位"线程太多导致泄漏丢失"场景 */
        MTT_TRACE(size, "SKIP reason=ctx_null(slot full)");
        mtt_log_stage(25, "malloc ctx==NULL (slot full) size=%zu, NOT tracking", size);
        mtt_resolve_raw_allocators();
        return (raw_malloc != NULL) ? raw_malloc(size) : NULL;
    }
    mtt_hook_inc_depth();
    int saved_hook = ctx->in_hook;
    ctx->in_hook = 1;

    mtt_resolve_raw_allocators();

    /* 库地址范围黑名单快速检查(MTT_LIB_BLACKLIST_FAST):
     * LR 在黑名单库内(lmdb/XML 等),跳过追踪,直接 raw_malloc。
     * 节省 8.5μs/次抓栈开销。用户未配置时几乎零开销(一次 atomic load)。 */
    if (MTT_LR_IN_BLACKLIST()) {
        MTT_TRACE(size, "SKIP reason=blacklist LR=%p", __builtin_return_address(0));
        void *ret = (raw_malloc != NULL) ? raw_malloc(size) : NULL;
        mtt_hook_dec_depth();
        ctx->in_hook = saved_hook;
        return ret;
    }

    /* 工具内部线程（reporter/HTTP）：直接透传，不追踪 */
    if (ctx->tool_internal) {
        MTT_TRACE(size, "SKIP reason=tool_internal(tid 复用残留?)");
        void *ret = (raw_malloc != NULL) ? raw_malloc(size) : NULL;
    mtt_hook_dec_depth();
    ctx->in_hook = saved_hook;
        return ret;
    }

    if (raw_malloc == NULL) {
    mtt_hook_dec_depth();
    ctx->in_hook = saved_hook;
        return NULL;
    }

    /* 0 字节分配：标准行为 */
    if (size == 0) {
        void *ret = raw_malloc(0);
    mtt_hook_dec_depth();
    ctx->in_hook = saved_hook;
        return ret;
    }

    mtt_ensure_init();
    mtt_state_t *s = mtt_state_get();
    mtt_log_stage(24, "malloc post-init size=%zu", size);

    /* 启动阶段宽限：跳过追踪，直接透传 */
    if (s != NULL && mtt_is_startup_phase(s)) {
        MTT_TRACE(size, "SKIP reason=startup_phase");
        void *ret = raw_malloc(size);
    mtt_hook_dec_depth();
    ctx->in_hook = saved_hook;
        return ret;
    }
    if (s == NULL) {
        MTT_TRACE(size, "SKIP reason=state_null");
        void *ret = raw_malloc(size);
    mtt_hook_dec_depth();
    ctx->in_hook = saved_hook;
        return ret;
    }

    /* 紧急禁用：直接透传 */
    if (atomic_load_explicit(&s->disabled, memory_order_acquire)) {
        MTT_TRACE(size, "SKIP reason=disabled(黑名单自检误判?)");
        void *ret = raw_malloc(size);
    mtt_hook_dec_depth();
    ctx->in_hook = saved_hook;
        return ret;
    }

    /* 先分配用户内存 */
    void *ptr = raw_malloc(size);
    if (ptr == NULL) {
    mtt_hook_dec_depth();
    ctx->in_hook = saved_hook;
        return NULL;
    }
    mtt_log_stage(26, "malloc raw_malloc done ptr=%p size=%zu", ptr, size);
    MTT_TRACE(size, "raw_malloc done ptr=%p", ptr);

    /* 采样与容量检查（不满足条件则放行不追踪） */
    {
        int track_ok = mtt_should_track(s, size);
        int over_cap = mtt_is_over_capacity(s);
        if (!track_ok || over_cap) {
            MTT_TRACE(size, "SKIP reason=sample/overcap track_ok=%d over_cap=%d",
                      track_ok, over_cap);
    mtt_hook_dec_depth();
    ctx->in_hook = saved_hook;
            return ptr;
        }
    }
    mtt_log_stage(27, "malloc past track/cap checks, calling entry_new");

    /* 创建追踪记录（内部使用 raw_malloc） */
    mtt_entry_t *e = mtt_entry_new(ptr, size);
    if (e == NULL) {
        MTT_TRACE(size, "SKIP reason=entry_new_failed(ptr=%p)", ptr);
    mtt_hook_dec_depth();
    ctx->in_hook = saved_hook;
        return ptr; /* 追踪失败不阻塞业务 */
    }
    mtt_log_stage(28, "malloc entry_new done e=%p frames=%d", (void*)e, e->stack_frames);
    MTT_TRACE(size, "entry_new done entry=%p frames=%d first=%p",
              (void*)e, e->stack_frames,
              e->stack_frames > 0 ? e->stack[0] : NULL);

    /* 持锁插入哈希表 + 原子更新计数器 */
    mtt_stripe_lock(s, ptr);

    /* 锁内二次检查容量:已达上限则跳过追踪,用户分配已成功。
     * 原 LRU 淘汰逻辑违反分段锁契约(只持 1/64 锁却遍历全部 4096 桶),
     * 与其他线程的 free 路径竞争 entry->next 指针,可能 UAF 或双释放。
     * 与 tracker.c:mtt_malloc 路径保持一致的简单跳过策略。 */
    if (atomic_load_explicit(&s->entry_count, memory_order_relaxed) >= MTT_MAX_ENTRIES) {
        MTT_TRACE(size, "SKIP reason=overcap(entry_count>=MAX)");
        atomic_fetch_add_explicit(&s->skipped_overcap, 1, memory_order_relaxed);
        mtt_stripe_unlock(s, ptr);
        mtt_entry_discard(s, e);
    mtt_hook_dec_depth();
    ctx->in_hook = saved_hook;
        return ptr;
    }

    e->alloc_num = atomic_fetch_add_explicit(&s->alloc_seq, 1, memory_order_relaxed) + 1;
    atomic_fetch_add_explicit(&s->alloc_count, 1, memory_order_relaxed);
    atomic_fetch_add_explicit(&s->current_bytes, size, memory_order_relaxed);
    atomic_fetch_add_explicit(&s->total_bytes,   size, memory_order_relaxed);

    /* CAS 更新峰值 */
    {
        int peak_changed = 0;
        size_t cur = atomic_load_explicit(&s->current_bytes, memory_order_relaxed);
        size_t old_peak = atomic_load_explicit(&s->peak_bytes, memory_order_relaxed);
        while (cur > old_peak) {
            if (atomic_compare_exchange_weak_explicit(&s->peak_bytes, &old_peak, cur,
                    memory_order_relaxed, memory_order_relaxed)) {
                peak_changed = 1;
                break;
            }
        }
        /* 峰值更新后通知 reporter 线程（借鉴 jemalloc prof_gdump）。
         * 仅在 LD_PRELOAD 路径（hooks.c）中设置，mtt_malloc API 路径中也设置。
         * ARM32: relaxed store 成本低廉，避免峰值漏报导致的延迟报告。 */
        if (peak_changed)
            atomic_store_explicit(&s->peak_updated, 1, memory_order_relaxed);
    }

    mtt_entry_add(s, e);
    mtt_stripe_unlock(s, ptr);
    mtt_log_stage(29, "malloc entry_add done, returning ptr=%p", ptr);
    MTT_TRACE(size, "ADDED entry=%p ptr=%p alloc_num=%llu frames=%d",
              (void*)e, ptr,
              (unsigned long long)e->alloc_num,
              e->stack_frames);

    mtt_hook_dec_depth();
    ctx->in_hook = saved_hook;
    return ptr;
}

/**
 * LD_PRELOAD 拦截的 free。
 */
void free(void *ptr)
{
    first_call_diag("free", &g_first_free_diag, 21);

    if (ptr == NULL) return;

    /* 池子范围检查：用户进程不应该 free 工具自身的 entry 池内存。
     * 若误传进来，静默吞掉（不调 raw_free，避免破坏池子结构）。
     * 真实业务 free 用户内存不会命中此条件，只在用户代码出错时触发。 */
    if (mtt_pool_contains(ptr)) {
        return;
    }

    /* 递归保护：栈回溯检测 */
    if (mtt_hook_enter() > 0) {
        mtt_resolve_raw_allocators();
        if (raw_free != NULL) raw_free(ptr);
        return;
    }
    mtt_per_thread_t *ctx = mtt_thread_get_cached();
    if (ctx == NULL) {
        /* 槽位满：降级直接释放,不维护 entry */
        mtt_log_stage(25, "free ctx==NULL (slot full), NOT untracking");
        mtt_resolve_raw_allocators();
        if (raw_free != NULL) raw_free(ptr);
        return;
    }
    mtt_hook_inc_depth();
    int saved_hook = ctx->in_hook;
    ctx->in_hook = 1;

    mtt_resolve_raw_allocators();

    /* 库地址范围黑名单(lmdb/XML 等):跳过追踪,直接 raw_free。
     * 黑名单库内部 malloc 当时未创建 entry,这里 free 也无需查/删 entry。
     * 边界场景:业务把黑名单库的指针交给业务代码 free,工具找不到 entry
     * 但 free 路径有 entry==NULL 检查,安全跳过。 */
    if (MTT_LR_IN_BLACKLIST()) {
        if (raw_free != NULL) raw_free(ptr);
        mtt_hook_dec_depth();
        ctx->in_hook = saved_hook;
        return;
    }

    /* 工具内部线程：直接透传 */
    if (ctx->tool_internal) {
        if (raw_free != NULL) raw_free(ptr);
    mtt_hook_dec_depth();
    ctx->in_hook = saved_hook;
        return;
    }

    if (raw_free == NULL) {
    mtt_hook_dec_depth();
    ctx->in_hook = saved_hook;
        return;
    }

    mtt_ensure_init();
    mtt_state_t *s = mtt_state_get();
    if (s == NULL) {
        raw_free(ptr);
    mtt_hook_dec_depth();
    ctx->in_hook = saved_hook;
        return;
    }

    if (atomic_load_explicit(&s->disabled, memory_order_acquire)) {
        raw_free(ptr);
    mtt_hook_dec_depth();
    ctx->in_hook = saved_hook;
        return;
    }

    mtt_stripe_lock(s, ptr);
    mtt_entry_t *e = mtt_entry_find(s, ptr);
    if (e != NULL) {
        if (e->size <= atomic_load_explicit(&s->current_bytes, memory_order_relaxed))
            atomic_fetch_sub_explicit(&s->current_bytes, e->size, memory_order_relaxed);
        else
            atomic_store_explicit(&s->current_bytes, 0, memory_order_relaxed);
        atomic_fetch_add_explicit(&s->free_count, 1, memory_order_relaxed);
        /* 临时分配检测：寿命<1秒→大概率非泄漏（借鉴 heaptrack 临时分配检测） */
        if (mtt_now_sec() - e->timestamp <= 1)
            atomic_fetch_add_explicit(&s->temp_alloc_count, 1, memory_order_relaxed);
        /* 延迟释放追踪：若释放时已超泄漏阈值→曾是"可疑泄漏"但后来释放了（借鉴 libleak late-free） */
        {
            time_t threshold = atomic_load_explicit(&s->leak_threshold_sec, memory_order_relaxed);
            if (threshold > 0 && (mtt_now_sec() - e->timestamp) > threshold)
                atomic_fetch_add_explicit(&s->free_expired_count, 1, memory_order_relaxed);
        }
        mtt_entry_remove(s, ptr);
    }
    mtt_stripe_unlock(s, ptr);
    raw_free(ptr);
    mtt_hook_dec_depth();
    ctx->in_hook = saved_hook;
}

/**
 * LD_PRELOAD 拦截的 calloc。
 */
void* calloc(size_t count, size_t size)
{
    first_call_diag("calloc", &g_first_calloc_diag, 22);

    /* 递归保护：栈回溯检测 */
    if (mtt_hook_enter() > 0) {
        mtt_resolve_raw_allocators();
        if (raw_malloc == NULL) return NULL;
        if (count > 0 && size > SIZE_MAX / count) return NULL;
        size_t total = count * size;
        void *p = raw_malloc(total);
        if (p != NULL) memset(p, 0, total);
        return p;
    }
    mtt_per_thread_t *ctx = mtt_thread_get_cached();
    if (ctx == NULL) {
        /* 槽位满：降级,不追踪 */
        mtt_log_stage(25, "calloc ctx==NULL (slot full) size=%zu, NOT tracking",
                      (size_t)(count * size));
        mtt_resolve_raw_allocators();
        if (raw_malloc == NULL) return NULL;
        if (count > 0 && size > SIZE_MAX / count) return NULL;
        size_t total = count * size;
        void *p = raw_malloc(total);
        if (p != NULL) memset(p, 0, total);
        return p;
    }
    /* 工具内部线程：直接透传 raw_malloc + memset，不追踪 */
    if (ctx->tool_internal) {
        mtt_resolve_raw_allocators();
        if (raw_malloc == NULL) return NULL;
        if (count > 0 && size > SIZE_MAX / count) return NULL;
        size_t t = count * size;
        void *p = raw_malloc(t);
        if (p != NULL) memset(p, 0, t);
        return p;
    }

    /* 整数溢出检查 */
    if (count > 0 && size > SIZE_MAX / count)
        return NULL;
    size_t total = count * size;

    /* 库地址范围黑名单(lmdb/XML 等):跳过追踪,直接 raw_malloc + memset。
     * 不调 malloc(total) 是因为 malloc hook 看到的 LR 是 calloc 函数体内 PC
     * (在 libmemorytracetool.so 范围),黑名单判断会失效。这里在 calloc 入口
     * 直接判断 LR(业务调用点或库内调用点),命中则绕过 malloc hook。 */
    if (MTT_LR_IN_BLACKLIST()) {
        mtt_resolve_raw_allocators();
        if (raw_malloc == NULL) return NULL;
        void *p = raw_malloc(total);
        if (p != NULL) memset(p, 0, total);
        return p;
    }

    /* 通过本文件的 malloc() 分配并追踪。
     * mtt_is_recursive_call() 确保 calloc→malloc 链路中
     * malloc 能正确识别调用栈中的 calloc 帧并绕过追踪。
     * g_in_hook 由 malloc 内部自行 save/restore。 */
    void *ptr = malloc(total);
    if (ptr != NULL) memset(ptr, 0, total);

    return ptr;
}

/**
 * LD_PRELOAD 拦截的 realloc。
 *
 * 优先使用 raw_realloc（libc 原生 realloc），避免手动 memcpy 带来的
 * 越界读取风险。仅在 raw_realloc 不可用（bootstrap 阶段）时降级为
 * malloc+memcpy+free 方案。
 */
void* realloc(void *ptr, size_t size)
{
    first_call_diag("realloc", &g_first_realloc_diag, 23);

    if (ptr == NULL) return malloc(size);
    if (size == 0) { free(ptr); return NULL; }

    /* 递归保护：栈回溯检测 */
    if (mtt_hook_enter() > 0) {
        mtt_resolve_raw_allocators();
        if (raw_realloc != NULL)
            return raw_realloc(ptr, size);
        if (raw_malloc == NULL) return NULL;
        void *new_ptr = raw_malloc(size);
        if (new_ptr == NULL) return NULL;
        if (raw_free != NULL) raw_free(ptr);
        return new_ptr;
    }
    mtt_per_thread_t *ctx = mtt_thread_get_cached();
    if (ctx == NULL) {
        /* 槽位满：降级,不追踪 */
        mtt_log_stage(25, "realloc ctx==NULL (slot full) size=%zu, NOT tracking", size);
        mtt_resolve_raw_allocators();
        if (raw_realloc != NULL) return raw_realloc(ptr, size);
        if (raw_malloc == NULL) return NULL;
        void *np = raw_malloc(size);
        if (np == NULL) return NULL;
        if (raw_free != NULL) raw_free(ptr);
        return np;
    }
    mtt_hook_inc_depth();
    int saved_hook = ctx->in_hook;
    ctx->in_hook = 1;

    mtt_resolve_raw_allocators();

    /* 库地址范围黑名单(lmdb/XML 等):跳过追踪,直接 raw_realloc。
     * 黑名单库内部 realloc 由 raw_realloc 处理,工具不维护 entry。
     * 如果走 malloc+memcpy+free fallback,内部各 hook 会各自检查黑名单。 */
    if (MTT_LR_IN_BLACKLIST()) {
        void *ret;
        if (raw_realloc != NULL) {
            ret = raw_realloc(ptr, size);
        } else {
            ret = (raw_malloc != NULL) ? raw_malloc(size) : NULL;
            if (ret != NULL && raw_free != NULL) raw_free(ptr);
        }
        mtt_hook_dec_depth();
        ctx->in_hook = saved_hook;
        return ret;
    }

    /* 工具内部线程：直接透传 */
    if (ctx->tool_internal) {
        void *ret;
        if (raw_realloc != NULL) {
            ret = raw_realloc(ptr, size);
        } else {
            ret = (raw_malloc != NULL) ? raw_malloc(size) : NULL;
            if (ret != NULL && raw_free != NULL) raw_free(ptr);
        }
    mtt_hook_dec_depth();
    ctx->in_hook = saved_hook;
        return ret;
    }

    if (raw_malloc == NULL) {
    mtt_hook_dec_depth();
    ctx->in_hook = saved_hook;
        return NULL;
    }

    mtt_ensure_init();
    mtt_state_t *s = mtt_state_get();
    if (s == NULL || atomic_load_explicit(&s->disabled, memory_order_acquire)) {
        /* 降级：优先使用 raw_realloc */
        if (raw_realloc != NULL) {
            void *ret = raw_realloc(ptr, size);
    mtt_hook_dec_depth();
    ctx->in_hook = saved_hook;
            return ret;
        }
        /* 无 raw_realloc：malloc + free 模拟(不拷贝,避免越界读)。
         * 旧 size 未知,若用 size 作为 memcpy 长度,新 size > 旧 size 时
         * 会越界读 ptr 之后的堆数据。与 tracker.c:mtt_realloc 同路径保持一致。
         * 此分支仅在初始化失败时走到,正常情况 raw_realloc 始终可用。 */
        void *new_ptr = raw_malloc(size);
        if (new_ptr == NULL) {
    mtt_hook_dec_depth();
    ctx->in_hook = saved_hook;
            return NULL;
        }
        if (raw_free != NULL) raw_free(ptr);
    mtt_hook_dec_depth();
    ctx->in_hook = saved_hook;
        return new_ptr;
    }

    /* ---- 正常追踪路径：使用 raw_realloc ---- */

    if (raw_realloc != NULL) {
        /* 分配前从追踪表读取旧条目（用于后续统计更新） */
        mtt_stripe_lock(s, ptr);
        mtt_entry_t *old_e = mtt_entry_find(s, ptr);
        mtt_stripe_unlock(s, ptr);

        void *new_ptr = raw_realloc(ptr, size);
        if (new_ptr == NULL) {
    mtt_hook_dec_depth();
    ctx->in_hook = saved_hook;
            return NULL;
        }

        if (old_e != NULL) {
            /* 旧指针有追踪记录：更新统计 + 替换条目 */
            mtt_stripe_lock(s, ptr);
            old_e = mtt_entry_find(s, ptr); /* 锁内再次确认 */
            if (old_e != NULL) {
                size_t sub_size = (old_e->size <= atomic_load_explicit(&s->current_bytes, memory_order_relaxed))
                    ? old_e->size : 0;
                if (sub_size > 0)
                    atomic_fetch_sub_explicit(&s->current_bytes, sub_size, memory_order_relaxed);
                else
                    atomic_store_explicit(&s->current_bytes, 0, memory_order_relaxed);
                atomic_fetch_add_explicit(&s->free_count, 1, memory_order_relaxed);
                mtt_entry_remove(s, ptr);
            }
            mtt_stripe_unlock(s, ptr);

            /* 创建新追踪记录（不阻塞业务） */
            if (!mtt_is_over_capacity(s)) {
                mtt_entry_t *new_e = mtt_entry_new(new_ptr, size);
                if (new_e != NULL) {
                    mtt_stripe_lock(s, new_ptr);
                    if (atomic_load_explicit(&s->entry_count, memory_order_relaxed) < MTT_MAX_ENTRIES) {
                        new_e->alloc_num = atomic_fetch_add_explicit(&s->alloc_seq, 1, memory_order_relaxed) + 1;
                        atomic_fetch_add_explicit(&s->alloc_count, 1, memory_order_relaxed);
                        atomic_fetch_add_explicit(&s->current_bytes, size, memory_order_relaxed);
                        atomic_fetch_add_explicit(&s->total_bytes, size, memory_order_relaxed);

                        {
                            int peak_changed = 0;
                            size_t cur = atomic_load_explicit(&s->current_bytes, memory_order_relaxed);
                            size_t old_peak = atomic_load_explicit(&s->peak_bytes, memory_order_relaxed);
                            while (cur > old_peak) {
                                if (atomic_compare_exchange_weak_explicit(&s->peak_bytes, &old_peak, cur,
                                        memory_order_relaxed, memory_order_relaxed)) {
                                    peak_changed = 1;
                                    break;
                                }
                            }
                            if (peak_changed)
                                atomic_store_explicit(&s->peak_updated, 1, memory_order_relaxed);
                        }
                        mtt_entry_add(s, new_e);
                    } else {
                        atomic_fetch_add_explicit(&s->skipped_overcap, 1, memory_order_relaxed);
                        mtt_entry_discard(s, new_e);
                    }
                    mtt_stripe_unlock(s, new_ptr);
                }
            }
        }
        /* else: 旧指针不在追踪表中（tracking 之前分配的），
         * raw_realloc 已完成实际内存操作，无需维护追踪表 */

    mtt_hook_dec_depth();
    ctx->in_hook = saved_hook;
        return new_ptr;
    }

    /* ---- raw_realloc 不可用（bootstrap 阶段）的降级路径 ---- */

    /* 先分配新内存（失败不破坏旧状态） */
    void *new_ptr = raw_malloc(size);
    if (new_ptr == NULL) {
    mtt_hook_dec_depth();
    ctx->in_hook = saved_hook;
        return NULL;
    }

    /* 创建新追踪记录 */
    mtt_entry_t *new_e = mtt_entry_new(new_ptr, size);
    if (new_e == NULL) {
        raw_free(new_ptr);
    mtt_hook_dec_depth();
    ctx->in_hook = saved_hook;
        return NULL;
    }

    /* 删除旧追踪记录（并获取旧大小以安全拷贝） */
    mtt_stripe_lock(s, ptr);
    mtt_entry_t *old_e = mtt_entry_find(s, ptr);
    size_t old_size = (old_e != NULL) ? old_e->size : 0;
    if (old_e != NULL) {
        if (old_e->size <= atomic_load_explicit(&s->current_bytes, memory_order_relaxed))
            atomic_fetch_sub_explicit(&s->current_bytes, old_e->size, memory_order_relaxed);
        else
            atomic_store_explicit(&s->current_bytes, 0, memory_order_relaxed);
        atomic_fetch_add_explicit(&s->free_count, 1, memory_order_relaxed);
        mtt_entry_remove(s, ptr);
    }
    mtt_stripe_unlock(s, ptr);

    /* 安全拷贝：仅拷贝已知的旧大小字节数，避免越界读取 */
    size_t copy_n = (old_size > 0) ? ((old_size < size) ? old_size : size) : 0;
    if (copy_n > 0)
        memcpy(new_ptr, ptr, copy_n);

    /* 插入新追踪记录 */
    mtt_stripe_lock(s, new_ptr);

    if (atomic_load_explicit(&s->entry_count, memory_order_relaxed) >= MTT_MAX_ENTRIES) {
        atomic_fetch_add_explicit(&s->skipped_overcap, 1, memory_order_relaxed);
        mtt_stripe_unlock(s, new_ptr);
        mtt_entry_discard(s, new_e);
        raw_free(ptr);
    mtt_hook_dec_depth();
    ctx->in_hook = saved_hook;
        return new_ptr;
    }

    new_e->alloc_num = atomic_fetch_add_explicit(&s->alloc_seq, 1, memory_order_relaxed) + 1;
    atomic_fetch_add_explicit(&s->alloc_count, 1, memory_order_relaxed);
    atomic_fetch_add_explicit(&s->current_bytes, size, memory_order_relaxed);
    atomic_fetch_add_explicit(&s->total_bytes,   size, memory_order_relaxed);

    {
        int peak_changed = 0;
        size_t cur = atomic_load_explicit(&s->current_bytes, memory_order_relaxed);
        size_t old_peak = atomic_load_explicit(&s->peak_bytes, memory_order_relaxed);
        while (cur > old_peak) {
            if (atomic_compare_exchange_weak_explicit(&s->peak_bytes, &old_peak, cur,
                    memory_order_relaxed, memory_order_relaxed)) {
                peak_changed = 1;
                break;
            }
        }
        if (peak_changed)
            atomic_store_explicit(&s->peak_updated, 1, memory_order_relaxed);
    }

    mtt_entry_add(s, new_e);
    mtt_stripe_unlock(s, new_ptr);

    raw_free(ptr);
    mtt_hook_dec_depth();
    ctx->in_hook = saved_hook;
    return new_ptr;
}

/* ======================================================================== *
 *              aligned_alloc / posix_memalign / reallocarray                 *
 * ======================================================================== */

/**
 * LD_PRELOAD 拦截的 aligned_alloc (C11)。
 * 优先用 raw_posix_memalign(若已解析),返回的指针可被 free() 正确释放
 * (libc free 识别 libc 内部分配的内存,无需追踪表反向查找)。
 *
 * 历史:原实现用 raw_malloc + 手动对齐,返回非 chunk-header 起点的 aligned
 * 指针,free(aligned) 会破坏堆。手动存原始指针到 ((void**)aligned)[-1]
 * 也是死代码,free 没有反向查找逻辑。
 *
 * 注意:aligned_alloc 不进入追踪系统(直接走 raw_posix_memalign)。
 * 嵌入式场景 aligned_alloc/posix_memalign 调用频率低,接受此折衷。 */
void* aligned_alloc(size_t alignment, size_t size)
{
    mtt_resolve_raw_allocators();

    /* C11 要求 alignment 为 2 的幂且 size 是 alignment 的整数倍;
     * POSIX/glibc 实现放宽了 size 的倍数要求,只要求 alignment 合法 */
    if (alignment == 0 || (alignment & (alignment - 1)) != 0) return NULL;
    if (alignment < sizeof(void*)) alignment = sizeof(void*);

    if (raw_posix_memalign != NULL) {
        void *p = NULL;
        if (raw_posix_memalign(&p, alignment, size ? size : 1) != 0)
            return NULL;
        return p;
    }

    /* raw_posix_memalign 不可用:回退到 raw_malloc。
     * glibc malloc 默认 16 字节对齐,alignment <= 16 时满足要求;
     * alignment > 16 时对齐保证被牺牲,但不做手动对齐(否则 free 崩)。 */
    if (raw_malloc == NULL) return NULL;
    return raw_malloc(size ? size : 1);
}

/** LD_PRELOAD 拦截的 posix_memalign (POSIX) */
int posix_memalign(void **memptr, size_t alignment, size_t size)
{
    if (alignment < sizeof(void*)) alignment = sizeof(void*);
    if ((alignment & (alignment - 1)) != 0) return 22; /* EINVAL */
    void *p = aligned_alloc(alignment, size);
    if (p == NULL) return 12; /* ENOMEM */
    *memptr = p;
    return 0;
}

/** LD_PRELOAD 拦截的 reallocarray (BSD) */
void* reallocarray(void *ptr, size_t nmemb, size_t size)
{
    if (nmemb > 0 && size > SIZE_MAX / nmemb) {
        errno = 12; /* ENOMEM */
        return NULL;
    }
    /* 黑名单快速检查:命中则 raw_realloc,绕过 realloc hook。
     * 否则 realloc hook 看到的 LR 是 reallocarray 函数体内 PC,黑名单失效。 */
    if (MTT_LR_IN_BLACKLIST()) {
        mtt_resolve_raw_allocators();
        if (raw_realloc != NULL) return raw_realloc(ptr, nmemb * size);
        /* raw_realloc 不可用:fallback 到 realloc(会走追踪,但罕见路径) */
    }
    return realloc(ptr, nmemb * size);
}

/** LD_PRELOAD 拦截的 memalign (过时) */
void* memalign(size_t alignment, size_t size)
{
    return aligned_alloc(alignment, size);
}

/** LD_PRELOAD 拦截的 valloc (过时) */
void* valloc(size_t size)
{
    return aligned_alloc((size_t)getpagesize(), size);
}

/* ======================================================================== *
 *            strdup / asprintf — 优化调用栈（跳过 libc 包装帧）                *
 * ======================================================================== */

/** LD_PRELOAD 拦截的 strdup：直接调 malloc，栈回溯跳过 strdup 自身 */
char* strdup(const char *s)
{
    /* 黑名单快速检查:命中则 raw_malloc + memcpy,绕过 malloc hook */
    if (MTT_LR_IN_BLACKLIST()) {
        mtt_resolve_raw_allocators();
        if (raw_malloc == NULL || s == NULL) return NULL;
        size_t len = strlen(s) + 1;
        char *p = (char*)raw_malloc(len);
        if (p != NULL) memcpy(p, s, len);
        return p;
    }
    size_t len = strlen(s) + 1;
    char *p = (char*)malloc(len);
    if (p != NULL) memcpy(p, s, len);
    return p;
}

/** LD_PRELOAD 拦截的 strndup */
char* strndup(const char *s, size_t n)
{
    /* 黑名单快速检查:同 strdup */
    if (MTT_LR_IN_BLACKLIST()) {
        mtt_resolve_raw_allocators();
        if (raw_malloc == NULL || s == NULL) return NULL;
        size_t len = strnlen(s, n);
        char *p = (char*)raw_malloc(len + 1);
        if (p != NULL) {
            memcpy(p, s, len);
            p[len] = '\0';
        }
        return p;
    }
    size_t len = strnlen(s, n);
    char *p = (char*)malloc(len + 1);
    if (p != NULL) {
        memcpy(p, s, len);
        p[len] = '\0';
    }
    return p;
}

/** LD_PRELOAD 拦截的 asprintf */
int asprintf(char **strp, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    int ret = vasprintf(strp, fmt, ap);
    va_end(ap);
    return ret;
}

/** LD_PRELOAD 拦截的 vasprintf */
int vasprintf(char **strp, const char *fmt, va_list ap)
{
    if (strp == NULL) return -1;
    va_list ap2;
    va_copy(ap2, ap);
    int len = vsnprintf(NULL, 0, fmt, ap);
    if (len < 0) { va_end(ap2); return -1; }

    /* 黑名单快速检查:命中则 raw_malloc,绕过 malloc hook。
     * asprintf 内部调 vasprintf,所以 asprintf 不需要单独检查。 */
    char *buf;
    if (MTT_LR_IN_BLACKLIST()) {
        mtt_resolve_raw_allocators();
        if (raw_malloc == NULL) { va_end(ap2); return -1; }
        buf = (char*)raw_malloc((size_t)len + 1);
    } else {
        buf = (char*)malloc((size_t)len + 1);
    }
    if (buf == NULL) { va_end(ap2); return -1; }
    int written = vsnprintf(buf, (size_t)len + 1, fmt, ap2);
    va_end(ap2);
    if (written < 0) {
        /* 注意:黑名单命中时 buf 是 raw_malloc 分配的,free hook 会查 entry
         * 找不到对应 entry,直接 raw_free,行为正确 */
        free(buf);
        return -1;
    }
    *strp = buf;
    return written;
}

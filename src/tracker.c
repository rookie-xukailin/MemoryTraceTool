/*
 * MemoryTraceTool — 核心追踪引擎。
 *
 * 本文件实现了内存泄漏检测的所有核心逻辑：
 *   - 原始分配器指针的延迟解析（dlsym + bootstrap 缓冲区兜底）
 *   - 以指针地址为键的哈希表存储分配记录（4096 桶，64 分段锁）
 *   - 调用栈捕获（backtrace）和符号解析
 *   - 采样与容量上限控制
 *   - 全局状态懒初始化（线程安全，双重检查锁定）
 *
 * 防递归策略（多层防护）：
 *   - 第1层: raw_malloc/raw_free 直接调用 libc，不触发 hook
 *   - 第2层: g_in_hook (__thread) 置位时 hook 透传到 raw_*
 *   - 第3层: bootstrap 静态缓冲区在 dlsym 阶段兜底
 *   - 第4层: g_in_capture (__thread) 防止 backtrace 重入
 *
 * 原子操作内存序约定：
 *   - 统计计数器（alloc_count, free_count, current_bytes...）：relaxed
 *     仅在报告线程周期读取用于展示，近似值可接受
 *   - 控制标志（initialized, disabled, g_raw_ready）：acquire/release
 *     确保相关数据结构的初始化对其他线程可见
 *   - 序号/采样计数（alloc_seq, sample_counter）：relaxed
 *     仅需原子递增，不需要同步其他数据
 */
#define _GNU_SOURCE
#include <signal.h>
#include "mtt_internal.h"
#include "reporter.h"
#include "time_series.h"
#include "http_server.h"
#include "per_thread.h"
#include "addr_validate.h"
#include "unwind_libunwind.h"
#include "stack_cache.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#if MTT_HAS_BACKTRACE
#include <execinfo.h>
#endif
#include <unistd.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <stdatomic.h>

/* 全局线程上下文槽位数组（替代 __thread 变量）。
 * 在 tracker.c 中定义，per_thread.h 中 extern 声明。
 * 64 字节对齐确保首元素落在缓存行边界。 */
mtt_per_thread_t g_threads[MTT_MAX_THREADS]
    __attribute__((aligned(64)));

/* ======================================================================== *
 *                    全局单例状态                                             *
 * ======================================================================== */

/**
 * 获取全局单例状态指针。
 *
 * 将定义放在 .c 文件中（而非头文件的 static inline），
 * 确保所有翻译单元共享同一实例。
 */
mtt_state_t* mtt_state_get(void)
{
    static mtt_state_t g_state = {0};
    return &g_state;
}

/* ======================================================================== *
 *                    原始分配器 — 始终调用真实的 libc                         *
 * ======================================================================== */

/* 全局函数指针：由 mtt_resolve_raw_allocators() 懒解析初始化。
 * volatile 限定防止编译器在跨函数调用边界时将其缓存在寄存器中，
 * 确保 CAS loser 线程在下次进入本函数时读到 CAS winner 写入的最新值。
 * 初始值为 NULL，调用者必须确保只在这些指针非 NULL 时使用。 */
raw_malloc_fn  volatile raw_malloc  = NULL;
raw_free_fn    volatile raw_free    = NULL;
raw_calloc_fn  volatile raw_calloc  = NULL;
raw_realloc_fn volatile raw_realloc = NULL;
raw_posix_memalign_fn volatile raw_posix_memalign = NULL;

/* 三档日志等级(由环境变量 MTT_DEBUG 控制)。
 *   0 = 静默(只输出 leak 报告 + heartbeat + HTTP API + SIGUSR1)
 *   1 = 关键事件(启动/退出/libunwind 崩溃/WARNING,默认)
 *   2 = 全量(等级 1 + 阶段日志 + scan 进度) */
_Atomic int mtt_debug_level = MTT_DEBUG_DEFAULT;

/* 栈回溯模式(由环境变量 MTT_UNWINDER 控制):
 * 0 = auto(libunwind 优先,失败 fallback backtrace)
 * 1 = libunwind only
 * 2 = glibc backtrace only(绕过 libunwind,HDM3 等环境崩溃时的 workaround)
 * 默认 0(auto=libunwind):实测 backtrace 虽快 6.5 倍,但在 HDM3 上
 * storageManager 场景会 coredump(backtrace 内部 _Unwind_Backtrace 在
 * 缺 unwind 表的 .so 上必崩且无保护),libunwind 有信号保护兜底。
 * 若需测试 backtrace 性能,用 MTT_UNWINDER=backtrace。 */
int g_unwinder_mode = 0;

/* 运行时栈回溯深度(默认 8 帧):由 MTT_MAX_STACK_FRAMES 环境变量覆盖。
 * 回溯循环/backtrace/FP chain 用此值,控制回溯成本。
 * 默认 8:泄漏点接口函数通常在帧 2-4,8 帧可区分且比 64 帧快 ~40%。
 * 调大(如 16/32/64)获更深栈但回溯更慢。 */
int g_max_stack_frames = 64;

/* fork 安全相关变量(放文件作用域,方便 mtt_fork_child 重置)。
 *
 * init_lock:mtt_ensure_init 内部串行化锁,fork 后子进程需要重新初始化
 * signal_thread_started:防止 mtt_signal_thread_start 重复启动的标志,fork 后重置
 */
static pthread_mutex_t g_init_lock = PTHREAD_MUTEX_INITIALIZER;
static _Atomic int g_signal_thread_started = 0;
/* g_signal_thread_running 定义在信号线程段(line 1589),这里前向声明让
 * mtt_fork_child(line 1495)可见 */
extern _Atomic int g_signal_thread_running;

/* ======================================================================== *
 *                    阶段标记日志(MTT_DEBUG=1 时定位崩溃用)                  *
 * ======================================================================== */

/**
 * 输出带阶段编号的诊断日志,定位 init / hook 崩溃用。
 *
 * 仅在 mtt_debug_level>=2(全量调试模式)时输出,等级 0/1 静默,
 * 关闭时只剩一次 atomic_load,热路径几乎零开销。用 stage_id 标识阶段
 * (数字越小越早),日志格式: "[MTT] S<id> [t=xxx]: <msg>\n"
 *
 * 线程安全:只使用栈缓冲区 + write(),不调用 malloc。
 *
 * @param stage_id  阶段编号(1~99,数字越小越早)
 * @param fmt       printf 风格格式串
 */
void mtt_log_stage(int stage_id, const char *fmt, ...)
{
    if (atomic_load_explicit(&mtt_debug_level, memory_order_relaxed) < 2)
        return;

    /* 取低 12 位作为线程短 ID(够区分线程,不暴露真实 tid 隐私),
     * 方便区分日志是同一线程顺序产生还是多线程交错产生 */
    unsigned long tid_short = (unsigned long)pthread_self() & 0xFFF;

    char buf[256];
    int off = snprintf(buf, sizeof(buf), "[MTT] S%d [t=%03lx]: ",
                       stage_id, tid_short);
    if (off <= 0 || off >= (int)sizeof(buf)) return;

    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf + off, sizeof(buf) - off, fmt, ap);
    va_end(ap);
    if (n < 0) return;
    if (off + n >= (int)sizeof(buf) - 1)
        n = (int)sizeof(buf) - off - 2;
    buf[off + n] = '\n';
    MTT_DIAG_WRITE(STDERR_FILENO, buf, (size_t)(off + n + 1));
}

/* CAS 保护的一次性解析标志 */
static atomic_int g_raw_resolved = 0;

/* raw_* 指针是否已完成 dlsym 解析（发布/订阅屏障） */
static atomic_int g_raw_ready = 0;

/* 递归保护：dlsym 内部可能触发 malloc，防止 resolve 自身递归 */
/* g_raw_resolving 已迁移至 per_thread.h 槽位数组 */

/*
 * 防递归核心标志 (__thread)：
 * 置位期间，hooks.c 的 malloc/free 等函数直接透传到 raw_*，
 * 不做任何追踪、不分配 entry、不捕获栈。
 * 使用 save/restore 模式支持嵌套。
 */
/* g_in_hook / g_tool_internal moved to per_thread.h */

/*
 * 工具内部线程标志：
 * reporter 线程和 HTTP 服务线程设置此标志，其后所有 malloc/free 直接透传 raw_*，
 * 不进入追踪系统，避免工具自身的分配污染泄漏报告。
 */


/* ======================================================================== *
 *                  Bootstrap 分配器（dlsym 阶段兜底）                         *
 * ======================================================================== */

/* 静态缓冲区：在 raw_* 解析完成前提供临时分配能力。
 * 多线程安全：使用原子偏移，各自分配不会破坏彼此数据。
 * 注意：bootstrap 分配的内存不回收，仅用于一次性初始化阶段。 */
static char           g_bootstrap_buf[MTT_BOOTSTRAP_BUF_SIZE];
static _Atomic size_t g_bootstrap_offset = 0;

static void* bootstrap_malloc(size_t size)
{
    /* 8 字节对齐 */
    size_t aligned = (size + 7) & ~((size_t)7);
    size_t old = atomic_fetch_add(&g_bootstrap_offset, aligned);
    if (old + aligned > MTT_BOOTSTRAP_BUF_SIZE)
        return NULL;
    return g_bootstrap_buf + old;
}

static void bootstrap_free(void *ptr)
{
    (void)ptr; /* bootstrap 分配不回收 */
}

static void* bootstrap_calloc(size_t count, size_t size)
{
    /* 整数溢出检查:与 hooks.c calloc 保持一致 */
    if (count > 0 && size > 0 && count > SIZE_MAX / size)
        return NULL;
    size_t total = count * size;
    void *p = bootstrap_malloc(total);
    if (p != NULL) {
        size_t actual = (total + 7) & ~((size_t)7);
        if (actual > 0) memset(p, 0, actual);
    }
    return p;
}

static void* bootstrap_realloc(void *ptr, size_t size)
{
    /* bootstrap realloc 简化实现：新分配 + 拷贝 + 释放旧（旧大小不可知） */
    if (ptr == NULL) return bootstrap_malloc(size);
    if (size == 0) { bootstrap_free(ptr); return NULL; }
    void *new_ptr = bootstrap_malloc(size);
    if (new_ptr == NULL) return NULL;
    /* 防御：旧大小不可知，限制拷贝上限 64KB 防止越界（仅 bootstrap 阶段） */
    size_t copy_n = (size < MTT_BOOTSTRAP_BUF_SIZE) ? size : MTT_BOOTSTRAP_BUF_SIZE;
    memcpy(new_ptr, ptr, copy_n);
    bootstrap_free(ptr);
    return new_ptr;
}

/* ======================================================================== *
 *                 原始分配器解析（懒初始化 + CAS + 递归保护）                   *
 * ======================================================================== */

/**
 * libc 库名候选列表（按优先级排列）。
 * glibc → musl → Android bionic → 通用 POSIX。
 */
static const char* libc_candidates[] = {
    "libc.so.6",       /* glibc (Linux) */
    "libc.so",         /* musl libc, 通用 POSIX */
    "libc.musl-aarch64.so.1",  /* musl on ARM64 */
    NULL
};

/**
 * 解析真正的 libc 分配函数指针。
 *
 * 使用 dlsym(RTLD_NEXT) 获取 libc 的 malloc/free/calloc/realloc，
 * 避免 LD_PRELOAD 模式下调用自身导致无限递归。
 *
 * 懒初始化：首次 hook 调用时触发，此时动态链接器已完全就绪。
 * 线程安全：CAS 确保多线程下仅执行一次。
 * 递归保护：g_raw_resolving 标志防止 dlsym 内部 malloc 回调。
 */
void mtt_resolve_raw_allocators(void)
{
    /* 快速路径：已完全解析（acquire 确保 raw_* 指针对其他线程可见） */
    if (atomic_load_explicit(&g_raw_ready, memory_order_acquire))
        return;

    /* 快速路径：前一次 CAS 失败后预置了 bootstrap，但 winner 尚未完成 */
    if (raw_malloc != NULL)
        return;

    /* 递归保护：dlsym 内部可能触发 malloc */
    mtt_per_thread_t *ctx = mtt_thread_get();
    if (ctx == NULL || ctx->raw_resolving)
        return;

    /* 预置 bootstrap 分配器：必须在 CAS 之前完成。
     * 确保 CAS 失败线程使用 bootstrap_*（非 NULL），避免空指针崩溃。
     * CAS 失败后，线程在下一次 mtt_resolve_raw_allocators() 调用时
     * 通过 g_raw_ready 检查（而非 raw_malloc != NULL）得知真正完成。
     * Winner 线程在约 0.1ms 内完成 dlsym，bootstrap 缓冲区足以支撑。 */
    raw_malloc  = bootstrap_malloc;
    raw_free    = bootstrap_free;
    raw_calloc  = bootstrap_calloc;
    raw_realloc = bootstrap_realloc;

    /* CAS 确保仅单线程执行 dlsym 解析 */
    int expected = 0;
    if (!atomic_compare_exchange_strong(&g_raw_resolved, &expected, 1))
        return;

    ctx->raw_resolving = 1;

    /* dlsym 内部可能触发 malloc，设置 g_in_hook 确保递归调用全部透传 */
    int saved_hook = ctx->in_hook;
    ctx->in_hook = 1;

    raw_malloc_fn real_malloc   = (raw_malloc_fn)dlsym(RTLD_NEXT, "malloc");
    raw_free_fn   real_free     = (raw_free_fn)dlsym(RTLD_NEXT, "free");
    raw_calloc_fn real_calloc   = (raw_calloc_fn)dlsym(RTLD_NEXT, "calloc");
    raw_realloc_fn real_realloc = (raw_realloc_fn)dlsym(RTLD_NEXT, "realloc");
    raw_posix_memalign_fn real_pma = (raw_posix_memalign_fn)dlsym(RTLD_NEXT, "posix_memalign");

    /* RTLD_NEXT 在某些 ARM32 系统上可能错误返回 LD_PRELOAD 自身,
     * 用 dladdr 验证解析到的函数不在 libmemorytracetool 内。
     * 仅在 dladdr 成功且文件名不含 libmemorytracetool 时接受,
     * dladdr 失败时拒绝(无法证明非 hook 自身,保守丢弃)。 */
    #define RAW_SAFE_SET(fn, val) do { \
        if ((val) != NULL) { \
            Dl_info _info; \
            if (dladdr((void*)(val), &_info) \
                && (_info.dli_fname == NULL \
                    || strstr(_info.dli_fname, "libmemorytracetool") == NULL)) { \
                (fn) = (val); \
            } \
        } \
    } while(0)
    RAW_SAFE_SET(raw_malloc,  real_malloc);
    RAW_SAFE_SET(raw_free,    real_free);
    RAW_SAFE_SET(raw_calloc,  real_calloc);
    RAW_SAFE_SET(raw_realloc, real_realloc);
    RAW_SAFE_SET(raw_posix_memalign, real_pma);
    #undef RAW_SAFE_SET

    /* RTLD_NEXT 失败时遍历 libc 候选库列表（dlopen/ptrace 注入路径）。
     * 通过检查 raw_* 是否仍为 bootstrap 函数来判断 RTLD_NEXT 是否成功，
     * 而非检查 NULL（bootstrap 预填充使 raw_* 始终非 NULL，
     * 原 NULL 检查条件始终为 false，导致 fallback 为死代码）。 */
    if (raw_malloc == bootstrap_malloc || raw_free == bootstrap_free ||
        raw_calloc == bootstrap_calloc || raw_realloc == bootstrap_realloc) {
        for (int i = 0; libc_candidates[i] != NULL; i++) {
            void *libc_handle = dlopen(libc_candidates[i], RTLD_LAZY);
            if (libc_handle == NULL) continue;

            /* 对每个 dlsym 返回值判空后再赋值，防止覆盖已有的 bootstrap 值 */
            if (raw_malloc == bootstrap_malloc) {
                raw_malloc_fn fn = (raw_malloc_fn)dlsym(libc_handle, "malloc");
                if (fn != NULL) raw_malloc = fn;
            }
            if (raw_free == bootstrap_free) {
                raw_free_fn fn = (raw_free_fn)dlsym(libc_handle, "free");
                if (fn != NULL) raw_free = fn;
            }
            if (raw_calloc == bootstrap_calloc) {
                raw_calloc_fn fn = (raw_calloc_fn)dlsym(libc_handle, "calloc");
                if (fn != NULL) raw_calloc = fn;
            }
            if (raw_realloc == bootstrap_realloc) {
                raw_realloc_fn fn = (raw_realloc_fn)dlsym(libc_handle, "realloc");
                if (fn != NULL) raw_realloc = fn;
            }
            if (raw_posix_memalign == NULL) {
                raw_posix_memalign_fn fn =
                    (raw_posix_memalign_fn)dlsym(libc_handle, "posix_memalign");
                if (fn != NULL) raw_posix_memalign = fn;
            }

            /* 不 dlclose：避免 raw_* 悬空。
             * 仅在全部解析完成后才跳出，否则继续尝试下一个候选库。 */
            if (raw_malloc != bootstrap_malloc && raw_free != bootstrap_free &&
                raw_calloc != bootstrap_calloc && raw_realloc != bootstrap_realloc)
                break;
        }
    }

    ctx->in_hook = saved_hook;
    ctx->raw_resolving = 0;

    /* 发布屏障：确保 raw_* 指针写入对所有线程可见后，再置 ready 标志 */
    atomic_store_explicit(&g_raw_ready, 1, memory_order_release);
}

/* ======================================================================== *
 *                       栈捕获（backtrace + 防重入）                          *
 * ======================================================================== */

/* __thread 递归保护：backtrace 内部可能触发 malloc */
/* g_in_capture moved to per_thread.h */

/**
 * 捕获当前调用栈并存入 entry->stack[]。
 *
 * 使用 backtrace() 获取最多 MTT_STACK_DEPTH 帧的返回地址。
 * g_in_capture (__thread) 防止 backtrace 内部 malloc 导致的无限递归。
 * save/restore 模式支持嵌套调用。
 *
 * ARM32 Thumb 兼容：backtrace 返回的地址 bit 0 在 Thumb 模式下为 1，
 * 影响哈希计算和 dladdr 符号解析，此处统一清除。
 *
 * 未来改进方向（借鉴 heaptrack trace_libunwind.cpp）：
 *   当前使用 glibc backtrace()（仅 glibc 可用），在 musl/bionic 上
 *   退化（MTT_HAS_BACKTRACE=0 → stack_frames=0）。
 *   迁移到 libunwind 可消除此限制：
 *   - uw_init() + unw_backtrace() 接口与 backtrace() 接近，改动最小
 *   - libunwind 内建 DWARF/ARM EH unwind 支持，无需 -rdynamic 或 unwind 表
 *   - 支持异步跨线程回溯（heaptrack 注入模式的核心能力）
 *   详见 stack_cache.c 头部注释中的 libunwind 改进说明。
 */
void mtt_capture_stack(mtt_entry_t *entry)
{
    if (entry == NULL) return;
    mtt_log_stage(60, "capture_stack enter entry=%p", (void*)entry);

    mtt_per_thread_t *ctx = mtt_thread_get();
    if (ctx == NULL || ctx->in_capture) {
        entry->stack_frames = 0;
        mtt_log_stage(61, "capture_stack skip (ctx null or in_capture)");
        return;
    }
    mtt_log_stage(62, "capture_stack ctx ok, in_capture=%d", ctx->in_capture);

    int saved = ctx->in_capture;
    ctx->in_capture = 1;

    int bt_frames = 0;

    /* 优先路径:libunwind(若可用且未被 MTT_UNWINDER=backtrace 禁用)
     * libunwind 内建 ARM EHABI + DWARF + FP chain 多策略 unwind,在 ARM32
     * -O2 -fomit-frame-pointer 二进制上通常能拿到比 glibc backtrace() 更深的栈
     * (实测 demo_nofp -O2 -fomit-frame-pointer:libunwind 5 帧 vs backtrace 3 帧)。
     * 软加载失败时自动回退到 glibc backtrace,行为完全等价于无 libunwind 集成。
     *
     * 注意:libunwind 仍受目标二进制的 .ARM.exidx 完整性约束 —— 若目标
     * 编译时未加 -funwind-tables,无 unwind 信息的函数处仍会终止。
     * 工具检测到此场景会输出 WARNING 提示用户重建(见 reporter.c Phase 1.3)。
     *
     * per-thread 降级:libunwind 崩过的线程被 mtt_libunwind_thread_disabled
     * 标记,跳过 libunwind 调用。同一栈上 backtrace 必崩(_Unwind_Backtrace
     * 同样踩雷),所以降级线程也跳过 backtrace,只走 FP chain 兜底 */
    int use_libunwind = (g_unwinder_mode != 2);
    int disabled = mtt_libunwind_thread_disabled();
    mtt_log_stage(63, "capture_stack use_libunwind=%d (mode=%d) disabled=%d",
                  use_libunwind, g_unwinder_mode, disabled);
    if (use_libunwind && !disabled && mtt_libunwind_available()) {
        mtt_log_stage(70, "capture_stack calling mtt_libunwind_capture");
        int n = mtt_libunwind_capture(entry->stack, g_max_stack_frames);
        mtt_log_stage(71, "capture_stack libunwind returned n=%d", n);
        if (n >= 2) {
            entry->stack_frames = n;
            ctx->in_capture = saved;
            mtt_log_stage(72, "capture_stack done via libunwind frames=%d", n);
            return;
        }
        /* n < 2:重新检查 disabled,因为 mtt_libunwind_capture 内可能刚 mark */
        disabled = mtt_libunwind_thread_disabled();
        if (disabled) {
            /* libunwind 刚崩(返回 -1 或 0/1 帧且已 mark),不能走 backtrace:
             * 同栈上 _Unwind_Backtrace 必崩,handler 已恢复 SIG_DFL → core dump。
             * 直接放弃栈信息,走 FP chain 兜底 */
            mtt_log_stage(74, "capture_stack skip backtrace (thread disabled after libunwind crash)");
        } else {
            /* libunwind 没崩只是浅栈(0/1 帧),落回 glibc backtrace 再试一次 */
            mtt_log_stage(73, "capture_stack libunwind weak (%d<2), falling back", n);
        }
    }

    /* backtrace 路径:
     *   - !disabled:正常线程,backtrace 直接调(无保护,默认栈不会崩)
     *   - disabled :libunwind 在本线程崩过,后续 capture 的栈不一定都坏,
     *                仍要尝试 backtrace 拿浅栈。但 backtrace 内部走
     *                _Unwind_Backtrace 也可能踩同一个雷,用 mtt_safe_backtrace
     *                包信号保护,崩了返回 0 走 FP chain 兜底。
     *                之前 v1 实现错误地完全跳过 backtrace,导致长期持有的
     *                内存(leak 表里大部分 entry)全部丢失栈信息 */
#if MTT_HAS_BACKTRACE
    if (!disabled) {
        entry->stack_frames = backtrace(entry->stack, g_max_stack_frames);
        if (entry->stack_frames < 0)
            entry->stack_frames = 0;
        for (int i = 0; i < entry->stack_frames; i++)
            entry->stack[i] = MTT_FIX_THUMB_ADDR(entry->stack[i]);
        bt_frames = entry->stack_frames;
    } else {
        entry->stack_frames = mtt_safe_backtrace(entry->stack, g_max_stack_frames);
        if (entry->stack_frames < 0)
            entry->stack_frames = 0;
        for (int i = 0; i < entry->stack_frames; i++)
            entry->stack[i] = MTT_FIX_THUMB_ADDR(entry->stack[i]);
        bt_frames = entry->stack_frames;
    }
#endif

    /* FP chain 兜底:仅当 backtrace 完全失败(0 帧)时启用。
     *
     * 历史教训(9f2e4ae 引入后修复):
     *   - 曾尝试 bt_frames<THRESHOLD 时也启用 FP chain,但 ARM32 Thumb-2 上
     *     __builtin_frame_address(0) 返回 r7 而非 r11,{prev_fp,lr} 偏移随
     *     prologue 变化,通用代码无法可靠读取 → 拿到 sl/r11 等垃圾值。
     *   - 真正可靠的 ARM unwind 需要解析 .ARM.exidx + DWARF,这正是
     *     libunwind 做的事(见 Phase 2 集成)。
     *
     * 当前限制:
     *   仅 bt_frames==0 触发,用最保守的安全校验。2-3 帧场景由 libunwind
     *   集成后接管,不再走 FP chain 兜底。
     *
     * 安全保证:
     *   1. 仅在 bt_frames == 0 时启动(backtrace 完全失败的兜底场景)
     *   2. prev_fp 必须严格大于 fp(ARM 栈向低地址增长,父帧地址更高)
     *   3. prev_fp - fp 不得超过 64KB(防止大跨度跳到未映射区)
     *   4. 每个 LR 必须落在可执行段(新增,addr_validate 提供)
     *   5. 循环上限 MTT_STACK_DEPTH,避免无限循环 */
    if (bt_frames == 0) {
        void *fp_stack[MTT_STACK_DEPTH];
        int fp_count = 0;
        void **fp = (void**)__builtin_frame_address(0);
        while (fp != NULL && fp_count < MTT_STACK_DEPTH) {
            void *prev_fp = fp[0];
            void *lr      = fp[1];
            if (lr == NULL) break;
            if (prev_fp == NULL) break;
            /* LR 必须落在可执行段内,过滤栈垃圾误判 */
            if (!mtt_addr_is_executable(MTT_FIX_THUMB_ADDR(lr))) break;
            /* 严格校验:父帧地址必须严格递增,且跨度 <= 64KB。
             * 防止无帧指针二进制上 prev_fp 为栈垃圾导致跳到无效地址。 */
            uintptr_t prev_addr = (uintptr_t)prev_fp;
            uintptr_t curr_addr = (uintptr_t)fp;
            if (prev_addr <= curr_addr) break;
            if (prev_addr - curr_addr > (UINT64_C(1) << 16)) break;
            fp_stack[fp_count] = MTT_FIX_THUMB_ADDR(lr);
            fp_count++;
            if (prev_fp == (void*)fp) break;
            fp = (void**)prev_fp;
        }
        if (fp_count > 0) {
            for (int i = 0; i < fp_count; i++)
                entry->stack[i] = fp_stack[i];
            entry->stack_frames = fp_count;
        }
    }

    ctx->in_capture = saved;
}

/* ======================================================================== *
 *                       采样与容量控制                                       *
 * ======================================================================== */

/**
 * 决定当前分配是否应被记录。
 *
 * 支持的判定模式（优先级从高到低）：
 *   1. 大分配豁免:size >= MTT_BIG_ALLOC_THRESHOLD(1MB)总是追踪
 *   2. 中等分配豁免:size >= MTT_SAMPLE_EXEMPT_THRESHOLD(1KB)总是追踪,
 *      不参与字节采样累加(避免大对象吃掉累加器配额)
 *   3. 字节统计采样(sample_rate > 0):size < 1KB 时按 2^sample_rate 字节
 *      平均步长概率采样,只统计小对象的累积
 *   4. 固定计数采样(sample_period > 0):每 N 次 alloc 记录 1 次(旧模式)
 *   5. 全量追踪(两者均为 0)
 *
 * 字节统计采样使用累加器方式：每次小对象 alloc 时将 size 累加到 sample_bytes_accum,
 * 当累加值超过 2^sample_rate 时，重置累加器并记录本次分配。
 *
 * @param s     全局状态指针（调用者已确保非 NULL）
 * @param size  本次分配的字节数
 * @return      1=应记录, 0=跳过
 */
int mtt_should_track(mtt_state_t *s, size_t size)
{
    /* 大分配总是追踪(>=1MB,已有豁免) */
    if (size >= MTT_BIG_ALLOC_THRESHOLD)
        return 1;

    /* 中等分配豁免(>=1KB):直接全量追踪,不参与字节采样累加。
     * 设计目的:中等对象不漏检 + 大对象不"吃掉"累加器配额 + 小对象采样率稳定。
     * 详见 mtt_internal.h MTT_SAMPLE_EXEMPT_THRESHOLD 注释 */
    if (size >= MTT_SAMPLE_EXEMPT_THRESHOLD)
        return 1;

    /* 字节统计采样模式(只对 <1KB 的小对象生效) */
    size_t rate = atomic_load_explicit(&s->sample_rate, memory_order_relaxed);
    if (rate > 0) {
        size_t step = (size_t)1 << rate; /* 2^sample_rate */
        size_t old_accum = atomic_fetch_add_explicit(&s->sample_bytes_accum, size,
                                                      memory_order_relaxed);
        if (old_accum + size >= step) {
            /* 达到采样阈值：重置累加器（减去 step）+ 记录本次 */
            atomic_fetch_sub_explicit(&s->sample_bytes_accum, step, memory_order_relaxed);
            return 1;
        }
        atomic_fetch_add_explicit(&s->skipped_sampled, 1, memory_order_relaxed);
        return 0;
    }

    /* 固定计数采样模式（旧模式，保持兼容） */
    unsigned period = atomic_load_explicit(&s->sample_period, memory_order_relaxed);
    if (period == 0)
        return 1; /* 全量追踪 */

    uint64_t c = atomic_fetch_add_explicit(&s->sample_counter, 1,
                                           memory_order_relaxed);
    if ((c % period) == 0)
        return 1;

    atomic_fetch_add_explicit(&s->skipped_sampled, 1, memory_order_relaxed);
    return 0;
}

/**
 * 检查调用栈帧中是否包含黑名单库（借鉴 libleak LEAK_LIB_BLACKLIST）。
 *
 * 遍历黑名单列表中逗号分隔的 .so 名称，
 * 逐一检查是否出现在符号字符串中（子串匹配）。
 *
 * @param s       全局状态指针
 * @param symbol  已解析的符号字符串，如 "func+0x1a4 (libblacklisted.so)"
 * @return        1=在黑名单中（应跳过）, 0=不在黑名单中
 */
int mtt_is_blacklisted(mtt_state_t *s, const char *symbol)
{
    if (s == NULL || symbol == NULL || !s->lib_blacklist_ready) return 0;
    if (s->lib_blacklist[0] == '\0') return 0;

    /* 遍历逗号分隔的黑名单列表，检查符号中是否包含目标库名 */
    char buf[512] = {0};
    memcpy(buf, s->lib_blacklist, sizeof(buf) - 1);
    char *token = strtok(buf, ",");
    while (token != NULL) {
        /* 跳过前导空白 */
        while (*token == ' ' || *token == '\t') token++;
        if (token[0] != '\0' && strstr(symbol, token) != NULL)
            return 1;
        token = strtok(NULL, ",");
    }
    return 0;
}

/* ======================================================================== *
 *     库地址范围黑名单(MTT_LIB_BLACKLIST_FAST)                              *
 * ======================================================================== *
 *  启动时解析 /proc/self/maps,记录黑名单库的地址范围。热路径 hook 用 LR
 *  (__builtin_return_address(0))快速判断,命中则跳过抓栈(节省 8.5μs/次)。
 *
 *  与 MTT_LIB_BLACKLIST 区别:
 *    - 现有 MTT_LIB_BLACKLIST:reporter scan 时按 symbol 字符串过滤(只影响显示)
 *    - 本次 MTT_LIB_BLACKLIST_FAST:热路径按地址范围过滤(直接跳过抓栈,省 CPU)
 *
 *  典型场景:BMC 业务调 lmdb / libxml2,库内部海量 malloc 触发工具抓栈,
 *  命令处理从 1 秒拖到 30~45 秒。设 MTT_LIB_BLACKLIST_FAST=liblmdb,libxml2
 *  后,这些库内部的 malloc 跳过抓栈,业务命令处理速度恢复。
 */
mtt_addr_range_t g_blacklist_ranges[MTT_BLACKLIST_RANGES_MAX];
int              g_blacklist_range_count = 0;
int              g_blacklist_fast_enabled = 0;

/**
 * 解析 MTT_LIB_BLACKLIST_FAST 环境变量 + /proc/self/maps,填充 g_blacklist_ranges。
 *
 * 流程:
 *   1. 读环境变量,逗号分隔成 tokens(类似 MTT_LIB_BLACKLIST)
 *   2. fopen /proc/self/maps 逐行解析 "起始-结束 rwxp ... pathname"
 *   3. pathname 包含某 token → 记录 [start, end]
 *
 * 失败处理:
 *   - 环境变量未设:静默 return,黑名单不启用
 *   - /proc/self/maps 不可读:静默 return,黑名单不启用(fallback 现状)
 *   - 范围数超过 MTT_BLACKLIST_RANGES_MAX:截断,输出 INFO 日志
 *
 * 由 mtt_ensure_init 在 init_lock 内调用,保证单线程首次执行。
 */
static void mtt_parse_blacklist_fast(void)
{
    const char *env = getenv("MTT_LIB_BLACKLIST_FAST");
    if (env == NULL || env[0] == '\0') {
        return;  /* 用户未配置,黑名单不启用 */
    }

    /* 复制到本地 buffer strtok 会修改 */
    char buf[512];
    size_t elen = strlen(env);
    if (elen >= sizeof(buf)) elen = sizeof(buf) - 1;
    memcpy(buf, env, elen);
    buf[elen] = '\0';

    /* 解析为 tokens(最多 16 个) */
    char *tokens[16];
    int ntokens = 0;
    char *tok = strtok(buf, ",");
    while (tok != NULL && ntokens < 16) {
        while (*tok == ' ' || *tok == '\t') tok++;  /* 跳过前导空白 */
        if (*tok != '\0') tokens[ntokens++] = tok;
        tok = strtok(NULL, ",");
    }
    if (ntokens == 0) return;

    /* 解析 /proc/self/maps */
    FILE *f = fopen("/proc/self/maps", "r");
    if (f == NULL) {
        char wbuf[128];
        int wlen = snprintf(wbuf, sizeof(wbuf),
            "[MTT] WARNING: /proc/self/maps not readable, MTT_LIB_BLACKLIST_FAST disabled\n");
        if (wlen > 0 && wlen < (int)sizeof(wbuf))
            MTT_LOG_INFO(wbuf, (size_t)wlen);
        return;  /* 嵌入式环境可能没 /proc,fallback 到现状 */
    }

    char line[512];
    int truncated = 0;
    while (fgets(line, sizeof(line), f) != NULL) {
        /* 行格式:"start-end rwxp offset dev inode pathname" */
        unsigned long start, end;
        char pathname[256] = {0};
        /* pathname 可能不存在(如 [stack]、[heap]),sscanf 返回 2 */
        int n = sscanf(line, "%lx-%lx %*s %*s %*s %*s %255[^\n]",
                       &start, &end, pathname);
        if (n < 2) continue;  /* 解析失败 */
        if (n < 3 || pathname[0] == '\0') continue;  /* 无 pathname(如 [heap]) */

        /* 检查 pathname 是否匹配任何 token */
        int matched = 0;
        for (int i = 0; i < ntokens; i++) {
            if (strstr(pathname, tokens[i]) != NULL) {
                matched = 1;
                break;
            }
        }
        if (!matched) continue;

        /* 匹配,记录地址范围 */
        if (g_blacklist_range_count >= MTT_BLACKLIST_RANGES_MAX) {
            truncated = 1;
            break;
        }
        g_blacklist_ranges[g_blacklist_range_count].start = (void*)start;
        g_blacklist_ranges[g_blacklist_range_count].end   = (void*)end;
        g_blacklist_range_count++;
    }
    fclose(f);

    if (g_blacklist_range_count > 0) {
        g_blacklist_fast_enabled = 1;
        char wbuf[256];
        int wlen = snprintf(wbuf, sizeof(wbuf),
            "[MTT] MTT_LIB_BLACKLIST_FAST enabled: %d address ranges (libraries: %s)%s\n",
            g_blacklist_range_count, env, truncated ? " [TRUNCATED]" : "");
        if (wlen > 0 && wlen < (int)sizeof(wbuf))
            MTT_LOG_INFO(wbuf, (size_t)wlen);

        /* 进程自检:如果当前进程的 /proc/self/exe 匹配黑名单关键词,
         * 说明本进程本身就是黑名单进程(如 busybox),禁用整个工具。
         * 这样 fork+exec 出来的子进程(继承 LD_PRELOAD 但自身是黑名单程序)
         * 不会启动 reporter/HTTP/signal,避免抢端口 + 噪音。
         *
         * 场景:diag_main(主进程)fork+exec busybox,busybox 继承 LD_PRELOAD。
         * 没有这段检查:busybox 第一次 malloc 触发 init,启动 HTTP :8080,
         * 和 diag_main daemon 的 HTTP 冲突。
         * 有这段检查:busybox 发现自己是黑名单进程 → disabled=1 → 不启动后台线程。 */
        char exe_path[256] = {0};
        ssize_t en = readlink("/proc/self/exe", exe_path, sizeof(exe_path) - 1);
        if (en > 0) {
            for (int i = 0; i < ntokens; i++) {
                if (strstr(exe_path, tokens[i]) != NULL) {
                    mtt_state_t *st = mtt_state_get();
                    if (st != NULL) {
                        atomic_store_explicit(&st->disabled, 1, memory_order_release);
                    }
                    char wbuf2[256];
                    int wlen2 = snprintf(wbuf2, sizeof(wbuf2),
                        "[MTT] Process exe (%s) matches blacklist '%s', "
                        "disabling tracking (no reporter/HTTP/signal)\n",
                        exe_path, tokens[i]);
                    if (wlen2 > 0 && wlen2 < (int)sizeof(wbuf2))
                        MTT_LOG_INFO(wbuf2, (size_t)wlen2);
                    break;
                }
            }
        }
    } else {
        char wbuf[160];
        int wlen = snprintf(wbuf, sizeof(wbuf),
            "[MTT] WARNING: MTT_LIB_BLACKLIST_FAST set but no matching libs found in /proc/self/maps\n");
        if (wlen > 0 && wlen < (int)sizeof(wbuf))
            MTT_LOG_INFO(wbuf, (size_t)wlen);
    }
}

/**
 * 判断 LR 是否在黑名单库地址范围内。
 *
 * 热路径调用(每次 malloc/free hook 入口)。开销 20~50 纳秒(几次指针比较)。
 * 命中(返回 1)的 malloc 跳过抓栈,直接 raw_malloc 返回。
 *
 * @param lr  __builtin_return_address(0) 在 hook 最外层取的直接 caller PC
 * @return    1=在黑名单库内(应跳过追踪),0=不在(正常追踪)
 */
int mtt_is_lr_in_blacklist(void *lr)
{
    if (!g_blacklist_fast_enabled || lr == NULL) return 0;
    for (int i = 0; i < g_blacklist_range_count; i++) {
        if (lr >= g_blacklist_ranges[i].start && lr < g_blacklist_ranges[i].end) {
            return 1;
        }
    }
    return 0;
}

/**
 * 检查当前是否处于启动阶段（应跳过追踪）。
 *
 * 当 MTT_SKIP_STARTUP_SEC > 0 时，在指定时间内不追踪分配，
 * 避免初始化阶段的大量一次性分配污染泄漏报告。
 *
 * @param s  全局状态指针
 * @return   1=启动阶段中（跳过追踪）, 0=正常追踪
 */
int mtt_is_startup_phase(mtt_state_t *s)
{
    if (s == NULL) return 0;
    time_t until = atomic_load_explicit(&s->startup_until, memory_order_relaxed);
    if (until > 0 && time(NULL) < until)
        return 1;
    return 0;
}

/**
 * 检查哈希表是否已达容量上限。
 *
 * @param s  全局状态指针（调用者已确保非 NULL）
 * @return   1=已达上限, 0=可继续添加
 */
int mtt_is_over_capacity(mtt_state_t *s)
{
    uint64_t n = atomic_load_explicit(&s->entry_count, memory_order_relaxed);
    if (n >= MTT_MAX_ENTRIES) {
        atomic_fetch_add_explicit(&s->skipped_overcap, 1, memory_order_relaxed);
        return 1;
    }
    return 0;
}

/* ======================================================================== *
 *                    哈希表操作（调用者必须持有对应分段锁）                      *
 * ======================================================================== */

/**
 * 在哈希桶中根据指针地址查找分配记录。
 *
 * @param s    全局状态指针（调用者已确保非 NULL）
 * @param ptr  内存指针（哈希键）
 * @return     找到的条目指针，未找到返回 NULL
 */
mtt_entry_t* mtt_entry_find(mtt_state_t *s, const void *ptr)
{
    if (s == NULL || ptr == NULL || s->buckets == NULL) return NULL;

    unsigned bucket = mtt_bucket_of(ptr, s->bucket_count, s->hash_seed);
    mtt_entry_t *e = s->buckets[bucket];
    while (e != NULL) {
        if (e->ptr == ptr) return e;
        e = e->next;
    }
    return NULL;
}

/**
 * 从哈希桶中删除指定指针的分配记录。
 *
 * 池子模式（ACTIVE）：从桶链表摘下后清空关键字段，归还 free list 复用。
 * Fallback 模式：直接 raw_free 单条释放。
 *
 * @param s    全局状态指针
 * @param ptr  内存指针
 */
void mtt_entry_remove(mtt_state_t *s, const void *ptr)
{
    if (s == NULL || ptr == NULL || s->buckets == NULL) return;

    unsigned bucket = mtt_bucket_of(ptr, s->bucket_count, s->hash_seed);
    mtt_entry_t **pp = &s->buckets[bucket];
    while (*pp != NULL) {
        if ((*pp)->ptr == ptr) {
            mtt_entry_t *dead = *pp;
            *pp = dead->next;
            atomic_fetch_sub_explicit(&s->entry_count, 1, memory_order_relaxed);
            mtt_log_stage(51, "entry_remove bucket=%u entry=%p ptr=%p",
                          bucket, (void*)dead, (void*)ptr);

            /* 池子模式：清空关键字段后按 entry 地址算 stripe 归还对应桶 */
            if (s->pool != NULL) {
                memset(dead, 0, sizeof(*dead));
                unsigned idx = mtt_stripe_of(dead, s->bucket_count, s->hash_seed);
                pthread_mutex_lock(&s->pool_locks[idx].lock);
                dead->next = s->pool_free_lists[idx];
                s->pool_free_lists[idx] = dead;
                pthread_mutex_unlock(&s->pool_locks[idx].lock);
                atomic_fetch_sub_explicit(&s->pool_used, 1, memory_order_relaxed);
                mtt_log_stage(52, "entry_remove returned to pool stripe=%u entry=%p",
                              idx, (void*)dead);
            } else if (raw_free != NULL) {
                /* Fallback：直接 raw_free */
                raw_free(dead);
            }
            return;
        }
        pp = &(*pp)->next;
    }
}

/**
 * 判断指针是否落在 entry 池范围内。
 *
 * 用户进程不应该 free 工具池子里的内存（池子由工具自申请、自管理）。
 * 若误传给 free()，应直接透传到 raw_free 之外，避免破坏池子结构。
 *
 * @param ptr  待检测指针
 * @return     1=落在池子内（不应被业务 free），0=不在池子内
 */
int mtt_pool_contains(const void *ptr)
{
    mtt_state_t *s = mtt_state_get();
    if (s == NULL || ptr == NULL) return 0;
    /* 必须先确认 initialized：init_lock 内的 pool/pool_raw_size 写入
     * 通过 initialized 的 release store 对其他线程可见。否则可能在
     * init 进行中读到 pool 非空但 pool_raw_size 还是旧值的不一致状态。 */
    if (!atomic_load_explicit(&s->initialized, memory_order_acquire)) return 0;
    if (s->pool == NULL) return 0;
    const char *base = (const char*)s->pool;
    const char *end  = base + s->pool_raw_size;
    const char *p    = (const char*)ptr;
    return (p >= base && p < end) ? 1 : 0;
}

/**
 * 将分配记录插入哈希桶头部（O(1) 插入）。
 *
 * @param s     全局状态指针
 * @param entry 要插入的条目（调用者已确保非 NULL）
 */
void mtt_entry_add(mtt_state_t *s, mtt_entry_t *entry)
{
    if (s == NULL || entry == NULL || s->buckets == NULL) return;

    unsigned bucket = mtt_bucket_of(entry->ptr, s->bucket_count, s->hash_seed);
    entry->next = s->buckets[bucket];
    s->buckets[bucket] = entry;
    atomic_fetch_add_explicit(&s->entry_count, 1, memory_order_relaxed);
    mtt_log_stage(50, "entry_add bucket=%u entry=%p ptr=%p count=%zu",
                  bucket, (void*)entry, (void*)entry->ptr,
                  (size_t)atomic_load_explicit(&s->entry_count, memory_order_relaxed));
}

/**
 * 归还/释放一个已分配但未插入桶链表的 entry。
 *
 * 用于 entry_new 成功后、未走到 entry_add 就因容量上限需要回滚的场景。
 * 池子模式下归还 free list；Fallback 模式下走 raw_free。
 *
 * @param s  全局状态指针（NULL 安全，函数立即返回）
 * @param e  待归还的 entry（NULL 安全，函数立即返回）
 */
void mtt_entry_discard(mtt_state_t *s, mtt_entry_t *e)
{
    if (s == NULL || e == NULL) return;
    mtt_log_stage(53, "entry_discard entry=%p", (void*)e);

    if (s->pool != NULL) {
        memset(e, 0, sizeof(*e));
        unsigned idx = mtt_stripe_of(e, s->bucket_count, s->hash_seed);
        pthread_mutex_lock(&s->pool_locks[idx].lock);
        e->next = s->pool_free_lists[idx];
        s->pool_free_lists[idx] = e;
        pthread_mutex_unlock(&s->pool_locks[idx].lock);
        atomic_fetch_sub_explicit(&s->pool_used, 1, memory_order_relaxed);
        mtt_log_stage(54, "entry_discard returned to pool stripe=%u entry=%p",
                      idx, (void*)e);
    } else if (raw_free != NULL) {
        raw_free(e);
    }
}

/**
 * 创建新的分配追踪记录。
 *
 * 优先走 entry 池模式（ACTIVE）：从 free list 取头，无 libc 调用。
 * 池子未就绪或申请失败时降级为 Fallback 模式：raw_malloc 单条申请。
 * 捕获调用栈和分配时间，调用方负责后续 entry_add 插入桶链表。
 *
 * @param ptr   分配的用户内存指针（可为 NULL，由调用者后设）
 * @param size  分配字节数
 * @return      新条目指针，池子满或 raw_malloc 失败时返回 NULL
 */
mtt_entry_t* mtt_entry_new(void *ptr, size_t size)
{
    mtt_state_t *s = mtt_state_get();

    /* 池子模式：按 ptr 算 stripe 从对应桶取头,本桶空 → trylock 扫邻居桶 */
    if (s != NULL && s->pool != NULL) {
        unsigned idx = mtt_stripe_of(ptr, s->bucket_count, s->hash_seed);
        mtt_entry_t *e = NULL;

        /* 首选:锁本桶取头 */
        pthread_mutex_lock(&s->pool_locks[idx].lock);
        e = s->pool_free_lists[idx];
        if (e != NULL) {
            s->pool_free_lists[idx] = e->next;
            atomic_fetch_add_explicit(&s->pool_used, 1, memory_order_relaxed);
        }
        pthread_mutex_unlock(&s->pool_locks[idx].lock);

        /* 本桶空 → trylock 顺序扫邻居桶,持一把锁,无 AB-BA 死锁风险 */
        if (e == NULL) {
            for (int k = 1; k < MTT_LOCK_STRIPES; k++) {
                unsigned try_idx = (unsigned)((idx + k) & (MTT_LOCK_STRIPES - 1));
                if (pthread_mutex_trylock(&s->pool_locks[try_idx].lock) != 0)
                    continue;
                e = s->pool_free_lists[try_idx];
                if (e != NULL) {
                    s->pool_free_lists[try_idx] = e->next;
                    atomic_fetch_add_explicit(&s->pool_used, 1, memory_order_relaxed);
                }
                pthread_mutex_unlock(&s->pool_locks[try_idx].lock);
                if (e != NULL) break;
            }
        }

        if (e == NULL) {
            /* 所有桶都空：跳过本次记录，调用方会更新 skipped_overcap */
            return NULL;
        }

        /* 清零整个结构体（同原 raw_malloc 路径，防止上次使用残留泄漏到栈缓存） */
        memset(e, 0, sizeof(*e));
        mtt_log_stage(40, "entry_new pool took e=%p", (void*)e);

        e->ptr           = ptr;
        e->size          = size;
        e->alloc_num     = 0;
        e->timestamp     = mtt_now_sec();
        e->next          = NULL;
        e->stack_frames  = 0;
        /* e->stack 已被上面 memset(e, 0, sizeof(*e)) 清零，无需重复 memset */

        mtt_capture_stack(e);
        mtt_log_stage(41, "entry_new capture_stack done frames=%d", e->stack_frames);
        return e;
    }

    /* Fallback：池子未就绪或申请失败，走旧 raw_malloc 路径 */
    if (raw_malloc == NULL) return NULL;

    mtt_entry_t *e = (mtt_entry_t*)raw_malloc(sizeof(mtt_entry_t));
    if (e == NULL) return NULL;

    /* 先清零整个结构体，防止 raw_malloc 返回未初始化内存导致
     * 字段（尤其是 timestamp/first_seen）在后续快照→泄漏站点→缓存复制
     * 链路中泄漏垃圾值到 JSON 输出（如 first_seen=-2464099233197811593）。 */
    memset(e, 0, sizeof(*e));

    e->ptr           = ptr;
    e->size          = size;
    e->alloc_num     = 0;
    e->timestamp     = mtt_now_sec();
    e->next          = NULL;
    e->stack_frames  = 0;
    /* e->stack 已被上面 memset(e, 0, sizeof(*e)) 清零，无需重复 memset */

    /* 捕获调用栈（内部有防重入保护 + Thumb bit 清除） */
    mtt_capture_stack(e);

    return e;
}

/* ======================================================================== *
 *                   读取进程名（/proc/self/exe）                               *
 * ======================================================================== */

/**
 * 从 /proc/self/exe 读取当前进程的可执行文件名。
 *
 * 使用 readlink() 系统调用（不触发 malloc），
 * 提取路径中最后一个 '/' 之后的纯文件名部分。
 * 当 /proc 不可用时（某些 ARM 嵌入式内核未挂载），
 * 使用 prctl(PR_GET_NAME) 作为备用方案。
 *
 * @param buf   输出缓冲区
 * @param size  缓冲区大小
 */
static void get_process_name(char *buf, size_t size)
{
    if (buf == NULL || size == 0) return;
    buf[0] = '\0';

    char exe_path[256] = {0};
    ssize_t len = readlink("/proc/self/exe", exe_path, sizeof(exe_path) - 1);
    if (len > 0) {
        exe_path[len] = '\0';

        /* 提取最后一个 '/' 之后的纯文件名 */
        const char *base = strrchr(exe_path, '/');
        if (base != NULL)
            base = base + 1;
        else
            base = exe_path;

        size_t n = strlen(base);
        if (n >= size) n = size - 1;
        memcpy(buf, base, n);
        buf[n] = '\0';
        return;
    }

    /* /proc 不可用时的备用方案：用 syscall 直接调 prctl,避免 extern 声明
     * 与系统头文件冲突,并消除 variadic 参数 ABI 差异风险(ARM32/ARM64) */
#ifdef __linux__
    {
        char comm[16] = {0};
        /* raw syscall: prctl(PR_GET_NAME=15, comm, 0, 0, 0)。
         * 全部参数显式转 unsigned long,匹配 ARM32/ARM64 syscall ABI。 */
        long rc = syscall(SYS_prctl, (long)15, (long)comm, 0L, 0L, 0L);
        if (rc == 0 && comm[0] != '\0') {
            size_t n = strlen(comm);
            if (n >= size) n = size - 1;
            memcpy(buf, comm, n);
            buf[n] = '\0';
            return;
        }
    }
#endif

    snprintf(buf, size, "unknown");
}

/* ======================================================================== *
 *                       全局状态初始化                                        *
 * ======================================================================== */

/**
 * 惰性初始化全局追踪状态（线程安全，双重检查锁定）。
 *
 * 初始化分两阶段：
 *   阶段1（锁外）：读取环境变量（getenv 不触发 malloc）
 *   阶段2（锁内）：初始化桶表、分段锁、计数器（纯内存操作 + raw_calloc）
 *
 * 阶段分离避免了锁内调用 getenv 可能触发 malloc → hook → 递归死锁。
 * 采用双重检查锁定模式：快速路径用 acquire load 检查 initialized 标志。
 *
 * 致命错误处理：若桶表分配失败，设置 disabled=1 + initialized=1，
 * 后续所有 hook 调用直接透传到 raw_*，不再重试初始化。
 */
/* fork handler 注册已移除,改由 hooks.c fork() 拦截接管 */

void mtt_ensure_init(void)
{
    /* 尽早读 MTT_DEBUG 并设置 mtt_debug_level,让后续阶段日志能按等级输出。
     * 否则 mtt_debug_level 要到阶段 13 才被设置,前 12 个阶段的崩溃定位不到。 */
    {
        const char *env_d = getenv("MTT_DEBUG");
        int early_level = MTT_DEBUG_DEFAULT;
        if (env_d != NULL) {
            int lv = atoi(env_d);
            if (lv < 0) lv = 0;
            if (lv > 2) lv = 2;
            early_level = lv;
        }
        atomic_store_explicit(&mtt_debug_level, early_level, memory_order_relaxed);
    }
    mtt_log_stage(1, "mtt_ensure_init enter pid=%d", (int)getpid());

    /* 尽早忽略 SIGPIPE：HTTP 客户端断开连接时 write() 会触发 SIGPIPE，
     * 默认行为是终止进程。此处用 sigaction(2) 替代 signal(2)：
     * sigaction 是 POSIX 标准接口，语义明确（不会像 signal 那样
     * 在 System V/BSD 之间摇摆），且 SA_RESTART 确保被中断的
     * 系统调用自动重试。 */
    {
        struct sigaction sa;
        memset(&sa, 0, sizeof(sa));
        sa.sa_handler = SIG_IGN;
        sa.sa_flags = SA_RESTART;
        sigaction(SIGPIPE, &sa, NULL);
    }
    mtt_log_stage(2, "SIGPIPE ignored");

    mtt_state_t *s = mtt_state_get();
    if (s == NULL) {
        mtt_log_stage(3, "FATAL: mtt_state_get returned NULL");
        return;
    }
    mtt_log_stage(3, "state ok");

    /* 快速路径：已初始化（acquire 确保初始化数据可见） */
    if (atomic_load_explicit(&s->initialized, memory_order_acquire)) {
        mtt_log_stage(4, "already initialized (fast path)");
        return;
    }
    mtt_log_stage(4, "not yet initialized, proceeding");

    /* 确保 raw_* 函数指针已解析 */
    mtt_resolve_raw_allocators();
    mtt_log_stage(5, "raw allocators resolved malloc=%p calloc=%p",
                  (void*)raw_malloc, (void*)raw_calloc);

    /* ---- 阶段1: 读取环境变量（无需持锁） ---- */
    int      want_disabled = 0;
    unsigned want_sample   = MTT_SAMPLE_DEFAULT;
    size_t   want_srate    = MTT_SAMPLE_RATE_DEFAULT; /* 默认使用字节统计采样 */
    time_t   want_leak_threshold = MTT_LEAK_THRESHOLD_DEFAULT;
    time_t   want_skip_startup   = MTT_SKIP_STARTUP_DEFAULT;
    /* entry 池容量:默认按 MTT_POOL_TARGET_BYTES(20MB) 反推 entry 数,
     * 让两个平台 pool 预占用都接近 20MB:
     *   ARM32 sizeof(mtt_entry_t)=288B → ~72817 entries × 288B = 20MB
     *   ARM64 sizeof(mtt_entry_t)=560B → ~37449 entries × 560B = 20MB
     * 被 [MIN, MAX] 夹紧,可被 MTT_POOL_ENTRIES 环境变量覆盖 */
    size_t   want_pool_entries   = MTT_POOL_TARGET_BYTES / sizeof(mtt_entry_t);
    if (want_pool_entries < MTT_POOL_ENTRIES_MIN) want_pool_entries = MTT_POOL_ENTRIES_MIN;
    if (want_pool_entries > MTT_POOL_ENTRIES_MAX) want_pool_entries = MTT_POOL_ENTRIES_MAX;
    int      want_debug    = MTT_DEBUG_DEFAULT;

    {
        const char *env_disable = getenv("MTT_DISABLE");
        if (env_disable != NULL && strcmp(env_disable, "1") == 0)
            want_disabled = 1;

        const char *env_debug = getenv("MTT_DEBUG");
        if (env_debug != NULL) {
            /* MTT_DEBUG=0 静默, 1 关键事件(默认), 2 全量调试 */
            int lv = atoi(env_debug);
            if (lv < 0) lv = 0;
            if (lv > 2) lv = 2;
            want_debug = lv;
        }

        const char *env_sample = getenv("MTT_SAMPLE");
        if (env_sample != NULL) {
            int sp = atoi(env_sample);
            if (sp >= 0 && sp <= MTT_SAMPLE_MAX_PERIOD) {
                want_sample = (unsigned)sp;
                want_srate = 0; /* 旧模式采样时禁用字节采样 */
            }
        }

        /* 字节统计采样率（MTT_SAMPLE_RATE=N → 平均 2^N 字节采样一次） */
        const char *env_srate = getenv("MTT_SAMPLE_RATE");
        if (env_srate != NULL) {
            int sr = atoi(env_srate);
            if (sr >= 0 && sr <= MTT_SAMPLE_RATE_MAX)
                want_srate = (size_t)sr;
        }

        /* entry 池容量（MTT_POOL_ENTRIES=N，控制工具自身预占用内存大小） */
        const char *env_pool = getenv("MTT_POOL_ENTRIES");
        if (env_pool != NULL) {
            long pe = atol(env_pool);
            if (pe >= (long)MTT_POOL_ENTRIES_MIN && pe <= (long)MTT_POOL_ENTRIES_MAX)
                want_pool_entries = (size_t)pe;
        }

        /* 泄漏判定阈值（MTT_LEAK_THRESHOLD_SEC=N，存活超过 N 秒→probable leak） */
        const char *env_thresh = getenv("MTT_LEAK_THRESHOLD_SEC");
        if (env_thresh != NULL) {
            int lt = atoi(env_thresh);
            if (lt >= 0)
                want_leak_threshold = (time_t)lt;
        }

        /* 跳过启动阶段（MTT_SKIP_STARTUP_SEC=N，进程启动 N 秒后再开始追踪） */
        const char *env_skip = getenv("MTT_SKIP_STARTUP_SEC");
        if (env_skip != NULL) {
            int ss = atoi(env_skip);
            if (ss >= 0)
                want_skip_startup = (time_t)ss;
        }

        /* 库黑名单（MTT_LIB_BLACKLIST=libfoo.so,libbar.so — 借鉴 libleak） */
        const char *env_blacklist = getenv("MTT_LIB_BLACKLIST");
        if (env_blacklist != NULL && env_blacklist[0] != '\0') {
            size_t blen = strlen(env_blacklist);
            if (blen >= sizeof(s->lib_blacklist)) blen = sizeof(s->lib_blacklist) - 1;
            memcpy(s->lib_blacklist, env_blacklist, blen);
            s->lib_blacklist[blen] = '\0';
            s->lib_blacklist_ready = 1;
        } else {
            s->lib_blacklist[0] = '\0';
            s->lib_blacklist_ready = 0;
        }

        /* 栈回溯选择（MTT_UNWINDER=auto|libunwind|backtrace）
         * HDM3 等环境如果 libunwind 崩,设 MTT_UNWINDER=backtrace 绕过 */
        const char *env_unw = getenv("MTT_UNWINDER");
        if (env_unw != NULL) {
            if (strcmp(env_unw, "libunwind") == 0) g_unwinder_mode = 1;
            else if (strcmp(env_unw, "backtrace") == 0) g_unwinder_mode = 2;
            else g_unwinder_mode = 0;  /* auto */
        }

        /* 栈回溯深度（MTT_MAX_STACK_FRAMES=N, 1~64, 默认 8）
         * 控制每次回溯最多抓几帧,兼顾性能和泄漏点区分度 */
        const char *env_frames = getenv("MTT_MAX_STACK_FRAMES");
        if (env_frames != NULL) {
            int f = atoi(env_frames);
            if (f >= 1 && f <= MTT_STACK_DEPTH)
                g_max_stack_frames = f;
        }
    }

    /* ---- 阶段2: 持锁初始化数据结构（双重检查锁定） ---- */
    mtt_log_stage(6, "env read done: pool_entries=%zu debug=%d",
                  want_pool_entries, want_debug);
    pthread_mutex_lock(&g_init_lock);
    mtt_log_stage(7, "init_lock acquired");

    /* 双重检查：可能在等锁期间已被其他线程初始化 */
    if (atomic_load_explicit(&s->initialized, memory_order_acquire)) {
        pthread_mutex_unlock(&g_init_lock);
        return;
    }

    /* 分配桶表 */
    s->bucket_count = MTT_BUCKETS;
    if (raw_calloc != NULL) {
        s->buckets = (mtt_entry_t**)raw_calloc(
            (size_t)s->bucket_count, sizeof(mtt_entry_t*));
    }
    if (s->buckets == NULL) {
        /* raw_calloc 失败或尚未就绪：使用 bootstrap_calloc */
        s->buckets = (mtt_entry_t**)bootstrap_calloc(
            (size_t)s->bucket_count, sizeof(mtt_entry_t*));
    }
    if (s->buckets == NULL) {
        /* 致命：无法分配桶表。
         * 设置 disabled=1 + initialized=1 永久降级，
         * 后续所有 hook 调用直接透传到 raw_*，不再重试初始化。 */
        atomic_store_explicit(&s->disabled, 1, memory_order_release);
        atomic_store_explicit(&s->initialized, 1, memory_order_release);
        pthread_mutex_unlock(&g_init_lock);
        return;
    }

    /* 生成随机哈希种子（64-bit，ARM32/ARM64 行为一致） */
    s->hash_seed = ((uint64_t)time(NULL) ^
                    ((uint64_t)getpid() << 16) ^
                    UINT64_C(0x9e3779b97f4a7c15));
    mtt_log_stage(8, "hash_seed=%016llx buckets=%u",
                  (unsigned long long)s->hash_seed, s->bucket_count);

    /* 初始化分段锁（缓存行对齐，避免 ARM 多核伪共享） */
    for (int i = 0; i < MTT_LOCK_STRIPES; i++)
        pthread_mutex_init(&s->bucket_locks[i].lock, NULL);

    /* 申请 entry 池：一次性大块 raw_malloc，entry 复用槽位。
     * 失败时降级为 Fallback 模式（entry_new/remove 走旧 raw_malloc 路径）。
     * 工具自身这次大申请不进 hook（raw_malloc 直调 libc），天然豁免。 */
    s->pool_capacity = want_pool_entries;
    s->pool_raw_size = want_pool_entries * sizeof(mtt_entry_t);
    s->pool = NULL;
    atomic_store_explicit(&s->pool_used, 0, memory_order_relaxed);
    atomic_store_explicit(&s->pool_mode, MTT_POOL_MODE_NONE, memory_order_relaxed);

    /* per-stripe pool: 64 把独立锁 + 64 桶 free_list,均分 entry 降竞争
     * pool_locks 复用 mtt_aligned_mutex_t 缓存行对齐,避免多核伪共享 */
    for (int i = 0; i < MTT_LOCK_STRIPES; i++) {
        pthread_mutex_init(&s->pool_locks[i].lock, NULL);
        s->pool_free_lists[i] = NULL;
    }

    if (raw_malloc != NULL) {
        s->pool = (mtt_entry_t*)raw_malloc(s->pool_raw_size);
    }
    if (s->pool == NULL && raw_calloc != NULL) {
        /* raw_malloc 失败时尝试 raw_calloc 兜底（同时完成清零） */
        s->pool = (mtt_entry_t*)raw_calloc(s->pool_capacity, sizeof(mtt_entry_t));
    }

    if (s->pool != NULL) {
        /* 均匀散到 64 桶:pool[i] 进 free_lists[i % MTT_LOCK_STRIPES]
         * 每桶 entry 数量差不超过 1,保证负载均衡 */
        for (size_t i = 0; i < s->pool_capacity; i++) {
            unsigned idx = (unsigned)(i % MTT_LOCK_STRIPES);
            s->pool[i].next = s->pool_free_lists[idx];
            s->pool_free_lists[idx] = &s->pool[i];
        }
        atomic_store_explicit(&s->pool_mode, MTT_POOL_MODE_ACTIVE, memory_order_relaxed);
        mtt_log_stage(9, "pool ACTIVE capacity=%zu bytes=%zu",
                      s->pool_capacity, s->pool_raw_size);
    } else {
        /* 池子申请失败：降级为旧模式，工具功能不丢，仅性能下降 */
        s->pool_capacity = 0;
        s->pool_raw_size = 0;
        atomic_store_explicit(&s->pool_mode, MTT_POOL_MODE_FALLBACK, memory_order_relaxed);
        mtt_log_stage(9, "pool FALLBACK (raw_malloc failed)");
    }

    /* 初始化原子计数器（relaxed：此时仅有当前线程可见，release store 最后做） */
    atomic_store_explicit(&s->alloc_seq,       0, memory_order_relaxed);
    atomic_store_explicit(&s->alloc_count,     0, memory_order_relaxed);
    atomic_store_explicit(&s->free_count,      0, memory_order_relaxed);
    atomic_store_explicit(&s->current_bytes,   0, memory_order_relaxed);
    atomic_store_explicit(&s->peak_bytes,      0, memory_order_relaxed);
    atomic_store_explicit(&s->total_bytes,     0, memory_order_relaxed);
    atomic_store_explicit(&s->skipped_sampled, 0, memory_order_relaxed);
    atomic_store_explicit(&s->skipped_overcap, 0, memory_order_relaxed);
    atomic_store_explicit(&s->sample_period,      want_sample, memory_order_relaxed);
    atomic_store_explicit(&s->sample_counter,     0, memory_order_relaxed);
    atomic_store_explicit(&s->sample_rate,        want_srate, memory_order_relaxed);
    atomic_store_explicit(&s->sample_bytes_accum, 0, memory_order_relaxed);
    atomic_store_explicit(&s->entry_count,        0, memory_order_relaxed);
    atomic_store_explicit(&s->disabled,           want_disabled, memory_order_relaxed);
    atomic_store_explicit(&s->peak_updated,       0, memory_order_relaxed);
    atomic_store_explicit(&s->leak_threshold_sec, want_leak_threshold, memory_order_relaxed);
    atomic_store_explicit(&s->temp_alloc_count,   0, memory_order_relaxed);
    atomic_store_explicit(&s->expired_alloc_count, 0, memory_order_relaxed);
    atomic_store_explicit(&s->free_expired_count,  0, memory_order_relaxed);
    atomic_store_explicit(&mtt_debug_level, want_debug, memory_order_relaxed);

    /* 设置启动阶段结束时间（0=不跳过） */
    if (want_skip_startup > 0)
        atomic_store_explicit(&s->startup_until, time(NULL) + want_skip_startup, memory_order_relaxed);
    else
        atomic_store_explicit(&s->startup_until, 0, memory_order_relaxed);

    /* 读取进程名 */
    get_process_name(s->proc_name, sizeof(s->proc_name));
    s->proc_name_ready = 1;

    /* 输出 pool 初始化日志（stderr，便于用户观察工具自身内存占用情况,
     * 受 MTT_DEBUG 控制,init 时 mtt_debug_level 已经在阶段 2 设置完成,
     * pool init 属关键事件(MTT_LOG_INFO,等级 >= 1 输出)） */
    {
        int mode = atomic_load_explicit(&s->pool_mode, memory_order_relaxed);
        char log_buf[160];
        if (mode == MTT_POOL_MODE_ACTIVE) {
            int len = snprintf(log_buf, sizeof(log_buf),
                "[MTT] pool init: mode=ACTIVE capacity=%zu bytes=%zu\n",
                s->pool_capacity, s->pool_raw_size);
            if (len > 0) MTT_LOG_INFO(log_buf, (size_t)len);
        } else if (mode == MTT_POOL_MODE_FALLBACK) {
            int len = snprintf(log_buf, sizeof(log_buf),
                "[MTT] pool init: mode=FALLBACK (raw_malloc per-entry)\n");
            if (len > 0) MTT_LOG_INFO(log_buf, (size_t)len);
        }
    }

    /* 解析 MTT_LIB_BLACKLIST_FAST + /proc/self/maps,填充黑名单地址范围。
     * init_lock 内 + initialized=1 之前,保证单线程首次执行 + 其他线程看到
     * initialized=1 时黑名单已就位。/proc/self/maps 不可读时静默 fallback。 */
    mtt_parse_blacklist_fast();
    mtt_log_stage(16, "blacklist_fast parsed (enabled=%d ranges=%d)",
                  g_blacklist_fast_enabled, g_blacklist_range_count);

    /* 标记初始化完成（release 确保上述所有初始化对其他线程可见） */
    atomic_store_explicit(&s->initialized, 1, memory_order_release);
    pthread_mutex_unlock(&g_init_lock);
    mtt_log_stage(10, "initialized=1, init_lock released");

    /* 先初始化时序数据（必须在 reporter 线程启动前完成） */
    mtt_ts_init();
    mtt_log_stage(11, "mtt_ts_init done");

    /* 启动子系统时设置 in_hook=1 + tool_internal=1,防止 pthread_create / socket
     * / bind 等内部调用 malloc() 被 hook 拦截并追踪为"疑似泄漏"。
     * - in_hook=1: 防止 pthread_create 内部 malloc 触发递归 hook
     * - tool_internal=1: 让 hook 的 tool_internal 检查路径透传 pthread_create
     *   内部的 _dl_allocate_tls(否则会被记录为泄漏,栈顶 _dl_allocate_tls →
     *   pthread_create → main)
     * save/restore 防止嵌套 mtt_ensure_init 调用破坏状态。 */
    mtt_per_thread_t *ctx = mtt_thread_get();
    int saved_hook = (ctx != NULL) ? ctx->in_hook : 0;
    int saved_tool = (ctx != NULL) ? ctx->tool_internal : 0;
    if (ctx != NULL) {
        ctx->in_hook = 1;
        ctx->tool_internal = 1;
    }

    /* 如果工具被禁用(如进程自检匹配黑名单:busybox 等),不启动后台线程。
     * disabled 标志在 init_lock 内的 mtt_parse_blacklist_fast 里设置。
     * 跳过 reporter/HTTP/signal 启动,避免 fork+exec 子进程抢端口 + 噪音。 */
    if (atomic_load_explicit(&s->disabled, memory_order_acquire)) {
        if (ctx != NULL) {
            ctx->in_hook = saved_hook;
            ctx->tool_internal = saved_tool;
        }
        mtt_log_stage(17, "tracking disabled (blacklist self-match), skipping background threads");
        return;
    }

    /* 启动周期报告线程（锁外，避免 pthread_create 内部 malloc → 递归） */
    mtt_reporter_start();
    mtt_log_stage(12, "reporter thread started");

    /* 启动 HTTP 服务器（从环境变量读取端口，0=禁用） */
    {
        uint16_t http_port = MTT_HTTP_DEFAULT_PORT;
        const char *env_port = getenv("MTT_HTTP_PORT");
        if (env_port != NULL) {
            int p = atoi(env_port);
            if (p > 0 && p <= 65535)
                http_port = (uint16_t)p;
            else if (p == 0)
                http_port = 0;
        }
        mtt_http_server_start(http_port);
        mtt_log_stage(13, "http server started port=%u", (unsigned)http_port);
        /* HTTP 启动属关键事件,等级 >= 1 输出(与 Reporter/Signal INFO 对齐) */
        {
            char hbuf[96];
            int hlen = snprintf(hbuf, sizeof(hbuf),
                "[MTT] HTTP server started port=%u\n", (unsigned)http_port);
            if (hlen > 0 && hlen < (int)sizeof(hbuf))
                MTT_LOG_INFO(hbuf, (size_t)hlen);
        }
    }

    /* 启动信号处理线程（SIGUSR1 触发即时报告） */
    mtt_signal_thread_start();
    mtt_log_stage(14, "signal thread started");

    if (ctx != NULL) {
        ctx->in_hook = saved_hook;
        ctx->tool_internal = saved_tool;
    }

    /* fork handler 由 hooks.c 的 fork() 拦截接管,不再用 pthread_atfork */
    mtt_log_stage(15, "mtt_ensure_init done");
}

/* ======================================================================== *
 *                 fork() 安全处理（防止子进程死锁）                             *
 * ======================================================================== */

/** fork 前：尝试获取所有分段锁，阻塞直到 reporter 完成当前扫描。
 *  非 static:hooks.c fork 拦截调用(等价 atfork prepare)。 */
void mtt_fork_prepare(void)
{
    mtt_state_t *s = mtt_state_get();
    if (s == NULL) return;
    /* 锁定所有 64 个分段锁，确保 fork 时刻没有线程在临界区内 */
    for (int i = 0; i < MTT_LOCK_STRIPES; i++)
        pthread_mutex_lock(&s->bucket_locks[i].lock);
}

/** fork 后（父进程）：释放所有锁。
 *  非 static:hooks.c fork 拦截调用(等价 atfork parent)。 */
void mtt_fork_parent(void)
{
    mtt_state_t *s = mtt_state_get();
    if (s == NULL) return;
    for (int i = 0; i < MTT_LOCK_STRIPES; i++)
        pthread_mutex_unlock(&s->bucket_locks[i].lock);
}

/** fork 后(子进程):重置所有工具状态,让子进程下次 malloc 时 mtt_ensure_init
 *  重新走完整 init 流程(启动 reporter/HTTP/signal 线程)。
 *
 *  本函数在 fork child 上下文中调用,只能用 async-signal-safe 操作
 *  (pthread_mutex_init / close / syscall / memset 都是 safe)。
 *  不调 pthread_create(不保证 safe),改用 initialized=0 让下次 malloc 触发 init。
 *
 *  调用路径:hooks.c 的 fork() 拦截(子进程返回后直接调用)。
 *  非 static:hooks.c 需跨文件调用。 */
void mtt_fork_child(void)
{
    mtt_state_t *s = mtt_state_get();
    if (s == NULL) return;

    /* 1. 重置后台线程标志(reporter / HTTP / signal 的"已启动"标志)
     *    fork 后这些线程不存在(fork 只复制调用线程),标志需清零
     *    让 mtt_reporter_start / mtt_http_server_start / mtt_signal_thread_start
     *    不再跳过 */
    mtt_reporter_reset_for_fork();
    mtt_http_reset_for_fork();
    atomic_store(&g_signal_thread_started, 0);
    atomic_store(&g_signal_thread_running, 0);

    /* 2. 重置 init_lock(fork 后 mutex 状态未定义) */
    pthread_mutex_init(&g_init_lock, NULL);

    /* 3. 清 per_thread 槽位:fork 只复制调用线程,其他线程的 tid 是脏值。
     *    保留当前线程槽位(它必然存活,正在跑 fork_child)。 */
    pid_t my_tid = (pid_t)syscall(SYS_gettid);
    for (int i = 0; i < MTT_MAX_THREADS; i++) {
        pid_t owner = atomic_load_explicit(&g_threads[i].tid, memory_order_acquire);
        if (owner != 0 && owner != my_tid) {
            atomic_store_explicit(&g_threads[i].tid, 0, memory_order_release);
        }
    }
    /* 重置 TLS 缓存(下次 malloc 时通过 mtt_thread_get_cached 重新填充) */
    mtt_tls_ctx = NULL;
    mtt_tls_cached_tid = 0;

    /* 3.5 重置当前线程槽位的 hook_depth + in_hook。
     * ARM64 BMC 上 libc 初始化可能 longjmp 跳过 dec_depth,导致 depth=1 残留。
     * fork 后子进程继承这个残留 → 子进程所有 malloc 被 SKIP → 不走 init → 不跟踪。
     * ARM32 depth=0(不残留),重置为 0 没变化。 */
    for (int i = 0; i < MTT_MAX_THREADS; i++) {
        if (atomic_load_explicit(&g_threads[i].tid, memory_order_acquire) == my_tid) {
            g_threads[i].hook_depth = 0;
            g_threads[i].in_hook = 0;
            break;
        }
    }

    /* 4. 重新初始化所有分段锁 + pool 锁(fork 后 mutex 状态未定义) */
    for (int i = 0; i < MTT_LOCK_STRIPES; i++) {
        pthread_mutex_init(&s->bucket_locks[i].lock, NULL);
        pthread_mutex_init(&s->pool_locks[i].lock, NULL);
    }

    /* 5. 重置所有原子计数器(子进程是全新追踪,父进程的数据无意义) */
    atomic_store(&s->entry_count, 0);
    atomic_store(&s->alloc_count, 0);
    atomic_store(&s->free_count, 0);
    atomic_store(&s->current_bytes, 0);
    atomic_store(&s->total_bytes, 0);
    atomic_store(&s->alloc_seq, 0);
    atomic_store(&s->sample_bytes_accum, 0);
    atomic_store(&s->skipped_sampled, 0);
    atomic_store(&s->skipped_overcap, 0);
    atomic_store(&s->pool_used, 0);
    atomic_store(&s->peak_updated, 0);
    atomic_store(&s->peak_bytes, 0);
    atomic_store(&s->leak_bytes_total, 0);

    /* 6. 清空桶表(子进程内存空间独立,父进程的追踪条目已无意义) */
    for (unsigned j = 0; j < s->bucket_count; j++)
        s->buckets[j] = NULL;

    /* 7. 重置 pool free_list(复用 pool 内存,子进程独立空间)。
     *    pool 数组本身继承自父进程(buckets/pool 都还在),
     *    只需重建 free_list 让 entry 可重新分配。 */
    for (int i = 0; i < MTT_LOCK_STRIPES; i++)
        s->pool_free_lists[i] = NULL;
    if (s->pool != NULL) {
        for (size_t i = 0; i < s->pool_capacity; i++) {
            unsigned idx = (unsigned)(i % MTT_LOCK_STRIPES);
            s->pool[i].next = s->pool_free_lists[idx];
            s->pool_free_lists[idx] = &s->pool[i];
        }
    }

    /* 8. 关键:重置 initialized=0,让子进程下次 malloc 时 mtt_ensure_init
     *    重新走完整 init 流程:
     *      - 读环境变量(重新解析 MTT_SAMPLE_RATE 等)
     *      - 重新启动 reporter / HTTP / signal 线程
     *      - 重新装 sigaction(unwind handler)
     *      - 设置 initialized=1
     *    buckets 数组 / pool 内存继承自父进程,init 内有 NULL 检查不会重新分配。 */
    atomic_store_explicit(&s->initialized, 0, memory_order_release);
}

/* fork handler 已改由 hooks.c 的 fork() 拦截接管(完整替代 pthread_atfork)。
 * 原因:某些 ARM64 BMC 上 pthread_atfork 符号解析失败(undefined symbol),
 * 导致 .so 加载崩溃。fork 拦截不依赖 pthread_atfork,且注册时机更可靠
 * (在任何 fork 调用时天然生效,不受 init 是否完成影响)。
 * hooks.c:fork() 内部调用 mtt_fork_prepare/parent/child 三个阶段。 */

/* ======================================================================== *
 *                 信号处理线程（SIGUSR1 触发即时报告）                         *
 * ======================================================================== */

/** 信号线程运行标志（非 static，atexit 处理器需要停止它） */
_Atomic int g_signal_thread_running = 0;

/** 信号处理线程主函数。使用 sigtimedwait() 每秒超时检查 running 标志。 */
static void* mtt_signal_thread_fn(void *arg)
{
    (void)arg;
    pthread_detach(pthread_self());

    /* 标记为工具内部线程:本线程的 malloc/free 都透传不追踪 */
    mtt_per_thread_t *ctx = mtt_thread_get();
    if (ctx != NULL) ctx->tool_internal = 1;

    sigset_t sigset;
    sigemptyset(&sigset);
    sigaddset(&sigset, MTT_SIGNAL_REPORT);

    while (atomic_load_explicit(&g_signal_thread_running, memory_order_acquire)) {
        /* sigtimedwait 超时 1 秒，定期检查 running 标志 */
        struct timespec timeout = {1, 0};
        siginfo_t info;
        int ret = sigtimedwait(&sigset, &info, &timeout);
        if (ret == MTT_SIGNAL_REPORT) {
            /* 收到 SIGUSR1：记录时序点 + 触发即时扫描 */
            mtt_ts_record_point();
            extern void mtt_reporter_signal_scan(void);
            mtt_reporter_signal_scan();
        }
        /* 超时(EAGAIN)或其他错误：重新检查 running 标志，继续循环 */
    }
    return NULL;
}

/**
 * 启动信号处理线程。
 *
 * 在子线程中阻塞等待 SIGUSR1，收到后立即触发 scan_and_report()。
 * 在 mtt_ensure_init() 末尾调用，reporter 线程启动之后。
 */
void mtt_signal_thread_start(void)
{
    /* 防止重复启动(用文件作用域的 g_signal_thread_started,fork 后可重置) */
    int expected = 0;
    if (!atomic_compare_exchange_strong(&g_signal_thread_started, &expected, 1))
        return;

    /* 在主线程中阻塞 SIGUSR1（子线程将通过 sigwait 接收） */
    sigset_t block_set;
    sigemptyset(&block_set);
    sigaddset(&block_set, MTT_SIGNAL_REPORT);
    pthread_sigmask(SIG_BLOCK, &block_set, NULL);

    atomic_store_explicit(&g_signal_thread_running, 1, memory_order_release);

    pthread_t tid;
    if (pthread_create(&tid, NULL, mtt_signal_thread_fn, NULL) != 0) {
        atomic_store_explicit(&g_signal_thread_running, 0, memory_order_release);
        return;
    }

    /* 诊断输出:Signal 线程就绪属关键事件(等级 >= 1 输出) */
    char diag[96] = {0};
    int len = snprintf(diag, sizeof(diag),
        "[MTT] Signal thread ready (kill -USR1 %d for instant report)\n",
        (int)getpid());
    if (len > 0 && len < (int)sizeof(diag))
        MTT_LOG_INFO(diag, (size_t)len);
}

/* ======================================================================== *
 *                    公共 API（宏模式使用）                                    *
 * ======================================================================== */

/**
 * 分配 size 字节内存并记录追踪信息。
 *
 * 先通过 raw_malloc 分配用户内存，再创建追踪记录。
 * 若追踪记录创建失败，用户分配仍成功（静默降级）。
 *
 * @param size  分配字节数
 * @return      分配的内存指针，失败返回 NULL
 */
void* mtt_malloc(size_t size)
{
    mtt_resolve_raw_allocators();

    if (raw_malloc == NULL) return NULL;
    if (size == 0) return raw_malloc(0); /* 标准行为：malloc(0) 合法 */

    mtt_ensure_init();
    mtt_state_t *s = mtt_state_get();
    if (s == NULL) return raw_malloc(size);

    if (atomic_load_explicit(&s->disabled, memory_order_acquire))
        return raw_malloc(size);

    /* 启动阶段：跳过追踪（减少初始化分配噪声） */
    if (mtt_is_startup_phase(s))
        return raw_malloc(size);

    /* 先分配用户内存 */
    void *ptr = raw_malloc(size);
    if (ptr == NULL) return NULL;

    /* 采样与容量检查 */
    if (!mtt_should_track(s, size) || mtt_is_over_capacity(s))
        return ptr; /* 放行但不追踪 */

    /* 创建追踪记录（raw_malloc 内部分配，不触发 hook） */
    mtt_entry_t *e = mtt_entry_new(ptr, size);
    if (e == NULL) return ptr; /* 追踪记录失败不阻塞业务 */

    /* 持锁插入哈希表 + 更新统计 */
    mtt_stripe_lock(s, ptr);

    /* 锁内二次检查容量：消除 TOCTOU 竞争窗口 */
    if (atomic_load_explicit(&s->entry_count, memory_order_relaxed) >= MTT_MAX_ENTRIES) {
        atomic_fetch_add_explicit(&s->skipped_overcap, 1, memory_order_relaxed);
        mtt_stripe_unlock(s, ptr);
        mtt_entry_discard(s, e);
        return ptr; /* 用户内存已分配，仅跳过追踪 */
    }

    e->alloc_num = atomic_fetch_add_explicit(&s->alloc_seq, 1, memory_order_relaxed) + 1;
    atomic_fetch_add_explicit(&s->alloc_count, 1, memory_order_relaxed);
    atomic_fetch_add_explicit(&s->current_bytes, size, memory_order_relaxed);
    atomic_fetch_add_explicit(&s->total_bytes,   size, memory_order_relaxed);

    /* CAS 更新峰值 */
    size_t cur = atomic_load_explicit(&s->current_bytes, memory_order_relaxed);
    size_t old_peak = atomic_load_explicit(&s->peak_bytes, memory_order_relaxed);
    while (cur > old_peak) {
        if (atomic_compare_exchange_weak_explicit(&s->peak_bytes, &old_peak, cur,
                memory_order_relaxed, memory_order_relaxed))
            break;
    }
    /* 通知 reporter 线程：峰值已更新（借鉴 jemalloc prof_gdump） */
    atomic_store_explicit(&s->peak_updated, 1, memory_order_relaxed);

    mtt_entry_add(s, e);
    mtt_stripe_unlock(s, ptr);

    return ptr;
}

/**
 * 释放内存并从追踪表删除。
 *
 * @param ptr  要释放的内存指针，NULL 时无操作
 */
void mtt_free(void *ptr)
{
    if (ptr == NULL) return;

    mtt_resolve_raw_allocators();
    if (raw_free == NULL) return;

    mtt_ensure_init();
    mtt_state_t *s = mtt_state_get();
    if (s == NULL) {
        raw_free(ptr);
        return;
    }

    if (atomic_load_explicit(&s->disabled, memory_order_acquire)) {
        raw_free(ptr);
        return;
    }

    mtt_stripe_lock(s, ptr);
    mtt_entry_t *e = mtt_entry_find(s, ptr);
    if (e != NULL) {
        /* 防止 current_bytes underflow */
        if (e->size <= atomic_load_explicit(&s->current_bytes, memory_order_relaxed))
            atomic_fetch_sub_explicit(&s->current_bytes, e->size, memory_order_relaxed);
        else
            atomic_store_explicit(&s->current_bytes, 0, memory_order_relaxed);
        atomic_fetch_add_explicit(&s->free_count, 1, memory_order_relaxed);
        mtt_entry_remove(s, ptr);
    }
    mtt_stripe_unlock(s, ptr);
    raw_free(ptr);
}

/**
 * 分配并零初始化内存。
 *
 * @param count  元素个数
 * @param size   每个元素大小
 * @return       零初始化的内存指针，溢出或分配失败返回 NULL
 */
void* mtt_calloc(size_t count, size_t size)
{
    /* 整数溢出检查 */
    if (count > 0 && size > SIZE_MAX / count)
        return NULL;
    size_t total = count * size;
    void *ptr = mtt_malloc(total);
    if (ptr != NULL) memset(ptr, 0, total);
    return ptr;
}

/**
 * 重新分配内存。
 *
 * 优先使用 raw_realloc（libc 原生 realloc），只在 raw_realloc 未就绪或
 * 旧指针不在追踪表中时才降级使用 raw_malloc+memcpy+raw_free 方案。
 *
 * @param ptr   旧指针（NULL 等价于 mtt_malloc(size)）
 * @param size  新大小（0 等价于 mtt_free(ptr)）
 * @return      新指针，失败返回 NULL
 */
void* mtt_realloc(void *ptr, size_t size)
{
    if (ptr == NULL) return mtt_malloc(size);
    if (size == 0) { mtt_free(ptr); return NULL; }

    mtt_resolve_raw_allocators();
    if (raw_malloc == NULL) return NULL;

    mtt_ensure_init();
    mtt_state_t *s = mtt_state_get();
    if (s == NULL || atomic_load_explicit(&s->disabled, memory_order_acquire)) {
        /* 降级路径：使用 raw_realloc（若可用），否则模拟 */
        if (raw_realloc != NULL)
            return raw_realloc(ptr, size);
        /* raw_realloc 不可用：malloc + free 模拟（无复制，旧大小未知无法安全 memcpy）。
         * 注意：无法查询旧分配大小，若 size > 原始大小则 memcpy 越界读取。
         * 此路径仅在初始化失败时走到，正常情况 raw_realloc 始终可用。
         * 不复制旧数据，避免潜在堆越界读取（防御性编程）。 */
        void *new_ptr = raw_malloc(size);
        if (new_ptr == NULL) return NULL;
        raw_free(ptr);
        return new_ptr;
    }

    /* 先利用 raw_realloc 完成真正的内存重分配。 */
    if (raw_realloc != NULL) {
        /* 锁内查找旧条目（用于后续统计更新） */
        mtt_stripe_lock(s, ptr);
        mtt_entry_t *old_e = mtt_entry_find(s, ptr);
        mtt_stripe_unlock(s, ptr);

        void *new_ptr = raw_realloc(ptr, size);
        if (new_ptr == NULL) return NULL;

        if (old_e != NULL) {
            /* 旧指针存在于追踪表：更新统计 + 替换条目 */
            mtt_stripe_lock(s, ptr);
            old_e = mtt_entry_find(s, ptr); /* 锁内再次确认 */
            if (old_e != NULL) {
                if (old_e->size <= atomic_load_explicit(&s->current_bytes, memory_order_relaxed))
                    atomic_fetch_sub_explicit(&s->current_bytes, old_e->size, memory_order_relaxed);
                else
                    atomic_store_explicit(&s->current_bytes, 0, memory_order_relaxed);
                atomic_fetch_add_explicit(&s->free_count, 1, memory_order_relaxed);
                mtt_entry_remove(s, ptr);
            }
            mtt_stripe_unlock(s, ptr);

            /* 创建新追踪记录 */
            if (!mtt_is_over_capacity(s)) {
                mtt_entry_t *new_e = mtt_entry_new(new_ptr, size);
                if (new_e != NULL) {
                    mtt_stripe_lock(s, new_ptr);
                    if (atomic_load_explicit(&s->entry_count, memory_order_relaxed) < MTT_MAX_ENTRIES) {
                        new_e->alloc_num = atomic_fetch_add_explicit(&s->alloc_seq, 1, memory_order_relaxed) + 1;
                        atomic_fetch_add_explicit(&s->alloc_count, 1, memory_order_relaxed);
                        atomic_fetch_add_explicit(&s->current_bytes, size, memory_order_relaxed);
                        atomic_fetch_add_explicit(&s->total_bytes, size, memory_order_relaxed);

                        size_t cur = atomic_load_explicit(&s->current_bytes, memory_order_relaxed);
                        size_t old_peak = atomic_load_explicit(&s->peak_bytes, memory_order_relaxed);
                        while (cur > old_peak) {
                            if (atomic_compare_exchange_weak_explicit(&s->peak_bytes, &old_peak, cur,
                                    memory_order_relaxed, memory_order_relaxed))
                                break;
                        }
                        atomic_store_explicit(&s->peak_updated, 1, memory_order_relaxed);
                        mtt_entry_add(s, new_e);
                    } else {
                        atomic_fetch_add_explicit(&s->skipped_overcap, 1, memory_order_relaxed);
                        mtt_entry_discard(s, new_e);
                    }
                    mtt_stripe_unlock(s, new_ptr);
                }
            }
        }
        return new_ptr;
    }

    /* raw_realloc 不可用时的降级路径（极端情况：bootstrap 阶段或平台无 realloc）。
     * 使用 malloc+memcpy+free 模拟。此处 s != NULL 且未禁用，可从追踪表获取旧大小。 */
    void *new_ptr = raw_malloc(size);
    if (new_ptr == NULL) return NULL;

    mtt_entry_t *new_e = mtt_entry_new(new_ptr, size);
    if (new_e == NULL) {
        raw_free(new_ptr);
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

    /* 安全拷贝：仅拷贝已知的旧大小字节数（old_size==0 时由 raw_realloc 处理） */
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
        return new_ptr;
    }

    new_e->alloc_num = atomic_fetch_add_explicit(&s->alloc_seq, 1, memory_order_relaxed) + 1;
    atomic_fetch_add_explicit(&s->alloc_count, 1, memory_order_relaxed);
    atomic_fetch_add_explicit(&s->current_bytes, size, memory_order_relaxed);
    atomic_fetch_add_explicit(&s->total_bytes,   size, memory_order_relaxed);

    size_t cur = atomic_load_explicit(&s->current_bytes, memory_order_relaxed);
    size_t old_peak = atomic_load_explicit(&s->peak_bytes, memory_order_relaxed);
    while (cur > old_peak) {
        if (atomic_compare_exchange_weak_explicit(&s->peak_bytes, &old_peak, cur,
                memory_order_relaxed, memory_order_relaxed))
            break;
    }
    atomic_store_explicit(&s->peak_updated, 1, memory_order_relaxed);

    mtt_entry_add(s, new_e);
    mtt_stripe_unlock(s, new_ptr);

    raw_free(ptr);
    return new_ptr;
}

/* ---- 统计查询（relaxed 原子读取，无需持锁） ---- */

size_t mtt_get_alloc_count(void)
{
    mtt_state_t *s = mtt_state_get();
    return (s != NULL) ? atomic_load_explicit(&s->alloc_count, memory_order_relaxed) : 0;
}

size_t mtt_get_free_count(void)
{
    mtt_state_t *s = mtt_state_get();
    return (s != NULL) ? atomic_load_explicit(&s->free_count, memory_order_relaxed) : 0;
}

size_t mtt_get_leak_count(void)
{
    mtt_state_t *s = mtt_state_get();
    if (s == NULL) return 0;
    size_t a = atomic_load_explicit(&s->alloc_count, memory_order_relaxed);
    size_t f = atomic_load_explicit(&s->free_count, memory_order_relaxed);
    return (a > f) ? (a - f) : 0;
}

size_t mtt_get_current_usage(void)
{
    mtt_state_t *s = mtt_state_get();
    return (s != NULL) ? atomic_load_explicit(&s->current_bytes, memory_order_relaxed) : 0;
}

size_t mtt_get_peak_usage(void)
{
    mtt_state_t *s = mtt_state_get();
    return (s != NULL) ? atomic_load_explicit(&s->peak_bytes, memory_order_relaxed) : 0;
}

size_t mtt_get_total_allocated(void)
{
    mtt_state_t *s = mtt_state_get();
    return (s != NULL) ? atomic_load_explicit(&s->total_bytes, memory_order_relaxed) : 0;
}

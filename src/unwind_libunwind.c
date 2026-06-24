/*
 * MemoryTraceTool — libunwind 软依赖栈回溯实现。
 *
 * dlopen 加载 libunwind,dlsym 解析 unw_backtrace,函数指针缓存。
 * 失败时永久标记不可用,后续调用零开销短路(atomic load)。
 *
 * 多线程安全:
 *   - pthread_once 保证 try_load 只执行一次(跨所有线程)
 *   - 函数指针写入在 pthread_once 串行化区间,读取无锁
 *   - dlsym/dlopen 本身线程安全(POSIX 保证)
 *
 * ARM32 Thumb bit 处理:
 *   libunwind 返回的地址在 Thumb 模式下 LSB=1,统一清除。
 *   复用 MTT_FIX_THUMB_ADDR 宏(mtt_internal.h)。
 */
#define _GNU_SOURCE
#include "unwind_libunwind.h"

#include <dlfcn.h>
#include <stddef.h>
#include <stdatomic.h>
#include <pthread.h>

#include "mtt_internal.h"   /* MTT_FIX_THUMB_ADDR */

/* libunwind unw_backtrace 函数指针类型
 * 原型: int unw_backtrace(void **buffer, int size);
 * 行为与 glibc backtrace() 相同,内部走 libunwind 多策略 unwind */
typedef int (*mtt_unw_backtrace_fn)(void **, int);

/* ---- 全局状态 ---- */

typedef struct {
    void                *handle;       /* dlopen 句柄,NULL=未加载 */
    mtt_unw_backtrace_fn backtrace;    /* unw_backtrace 函数指针 */
    atomic_int           available;    /* 0=未探测, 1=可用, -1=不可用 */
    pthread_once_t       once;         /* 串行化首次加载 */
} libunwind_state_t;

static libunwind_state_t g_libunwind = {
    .handle    = NULL,
    .backtrace = NULL,
    .available = 0,
    .once      = PTHREAD_ONCE_INIT,
};

/* ---- 内部加载函数 ---- */

/**
 * dlopen 加载 libunwind 并解析 unw_backtrace 符号。
 *
 * 尝试顺序(覆盖常见发行版):
 *   1. libunwind.so.8       — Debian/Ubuntu 标准名
 *   2. libunwind.so.7       — 较旧发行版
 *   3. libunwind.so         — 开发机或自定义构建
 *   4. libunwind-aarch64.so.8 / libunwind-arm.so.8 — 架构特定(少见)
 *
 * 符号解析:
 *   优先 unw_backtrace(对外公共符号),
 *   兜底 _UL_backtrace / _U_backtrace(libunwind 内部命名)。
 */
static void try_load_libunwind(void)
{
    /* 候选 soname:从最常见到兜底 */
    static const char *const sonames[] = {
        "libunwind.so.8",
        "libunwind.so.7",
        "libunwind.so",
        "libunwind-aarch64.so.8",
        "libunwind-arm.so.8",
        NULL,
    };

    for (int i = 0; sonames[i] != NULL; i++) {
        g_libunwind.handle = dlopen(sonames[i], RTLD_LAZY | RTLD_LOCAL);
        if (g_libunwind.handle != NULL) break;
    }

    if (g_libunwind.handle == NULL) {
        atomic_store_explicit(&g_libunwind.available, -1, memory_order_release);
        return;
    }

    /* 解析 unw_backtrace 函数指针:尝试多个可能的符号名 */
    static const char *const symbols[] = {
        "unw_backtrace",     /* 公共 API (libunwind.h 声明) */
        "_UL_backtrace",     /* 本地 unwind 命名 */
        "_U_backtrace",      /* 通用命名 */
        NULL,
    };
    for (int i = 0; symbols[i] != NULL; i++) {
        g_libunwind.backtrace =
            (mtt_unw_backtrace_fn)dlsym(g_libunwind.handle, symbols[i]);
        if (g_libunwind.backtrace != NULL) break;
    }

    if (g_libunwind.backtrace != NULL) {
        atomic_store_explicit(&g_libunwind.available, 1, memory_order_release);
    } else {
        /* 库加载了但没有 backtrace 符号(罕见):关闭并永久标记不可用 */
        dlclose(g_libunwind.handle);
        g_libunwind.handle = NULL;
        atomic_store_explicit(&g_libunwind.available, -1, memory_order_release);
    }
}

/* ---- 公共 API ---- */

int mtt_libunwind_available(void)
{
    pthread_once(&g_libunwind.once, try_load_libunwind);
    return atomic_load_explicit(&g_libunwind.available, memory_order_acquire) == 1;
}

int mtt_libunwind_capture(void **frames, int max_frames)
{
    if (frames == NULL || max_frames <= 0) return -1;

    pthread_once(&g_libunwind.once, try_load_libunwind);
    if (atomic_load_explicit(&g_libunwind.available, memory_order_acquire) != 1)
        return -1;

    int n = g_libunwind.backtrace(frames, max_frames);
    if (n < 0) n = 0;

    /* 清除 ARM32 Thumb bit(LSB=1),与 backtrace() 后处理保持一致,
     * 让下游 hash/dladdr 不受 Thumb 状态干扰 */
    for (int i = 0; i < n; i++)
        frames[i] = MTT_FIX_THUMB_ADDR(frames[i]);

    return n;
}

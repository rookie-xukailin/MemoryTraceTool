/*
 * MemoryTraceTool — 可执行地址区间校验实现。
 *
 * 实现要点：
 *   - 使用 open()/read() 而非 fopen()，避免 stdio 内部 malloc 在
 *     钩子上下文中触发递归（虽然 in_hook 已经做了重入保护，但
 *     更彻底地绕开 stdio 可以零成本消除这一类风险）
 *   - 静态 16KB 缓冲区承载 /proc/self/maps 全文，典型 Linux 进程
 *     maps 文件约 4-8KB，足以容纳
 *   - 解析后区间按地址升序存储，二分查找 O(log N)
 *
 * 解析格式（典型 /proc/self/maps 一行）：
 *   7ffff7a10000-7ffff7bc0000 r-xp 00000000 08:01 1234567 /lib/x86_64-linux-gnu/libc-2.31.so
 *   └── lo ─────┘ └── hi ─────┘ └perm┘ └offset┘ └dev─┘ └inode┘ └──── path ────┘
 *
 * 仅当 perm 包含 'x' 时记录该区间。
 */
#define _GNU_SOURCE
#include "addr_validate.h"

#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <pthread.h>
#include <stdatomic.h>

#include "mtt_internal.h"   /* MTT_FIX_THUMB_ADDR */

/* ---- 配置常量 ---- */

/** 最大缓存的可执行段数量；典型 Linux 进程 30-100 个，256 留充足余量 */
#define MTT_MAX_EXEC_RANGES 256

/** /proc/self/maps 单次读取的静态缓冲区大小（字节） */
#define MTT_MAPS_BUF_SIZE   16384

/** libname 短名最大长度（含 '\0'） */
#define MTT_LIBNAME_MAX     64

/* ---- 数据结构 ---- */

/** 单条可执行区间记录 */
typedef struct {
    uintptr_t lo;                       /* 区间下界（含） */
    uintptr_t hi;                       /* 区间上界（不含） */
    char      libname[MTT_LIBNAME_MAX]; /* 映像短名（basename） */
} exec_range_t;

/* ---- 全局静态状态 ---- */

/** 可执行段数组，BSS 零初始化 */
static exec_range_t g_ranges[MTT_MAX_EXEC_RANGES];

/** 当前已生效的区间数；atomic 保证读路径无锁 */
static atomic_int g_range_count = 0;

/** pthread_once 控制 init 只执行一次 */
static pthread_once_t g_init_once = PTHREAD_ONCE_INIT;

/** refresh 用顺序锁：保证写时无读，避免读到半成品区间 */
static pthread_mutex_t g_refresh_lock = PTHREAD_MUTEX_INITIALIZER;

/* ---- 内部解析函数 ---- */

/**
 * 解析 /proc/self/maps 内容到 g_ranges。
 *
 * 失败时 g_range_count 保持原值（首次失败=0），调用方降级处理。
 * 注意：本函数可能从 pthread_once 或 refresh 路径调用，需保证幂等。
 */
static void parse_maps_locked(void)
{
    int fd = open("/proc/self/maps", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return;

    /* 静态缓冲区，避免在钩子上下文触发 malloc */
    static char buf[MTT_MAPS_BUF_SIZE];
    size_t total = 0;
    while (total < sizeof(buf) - 1) {
        ssize_t r = read(fd, buf + total, sizeof(buf) - 1 - total);
        if (r <= 0) break;
        total += (size_t)r;
    }
    close(fd);
    buf[total] = '\0';

    /* 临时写入本地数组，全部解析成功后再原子发布 */
    exec_range_t tmp[MTT_MAX_EXEC_RANGES];
    int n = 0;

    char *line = buf;
    char *end  = buf + total;
    while (n < MTT_MAX_EXEC_RANGES && line < end) {
        /* 找到行尾 */
        char *eol = memchr(line, '\n', (size_t)(end - line));
        if (eol == NULL) eol = end;
        char saved_eol = *eol;
        *eol = '\0';

        /* 解析 "lo-hi perm offset dev inode path"
         * %n 不计入返回值，需用单独变量承接 */
        unsigned long lo_ul = 0, hi_ul = 0;
        char perm[8] = {0};
        int path_off = -1;
        int matched = sscanf(line, "%lx-%lx %7s %*x %*x:%*x %*u %n",
                             &lo_ul, &hi_ul, perm, &path_off);
        if (matched >= 3 && path_off > 0 && strchr(perm, 'x') != NULL) {
            tmp[n].lo = (uintptr_t)lo_ul;
            tmp[n].hi = (uintptr_t)hi_ul;

            /* 提取 basename：跳过前导空白，取最后一个 '/' 之后的内容 */
            const char *path = line + path_off;
            while (*path == ' ' || *path == '\t') path++;
            const char *base = strrchr(path, '/');
            base = (base != NULL) ? base + 1 : path;

            size_t len = strlen(base);
            if (len >= MTT_LIBNAME_MAX) len = MTT_LIBNAME_MAX - 1;
            memcpy(tmp[n].libname, base, len);
            tmp[n].libname[len] = '\0';

            n++;
        }

        /* 恢复并跳到下一行 */
        *eol = saved_eol;
        line = (eol < end) ? eol + 1 : end;
    }

    /* 原子发布：先写数组，再更新 count（release 序确保顺序） */
    memcpy(g_ranges, tmp, sizeof(exec_range_t) * (size_t)n);
    atomic_store_explicit(&g_range_count, n, memory_order_release);
}

/* ---- 公共 API ---- */

void mtt_addr_validate_init(void)
{
    pthread_once(&g_init_once, parse_maps_locked);
}

void mtt_addr_validate_refresh(void)
{
    pthread_mutex_lock(&g_refresh_lock);
    parse_maps_locked();
    pthread_mutex_unlock(&g_refresh_lock);
}

int mtt_addr_is_executable(void *addr)
{
    if (addr == NULL) return 0;

    mtt_addr_validate_init();

    /* 清除 Thumb bit（ARM32）— 可执行地址在 r-xp 段内对齐到 2/4 字节，
     * LSB 在 Thumb 模式下可能为 1，校验前必须清除 */
    uintptr_t a = (uintptr_t)MTT_FIX_THUMB_ADDR(addr);

    int n = atomic_load_explicit(&g_range_count, memory_order_acquire);
    if (n <= 0) return 0;

    /* 二分查找：/proc/self/maps 天然按地址升序输出 */
    int lo = 0, hi = n - 1;
    while (lo <= hi) {
        int mid = lo + (hi - lo) / 2;
        if (a < g_ranges[mid].lo)
            hi = mid - 1;
        else if (a >= g_ranges[mid].hi)
            lo = mid + 1;
        else
            return 1;
    }
    return 0;
}

const char* mtt_addr_libname(void *addr)
{
    if (addr == NULL) return NULL;

    mtt_addr_validate_init();

    uintptr_t a = (uintptr_t)MTT_FIX_THUMB_ADDR(addr);

    int n = atomic_load_explicit(&g_range_count, memory_order_acquire);
    if (n <= 0) return NULL;

    int lo = 0, hi = n - 1;
    while (lo <= hi) {
        int mid = lo + (hi - lo) / 2;
        if (a < g_ranges[mid].lo)
            hi = mid - 1;
        else if (a >= g_ranges[mid].hi)
            lo = mid + 1;
        else
            return g_ranges[mid].libname;
    }
    return NULL;
}

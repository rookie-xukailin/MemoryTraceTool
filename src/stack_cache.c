/*
 * MemoryTraceTool — 栈帧缓存模块。
 *
 * 同一调用路径的数千次分配共享一份栈帧缓存，避免重复 dladdr() 解析。
 * 使用 xxHash64 对原始帧地址数组计算 hash，开放哈希表存储。
 *
 * 线程安全：仅由 reporter 后台线程访问，无竞争。
 * 硬上限 MTT_STACK_CACHE_SIZE（4096），超限后新栈不缓存。
 *
 * 符号解析使用 dladdr() 为首选，backtrace_symbols() 为兜底。
 * 统一输出格式: "func+0xOFFSET (libname)"。
 *
 * ARM32 Thumb 兼容：帧地址在捕获阶段（tracker.c:mtt_capture_stack）
 * 已清除 Thumb bit（LSB），本模块不再重复处理。若未来新增入口点
 * 未经过 mtt_capture_stack，需确保传入的地址 LSB 已清除。
 */

#define _GNU_SOURCE
#include "stack_cache.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#if MTT_HAS_BACKTRACE
#include <execinfo.h>
#endif

/* ---- 全局栈缓存单例 ---- */

static mtt_stack_cache_t g_stack_cache = {{{0}}, 0, PTHREAD_MUTEX_INITIALIZER};

mtt_stack_cache_t* mtt_stack_cache_get(void)
{
    return &g_stack_cache;
}

/* ======================================================================== *
 *                     xxHash64 实现（公共域）                                  *
 * ======================================================================== */

/* xxHash64 素数常量 */
#define XXH_PRIME64_1 0x9E3779B185EBCA87ULL
#define XXH_PRIME64_2 0xC2B2AE3D27D4EB4FULL
#define XXH_PRIME64_3 0x165667B19E3779F9ULL
#define XXH_PRIME64_4 0x85EBCA77C2B2AE63ULL
#define XXH_PRIME64_5 0x27D4EB2F165667C5ULL

static uint64_t xxhash64_round(uint64_t acc, uint64_t input)
{
    acc += input * XXH_PRIME64_2;
    acc = (acc << 31) | (acc >> 33); /* rotate left 31 */
    acc *= XXH_PRIME64_1;
    return acc;
}

/**
 * 对一组原始帧地址计算 xxHash64。
 *
 * 在 ARM32 上，64-bit 移位操作（如 >> 33, >> 63）需要编译器生成
 * 辅助指令序列，性能略低于 64-bit 架构，但功能正确。
 *
 * @param frames       原始帧地址数组（来自 backtrace，Thumb bit 已清除）
 * @param frame_count  帧数
 * @param seed         哈希种子
 * @return             64 位哈希值
 */
static uint64_t xxhash64_frames(void **frames, int frame_count, uint64_t seed)
{
    uint64_t h64 = 0;
    const uint8_t *p = (const uint8_t*)frames;
    size_t total_bytes = (size_t)frame_count * sizeof(void*);

    if (total_bytes >= 32) {
        uint64_t v1 = seed + XXH_PRIME64_1 + XXH_PRIME64_2;
        uint64_t v2 = seed + XXH_PRIME64_2;
        uint64_t v3 = seed + 0;
        uint64_t v4 = seed - XXH_PRIME64_1;

        while (total_bytes >= 32) {
            uint64_t k1 = 0, k2 = 0, k3 = 0, k4 = 0;
            memcpy(&k1, p,      8); p += 8;
            memcpy(&k2, p,      8); p += 8;
            memcpy(&k3, p,      8); p += 8;
            memcpy(&k4, p,      8); p += 8;
            total_bytes -= 32;

            v1 = xxhash64_round(v1, k1);
            v2 = xxhash64_round(v2, k2);
            v3 = xxhash64_round(v3, k3);
            v4 = xxhash64_round(v4, k4);
        }

        h64 = ((v1 << 1) | (v1 >> 63))  /* rotate left 1 */
            + ((v2 << 7) | (v2 >> 57))  /* rotate left 7 */
            + ((v3 << 12) | (v3 >> 52)) /* rotate left 12 */
            + ((v4 << 18) | (v4 >> 46)); /* rotate left 18 */

        h64 = xxhash64_round(h64, v1);
        h64 = xxhash64_round(h64, v2);
        h64 = xxhash64_round(h64, v3);
        h64 = xxhash64_round(h64, v4);
    } else {
        h64 = seed + XXH_PRIME64_5;
    }

    h64 += total_bytes;

    while (total_bytes >= 8) {
        uint64_t k1 = 0;
        memcpy(&k1, p, 8); p += 8;
        k1 *= XXH_PRIME64_2;
        k1 = (k1 << 31) | (k1 >> 33);
        k1 *= XXH_PRIME64_1;
        h64 ^= k1;
        h64 = ((h64 << 27) | (h64 >> 37)) * XXH_PRIME64_1 + XXH_PRIME64_4;
        total_bytes -= 8;
    }
    if (total_bytes >= 4) {
        uint32_t k1 = 0;
        memcpy(&k1, p, 4); p += 4;
        h64 ^= (uint64_t)k1 * XXH_PRIME64_1;
        h64 = ((h64 << 23) | (h64 >> 41)) * XXH_PRIME64_2 + XXH_PRIME64_3;
        total_bytes -= 4;
    }
    while (total_bytes > 0) {
        h64 ^= (uint64_t)(*p) * XXH_PRIME64_5;
        h64 = ((h64 << 11) | (h64 >> 53)) * XXH_PRIME64_1;
        p++;
        total_bytes--;
    }

    /* 最终混洗 */
    h64 ^= h64 >> 33;
    h64 *= XXH_PRIME64_2;
    h64 ^= h64 >> 29;
    h64 *= XXH_PRIME64_3;
    h64 ^= h64 >> 32;

    return h64;
}

/* ======================================================================== *
 *                         公共接口                                          *
 * ======================================================================== */

/**
 * 对 frame_count 个帧地址计算 hash。
 *
 * 供外部（如 reporter）使用，在不缓存栈时也能获得去重键。
 * 帧地址应已在捕获阶段（mtt_capture_stack）清除了 Thumb bit。
 * 作为安全网，此处再次对每个地址执行 Thumb bit 清除。
 */
uint64_t mtt_stack_hash_compute(void **frames, int frame_count)
{
    if (frames == NULL || frame_count <= 0) return 0;
    /* 跳过内部帧：从第 2 帧开始（第 0 帧是 mtt_capture_stack 本身） */
    int start = (frame_count > 1) ? 1 : 0;
    int count = frame_count - start;
    if (count <= 0) return 0;

    /* 安全网：对每个帧地址清除 Thumb bit（ARM32 兼容）。
     * 正常路径下此操作是空操作（LSB 已在捕获阶段清除）。
     * 使用栈上临时数组避免修改调用者数据。 */
    void *clean_frames[MTT_STACK_DEPTH];
    for (int i = 0; i < count; i++) {
        clean_frames[i] = MTT_FIX_THUMB_ADDR(frames[start + i]);
    }
    return xxhash64_frames(clean_frames, count, 0x9e3779b97f4a7c15ULL);
}

/**
 * 查找或插入栈帧缓存条目。
 */
mtt_stack_entry_t* mtt_stack_cache_lookup(void **frames, int frame_count)
{
    if (frames == NULL || frame_count <= 0) return NULL;

    mtt_stack_cache_t *cache = mtt_stack_cache_get();
    if (cache == NULL) return NULL;

    uint64_t hash = mtt_stack_hash_compute(frames, frame_count);
    unsigned bucket = (unsigned)(hash & (uint64_t)(MTT_STACK_CACHE_SIZE - 1));

    pthread_mutex_lock(&cache->lock);

    /* 查找已有条目 */
    mtt_stack_entry_t *e = cache->entries[bucket];
    while (e != NULL) {
        if (e->hash == hash && e->frame_count == frame_count) {
            /* 逐帧比较地址（避免 hash 碰撞误判） */
            int match = 1;
            for (int i = 0; i < frame_count; i++) {
                if (e->frames[i] != MTT_FIX_THUMB_ADDR(frames[i])) {
                    match = 0;
                    break;
                }
            }
            if (match) {
                pthread_mutex_unlock(&cache->lock);
                return e;
            }
        }
        e = e->next;
    }

    /* 未命中，检查是否可以插入新条目 */
    if (cache->count >= MTT_STACK_CACHE_SIZE) {
        pthread_mutex_unlock(&cache->lock);
        return NULL; /* 缓存满 */
    }

    /* 分配新条目 */
    mtt_stack_entry_t *new_entry = (mtt_stack_entry_t*)raw_malloc(
        sizeof(mtt_stack_entry_t));
    if (new_entry == NULL) {
        pthread_mutex_unlock(&cache->lock);
        return NULL;
    }

    memset(new_entry, 0, sizeof(*new_entry));
    new_entry->hash        = hash;
    new_entry->frame_count = frame_count;
    new_entry->is_resolved = 0;
    /* 存入前清除 Thumb bit */
    for (int i = 0; i < frame_count; i++) {
        new_entry->frames[i] = MTT_FIX_THUMB_ADDR(frames[i]);
    }

    /* 插入链表头部 */
    new_entry->next = cache->entries[bucket];
    cache->entries[bucket] = new_entry;
    cache->count++;

    pthread_mutex_unlock(&cache->lock);
    return new_entry;
}

/* ======================================================================== *
 *                      符号解析（dladdr + backtrace_symbols 兜底）              *
 * ======================================================================== */

/**
 * 解析单个帧地址为可读符号字符串。
 *
 * 格式: "func_name+0xOFFSET (libname)"
 * 首选 dladdr() 解析，失败时回退到 backtrace_symbols()。
 *
 * 注意：addr 参数应已清除 Thumb bit（调用者负责确保）。
 * 在 ARM32 上，若 addr 保留了 Thumb bit，dladdr() 可能找不到符号。
 *
 * @param addr      帧地址（Thumb bit 已清除）
 * @param out       输出缓冲区
 * @param out_size  缓冲区大小
 */
static void resolve_one_frame(void *addr, char *out, size_t out_size)
{
    if (addr == NULL || out == NULL || out_size == 0) return;
    out[0] = '\0';

    char func_name[256] = {0};
    const char *lib_name = "??";
    ptrdiff_t   func_off = 0;

    Dl_info info;
    memset(&info, 0, sizeof(info));

    if (dladdr(addr, &info)) {
        const char *fname = (info.dli_fname != NULL) ? info.dli_fname : "??";
        const char *base  = strrchr(fname, '/');
        if (base != NULL) fname = base + 1;
        lib_name = fname;

        if (info.dli_sname != NULL) {
            size_t nlen = strlen(info.dli_sname);
            if (nlen >= sizeof(func_name)) nlen = sizeof(func_name) - 1;
            memcpy(func_name, info.dli_sname, nlen);
            func_name[nlen] = '\0';
            func_off = (char*)addr - (char*)info.dli_saddr;
            if (func_off < 0) func_off = 0;
        } else {
            /* dli_sname 为 NULL：尝试 backtrace_symbols 提取函数名。
             * 在不使用 -rdynamic 编译时，backtrace_symbols 返回格式为
             * "binary(+0xOFFSET) [0xADDR]" — 函数名为空，但偏移仍在。
             * 需同时处理函数名为空和不为空两种情况。 */
#if MTT_HAS_BACKTRACE
            char **syms = backtrace_symbols(&addr, 1);
            if (syms != NULL && syms[0] != NULL) {
                char *paren = strchr(syms[0], '(');
                char *plus  = (paren != NULL) ? strchr(paren, '+') : NULL;
                char *rparen = (paren != NULL) ? strchr(paren, ')') : NULL;
                if (paren != NULL && plus != NULL && rparen != NULL
                    && plus > paren && plus < rparen) {
                    /* 尝试提取函数名（可能为空字符串） */
                    size_t nlen = (size_t)(plus - paren - 1);
                    if (nlen > 0) {
                        if (nlen >= sizeof(func_name)) nlen = sizeof(func_name) - 1;
                        memcpy(func_name, paren + 1, nlen);
                        func_name[nlen] = '\0';
                    }
                    /* 无论函数名是否为空，都提取偏移（相对于 binary 加载地址，
                     * 可用于 addr2line -e binary 0xOFFSET） */
                    func_off = (ptrdiff_t)strtoul(plus + 1, NULL, 16);
                } else if (paren != NULL && rparen != NULL && rparen > paren + 1) {
                    /* 无 '+' 号但有函数名：格式 "binary(func)" */
                    size_t nlen = (size_t)(rparen - paren - 1);
                    if (nlen > 0) {
                        if (nlen >= sizeof(func_name)) nlen = sizeof(func_name) - 1;
                        memcpy(func_name, paren + 1, nlen);
                        func_name[nlen] = '\0';
                    }
                }
                free(syms);
            }
#endif
            if (func_name[0] == '\0')
                snprintf(func_name, sizeof(func_name), "??");
            /* 若 backtrace_symbols 未提供偏移，回退到 dli_fbase 相对偏移 */
            if (func_off == 0) {
                func_off = (char*)addr - (char*)info.dli_fbase;
                if (func_off < 0) func_off = 0;
            }
        }
    } else {
        /* dladdr 完全失败：从 backtrace_symbols 解析 */
#if MTT_HAS_BACKTRACE
        char **syms = backtrace_symbols(&addr, 1);
        if (syms != NULL && syms[0] != NULL) {
            char *paren = strchr(syms[0], '(');
            char *plus  = (paren != NULL) ? strchr(paren, '+') : NULL;
            char *rparen = (paren != NULL) ? strchr(paren, ')') : NULL;

            if (paren != NULL && plus != NULL && rparen != NULL &&
                plus > paren && plus < rparen) {
                size_t nlen = (size_t)(plus - paren - 1);
                if (nlen >= sizeof(func_name)) nlen = sizeof(func_name) - 1;
                memcpy(func_name, paren + 1, nlen);
                func_name[nlen] = '\0';
                func_off = (ptrdiff_t)strtoul(plus + 1, NULL, 16);
            } else if (paren != NULL && rparen != NULL && rparen > paren + 1) {
                size_t nlen = (size_t)(rparen - paren - 1);
                if (nlen >= sizeof(func_name)) nlen = sizeof(func_name) - 1;
                memcpy(func_name, paren + 1, nlen);
                func_name[nlen] = '\0';
                /* 无偏移，保持 func_off=0 */
            }
            free(syms);
        }
#endif
        if (func_name[0] == '\0')
            snprintf(func_name, sizeof(func_name), "%p", addr);
    }

    snprintf(out, out_size, "%s+%#tx (%s)", func_name, func_off, lib_name);
}

/**
 * 懒解析栈帧符号。
 *
 * 仅首次调用时解析（is_resolved 标志控制），
 * 结果缓存到 entry->resolved[][]。
 */
void mtt_stack_resolve(mtt_stack_entry_t *entry)
{
    if (entry == NULL || entry->is_resolved) return;

    for (int i = 0; i < entry->frame_count; i++) {
        resolve_one_frame(entry->frames[i],
                          entry->resolved[i], MTT_SYMBOL_MAX);
    }
    entry->is_resolved = 1;
}

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
 *
 * 未来改进方向（借鉴 heaptrack v1.5.0）：
 *   - libunwind 替代 backtrace()：heaptrack 使用 libunwind（trace_libunwind.cpp）
 *     替代 glibc backtrace()。libunwind 优势：
 *     (a) 跨平台 — 支持 glibc/musl/bionic，ARM32/ARM64/x86_64 全部覆盖
 *     (b) 异步 unwind — 不依赖 -rdynamic，可直接解析 .symtab/.dynsym
 *     (c) DWARF/ARM EH 多格式支持 — 不需要 .eh_frame/.debug_frame
 *     (d) 跨线程栈回溯 — heaptrack 注入模式下对目标进程的任意线程回溯
 *     当前 MTT_HAS_BACKTRACE=0 时（musl/bionic）完全无栈回溯，迁移 libunwind
 *     可彻底消除此限制，且无需用户添加 -rdynamic 链接选项。
 *   - DwarfDieCache: heaptrack 通过 libdw 直接从 DWARF 调试信息中读取
 *     源文件名和行号，远超 dladdr+backtrace_symbols 的精度（仅函数名+偏移）。
 *   - 按地址缓存符号：heaptrack 的 SymbolCache 以帧地址为键，而非完整调用栈。
 *     同一帧地址（如 libc 内部 malloc）可能出现在数千个不同调用栈中，
 *     按地址缓存可消除跨栈的重复 dladdr() 开销。下文 ADDR_SYMBOL_CACHE 实现此优化。
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

/* ---- C++ 符号反修饰（借鉴 heaptrack Demangler） ---- */
/** 检测 __cxa_demangle 是否可用（需要链接 libstdc++ 或 libc++） */
#if defined(__has_include) && __has_include(<cxxabi.h>)
    #define MTT_HAS_CXXABI 1
    #include <cxxabi.h>
#else
    #define MTT_HAS_CXXABI 0
#endif

/* ---- 全局栈缓存单例 ---- */

static mtt_stack_cache_t g_stack_cache = {0};

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
    if (frames == NULL || frame_count <= 0) return 0;

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
 *        按地址缓存符号解析结果（借鉴 heaptrack SymbolCache 设计）                *
 * ======================================================================== *
 * heaptrack 的 SymbolCache 以帧地址为键进行符号缓存，而非以完整调用栈为键。
 * 这避免了同一帧地址（如 libc 内部的 malloc 封装函数）在跨数千个不同调用栈
 * 出现时重复调用 dladdr()。
 *
 * 设计：
 *   - 512 个桶的开放哈希表，键为帧地址（void*），值为解析后的符号字符串
 *   - 简单替换策略：桶满时覆盖最旧条目（非 LRU，追求零分配开销）
 *   - 线程安全：仅由 reporter 后台线程访问，无竞争
 *   - 零附加 malloc：符号字符串存储在 entry->cached_symbol 的静态数组中
 */
#define ADDR_CACHE_BUCKETS 512

/** 单条地址符号缓存条目 */
typedef struct {
    void   *addr;                                /* 帧地址（键），NULL=空闲槽位 */
    char    symbol[MTT_SYMBOL_MAX];              /* 解析后的符号字符串 */
} addr_cache_entry_t;

/** 按地址索引的符号解析结果缓存 */
typedef struct {
    addr_cache_entry_t entries[ADDR_CACHE_BUCKETS];
} addr_symbol_cache_t;

static addr_symbol_cache_t g_addr_cache = {{{0}}};

/**
 * 在地址符号缓存中查找已解析的符号。
 *
 * 使用乘法哈希映射地址到桶，桶内线性扫描最多 4 个槽位（有限探测）。
 * 命中时直接复制结果到 out 缓冲区，避免重复调用 dladdr()。
 *
 * @param addr      帧地址
 * @param out       输出缓冲区
 * @param out_size  缓冲区大小
 * @return          1=命中（已复制到 out），0=未命中
 */
static int addr_cache_lookup(void *addr, char *out, size_t out_size)
{
    if (addr == NULL || out == NULL || out_size == 0) return 0;

    /* 乘法哈希：右移 3 位剔除对齐零位 */
    uint64_t h = ((uint64_t)(uintptr_t)addr >> 3) * UINT64_C(11400714819323198485);
    unsigned bucket = (unsigned)(h & (uint64_t)(ADDR_CACHE_BUCKETS - 1));

    /* 线性探测最多 4 个槽位 */
    for (unsigned i = 0; i < 4; i++) {
        unsigned idx = (bucket + i) & (ADDR_CACHE_BUCKETS - 1);
        if (g_addr_cache.entries[idx].addr == addr) {
            size_t n = strlen(g_addr_cache.entries[idx].symbol);
            if (n >= out_size) n = out_size - 1;
            memcpy(out, g_addr_cache.entries[idx].symbol, n);
            out[n] = '\0';
            return 1;
        }
    }
    return 0;
}

/**
 * 将解析后的符号插入地址缓存。
 *
 * 简单替换策略：若 hash 桶的前 4 个槽位中有空槽则填入，
 * 否则覆盖桶内第一个槽位（最旧条目），避免链表分配开销。
 *
 * @param addr    帧地址
 * @param symbol  已解析的符号字符串（会被复制）
 */
static void addr_cache_insert(void *addr, const char *symbol)
{
    if (addr == NULL || symbol == NULL) return;

    uint64_t h = ((uint64_t)(uintptr_t)addr >> 3) * UINT64_C(11400714819323198485);
    unsigned bucket = (unsigned)(h & (uint64_t)(ADDR_CACHE_BUCKETS - 1));

    /* 查找空槽位 */
    for (unsigned i = 0; i < 4; i++) {
        unsigned idx = (bucket + i) & (ADDR_CACHE_BUCKETS - 1);
        if (g_addr_cache.entries[idx].addr == NULL
            || g_addr_cache.entries[idx].addr == addr) {
            g_addr_cache.entries[idx].addr = addr;
            size_t n = strlen(symbol);
            if (n >= MTT_SYMBOL_MAX) n = MTT_SYMBOL_MAX - 1;
            memcpy(g_addr_cache.entries[idx].symbol, symbol, n);
            g_addr_cache.entries[idx].symbol[n] = '\0';
            return;
        }
    }
    /* 所有 4 个槽位都被占用且关键字不匹配：覆盖第一个槽位 */
    size_t n = strlen(symbol);
    if (n >= MTT_SYMBOL_MAX) n = MTT_SYMBOL_MAX - 1;
    g_addr_cache.entries[bucket].addr = addr;
    memcpy(g_addr_cache.entries[bucket].symbol, symbol, n);
    g_addr_cache.entries[bucket].symbol[n] = '\0';
}

/* ======================================================================== *
 *       C++ 符号反修饰（借鉴 heaptrack Demangler / __cxa_demangle）           *
 * ======================================================================== */

/**
 * 对函数名进行 C++ 符号反修饰。
 *
 * 若函数名包含 C++ mangled name 特征（以 _Z 开头），
 * 调用 __cxa_demangle 将其转换为人类可读形式，
 * 如 "_ZN4MyClass6MethodEi" → "MyClass::Method(int)"。
 *
 * 注意：
 *   - __cxa_demangle 内部会调用 malloc 分配缓冲区，需配对 free
 *   - 若反修饰失败或名称不需反修饰（C 函数），返回原始名称
 *   - 需要链接 libstdc++（-lstdc++）或 clang 的 libc++abi
 *   - 借鉴 heaptrack interpret/demangler.h 的设计思路
 *
 * @param mangled   原始函数名（可能经过 C++ name mangling）
 * @param buf       输出缓冲区（用于存储反修饰后的名称或原始名称的副本）
 * @param buf_size  缓冲区大小
 */
static void demangle_symbol(const char *mangled, char *buf, size_t buf_size)
{
    if (mangled == NULL || buf == NULL || buf_size == 0) return;
    buf[0] = '\0';

#if MTT_HAS_CXXABI
    /* 仅对 C++ mangled 名称进行反修饰（以 _Z 开头是 Itanium C++ ABI 的特征） */
    if (mangled[0] == '_' && mangled[1] == 'Z') {
        int status = 0;
        char *demangled = abi::__cxa_demangle(mangled, NULL, NULL, &status);
        if (status == 0 && demangled != NULL) {
            size_t n = strlen(demangled);
            if (n >= buf_size) n = buf_size - 1;
            memcpy(buf, demangled, n);
            buf[n] = '\0';
            free(demangled);
            return;
        }
        /* demangle 失败（status != 0 或 demangled == NULL）：fallthrough 到原始名称 */
        if (demangled != NULL) free(demangled);
    }
#else
    (void)mangled;
#endif

    /* 不需要反修饰或反修饰失败：复制原始名称 */
    size_t n = strlen(mangled);
    if (n >= buf_size) n = buf_size - 1;
    memcpy(buf, mangled, n);
    buf[n] = '\0';
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
 * C++ 符号自动反修饰（__cxa_demangle），如 _ZN3Foo3barEi → Foo::bar(int)。
 * 解析结果缓存到按地址索引的 hash 表，消除跨栈重复 dladdr() 调用。
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

    /* 快速路径：地址符号缓存命中（借鉴 heaptrack SymbolCache 设计） */
    if (addr_cache_lookup(addr, out, out_size))
        return;

    char func_name[256] = {0};
    const char *lib_name = "??";
    ptrdiff_t   func_off = 0;
    ptrdiff_t   file_off = 0;  /* addr2line 可用的文件内偏移（addr - dli_fbase） */

    Dl_info info;
    memset(&info, 0, sizeof(info));

    if (dladdr(addr, &info)) {
        const char *fname = (info.dli_fname != NULL) ? info.dli_fname : "??";
        const char *base  = strrchr(fname, '/');
        if (base != NULL) fname = base + 1;
        lib_name = fname;

        /* 总是计算文件内偏移（addr2line -e 可直接使用此值） */
        if (info.dli_fbase != NULL) {
            file_off = (char*)addr - (char*)info.dli_fbase;
            if (file_off < 0) file_off = 0;
        }

        if (info.dli_sname != NULL) {
            /* dladdr 成功解析符号名（需要 -rdynamic 链接选项）。
             * 偏移 = 返回地址 - 函数入口地址 → 函数内偏移 */
            size_t nlen = strlen(info.dli_sname);
            if (nlen >= sizeof(func_name)) nlen = sizeof(func_name) - 1;
            memcpy(func_name, info.dli_sname, nlen);
            func_name[nlen] = '\0';
            /* ARM32 Thumb: dli_saddr 的 LSB 可能为 1（Thumb 符号编码），
             * 但 addr 的 LSB 已由调用方清除。统一清除 LSB 后计算偏移，
             * 避免 func+0x1 代替 func+0x0 的偏移偏差。
             * ARM32 QEMU 防御：dli_saddr 在极端情况下可能为 NULL
             * （尽管 man page 保证 dli_sname != NULL ⇒ dli_saddr != NULL，
             *  但 qemu-user 的 dladdr 实现可能违反此契约）。 */
            if (info.dli_saddr != NULL) {
                func_off = (char*)addr - (char*)MTT_FIX_THUMB_ADDR(info.dli_saddr);
                if (func_off < 0) func_off = 0;
            }

            /* ARM32 QEMU 误判修正：若 dladdr 将主二进制中的地址误识别为
             * libmemorytracetool.so 中的地址，尝试用 backtrace_symbols 修正库名和函数名。
             * 仅修正库名是不够的——dladdr 在 ARM32 QEMU 下返回的 dli_sname 也属于
             * libmemorytracetool.so（如 mtt_capture_stack），会被内部帧过滤器拦截，
             * 导致 write_leak_json 退化为原始 hex 地址输出。 */
#if MTT_HAS_BACKTRACE
            if (lib_name != NULL && strstr(lib_name, "libmemorytracetool") != NULL) {
                char **syms = backtrace_symbols(&addr, 1);
                if (syms != NULL && syms[0] != NULL) {
                    /* 解析格式: "binary(func+0xOFFSET) [0xADDR]" 或 "binary(+0xOFFSET) [0xADDR]" */
                    char *paren = strchr(syms[0], '(');
                    char *plus  = (paren != NULL) ? strchr(paren, '+') : NULL;
                    char *rparen = (paren != NULL) ? strchr(paren, ')') : NULL;

                    /* 提取二进制/库名（paren 之前的部分） */
                    if (paren != NULL && paren > syms[0]) {
                        const char *bin_start = syms[0];
                        if (bin_start[0] == '.' && bin_start[1] == '/')
                            bin_start += 2;
                        ptrdiff_t bin_len = paren - bin_start;
                        while (bin_len > 0 && (bin_start[bin_len - 1] == ' '
                                               || bin_start[bin_len - 1] == '\t'))
                            bin_len--;
                        if (bin_len > 0) {
                            static char alt_lib2[256];
                            size_t copy_n = (size_t)bin_len;
                            if (copy_n >= sizeof(alt_lib2)) copy_n = sizeof(alt_lib2) - 1;
                            memcpy(alt_lib2, bin_start, copy_n);
                            alt_lib2[copy_n] = '\0';
                            lib_name = alt_lib2;
                        }
                    }

                    /* 提取函数名和偏移（paren -> plus -> rparen）。
                     * ARM32 QEMU 关键修正：若 backtrace_symbols 未提供函数名
                     * （nlen==0，如 "binary(+0xOFFSET) [0xADDR]"），则清空 func_name
                     * 以便后续 "??" 回退。之前保留 dli_sname（如 mtt_entry_new）的策略
                     * 会导致 write_leak_json 内部帧过滤器拦截该符号（mtt_ 前缀匹配），
                     * 进而所有已解析帧均被过滤，触发 hex 地址兜底输出。
                     * 清空 func_name 后，"??+偏移" 格式可通过过滤器在 JSON 中渲染。 */
                    if (paren != NULL && plus != NULL && rparen != NULL
                        && plus > paren && plus < rparen) {
                        size_t nlen = (size_t)(plus - paren - 1);
                        if (nlen > 0 && nlen < sizeof(func_name)) {
                            memcpy(func_name, paren + 1, nlen);
                            func_name[nlen] = '\0';
                        } else {
                            /* backtrace_symbols 无函数名：清空以触发 "??" 回退，
                             * 避免保留 dli_sname（ARM32 QEMU 下为内部 mtt_ 函数） */
                            func_name[0] = '\0';
                        }
                        /* 使用 backtrace_symbols 的函数相对偏移 */
                        func_off = (ptrdiff_t)strtoul(plus + 1, NULL, 16);
                    } else if (paren != NULL && rparen != NULL && rparen > paren + 1) {
                        /* 格式: "binary(func)" — 有函数名但无偏移 */
                        size_t nlen = (size_t)(rparen - paren - 1);
                        if (nlen > 0 && nlen < sizeof(func_name)) {
                            memcpy(func_name, paren + 1, nlen);
                            func_name[nlen] = '\0';
                        }
                    } else {
                        /* 无 '+' 号且无有效函数名：清空 func_name，
                         * 后续统一回退为 "??+偏移" 格式 */
                        func_name[0] = '\0';
                    }
                    free(syms);
                }
                /* ARM32 QEMU 防御：若 backtrace_symbols 也未提供函数名
                 * （如格式 "binary(+0xOFFSET) [0xADDR]" 中函数名为空），
                 * 回退为 "??+偏移" 格式，避免输出以 '+' 开头的空函数名。
                 * 此格式不会被内部帧过滤器拦截（因为不匹配 mtt_/backtrace 等），
                 * 能在 JSON 输出中正确渲染调用栈帧。 */
                if (func_name[0] == '\0') {
                    snprintf(func_name, sizeof(func_name), "??");
                }
            }
#endif
        } else {
            /* dli_sname 为 NULL：缺少 -rdynamic 导致符号未导出到 .dynsym 表。
             * 偏移使用 dli_fbase（dladdr 成功就有），确保与 addr2line -e 兼容。
             * 注意：必须在 backtrace_symbols 之前计算偏移，避免其覆盖 dli_fbase 结果。 */
            if (info.dli_fbase != NULL) {
                func_off = (char*)addr - (char*)info.dli_fbase;
                if (func_off < 0) func_off = 0;
            }
#if MTT_HAS_BACKTRACE
            /* 回退到 backtrace_symbols() 用于提取函数名和库名。
             * 格式取决于是否启用 -rdynamic：
             *   有 -rdynamic: "binary(func+0xOFFSET) [0xADDR]"
             *   无 -rdynamic: "binary(+0xOFFSET) [0xADDR]" — 函数名为空
             *
             * ARM32 QEMU 特例：qemu-user 下 dladdr 可能将主二进制中的地址
             * 误识别为 LD_PRELOAD 库（libmemorytracetool.so）中的地址。
             * 此时 backtrace_symbols 仍能返回正确的二进制名称，
             * 优先使用 backtrace_symbols 的库名替换 dladdr 结果。 */
            char **syms = backtrace_symbols(&addr, 1);
            if (syms != NULL && syms[0] != NULL) {
                /* 从 backtrace_symbols 提取二进制名称（'(' 之前的部分） */
                char *paren = strchr(syms[0], '(');
                char *plus  = (paren != NULL) ? strchr(paren, '+') : NULL;
                char *rparen = (paren != NULL) ? strchr(paren, ')') : NULL;

                /* 提取库名：若 backtrace_symbols 提供了有效名称，
                 * 且 dladdr 返回的名称包含 "libmemorytracetool"（ARM32 QEMU 误判），
                 * 则用 backtrace_symbols 的库名覆盖 */
                if (paren != NULL && paren > syms[0]) {
                    /* 库名 = syms[0] 到 paren 之间的内容，去除 '[' 和尾部空格 */
                    const char *bin_start = syms[0];
                    /* 跳过 './' 前缀 */
                    if (bin_start[0] == '.' && bin_start[1] == '/')
                        bin_start += 2;
                    /* 跳过 '[' 前缀（某些平台格式 "[0xADDR] binary(func+...)")，
                     * 检查第一个字符是否为 '[' 且不是完整的 '[' 在开头 */
                    if (bin_start[0] == '[') {
                        const char *space = strchr(bin_start, ' ');
                        if (space != NULL) bin_start = space + 1;
                    }
                    ptrdiff_t bin_len = paren - bin_start;
                    while (bin_len > 0 && (bin_start[bin_len - 1] == ' '
                                           || bin_start[bin_len - 1] == '\t'))
                        bin_len--;
                    if (bin_len > 0) {
                        /* 若 dladdr 返回的库名包含 libmemorytracetool，优先用
                         * backtrace_symbols 的库名（ARM32 QEMU 误判修正） */
                        if (lib_name != NULL && strstr(lib_name, "libmemorytracetool") != NULL) {
                            static char alt_lib[256];
                            size_t copy_n = (size_t)bin_len;
                            if (copy_n >= sizeof(alt_lib)) copy_n = sizeof(alt_lib) - 1;
                            memcpy(alt_lib, bin_start, copy_n);
                            alt_lib[copy_n] = '\0';
                            lib_name = alt_lib;
                        }
                    }
                }

                if (paren != NULL && plus != NULL && rparen != NULL
                    && plus > paren && plus < rparen) {
                    /* 尝试提取函数名（可能为空字符串，取决于 -rdynamic） */
                    size_t nlen = (size_t)(plus - paren - 1);
                    if (nlen > 0) {
                        if (nlen >= sizeof(func_name)) nlen = sizeof(func_name) - 1;
                        memcpy(func_name, paren + 1, nlen);
                        func_name[nlen] = '\0';
                    }
                    /* 从 backtrace_symbols 提取偏移。
                     * backtrace_symbols 读取完整符号表（.symtab + .dynsym），
                     * 当找到函数名时其偏移为 function-relative（如 main+0x460），
                     * 当函数名为空时偏移为 file-relative（兼容 addr2line）。
                     * 优先于 dli_fbase 偏移，解决无 -rdynamic 时出现
                     * "??+0x17e6" 而非 "main+0x460" 的问题。 */
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
            if (func_name[0] == '\0') {
                /* 无 -rdynamic 时无法解析函数名 */
                snprintf(func_name, sizeof(func_name), "??");
            }
        }
    } else {
        /* dladdr 完全失败（静态链接或地址无效）：从 backtrace_symbols 解析 */
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
                /* 无偏移，保持 func_off = 0 */
            }
            free(syms);
        }
#endif
        if (func_name[0] == '\0')
            snprintf(func_name, sizeof(func_name), "%p", addr);
    }

    /* C++ 符号反修饰（借鉴 heaptrack Demangler） */
    {
        char demangled_name[256] = {0};
        demangle_symbol(func_name, demangled_name, sizeof(demangled_name));
        snprintf(out, out_size, "%s+%#tx (%s+%#tx)", demangled_name, func_off, lib_name, file_off);
    }

    /* 缓存到按地址索引的符号缓存（后续同一帧地址命中缓存，跳过 dladdr） */
    addr_cache_insert(addr, out);
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

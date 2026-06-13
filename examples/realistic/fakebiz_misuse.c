/*
 * 模拟"不规范"业务库:
 *   - strdup 不 free
 *   - asprintf 不 free
 *   - realloc 失败时丢失原指针(经典 leak)
 *   - 全局缓冲区不断累积(模拟"缓存"无限增长)
 * 编译为 fakebiz_misuse.so
 */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

__attribute__((visibility("default"))) void biz_misuse_strdup(int n)
{
    /* 故意:strdup 分配后丢失指针 */
    for (int i = 0; i < n; i++) {
        char *s = strdup("this string leaks every time");
        (void)s;  /* 故意丢弃 */
    }
}

__attribute__((visibility("default"))) void biz_misuse_asprintf(int n)
{
    /* 故意:asprintf 分配后丢失指针 */
    char *buf = NULL;
    for (int i = 0; i < n; i++) {
        if (asprintf(&buf, "iteration %d payload", i) >= 0) {
            /* 不 free,继续下一轮覆盖 buf 指针 */
        }
    }
}

__attribute__((visibility("default"))) void biz_misuse_realloc_bad(int n)
{
    /* 经典 bug:realloc 失败时返回 NULL,原指针未保存 → 内存泄漏 */
    char *p = malloc(16);
    if (!p) return;
    for (int i = 0; i < n; i++) {
        char *np = realloc(p, 16 * 1024 * 1024);  /* 故意请求巨大,会失败 */
        if (np == NULL) {
            /* 错误处理:这里应该是 free(p) 然后退出,但我们什么都不做,
             * 下一轮 realloc(p, ...) 再次失败 — p 一直没释放 */
            continue;
        }
        p = np;
    }
    /* 函数结束时 p 未释放,且 np 失败时 p 已"丢失" */
}

static char *g_cache[64];
static int g_cache_idx = 0;

__attribute__((visibility("default"))) void biz_misuse_global_cache(int n)
{
    /* 模拟全局缓存无限增长 */
    for (int i = 0; i < n && g_cache_idx < 64; i++) {
        g_cache[g_cache_idx] = malloc(256);
        if (g_cache[g_cache_idx])
            memset(g_cache[g_cache_idx], 0xCD, 256);
        g_cache_idx++;
    }
}

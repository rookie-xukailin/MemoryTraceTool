/*
 * 模拟"开源动态库 release 二进制"(如 cJSON/openssl/sqlite 编译产物)
 *
 * 关键特征:
 *   - 编译选项 -O2 -fomit-frame-pointer -fvisibility=hidden
 *   - 不加 -funwind-tables(模拟开源库未导出 unwind info)
 *   - 内部函数全部 hidden(只在 .symtab,不在 .dynsym)
 *   - 导出 API 用 visibility("default")
 *
 * 测试场景(T29):验证工具在目标 .so 缺 unwind info 时:
 *   1. 不挂进程(libunwind 走进去可能 SIGSEGV,handler 应拦截)
 *   2. 仍能定位到导出 API 的调用点(浅栈 2-3 帧)
 *   3. 检测到栈过浅时输出 WARNING
 *
 * 验证 commit 839821a 的核心保护场景:闭源/缺 unwind info .so 触发 SIGSEGV 时
 * 工具不挂。
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* 内部函数全部 hidden,模拟开源库内部实现 */
__attribute__((visibility("hidden"), noinline))
static char *opensource_parse_internal(const char *data, size_t len)
{
    /* 模拟 cJSON_ParseString / sqlite3_exec 内部分配 */
    char *p = (char *)malloc(len + 1);
    if (p != NULL) {
        memcpy(p, data, len);
        p[len] = '\0';
    }
    return p;  /* 故意泄漏,模拟开源库 bug */
}

__attribute__((visibility("hidden"), noinline))
static void *opensource_compile_node(int idx)
{
    char buf[64];
    snprintf(buf, sizeof(buf), "node_%d_data", idx);
    return opensource_parse_internal(buf, strlen(buf));
}

__attribute__((visibility("hidden"), noinline))
static int opensource_run_loop(int n)
{
    for (int i = 0; i < n; i++) {
        /* 多层调用,模拟开源库内部复杂逻辑 */
        void *node = opensource_compile_node(i);
        (void)node;  /* 故意不 free,模拟开源库 bug */
    }
    return 0;
}

/* 导出 API:用 visibility("default"),业务通过 dlsym 调用 */
__attribute__((visibility("default")))
void opensource_api(int n)
{
    /* 模拟 cJSON_Print / sqlite3_prepare / openssl SSL_read 等开源 API */
    opensource_run_loop(n);
}

/* 另一个导出 API,模拟不同调用路径 */
__attribute__((visibility("default")))
void opensource_init(void)
{
    /* 模拟全局初始化的内存分配(也泄漏) */
    (void)opensource_parse_internal("init_data", 9);
}

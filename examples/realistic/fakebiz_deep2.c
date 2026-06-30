/*
 * 多层 .so 嵌套 - 底层
 * 模拟 RPC 业务调用链最底层:.so C
 *
 * 被 fakebiz_deep1.so dlopen 调用,
 * 内部产生响应序列化泄漏 + 业务数据泄漏。
 *
 * 编译选项:-O2 -fomit-frame-pointer (匹配 flasher release)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

__attribute__((noinline)) static char *build_rpc_response(int task_id)
{
    /* 模拟 RPC 响应序列化,故意泄漏 */
    char *buf = malloc(256);
    if (buf) {
        memset(buf, 0, 256);
        snprintf(buf, 256, "rpc_resp_task_%d_payload", task_id);
    }
    return buf;
}

__attribute__((noinline)) static void cache_business_data(int task_id)
{
    /* 模拟业务数据缓存(无淘汰策略),每次调用都增长 */
    char *data = malloc(64);
    if (data) {
        memset(data, 0, 64);
        snprintf(data, 64, "biz_cache_%d", task_id);
    }
    /* 故意不释放:模拟业务侧全局缓存无上限 */
}

__attribute__((visibility("default"))) void biz_deep2_perform(int task_id)
{
    char *resp = build_rpc_response(task_id);
    (void)resp;
    cache_business_data(task_id);
}

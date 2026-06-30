/*
 * 多层 .so 嵌套 - 中间层
 * 模拟 RPC 业务调用链:.so A → .so B → .so C
 *
 * fakebiz_deep1.so 由上层 demo dlopen 调用,
 * 内部 dlopen fakebiz_deep2.so 形成链式调用,
 * backtrace 跨 3 层 .so 边界。
 *
 * 编译选项:-O2 -fomit-frame-pointer (匹配 flasher release)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>

typedef void (*deep2_func_t)(int);

__attribute__((noinline)) static char *build_rpc_request(int task_id)
{
    /* 模拟 RPC 请求序列化 buffer 构造,故意泄漏 */
    char *buf = malloc(128);
    if (buf) {
        memset(buf, 0, 128);
        snprintf(buf, 128, "rpc_req_task_%d", task_id);
    }
    return buf;
}

__attribute__((noinline)) static void invoke_deep2(int task_id)
{
    /* dlopen deep2.so,形成 .so A → .so B → .so C 链式调用 */
    void *handle = dlopen("./fakebiz_deep2.so", RTLD_NOW);
    if (handle == NULL) {
        fprintf(stderr, "[deep1] dlopen deep2 failed: %s\n", dlerror());
        return;
    }
    deep2_func_t fn = (deep2_func_t)dlsym(handle, "biz_deep2_perform");
    if (fn != NULL) {
        fn(task_id);
    }
    /* 故意不 dlclose:模拟 RPC 客户端 .so 长期持有 */
}

__attribute__((visibility("default"))) void biz_deep1_handle(int task_id)
{
    /* 中间层:序列化 + 调下层 */
    char *req = build_rpc_request(task_id);
    (void)req;
    invoke_deep2(task_id);
}

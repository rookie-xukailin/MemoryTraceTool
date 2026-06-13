/*
 * 模拟"正常"业务库:有内存泄漏,但调用方式规范
 * 编译为 fakebiz_normal.so
 */
#include <stdlib.h>
#include <string.h>

__attribute__((noinline)) static char* dup_message(int idx)
{
    /* 模拟日志构造:内部泄漏 */
    char *p = malloc(64);
    if (p) memset(p, 0, 64);
    return p;  /* 故意不释放 */
}

__attribute__((noinline)) static void inner_work(int depth)
{
    if (depth <= 0) {
        dup_message(depth);
        return;
    }
    inner_work(depth - 1);
}

__attribute__((visibility("default"))) void biz_normal_call(int times)
{
    for (int i = 0; i < times; i++) {
        inner_work(3);  /* 多层调用栈,模拟业务逻辑深度 */
    }
}

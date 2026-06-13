/*
 * 综合性 demo:模拟 flasher 类型的真实业务进程
 *   - 进程内自己泄漏
 *   - 通过 dlopen 调用动态库,库内泄漏
 *   - 通过 dlopen 调用动态库的不规范用法导致泄漏
 *   - 故意 dlopen 不 dlclose(模拟模块未卸载)
 *
 * 编译选项:-O2 -fomit-frame-pointer (模拟 release flasher)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dlfcn.h>

__attribute__((noinline)) static void leak_in_process(int idx)
{
    /* 进程内多层调用栈 + 泄漏 */
    void *p = malloc(32 + idx);
    if (p) {
        memset(p, 0xAA, 32 + idx);
        ((volatile char*)p)[0] = (char)idx;
    }
    /* 故意不释放 */
}

typedef void (*biz_func_t)(int);

static void call_biz(const char *so_path, const char *sym, int arg, const char *tag)
{
    void *handle = dlopen(so_path, RTLD_NOW);
    if (handle == NULL) {
        printf("[%s] dlopen failed: %s\n", tag, dlerror());
        return;
    }
    biz_func_t fn = (biz_func_t)dlsym(handle, sym);
    if (fn == NULL) {
        printf("[%s] dlsym %s failed: %s\n", tag, sym, dlerror());
        dlclose(handle);
        return;
    }
    fn(arg);
    /* 故意:不 dlclose(handle) — 模拟模块未卸载 */
    printf("[%s] called %s(%d) — handle kept open\n", tag, sym, arg);
}

int main(void)
{
    printf("=== Realistic Demo (flasher-like) ===\n");
    printf("PID: %d\n\n", (int)getpid());

    /* 场景 1:进程内直接泄漏 (5 次) */
    printf("--- Scenario 1: in-process leaks ---\n");
    for (int i = 0; i < 5; i++)
        leak_in_process(i);

    /* 场景 2:调用 fakebiz_normal.so (内部泄漏,3 次调用,每次 4 个 inner) */
    printf("\n--- Scenario 2: business lib normal leaks ---\n");
    call_biz("./fakebiz_normal.so", "biz_normal_call", 4, "biz_normal");

    /* 场景 3:调用 fakebiz_misuse.so 多个不规范函数 */
    printf("\n--- Scenario 3: business lib misuse patterns ---\n");
    call_biz("./fakebiz_misuse.so", "biz_misuse_strdup", 5, "misuse_strdup");
    call_biz("./fakebiz_misuse.so", "biz_misuse_asprintf", 5, "misuse_asprintf");
    call_biz("./fakebiz_misuse.so", "biz_misuse_realloc_bad", 3, "misuse_realloc");
    call_biz("./fakebiz_misuse.so", "biz_misuse_global_cache", 8, "misuse_cache");

    printf("\nWaiting 3s for hook + scan...\n");
    sleep(3);
    return 0;
}

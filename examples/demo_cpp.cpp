/*
 * 最小 C++ demo — 验证 C++ 异常 unwind 路径与 backtrace 共存
 *
 * 覆盖场景:
 *   - new / delete 配对(正常)
 *   - new[] / delete[] 配对(正常)
 *   - new 不 delete(泄漏)
 *   - throw / catch 异常路径下 malloc
 *   - std::string / std::vector 内部堆分配
 *
 * 编译选项:-O2 -fomit-frame-pointer (匹配 flasher release)
 */
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <new>
#include <stdexcept>
#include <string>
#include <vector>
#include <unistd.h>

__attribute__((noinline)) static void leak_via_new(int idx)
{
    /* C++ 风格泄漏:new 后不 delete */
    char *p = new char[64];
    if (p) memset(p, 0xCC, 64);
    p[0] = (char)idx;
    /* 故意不 delete[] */
}

__attribute__((noinline)) static void throw_and_catch(int idx)
{
    /* 异常路径下分配,验证 libgcc_s unwinder 不与 backtrace 冲突 */
    try {
        if (idx % 3 == 0) {
            throw std::runtime_error("simulated business error");
        }
        /* 正常路径:heap 分配 */
        char *p = new char[32];
        if (p) memset(p, 0xDD, 32);
        delete[] p;
    } catch (const std::exception &e) {
        /* catch 路径:再分配一次,故意泄漏 */
        char *err = new char[128];
        if (err) {
            memset(err, 0, 128);
            strncpy(err, e.what(), 127);
        }
        /* 故意不 delete err */
    }
}

__attribute__((noinline)) static void stl_leak(int idx)
{
    /* STL 容器内部堆分配,移动语义下故意泄漏 */
    std::string *s = new std::string("business_payload_");
    s->append(std::to_string(idx));
    s->append("_leaked");
    /* 故意不 delete s */
}

__attribute__((noinline)) static void stl_normal(int n)
{
    /* 正常用法:vector 作用域结束自动释放 */
    std::vector<int> v;
    v.reserve(n);
    for (int i = 0; i < n; i++) v.push_back(i);
}

int main(void)
{
    printf("=== C++ Demo (exception + STL) ===\n");
    printf("PID: %d\n\n", (int)getpid());

    printf("--- Scenario 1: new without delete ---\n");
    for (int i = 0; i < 5; i++) leak_via_new(i);

    printf("--- Scenario 2: throw/catch path ---\n");
    for (int i = 0; i < 6; i++) throw_and_catch(i);

    printf("--- Scenario 3: STL heap leak ---\n");
    for (int i = 0; i < 4; i++) stl_leak(i);

    printf("--- Scenario 4: STL normal (auto-free) ---\n");
    for (int i = 0; i < 10; i++) stl_normal(100);

    printf("\nWaiting 3s for hook + scan...\n");
    sleep(3);
    return 0;
}

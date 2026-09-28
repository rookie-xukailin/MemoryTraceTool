// telemetry.cpp — 遥测采集实现
//
// 【注入 bug】ingest() 每轮泄漏一条 std::string：
//   new 分配的缓冲存入 volatile sink —— 指针真实逃逸，
//   编译器无法用"分配省略"删掉这个 new（-Os/-O2 下都保留），
//   模拟真实工程里"容器满了没清理"的遗忘型泄漏。
// 预期分类：probable（同一调用点存活数每轮 +1）。
#include "telemetry.hpp"
#include <stdexcept>
#include <vector>

namespace devmgr {

// 逃逸槽：防止编译器把 new/delete 配对优化掉
static std::string* volatile g_leak_sink = nullptr;

void TelemetryCollector::ingest(const std::string& payload)
{
    // 构造完整拷贝（operator new 的调用点在本函数，栈帧可辨识）
    auto* kept = new std::string("telemetry/" + payload);
    g_leak_sink = kept;               // 真实逃逸：不 delete
    leaked_count_++;
}

void TelemetryCollector::periodic_flush(unsigned round)
{
    if (round % 10 != 0)
        return;
    try {
        // 模拟后端暂不可达：构造异常 → 栈展开 → 捕获
        if (round % 20 == 0)
            throw std::runtime_error("backend unreachable");
        (void)round;
    } catch (const std::exception& e) {
        // 捕获后继续运行：验证异常机制与工具的抓栈/静态 libunwind 无冲突
        (void)e;
    }
}

} // namespace devmgr

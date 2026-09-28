// telemetry.hpp — 遥测采集（增长泄漏 + 异常路径）
#pragma once
#include <string>

namespace devmgr {

class TelemetryCollector {
public:
    // 【注入 bug】每轮 ingest 泄漏一条 payload（operator new）
    void ingest(const std::string& payload);

    // 异常路径：periodic_flush 每 flush_every 轮抛一次、内部捕获
    // （验证 throw/catch 栈展开与工具抓栈共存）
    void periodic_flush(unsigned round);

    static size_t leaked_count() { return leaked_count_; }

private:
    static inline size_t leaked_count_ = 0;
};

} // namespace devmgr

// device_manager.hpp — 设备管理器（核心场景：启动 new → 信号 delete → 重建）
#pragma once
#include <vector>
#include <cstddef>

namespace devmgr {

class Device;

class DeviceManager {
public:
    DeviceManager() = default;
    ~DeviceManager();

    void bootstrap(unsigned device_count);  // 启动：new 全部设备（长期持有）
    void restart_cycle();                   // 重启 RPC：delete 全部并重建
    void poll_all();                        // 每轮采集（深调用链：读设备→发事件）
    size_t device_count() const { return devices_.size(); }

private:
    void destroy_all();
    std::vector<Device*> devices_;          // 裸指针所有权（模拟存量代码风格）
};

} // namespace devmgr

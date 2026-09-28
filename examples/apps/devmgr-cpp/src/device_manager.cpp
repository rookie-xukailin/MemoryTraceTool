// device_manager.cpp — 设备管理器实现
//
// 核心验证场景（贴近"主机重启压力测试"）：
//   bootstrap()  启动时 new 12 个设备对象（Sensor/Actuator 交替），长期持有；
//   restart_cycle() 收到 SIGUSR2（模拟主机重启 RPC）→ 全部 delete → 重新 new。
//
// 预期分类：
//   首轮持有期：老化后 long_lived；释放：证据入 late-free 历史；
//   重建后：session_scoped —— 周期作用域内存，非泄漏。
// 每个设备对象的 new 调用点在 create_devices()（虚构造经派生类 operator new）。
#include "device_manager.hpp"
#include "device.hpp"
#include "event_bus.hpp"
#include <cstdio>

namespace devmgr {

namespace {
// 长持有多例：全局注册表 new 后永不释放（long_lived 典型）
struct Registry {
    std::vector<std::string> known_devices;
    Registry() { known_devices.reserve(64); }
};
Registry* g_registry = nullptr;
} // namespace

DeviceManager::~DeviceManager() { destroy_all(); }

void DeviceManager::bootstrap(unsigned device_count)
{
    if (!g_registry)
        g_registry = new Registry();          // 长持有单例

    for (unsigned i = 0; i < device_count; i++) {
        std::string name = (i % 2 == 0) ? "sensor_dev" : "actuator_dev";
        name += std::to_string(i);
        Device* d = nullptr;
        if (i % 2 == 0)
            d = new SensorDevice(name, i);    // 核心场景分配点（虚析构保证正确释放）
        else
            d = new ActuatorDevice(name, i);
        devices_.push_back(d);
        g_registry->known_devices.push_back(name);
    }
    std::printf("[devmgr] bootstrapped %zu devices\n", devices_.size());
}

void DeviceManager::destroy_all()
{
    for (Device* d : devices_)
        delete d;                             // 虚析构 → operator delete → free hook
    devices_.clear();
}

void DeviceManager::restart_cycle()
{
    destroy_all();
    bootstrap(12);   // 与首启相同的设备拓扑
    std::printf("[devmgr] restart cycle done (devices rebuilt)\n");
}

void DeviceManager::poll_all()
{
    // 深调用链：poll_all → Device::read_telemetry(虚) → ostringstream 内部分配 → publish
    for (Device* d : devices_) {
        std::string tele = d->read_telemetry();
        event_bus().publish("telemetry", tele);
    }
}

} // namespace devmgr

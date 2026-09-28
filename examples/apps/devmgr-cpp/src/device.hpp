// device.hpp — 设备基类与派生类（继承/虚函数/多态分配）
#pragma once
#include <string>

namespace devmgr {

class Device {
public:
    Device(std::string name, unsigned unit);
    virtual ~Device();

    virtual std::string read_telemetry() const = 0;   // 虚函数：深栈+多态
    const std::string&  name() const { return name_; }

protected:
    std::string name_;
    unsigned    unit_;
};

class SensorDevice final : public Device {
public:
    SensorDevice(std::string name, unsigned unit);
    std::string read_telemetry() const override;
};

class ActuatorDevice final : public Device {
public:
    ActuatorDevice(std::string name, unsigned unit);
    std::string read_telemetry() const override;
};

} // namespace devmgr

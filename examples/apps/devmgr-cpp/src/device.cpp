// device.cpp — 设备实现
#include "device.hpp"
#include <sstream>

namespace devmgr {

Device::Device(std::string name, unsigned unit)
    : name_(std::move(name)), unit_(unit) {}

Device::~Device() = default;

SensorDevice::SensorDevice(std::string name, unsigned unit)
    : Device(std::move(name), unit) {}

std::string SensorDevice::read_telemetry() const
{
    // 组包过程产生若干 std::string 内部缓冲（正常配对，随返回值释放/移动）
    std::ostringstream oss;
    oss << name_ << "/unit" << unit_ << "/temp=" << (45 + (unit_ % 10)) << ".5C";
    return oss.str();
}

ActuatorDevice::ActuatorDevice(std::string name, unsigned unit)
    : Device(std::move(name), unit) {}

std::string ActuatorDevice::read_telemetry() const
{
    std::ostringstream oss;
    oss << name_ << "/unit" << unit_ << "/state=on/duty=" << (unit_ * 7 % 100) << "%";
    return oss.str();
}

} // namespace devmgr

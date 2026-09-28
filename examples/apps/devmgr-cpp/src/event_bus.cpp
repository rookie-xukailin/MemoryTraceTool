// event_bus.cpp — 事件总线实现
#include "event_bus.hpp"

namespace devmgr {

EventBus& event_bus()
{
    // 函数级静态单例：首次调用 new，进程存活期永不释放（long_lived 典型）
    static EventBus* inst = new EventBus();
    return *inst;
}

void EventBus::subscribe(const std::string& topic, Handler h)
{
    routes_[topic] = h;   // std::map 节点 new + std::string key 拷贝
}

void EventBus::unsubscribe(const std::string& topic)
{
    routes_.erase(topic); // 配对释放
}

void EventBus::publish(const std::string& topic, const std::string& payload)
{
    auto it = routes_.find(topic);
    if (it != routes_.end())
        it->second(payload);
}

} // namespace devmgr

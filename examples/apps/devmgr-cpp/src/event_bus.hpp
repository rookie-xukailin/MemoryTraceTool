// event_bus.hpp — 事件总线（STL 容器正常配对场景）
#pragma once
#include <map>
#include <string>

namespace devmgr {

class EventBus {
public:
    using Handler = void (*)(const std::string&);

    void subscribe(const std::string& topic, Handler h);   // map 节点分配
    void unsubscribe(const std::string& topic);            // 节点释放（配对）
    void publish(const std::string& topic, const std::string& payload);

private:
    std::map<std::string, Handler> routes_;
};

EventBus& event_bus();   // 全局单例（其本身 long_lived）

} // namespace devmgr

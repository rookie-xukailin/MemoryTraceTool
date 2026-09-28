// main.cpp — devmgr 守护进程入口
//
// 信号约定：SIGUSR2 = "主机重启 RPC"（释放并重建设备）；SIGUSR1 留给 MemoryTraceTool。
#include "device_manager.hpp"
#include "event_bus.hpp"
#include "telemetry.hpp"

#include <csignal>
#include <unistd.h>
#include <cstdio>

static volatile sig_atomic_t g_restart_requested = 0;

extern "C" void on_restart_rpc(int) { g_restart_requested = 1; }  // async-signal-safe

int main()
{
    setvbuf(stdout, NULL, _IOLBF, 0);   /* 行缓冲：管道/重定向也即时可见 */
    std::printf("[devmgr] starting (pid=%d)\n", getpid());
    signal(SIGUSR2, on_restart_rpc);

    using namespace devmgr;

    // 订阅事件（STL 正常配对：每轮 subscribe/unsubscribe）
    EventBus& bus = event_bus();
    static unsigned round = 0;
    bus.subscribe("telemetry", [](const std::string& payload) {
        TelemetryCollector collector;
        collector.ingest(payload);           // 【泄漏点】每轮 +1 条
        collector.periodic_flush(round);     // 每 10 轮 throw/catch
    });

    DeviceManager mgr;
    mgr.bootstrap(12);                       // 核心场景：启动 new

    for (;;) {
        if (g_restart_requested) {           // 重启 RPC：释放并重建
            g_restart_requested = 0;
            mgr.restart_cycle();
        }
        mgr.poll_all();                      // 深调用链采集
        bus.unsubscribe("telemetry");        // STL 配对（下轮重新订阅）
        bus.subscribe("telemetry", [](const std::string& payload) {
            TelemetryCollector collector;
            collector.ingest(payload);
            collector.periodic_flush(round);
        });
        ++round;
        usleep(2000 * 1000);
    }
    return 0;
}

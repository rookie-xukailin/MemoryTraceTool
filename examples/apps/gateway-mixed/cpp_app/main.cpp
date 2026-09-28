// main.cpp — gateway-mixed 入口
// 信号约定：SIGUSR2 = "主机重启 RPC"；SIGUSR1 留给 MemoryTraceTool。
#include "gateway.hpp"
#include "netcore.h"

#include <csignal>
#include <unistd.h>
#include <cstdio>

int main()
{
    setvbuf(stdout, NULL, _IOLBF, 0);   /* 行缓冲：管道/重定向也即时可见 */
    std::printf("[gateway] starting (pid=%d)\n", getpid());
    signal(SIGUSR2, gateway::request_restart_cycle);

    if (gateway::start() != 0)
        return 1;

    unsigned round = 0;
    for (;;) {
        gateway::process_restart();   // 处理重启 RPC（C 层释放重建）
        gateway::poll_once();         // 一轮业务（跨语言调用链）
        if (++round % 15 == 0)
            std::printf("[gateway] round=%u session=%zuB\n",
                        round, netcore_session_size());
        usleep(2000 * 1000);
    }
    return 0;
}

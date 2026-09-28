// gateway.hpp — 网关业务编排
#pragma once
#include <cstddef>

namespace gateway {

int  start();                 // 初始化 C 核心 + 会话创建（核心场景起点）
void poll_once();             // 一轮：收帧→解码（含 C 泄漏点与 C++ 泄漏点）
void request_restart_cycle(int sig); // SIGUSR2 handler：置重启标志
void process_restart();       // 主循环：调 C 层 netcore_session_rebuild()

} // namespace gateway

// gateway.cpp — 网关业务编排（跨语言调用链）
#include "gateway.hpp"
#include "netcore.h"
#include "codec.hpp"

#include <csignal>
#include <cstdio>

namespace gateway {

static volatile sig_atomic_t s_restart = 0;
extern "C" void gateway_on_sigusr2(int) { s_restart = 1; }

int start()
{
    std::printf("[gateway] netcore init\n");
    netcore_init();
    if (netcore_session_create() != 0) {
        std::printf("[gateway] FATAL: session create failed\n");
        return -1;
    }
    std::printf("[gateway] session created (%zu bytes)\n", netcore_session_size());
    return 0;
}

void poll_once()
{
    // 深调用链（跨 .so 边界）：
    //   poll_once → netcore_recv(libnetcore.so) → frame_parse → malloc
    for (unsigned conn = 0; conn < 6; conn++) {
        unsigned char* frame = nullptr;
        size_t len = 0;
        if (netcore_recv(conn, &frame, &len) == 0 && frame) {
            decode_frame(frame, len);            // C++ 侧释放 C 分配的内存
        }
    }
    // 【C++ 泄漏点】每轮缓存一条（operator new，增长型）
    codec_cache_put("conn_stats");
}

void request_restart_cycle(int sig)
{
    (void)sig;
    s_restart = 1;
}

void process_restart()
{
    if (!s_restart)
        return;
    s_restart = 0;
    std::printf("[gateway] restart RPC: rebuilding C-core session\n");
    netcore_session_rebuild();   // C 层：释放并重建会话缓冲
}

} // namespace gateway

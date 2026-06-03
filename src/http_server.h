/*
 * MemoryTraceTool — 嵌入式 HTTP 服务器模块。
 *
 * 轻量级 HTTP/1.0 服务器，运行在 detach 后台线程中，
 * 为 Web 仪表盘提供静态 HTML 页面和 JSON API。
 *
 * 由 MTT_HTTP_PORT 环境变量控制（0=禁用，默认禁用），
 * 零外部依赖：纯 C 实现，HTTP 解析和 JSON 序列化全部手写。
 *
 * 线程安全：后端数据通过 reporter 缓存访问（cache_lock），
 * 无阻塞 I/O（select 超时 1 秒），不影响分配热路径。
 */
#ifndef MTT_HTTP_SERVER_H
#define MTT_HTTP_SERVER_H

#include "mtt_internal.h"
#include <stdint.h>

/** HTTP 服务器状态 */
typedef struct {
    _Atomic int running;  /* 1=运行中, 0=停止请求 */
    int       listen_fd;  /* 监听 socket */
    uint16_t  port;       /* 实际绑定的端口号 */
    pthread_t thread;     /* HTTP 工作线程 */
} mtt_http_server_t;

/* ---- API ---- */

/**
 * 启动 HTTP 服务器（如果端口 > 0）。
 *
 * 创建 TCP socket 绑定到 0.0.0.0:port，启动后台线程处理请求。
 * 若 bind 失败则尝试后续 5 个端口（port+1 ~ port+5）。
 * 通过 write 将实际端口号输出到 stderr。
 *
 * @param port  监听端口（0=禁用），来自 MTT_HTTP_PORT 环境变量
 */
void mtt_http_server_start(uint16_t port);

/**
 * 停止 HTTP 服务器。
 *
 * 关闭 listen_fd，设置 running=0，不 join 线程
 *（detach 线程在下一次 accept/select 超时后自行退出）。
 */
void mtt_http_server_stop(void);

#endif /* MTT_HTTP_SERVER_H */

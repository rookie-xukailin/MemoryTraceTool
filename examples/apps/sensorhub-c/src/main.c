/* main.c — sensorhub 守护进程入口。
 *
 * 主循环：2s 一轮采集 + 会话重建检查；
 * 信号：SIGUSR2 = "主机重启 RPC"（释放会话并重建）；SIGUSR1 留给 MemoryTraceTool。
 */
#include "config.h"
#include "session.h"
#include "sensor.h"
#include "storage.h"
#include "log.h"

#include <signal.h>
#include <unistd.h>
#include <stdio.h>

int main(void)
{
    log_init();
    log_printf("sensorhub starting (pid=%d)", getpid());

    /* 重启 RPC 信号：handler 只置标志（async-signal-safe），主循环处理 */
    signal(SIGUSR2, session_request_rebuild);

    /* 启动序列：配置（长持有）→ 存储 → 会话（核心场景）→ 传感器 */
    if (config_load() != 0) {
        log_printf("FATAL: config load failed");
        return 1;
    }
    storage_init(config_get()->storage_capacity);
    if (session_create() != 0) {
        log_printf("FATAL: session create failed");
        return 1;
    }
    sensor_init(config_get()->sensor_count);

    /* 主循环 */
    unsigned round = 0;
    for (;;) {
        session_poll();          /* 处理重启 RPC 的重建请求 */
        sensor_poll_all();       /* 采集一轮（含泄漏点） */

        if (++round % 15 == 0)   /* ~30s 汇报一次 */
            log_printf("round=%u session=%zuB leaked=%zuB",
                       round, session_size(), sensor_leaked_total());

        usleep(2000 * 1000);     /* 2s 采集周期 */
    }
    return 0;
}

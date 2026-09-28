/* config.c — 配置表加载。
 *
 * 内存行为：进程启动时一次性申请配置数组，之后全程持有、永不释放
 * （配置表是守护进程的典型全局单例数据）。
 * 预期分类：long_lived —— 已老化、数量恒为 1、从未观察到释放。
 */
#include "config.h"
#include "log.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

static app_config_t g_cfg;

int config_load(void)
{
    /* 模拟从配置文件/环境展开出 8 路传感器配置 */
    const size_t n = 8;
    g_cfg.sensors = calloc(n, sizeof(sensor_cfg_t));
    if (!g_cfg.sensors)
        return -1;

    for (size_t i = 0; i < n; i++) {
        snprintf(g_cfg.sensors[i].name, sizeof(g_cfg.sensors[i].name),
                 "thermal_cpu%zu", i);
        g_cfg.sensors[i].poll_interval_ms = 2000;
        g_cfg.sensors[i].sample_count = 16;
    }
    g_cfg.sensor_count = n;
    g_cfg.storage_capacity = 256;

    log_printf("config loaded: %zu sensors, storage=%u",
               g_cfg.sensor_count, g_cfg.storage_capacity);
    return 0;
}

const app_config_t *config_get(void)
{
    return &g_cfg;
}

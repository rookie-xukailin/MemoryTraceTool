/* config.h — 配置表（长持有场景） */
#ifndef SH_CONFIG_H
#define SH_CONFIG_H

#include <stddef.h>

typedef struct {
    char     name[32];
    unsigned poll_interval_ms;
    unsigned sample_count;
} sensor_cfg_t;

typedef struct {
    sensor_cfg_t *sensors;      /* 启动加载，进程存活期永不释放 */
    size_t        sensor_count;
    unsigned      storage_capacity;
} app_config_t;

int  config_load(void);              /* 启动时调用一次 */
const app_config_t *config_get(void);

#endif

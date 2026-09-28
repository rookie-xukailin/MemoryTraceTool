/* sensor.c — 传感器采集模块。
 *
 * 内存行为（每轮 poll）：
 *   1. 正常路径：sample_frame 分配 → storage 写入 → 释放（配对，临时分配）；
 *   2. 【注入的 bug】sensor_poll 的校准分支每次泄漏 64B 原始采样帧
 *      —— 模拟"每个采集周期悄悄漏一块"的真实缺陷。
 *
 * 预期分类：
 *   - 正常采样帧：不进嫌疑区（寿命 <1s）
 *   - 泄漏帧（同一调用点，每轮 +64B）：probable —— 存活数持续刷历史峰值
 */
#include "sensor.h"
#include "storage.h"
#include "log.h"
#include <stdlib.h>
#include <string.h>

static unsigned s_sensor_count = 0;
static size_t   s_leaked_total = 0;

/* 单帧采集：malloc → 填充 → 上抛（所有权移交 storage 写入路径） */
static int sample_frame(unsigned sensor_id)
{
    unsigned char *frame = malloc(512);          /* 正常帧：最终被释放 */
    if (!frame)
        return -1;
    memset(frame, (int)(sensor_id & 0xFF), 512);

    storage_write(sensor_id, frame, 512);        /* 深调用链：见 storage.c */
    free(frame);
    return 0;
}

void sensor_init(unsigned sensor_count)
{
    s_sensor_count = sensor_count;
}

void sensor_poll_all(void)
{
    static unsigned seq = 0;
    seq++; /* 轮询计数（模拟真实采集序号） */

    for (unsigned id = 0; id < s_sensor_count; id++) {
        sample_frame(id);

        /* 【注入 bug】cpu0 每轮校准泄漏 64B —— 增长型泄漏点 */
        if (id == 0) {
            unsigned char *calib = malloc(64);
            if (calib) {
                memset(calib, 0xA5, 64);
                /* 忘记 free —— 真实工程里最常见的泄漏形态 */
                s_leaked_total += 64;
            }
        }
    }
}

size_t sensor_leaked_total(void)
{
    return s_leaked_total;
}

/* sensor.h — 传感器采集（正常配对 + 增长泄漏点） */
#ifndef SH_SENSOR_H
#define SH_SENSOR_H

#include <stddef.h>

void  sensor_init(unsigned sensor_count);
void  sensor_poll_all(void);       /* 每轮采集：正常 alloc/free + 一个泄漏点 */
size_t sensor_leaked_total(void);  /* 累计泄漏字节数（自观测用） */

#endif

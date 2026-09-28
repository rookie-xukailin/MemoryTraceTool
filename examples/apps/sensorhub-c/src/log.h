/* log.h — 轻量日志模块（临时分配场景） */
#ifndef SH_LOG_H
#define SH_LOG_H

void log_init(void);
void log_printf(const char *fmt, ...);

#endif

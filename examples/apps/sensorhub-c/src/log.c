/* log.c — 轻量日志模块。
 * 每条日志 malloc 格式缓冲、写完立即 free：
 * 短寿命分配（<1s），验证工具的 temp-alloc 识别——不应进嫌疑区。 */
#include "log.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>

void log_init(void)
{
    setvbuf(stdout, NULL, _IOLBF, 0);
}

void log_printf(const char *fmt, ...)
{
    char prefix[32];
    time_t now = time(NULL);
    struct tm tm_buf;
    localtime_r(&now, &tm_buf);
    strftime(prefix, sizeof(prefix), "%H:%M:%S", &tm_buf);

    /* 临时缓冲：分配 → 使用 → 立即释放（短寿命） */
    char *line = malloc(2048);
    if (!line)
        return;

    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(line, 2048, fmt, ap);
    va_end(ap);

    if (n > 0)
        fprintf(stdout, "[%s] %s\n", prefix, line);

    free(line);
}

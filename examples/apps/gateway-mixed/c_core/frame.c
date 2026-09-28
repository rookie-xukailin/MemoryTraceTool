/* frame.c — 帧解析实现（栈顶帧位于 libnetcore.so 内的泄漏场景）
 *
 * frame_parse(): malloc 结果帧（调用方释放，跨边界所有权正常路径）
 *                + 每帧泄漏 24B CRC 尾缀块（C 库内部的增长泄漏点）
 * 预期分类：泄漏站点 probable，栈显示 netcore.so 内的调用链。
 */
#include "frame.h"
#include <stdlib.h>
#include <string.h>

static size_t s_leaked_total = 0;

int frame_parse(unsigned conn_id, unsigned gen,
                unsigned char **out_frame, size_t *out_len)
{
    size_t flen = 128 + (conn_id % 32);
    unsigned char *frame = malloc(flen);
    if (!frame)
        return -1;
    memset(frame, (int)((conn_id + gen) & 0xFF), flen);

    /* 【注入 bug】CRC 尾缀块：parse 时挂上，从不释放 */
    unsigned char *crc_tail = malloc(24);
    if (crc_tail) {
        memset(crc_tail, 0x5A, 24);
        s_leaked_total += 24;
        /* 指针丢失 —— 真实 C 库里最常见的泄漏写法 */
    }

    *out_frame = frame;
    *out_len = flen;
    return 0;
}

size_t frame_leaked_total(void)
{
    return s_leaked_total;
}

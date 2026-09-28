/* frame.h — 帧解析（C 库内部） */
#ifndef FRAME_H
#define FRAME_H

#include <stddef.h>

/* 解析一帧：内部分配结果缓冲（调用方负责释放）。
 * 【注入 bug】每帧额外泄漏 24B 尾缀校验块。 */
int frame_parse(unsigned conn_id, unsigned gen,
                unsigned char **out_frame, size_t *out_len);

size_t frame_leaked_total(void);

#endif

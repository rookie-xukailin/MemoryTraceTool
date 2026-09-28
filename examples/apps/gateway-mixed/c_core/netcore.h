/* netcore.h — C 协议核心（导出接口，编译为 libnetcore.so）
 *
 * 会话缓冲生命周期（核心场景）：
 *   netcore_session_create()  启动时申请，长期持有；
 *   netcore_session_rebuild() "主机重启 RPC"时由应用调用：释放并重建。
 */
#ifndef NETCORE_H
#define NETCORE_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

int    netcore_init(void);
int    netcore_session_create(void);
void   netcore_session_rebuild(void);   /* 释放并重建（重启 RPC 到达时调用） */
size_t netcore_session_size(void);

/* 帧接收路径（深调用链入口，内部分配见 frame.c） */
int netcore_recv(unsigned conn_id, unsigned char **out_frame, size_t *out_len);

#ifdef __cplusplus
}
#endif

#endif

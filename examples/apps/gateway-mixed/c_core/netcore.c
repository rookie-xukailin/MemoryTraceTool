/* netcore.c — C 协议核心实现（libnetcore.so）
 *
 * 会话缓冲：启动申请 128 连接 × 2KB 收包环，长期持有；
 * 收到重启 RPC（应用层转调 netcore_session_rebuild）→ 释放重建。
 * 预期分类：long_lived →（释放+重建后）session_scoped。
 */
#include "netcore.h"
#include "frame.h"
#include <stdlib.h>
#include <string.h>

#define NETCORE_CONNS    128
#define NETCORE_RING_SZ  2048

static unsigned char *s_ring = NULL;      /* 会话缓冲（单块） */
static size_t         s_ring_size = 0;
static unsigned       s_gen = 0;

int netcore_init(void)
{
    return 0;
}

int netcore_session_create(void)
{
    if (s_ring)
        return 0;
    s_ring = malloc(NETCORE_CONNS * NETCORE_RING_SZ);
    if (!s_ring)
        return -1;
    memset(s_ring, 0, NETCORE_CONNS * NETCORE_RING_SZ);
    s_ring_size = NETCORE_CONNS * NETCORE_RING_SZ;
    s_gen++;
    return 0;
}

void netcore_session_rebuild(void)
{
    free(s_ring);                          /* 老化释放：late-free 证据点 */
    s_ring = NULL;
    s_ring_size = 0;
    netcore_session_create();
}

size_t netcore_session_size(void)
{
    return s_ring_size;
}

/* 深调用链：netcore_recv → frame_parse（.so 内部分配） */
int netcore_recv(unsigned conn_id, unsigned char **out_frame, size_t *out_len)
{
    if (conn_id >= NETCORE_CONNS)
        return -1;
    /* 模拟从环上取帧：frame_parse 内部 malloc 结果帧 */
    return frame_parse(conn_id, s_gen, out_frame, out_len);
}

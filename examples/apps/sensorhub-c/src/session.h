/* session.h — 采集会话上下文（核心场景：启动申请 → 信号释放 → 重建）
 *
 * 模拟 BMC 场景：进程启动时申请一块会话级缓冲区长期持有；
 * 收到"主机重启 RPC 信号"后释放并立即重建（下一个主机启动周期）。
 * 通过 SIGUSR2 模拟该 RPC（SIGUSR1 保留给 MemoryTraceTool）。
 */
#ifndef SH_SESSION_H
#define SH_SESSION_H

#include <signal.h>

int      session_create(void);   /* 申请会话缓冲（~256KB，长期持有） */
void     session_destroy(void);  /* 释放会话缓冲（重启 RPC 到达时调用） */
void     session_request_rebuild(int sig); /* 信号 handler：置重建标志 */
void     session_poll(void);     /* 主循环调用：处理重建请求 */
size_t   session_size(void);     /* 当前会话缓冲字节数（0=未持有） */

#endif

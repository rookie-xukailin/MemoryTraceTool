/* session.c — 采集会话上下文。
 *
 * 核心验证场景（贴近"主机重启压力测试"）：
 *   1. 进程启动 → session_create() 申请 256 路传感器的会话缓冲，长期持有；
 *   2. 收到 SIGUSR2（模拟主机重启 RPC）→ 释放整块缓冲并立即重建，
 *      对应"主机重启时业务收到 RPC 后释放内存，主机起来后再申请"的循环。
 *
 * 预期分类（MemoryTraceTool）：
 *   - 首轮持有期：老化后 long_lived（数量稳定、未观察到释放）
 *   - 释放：证据入 late-free 历史
 *   - 重建后：session_scoped —— 周期作用域内存，非泄漏
 */
#include "session.h"
#include "log.h"
#include <stdlib.h>
#include <string.h>

#define SESSION_SLOTS   256
#define SESSION_SLOT_SZ 1024

static volatile sig_atomic_t s_rebuild_requested = 0;
static unsigned char *s_buf = NULL;      /* 会话缓冲（单块大分配） */
static size_t         s_buf_size = 0;
static unsigned       s_generation = 0;  /* 已经历的"主机周期"数 */

void session_request_rebuild(int sig)
{
    (void)sig;                          /* async-signal-safe：只置标志 */
    s_rebuild_requested = 1;
}

int session_create(void)
{
    if (s_buf)
        return 0;

    /* 单块连续缓冲：256 slot × 1KB，模拟会话级聚合缓冲 */
    s_buf = malloc(SESSION_SLOTS * SESSION_SLOT_SZ);
    if (!s_buf)
        return -1;
    memset(s_buf, 0, SESSION_SLOTS * SESSION_SLOT_SZ);
    s_buf_size = SESSION_SLOTS * SESSION_SLOT_SZ;
    s_generation++;

    log_printf("session created (gen=%u, %zu bytes)", s_generation, s_buf_size);
    return 0;
}

void session_destroy(void)
{
    if (!s_buf)
        return;
    free(s_buf);
    s_buf = NULL;
    s_buf_size = 0;
    log_printf("session destroyed (restart RPC)");
}

void session_poll(void)
{
    if (s_rebuild_requested) {
        s_rebuild_requested = 0;
        session_destroy();
        if (session_create() != 0)
            log_printf("session rebuild FAILED");
        else
            log_printf("session rebuilt for new host cycle (gen=%u)",
                       s_generation);
    }
}

size_t session_size(void)
{
    return s_buf_size;
}

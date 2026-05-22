/*
 * MemoryTraceTool 守护进程（mttd）数据结构定义。
 *
 * 定义了 IPC 协议常量、守护进程端泄漏记录和进程记录的数据结构。
 * 该头文件被 daemon.c（守护进程服务端）和 client.c（被监控进程客户端）共用，
 * 以确保双方对序列化格式保持一致。
 */
#ifndef MTT_DAEMON_H
#define MTT_DAEMON_H

#include <stddef.h>
#include <stdint.h>
#include <pthread.h>

/* IPC 协议常量 */
#define MTT_SOCK_PATH        "/tmp/mttd.sock"  /* Unix Domain Socket 路径 */
#define MTT_MAX_PROCS        128               /* 守护进程最大监控进程数（高负载场景上调） */
#define MTT_MAX_LEAKS        256               /* 每个进程最大泄漏记录数 */
#define MTT_SYMBOL_MAX       256               /* 单帧符号字符串最大长度 */
#define MTT_MAX_STACK        8                 /* 每个泄漏记录保留的栈帧数 */

/* 连接管理常量 */
#define MTT_CLIENT_TIMEOUT_S 30                /* 客户端空闲超时（秒） */
#define MTT_UNIX_BUF_SZ      16384             /* Unix socket 缓冲区大小 */

/* ---- 守护进程端泄漏记录 ---- */

/** 守护进程存储的单条泄漏信息（从客户端 LEAK/FRAME 消息反序列化） */
typedef struct {
    size_t  size;                            /* 泄漏字节数 */
    char    file[128];                       /* 源文件名 */
    int     line;                            /* 源文件行号 */
    int     nframes;                         /* 实际栈帧数 */
    char    frames[MTT_MAX_STACK][MTT_SYMBOL_MAX]; /* 各帧符号字符串数组 */
} mttd_leak_t;

/* ---- 每个被监控进程的记录 ---- */

/** 守护进程维护的单个被监控进程数据 */
typedef struct {
    int     pid;                             /* 操作系统进程 ID */
    char    name[256];                       /* 进程名（来自 HELLO 消息） */
    int     active;                          /* 是否仍在运行（BYE 消息后设为 0） */
    size_t  total_leaked;                    /* 该进程总计泄漏字节数 */
    int     leak_count;                      /* 当前泄漏条数 */
    int     leak_cap;                        /* leaks 数组容量 */
    time_t  last_seen;                       /* 最后一次收到报告的时间戳 */

    mttd_leak_t* leaks;                      /* 动态分配的泄漏记录数组 */

    pthread_mutex_t lock;                    /* 保护本进程数据的互斥锁 */
} mttd_proc_t;

#endif

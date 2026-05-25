/*
 * MemoryTraceTool — 运行时库注入模块（ptrace + GOT 热修补）。
 *
 * 本模块通过 ptrace 系统调用将 libmemorytracetool.so 注入到
 * 正在运行的目标进程中，并修补其 GOT 表项使 malloc/free/calloc/realloc
 * 重定向到我们的钩子函数。
 *
 * 支持架构：x86_64 / ARM32 (EABI) / AArch64。
 * 编译时通过预处理器宏自动适配 ELF 类型、寄存器布局和调用约定。
 */
#ifndef MTT_INJECTOR_H
#define MTT_INJECTOR_H

#include <sys/types.h>

/* 注入状态码 */
typedef enum {
    INJECT_OK = 0,           /* 注入成功 */
    INJECT_ERR_ATTACH,       /* ptrace ATTACH 失败（权限不足 / 僵尸进程） */
    INJECT_ERR_DLOPEN,       /* __libc_dlopen_mode 调用返回 NULL */
    INJECT_ERR_GOT,          /* 未找到任何 malloc/free GOT 表项（静态链接？） */
    INJECT_ERR_PERM,         /* EPERM — 需要 root 或 ptrace_scope=0 */
    INJECT_ERR_CRASH,        /* 目标进程在注入过程中崩溃 */
    INJECT_ERR_NOTFOUND,     /* PID 不存在 */
    INJECT_ERR_BUSY,         /* 目标进程已被注入 */
    INJECT_ERR_TIMEOUT,      /* 注入操作超时 */
} inject_status_t;

/* 注入结果 */
typedef struct {
    inject_status_t status;
    char            err_msg[256];  /* 人类可读的错误描述 */
    pid_t           pid;
    unsigned long   lib_base;      /* 注入后 .so 在目标进程中的基地址，0=未知 */
    int             patched_count; /* 成功修补的 GOT 表项数 */
    char            patched_names[128]; /* 逗号分隔的已修补符号名，如 "malloc,free,calloc" */
} inject_result_t;

/* 要钩取的符号名列表（以 NULL 结尾） */
#define INJECT_HOOK_COUNT 4
extern const char* g_inject_hook_names[INJECT_HOOK_COUNT + 1];

/**
 * 将 libmemorytracetool.so 注入到目标进程并修补其 GOT。
 *
 * 工作流程：ptrace ATTACH → 远程调用 __libc_dlopen_mode → GOT 修补 → DETACH
 *
 * @param pid       目标进程 PID
 * @param lib_path  要注入的 .so 文件的绝对路径
 * @return          注入结果（状态码 + 描述信息）
 */
inject_result_t inject_library(pid_t pid, const char* lib_path);

#endif /* MTT_INJECTOR_H */

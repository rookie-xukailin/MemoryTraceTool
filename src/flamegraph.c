/*
 * MemoryTraceTool — Flamegraph 输出模块实现。
 *
 * 生成 collapsed stacks 格式文件（兼容 Brendan Gregg 的 flamegraph.pl）。
 *
 * collapsed stacks 格式说明：
 *   每行：func1;func2;...;funcN count
 *   - 分号分隔的函数名代表调用栈（栈底在前，栈顶在后）
 *   - count 为该调用栈的采样次数或字节数
 *   - 管道到 flamegraph.pl 即可生成 SVG 火焰图
 *
 * 用法：flamegraph.pl /var/log/mtt/<pid>_<name>.folded > flame.svg
 */
#define _GNU_SOURCE
#include "flamegraph.h"
#include "stack_cache.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

/* 前向声明：site_stack_pair_t 定义在 reporter.c 中 */
typedef struct {
    mtt_leak_site_t  *site;
    mtt_stack_entry_t *stack_entry;
} site_stack_pair_t;

/**
 * 将泄漏站点列表写入 collapsed stacks 格式文件。
 *
 * 遍历所有泄漏站点，对每个站点提取已解析的栈帧符号，
 * 过滤内部帧后按 collapsed stacks 格式输出。
 * 栈帧顺序反转：栈顶（调用点）→ 栈底（main），与火焰图惯例一致。
 *
 * @param log_dir   日志目录路径
 * @param proc_name 进程名
 * @param sites     排序后的泄漏站点指针数组
 * @param count     站点数量
 * @param pairs     站点到栈缓存映射数组（site_stack_pair_t*）
 */
void mtt_flamegraph_write(const char *log_dir, const char *proc_name,
                          mtt_leak_site_t **sites, size_t count,
                          void **pairs)
{
    if (log_dir == NULL || proc_name == NULL || sites == NULL || pairs == NULL)
        return;
    if (count == 0) return;

    /* 构建 .folded 文件路径 */
    char fg_path[512] = {0};
    snprintf(fg_path, sizeof(fg_path), "%s/%d_%s.folded",
             log_dir, (int)getpid(), proc_name);

    FILE *fp = fopen(fg_path, "w");
    if (fp == NULL) return;

    /* 辅助函数：判断帧是否内部帧（与 reporter.c 中一致） */
    #define IS_INTERNAL(sym) \
        ((sym) == NULL || (sym)[0] == '\0' || \
         strstr((sym), "libmemorytracetool") != NULL || \
         strstr((sym), "mtt_") == (sym) || \
         strstr((sym), "capture_stack") != NULL || \
         strstr((sym), "backtrace") != NULL)

    for (size_t i = 0; i < count; i++) {
        if (sites[i] == NULL || sites[i]->count == 0) continue;

        site_stack_pair_t *pair = (site_stack_pair_t*)pairs[i];
        if (pair == NULL) continue;

        mtt_stack_entry_t *se = pair->stack_entry;
        if (se == NULL || !se->is_resolved) continue;

        /* 收集非内部帧的函数名（过滤掉内部帧和库名部分） */
        /* 格式: "func+0xOFFSET (libname)" → 提取 "func+0xOFFSET" */
        char frames[MTT_STACK_DEPTH][MTT_SYMBOL_MAX];
        int frame_count = 0;

        for (int j = 0; j < se->frame_count && frame_count < MTT_STACK_DEPTH; j++) {
            const char *sym = se->resolved[j];
            if (IS_INTERNAL(sym)) continue;

            /* 提取函数名+偏移部分（去掉括号内的库名） */
            const char *paren = strchr(sym, '(');
            size_t len;
            if (paren != NULL && paren > sym) {
                len = (size_t)(paren - sym);
                /* 去除尾部空格 */
                while (len > 0 && sym[len - 1] == ' ') len--;
            } else {
                len = strlen(sym);
            }

            if (len >= MTT_SYMBOL_MAX) len = MTT_SYMBOL_MAX - 1;
            memcpy(frames[frame_count], sym, len);
            frames[frame_count][len] = '\0';
            frame_count++;
        }

        if (frame_count == 0) continue;

        /* collapsed stacks 格式：从栈底到栈顶（反转顺序输出） */
        for (int j = frame_count - 1; j >= 0; j--) {
            fprintf(fp, "%s", frames[j]);
            if (j > 0) fputc(';', fp);
        }
        /* 输出该栈的占用字节数作为 count */
        fprintf(fp, " %zu\n", sites[i]->total_size);
    }

    fclose(fp);
}

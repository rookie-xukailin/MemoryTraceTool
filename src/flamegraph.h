/*
 * MemoryTraceTool — Flamegraph 输出模块。
 *
 * 生成 collapsed stacks 格式文件（兼容 Brendan Gregg 的 flamegraph.pl），
 * 每行格式：func1;func2;funcN count，可直接生成 SVG 火焰图。
 *
 * 用法：flamegraph.pl /var/log/mtt/xxx.folded > flame.svg
 */
#ifndef MTT_FLAMEGRAPH_H
#define MTT_FLAMEGRAPH_H

#include "mtt_internal.h"
#include "reporter.h"

/**
 * 将泄漏站点列表写入 collapsed stacks 格式文件。
 *
 * 文件路径与报告日志同目录，后缀 .folded。
 * 每个泄漏站点输出一行：func1;func2;funcN total_size，
 * 函数名之间用分号分隔，栈底在前（caller），栈顶在后（callee）。
 *
 * @param log_dir   日志目录路径
 * @param proc_name 进程名
 * @param sites     排序后的泄漏站点指针数组
 * @param count     站点数量
 * @param pairs     站点到栈缓存的映射数组
 */
void mtt_flamegraph_write(const char *log_dir, const char *proc_name,
                          mtt_leak_site_t **sites, size_t count,
                          void **pairs);

#endif /* MTT_FLAMEGRAPH_H */

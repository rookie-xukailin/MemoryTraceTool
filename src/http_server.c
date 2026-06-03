/*
 * MemoryTraceTool — 嵌入式 HTTP 服务器模块实现。
 *
 * 轻量级 HTTP/1.0 服务器，运行在 detach 后台线程中，
 * 为 Web 仪表盘提供静态 HTML 和 JSON API。
 *
 * 零外部依赖：
 *   - HTTP 解析手写（仅支持 GET /path HTTP/1.0）
 *   - JSON 序列化手写（snprintf）
 *   - HTML 仪表盘编译为 static const 字符串（存放在 .rodata 段）
 *
 * 线程安全：后端数据通过 reporter 的 cache_lock 读取缓存副本，
 * 不直接访问哈希表，不影响分配热路径。
 *
 * 资源控制：
 *   - select 超时 1 秒，响应 running 停止请求
 *   - 每个客户端连接在处理后立即关闭
 *   - 内嵌 HTML 是 static const，零运行时分配
 *   - JSON 响应缓冲区每次 raw_malloc + raw_free，无累积
 */
#define _GNU_SOURCE
#include "http_server.h"
#include "reporter.h"
#include "stack_cache.h"
#include "time_series.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/** HTTP 服务器单例 */
static mtt_http_server_t g_http_server = {0};

/* ======================================================================== *
 *                    Web 仪表盘 HTML（内嵌静态字符串）                        *
 * ======================================================================== */

/**
 * 嵌入式 HTML 仪表盘。
 *
 * 纯静态页面（无外部 JS/CSS 依赖），使用 Canvas API 绘制堆内存趋势图。
 * 每 5 秒通过 fetch 刷新数据，支持暗色模式。
 *
 * 设计要点：
 *   - 大图（Canvas 全宽 800x400）：蓝色面积线 = current_bytes，橙色虚线 = peak_bytes
 *   - 鼠标悬停显示精确数值
 *   - 泄漏站点表按 total_size 降序，可展开查看栈帧
 *   - 每帧格式 "func+0xOFFSET (libname)" — 可直接用于 addr2line
 *   - "复制 addr2line 命令" 按钮
 */
static const char g_dashboard_html[] =
"<!DOCTYPE html>\n"
"<html lang=\"zh\">\n"
"<head>\n"
"<meta charset=\"UTF-8\">\n"
"<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n"
"<meta http-equiv=\"Cache-Control\" content=\"no-cache\">\n"
"<title>MemoryTraceTool</title>\n"
"<style>\n"
":root {\n"
"  --bg: #ffffff; --bg2: #f6f8fa; --text: #24292f; --border: #d0d7de;\n"
"  --accent: #0969da; --orange: #d97706; --green: #16a34a;\n"
"  --warn: #dc2626; --card: #ffffff;\n"
"}\n"
"@media (prefers-color-scheme: dark) {\n"
"  :root {\n"
"    --bg: #0d1117; --bg2: #161b22; --text: #c9d1d9; --border: #30363d;\n"
"    --accent: #58a6ff; --orange: #f0b755; --green: #3fb950;\n"
"    --warn: #f85149; --card: #161b22;\n"
"  }\n"
"}\n"
"* { box-sizing: border-box; margin: 0; padding: 0; }\n"
"body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif;\n"
"  background: var(--bg); color: var(--text); line-height: 1.5; }\n"
".container { max-width: 1200px; margin: 0 auto; padding: 20px; }\n"
"h1 { font-size: 1.5rem; margin-bottom: 4px; }\n"
".subtitle { color: #6e7681; font-size: 0.85rem; margin-bottom: 20px; }\n"
".card { background: var(--card); border: 1px solid var(--border); border-radius: 6px;\n"
"  padding: 16px; margin-bottom: 16px; }\n"
".card h2 { font-size: 1.1rem; margin-bottom: 12px; border-bottom: 1px solid var(--border); padding-bottom: 8px; }\n"
".stats { display: flex; flex-wrap: wrap; gap: 12px; margin-bottom: 16px; }\n"
".stat { background: var(--bg2); border-radius: 6px; padding: 10px 14px; min-width: 130px; }\n"
".stat .val { font-size: 1.3rem; font-weight: 600; }\n"
".stat .lbl { font-size: 0.75rem; color: #6e7681; }\n"
"canvas { width: 100%; max-width: 100%; display: block; border-radius: 4px; }\n"
"table { width: 100%; border-collapse: collapse; font-size: 0.85rem; }\n"
"th, td { text-align: left; padding: 8px 10px; border-bottom: 1px solid var(--border); }\n"
"th { background: var(--bg2); position: sticky; top: 0; }\n"
"tr:hover { background: var(--bg2); }\n"
".stack-row { display: none; background: var(--bg2); }\n"
".stack-row.open { display: table-row; }\n"
".stack-cell { padding: 8px 10px 8px 30px; font-family: 'SF Mono', 'Consolas', monospace;\n"
"  font-size: 0.78rem; white-space: pre-wrap; word-break: break-all; }\n"
".stack-cell .btn { font-size: 0.7rem; padding: 2px 6px; cursor: pointer;\n"
"  background: var(--accent); color: #fff; border: none; border-radius: 3px; margin-left: 8px; }\n"
".leak-row { cursor: pointer; }\n"
".diff-high { background: rgba(220,38,38,0.08); }\n"
".tooltip { position: absolute; background: #1f2328; color: #fff; padding: 4px 8px;\n"
"  border-radius: 4px; font-size: 0.8rem; pointer-events: none; display: none; z-index: 10; }\n"
".refresh { font-size: 0.75rem; color: #6e7681; float: right; }\n"
"</style>\n"
"</head>\n"
"<body>\n"
"<div class=\"container\">\n"
"<h1>MemoryTraceTool</h1>\n"
"<div class=\"subtitle\" id=\"info\">加载中...</div>\n"
"<div class=\"card\">\n"
"  <h2>堆内存趋势 <span class=\"refresh\" id=\"refresh\">每 5 秒刷新</span></h2>\n"
"  <div class=\"stats\" id=\"stats\"></div>\n"
"  <canvas id=\"chart\" width=\"800\" height=\"400\"></canvas>\n"
"  <div class=\"tooltip\" id=\"tip\"></div>\n"
"</div>\n"
"<div class=\"card\">\n"
"  <h2>泄漏站点排行（按占用大小降序）</h2>\n"
"  <table>\n"
"    <thead><tr><th>#</th><th>次数</th><th>单次大小</th><th>总占用</th><th>首次出现</th><th>最后出现</th></tr></thead>\n"
"    <tbody id=\"leaks-tbody\"></tbody>\n"
"  </table>\n"
"</div>\n"
"</div>\n"
"<script>\n"
"var data = null;\n"
"var chartCanvas = document.getElementById('chart');\n"
"var ctx = chartCanvas.getContext('2d');\n"
"var tip = document.getElementById('tip');\n"
"\n"
"function formatBytes(b) {\n"
"  if (b >= 1048576) return (b/1048576).toFixed(2) + ' MB';\n"
"  if (b >= 1024) return (b/1024).toFixed(2) + ' KB';\n"
"  return b + ' B';\n"
"}\n"
"\n"
"function formatTime(ts) {\n"
"  var d = new Date(ts * 1000);\n"
"  return d.toLocaleTimeString();\n"
"}\n"
"\n"
"function drawChart() {\n"
"  if (!data || !data.time_series || data.time_series.length === 0) return;\n"
"  var W = chartCanvas.width, H = chartCanvas.height;\n"
"  ctx.clearRect(0, 0, W, H);\n"
"  var pad = {top: 30, right: 30, bottom: 50, left: 80};\n"
"  var pw = W - pad.left - pad.right;\n"
"  var ph = H - pad.top - pad.bottom;\n"
"  var ts = data.time_series;\n"
"\n"
"  var maxBytes = 0;\n"
"  for (var i = 0; i < ts.length; i++) {\n"
"    if (ts[i].peak > maxBytes) maxBytes = ts[i].peak;\n"
"    if (ts[i].cur > maxBytes) maxBytes = ts[i].cur;\n"
"  }\n"
"  if (maxBytes === 0) maxBytes = 1;\n"
"\n"
"  function x(i) { return pad.left + (i / (ts.length - 1)) * pw; }\n"
"  function y(v) { return pad.top + ph - (v / maxBytes) * ph; }\n"
"\n"
"  /* 网格 */\n"
"  ctx.strokeStyle = getComputedStyle(document.documentElement).getPropertyValue('--border').trim();\n"
"  ctx.lineWidth = 0.5;\n"
"  for (var j = 0; j <= 4; j++) {\n"
"    var val = (maxBytes / 4) * j;\n"
"    var yy = y(val);\n"
"    ctx.beginPath(); ctx.moveTo(pad.left, yy); ctx.lineTo(W - pad.right, yy); ctx.stroke();\n"
"    ctx.fillStyle = getComputedStyle(document.documentElement).getPropertyValue('--text').trim();\n"
"    ctx.font = '10px sans-serif'; ctx.textAlign = 'right';\n"
"    ctx.fillText(formatBytes(val), pad.left - 6, yy + 3);\n"
"  }\n"
"\n"
"  /* area fill */\n"
"  ctx.beginPath();\n"
"  ctx.moveTo(x(0), pad.top + ph);\n"
"  for (var i = 0; i < ts.length; i++) ctx.lineTo(x(i), y(ts[i].cur));\n"
"  ctx.lineTo(x(ts.length - 1), pad.top + ph);\n"
"  ctx.closePath();\n"
"  ctx.fillStyle = 'rgba(9, 105, 218, 0.15)';\n"
"  ctx.fill();\n"
"\n"
"  /* cur line */\n"
"  ctx.beginPath();\n"
"  for (var i = 0; i < ts.length; i++) {\n"
"    if (i === 0) ctx.moveTo(x(i), y(ts[i].cur));\n"
"    else ctx.lineTo(x(i), y(ts[i].cur));\n"
"  }\n"
"  ctx.strokeStyle = '#0969da'; ctx.lineWidth = 2;\n"
"  ctx.stroke();\n"
"\n"
"  /* peak line (dashed) */\n"
"  ctx.beginPath();\n"
"  ctx.setLineDash([4, 4]);\n"
"  for (var i = 0; i < ts.length; i++) {\n"
"    if (i === 0) ctx.moveTo(x(i), y(ts[i].peak));\n"
"    else ctx.lineTo(x(i), y(ts[i].peak));\n"
"  }\n"
"  ctx.strokeStyle = '#d97706'; ctx.lineWidth = 1.5;\n"
"  ctx.stroke();\n"
"  ctx.setLineDash([]);\n"
"\n"
"  /* legend */\n"
"  ctx.fillStyle = '#0969da'; ctx.fillRect(pad.left + 10, 10, 12, 12);\n"
"  ctx.fillStyle = getComputedStyle(document.documentElement).getPropertyValue('--text').trim();\n"
"  ctx.font = '11px sans-serif'; ctx.textAlign = 'left';\n"
"  ctx.fillText('current_bytes', pad.left + 26, 20);\n"
"  ctx.strokeStyle = '#d97706'; ctx.setLineDash([4,4]);\n"
"  ctx.beginPath(); ctx.moveTo(pad.left + 120, 16); ctx.lineTo(pad.left + 150, 16); ctx.stroke();\n"
"  ctx.setLineDash([]);\n"
"  ctx.fillText('peak_bytes', pad.left + 156, 20);\n"
"\n"
"  /* X axis time labels */\n"
"  var steps = Math.min(10, ts.length);\n"
"  for (var i = 0; i <= steps; i++) {\n"
"    var idx = Math.floor((ts.length - 1) * i / steps);\n"
"    if (idx >= ts.length) idx = ts.length - 1;\n"
"    var xx = x(idx);\n"
"    ctx.fillStyle = getComputedStyle(document.documentElement).getPropertyValue('--text').trim();\n"
"    ctx.font = '10px sans-serif'; ctx.textAlign = 'center';\n"
"    ctx.fillText(formatTime(ts[idx].ts), xx, H - pad.bottom + 20);\n"
"  }\n"
"\n"
"  /* mouse hover */\n"
"  chartCanvas.onmousemove = function(e) {\n"
"    var rect = chartCanvas.getBoundingClientRect();\n"
"    var scaleX = chartCanvas.width / rect.width;\n"
"    var mx = (e.clientX - rect.left) * scaleX;\n"
"    var my = (e.clientY - rect.top) * scaleX;\n"
"    for (var i = 0; i < ts.length; i++) {\n"
"      var dx = Math.abs(mx - x(i));\n"
"      if (dx < 5) {\n"
"        tip.style.display = 'block';\n"
"        tip.style.left = (e.clientX + 15) + 'px';\n"
"        tip.style.top = (e.clientY - 30) + 'px';\n"
"        tip.textContent = formatTime(ts[i].ts) + ' | cur: ' + formatBytes(ts[i].cur)\n"
"          + ' | peak: ' + formatBytes(ts[i].peak) + ' | allocs: ' + ts[i].allocs + ' | frees: ' + ts[i].frees;\n"
"        return;\n"
"      }\n"
"    }\n"
"    tip.style.display = 'none';\n"
"  };\n"
"}\n"
"\n"
"function renderStats(stats) {\n"
"  var el = document.getElementById('stats');\n"
"  el.innerHTML =\n"
"    '<div class=\"stat\"><div class=\"val\">' + formatBytes(stats.current_bytes) + '</div><div class=\"lbl\">当前未释放</div></div>'\n"
"    + '<div class=\"stat\"><div class=\"val\">' + formatBytes(stats.peak_bytes) + '</div><div class=\"lbl\">历史峰值</div></div>'\n"
"    + '<div class=\"stat\"><div class=\"val\">' + (stats.alloc_count || 0).toLocaleString() + '</div><div class=\"lbl\">累计分配次数</div></div>'\n"
"    + '<div class=\"stat\"><div class=\"val\">' + (stats.free_count || 0).toLocaleString() + '</div><div class=\"lbl\">累计释放次数</div></div>'\n"
"    + '<div class=\"stat\"><div class=\"val\">' + (stats.leak_count || 0).toLocaleString() + '</div><div class=\"lbl\">疑似泄漏</div></div>'\n"
"    + '<div class=\"stat\"><div class=\"val\">' + formatBytes(stats.total_allocated || 0) + '</div><div class=\"lbl\">累计分配总量</div></div>';\n"
"}\n"
"\n"
"function addr2line(frame) {\n"
"  /* 从 \"func+0xOFFSET (libname)\" 提取 libname 和 offset */\n"
"  var m1 = frame.match(/\\((.+)\\)$/);\n"
"  var m2 = frame.match(/\\+(0x[0-9a-fA-F]+)/);\n"
"  if (m1 && m2) {\n"
"    return 'addr2line -e ' + m1[1] + ' -f -C ' + m2[1];\n"
"  }\n"
"  return '';\n"
"}\n"
"\n"
"function renderLeaks(leaks) {\n"
"  var tbody = document.getElementById('leaks-tbody');\n"
"  if (!leaks || leaks.length === 0) {\n"
"    tbody.innerHTML = '<tr><td colspan=\"6\" style=\"text-align:center;color:#6e7681\">暂无泄漏数据</td></tr>';\n"
"    return;\n"
"  }\n"
"  var rows = '';\n"
"  for (var i = 0; i < leaks.length; i++) {\n"
"    var l = leaks[i];\n"
"    var diff = '';\n"
"    if (l.diff_size && l.diff_size > 0) diff = ' class=\"diff-high\" title=\"本次增长 ' + formatBytes(l.diff_size) + '\"';\n"
"    var stack = '';\n"
"    if (l.stack && l.stack.length > 0) {\n"
"      stack = '<tr class=\"stack-row\" id=\"s' + i + '\"><td colspan=\"6\" class=\"stack-cell\">';\n"
"      for (var j = 0; j < l.stack.length; j++) {\n"
"        var al = addr2line(l.stack[j]);\n"
"        stack += '<div>' + (j===0?'<b>&rarr; ':'  ') + l.stack[j];\n"
"        if (al) stack += ' <button class=\"btn\" onclick=\"navigator.clipboard.writeText(\\'' + al.replace(/'/g, \"\\\\'\") + '\\');this.textContent=\\'已复制\\';setTimeout(()=>this.textContent=\\'addr2line\\',1500)\">addr2line</button>';\n"
"        stack += '</div>';\n"
"      }\n"
"      stack += '</td></tr>';\n"
"    }\n"
"    rows += '<tr class=\"leak-row\"' + diff + ' onclick=\"var s=document.getElementById(\\'s' + i + '\\');s.classList.toggle(\\'open\\')\">'\n"
"      + '<td>' + (i+1) + '</td>'\n"
"      + '<td>' + l.count.toLocaleString() + '</td>'\n"
"      + '<td>' + formatBytes(l.per_leak_size) + '</td>'\n"
"      + '<td><b>' + formatBytes(l.total_size) + '</b></td>'\n"
"      + '<td>' + formatTime(l.first_seen) + '</td>'\n"
"      + '<td>' + formatTime(l.last_seen) + '</td>'\n"
"      + '</tr>' + stack;\n"
"  }\n"
"  tbody.innerHTML = rows;\n"
"}\n"
"\n"
"function refresh() {\n"
"  document.getElementById('refresh').textContent = '刷新中...';\n"
"  fetch('/api/data').then(function(r) { return r.json(); }).then(function(d) {\n"
"    data = d;\n"
"    document.getElementById('info').textContent =\n"
"      'PID: ' + d.pid + ' | ' + d.proc_name + ' | 会话: ' + formatTime(d.session_start)\n"
"      + ' | 上次扫描: ' + formatTime(d.last_scan);\n"
"    renderStats(d.stats || {});\n"
"    drawChart();\n"
"    renderLeaks(d.leaks || []);\n"
"    document.getElementById('refresh').textContent = '已刷新 — ' + new Date().toLocaleTimeString();\n"
"  }).catch(function() {\n"
"    document.getElementById('refresh').textContent = '刷新失败，稍后重试';\n"
"  });\n"
"}\n"
"refresh();\n"
"setInterval(refresh, 5000);\n"
"</script>\n"
"</body>\n"
"</html>\n";

/* ======================================================================== *
 *                       JSON 序列化辅助函数                                  *
 * ======================================================================== */

/** esc 字符串用于 JSON（仅处理双引号和反斜杠，简单但安全） */
static void json_escape(FILE *fp, const char *str)
{
    if (fp == NULL || str == NULL) return;
    for (const char *p = str; *p != '\0'; p++) {
        if (*p == '"' || *p == '\\') fputc('\\', fp);
        fputc(*p, fp);
    }
}

/** 写入单个泄漏站点 JSON 数据（不含外层大括号） */
static void json_write_leak_site(FILE *fp, mtt_leak_site_t *site,
                                  mtt_stack_entry_t *se, int index)
{
    if (fp == NULL || site == NULL) return;

    fprintf(fp, "{\"hash\":\"0x%llx\",\"count\":%zu,\"per_leak_size\":%zu,"
            "\"total_size\":%zu,\"first_seen\":%ld,\"last_seen\":%ld",
            (unsigned long long)site->stack_hash, site->count,
            site->per_leak_size, site->total_size,
            (long)site->first_seen, (long)site->last_seen);

    /* 写入已解析的栈帧 */
    fprintf(fp, ",\"stack\":[");
    if (se != NULL && se->is_resolved) {
        int first = 1;
        for (int j = 0; j < se->frame_count; j++) {
            const char *sym = se->resolved[j];
            /* 过滤内部帧 */
            if (sym == NULL || sym[0] == '\0'
                || strstr(sym, "libmemorytracetool") != NULL
                || strstr(sym, "mtt_") == sym
                || strstr(sym, "capture_stack") != NULL
                || strstr(sym, "backtrace") != NULL)
                continue;
            if (!first) fputc(',', fp);
            first = 0;
            fputc('"', fp);
            json_escape(fp, sym);
            fputc('"', fp);
        }
    }
    fprintf(fp, "]}");
}

/* ======================================================================== *
 *                        HTTP 请求处理器                                     *
 * ======================================================================== */

/** reporter 外部单例引用（定义在 reporter.c） */
extern void* g_reporter_mtt_reporter_t;

/**
 * 处理 GET / — 返回仪表盘 HTML。
 */
static void handle_root(int client_fd)
{
    const char *header =
        "HTTP/1.0 200 OK\r\n"
        "Content-Type: text/html; charset=utf-8\r\n"
        "Cache-Control: no-cache\r\n"
        "Connection: close\r\n"
        "\r\n";

    if (write(client_fd, header, strlen(header)) < 0) return;
    write(client_fd, g_dashboard_html, strlen(g_dashboard_html));
}

/**
 * 处理 GET /api/data — 返回综合 JSON 数据。
 *
 * 包含：进程信息、统计摘要、时序数据（最近 360 点）、top 泄漏站点（最多 50 条）。
 * 从 reporter 缓存中读取，持 cache_lock 保护。
 */
static void handle_api_data(int client_fd)
{
    mtt_reporter_t *rep = mtt_reporter_get();

    /* 读取 reporter 缓存（持缓存锁） */
    pthread_mutex_lock(&rep->cache_lock);

    /* 读取统计值 */
    mtt_state_t *s = mtt_state_get();
    size_t cur_bytes  = (s != NULL) ? atomic_load_explicit(&s->current_bytes, memory_order_relaxed) : 0;
    size_t peak_bytes = (s != NULL) ? atomic_load_explicit(&s->peak_bytes, memory_order_relaxed) : 0;
    size_t allocs     = (s != NULL) ? atomic_load_explicit(&s->alloc_count, memory_order_relaxed) : 0;
    size_t frees      = (s != NULL) ? atomic_load_explicit(&s->free_count, memory_order_relaxed) : 0;
    size_t total_alloc = (s != NULL) ? atomic_load_explicit(&s->total_bytes, memory_order_relaxed) : 0;
    size_t leak_count = (allocs > frees) ? (allocs - frees) : 0;

    const char *proc_name = "unknown";
    if (s != NULL && s->proc_name_ready && s->proc_name[0] != '\0')
        proc_name = s->proc_name;

    /* 写入 HTTP 响应 header */
    const char *header =
        "HTTP/1.0 200 OK\r\n"
        "Content-Type: application/json; charset=utf-8\r\n"
        "Cache-Control: no-cache\r\n"
        "Connection: close\r\n"
        "\r\n";
    write(client_fd, header, strlen(header));

    char buf[8192] = {0};
    int len;

    len = snprintf(buf, sizeof(buf),
        "{\"pid\":%d,\"proc_name\":\"%s\",\"session_start\":%ld,\"last_scan\":%ld,"
        "\"stats\":{\"current_bytes\":%zu,\"peak_bytes\":%zu,\"alloc_count\":%zu,"
        "\"free_count\":%zu,\"leak_count\":%zu,\"total_allocated\":%zu}",
        (int)getpid(), proc_name,
        (long)rep->session_start,
        (long)time(NULL),
        cur_bytes, peak_bytes, allocs, frees, leak_count, total_alloc);
    write(client_fd, buf, (size_t)len);

    /* 时序数据（最近最多 360 点） */
    write(client_fd, ",\"time_series\":[", 18);
    if (rep->cached_ts_data != NULL && rep->cached_ts_count > 0) {
        int wrote_first = 0;
        for (uint32_t i = 0; i < rep->cached_ts_count; i++) {
            mtt_ts_point_t *pt = &rep->cached_ts_data[i];
            if (pt->timestamp == 0) continue;
            if (wrote_first) write(client_fd, ",", 1);
            wrote_first = 1;
            len = snprintf(buf, sizeof(buf),
                "{\"ts\":%ld,\"cur\":%zu,\"peak\":%zu,\"allocs\":%zu,\"frees\":%zu,\"entries\":%zu}",
                (long)pt->timestamp, pt->current_bytes, pt->peak_bytes,
                pt->alloc_count, pt->free_count, pt->entry_count);
            write(client_fd, buf, (size_t)len);
        }
    }
    write(client_fd, "]", 1);

    /* 泄漏站点（最多 50 条） */
    write(client_fd, ",\"leaks\":[", 10);
    if (rep->cached_sites != NULL && rep->cached_site_count > 0) {
        size_t show_count = rep->cached_site_count;
        if (show_count > 50) show_count = 50;
        for (size_t i = 0; i < show_count; i++) {
            if (i > 0) write(client_fd, ",", 1);
            mtt_stack_entry_t *se = NULL;
            if (rep->cached_pairs != NULL) {
                void **pp = rep->cached_pairs;
                for (size_t j = 0; j < rep->cached_site_count; j++) {
                    if (pp[j] == NULL) continue;
                    mtt_leak_site_t *ps = *(mtt_leak_site_t**)pp[j];
                    if (ps == rep->cached_sites[i]) {
                        se = *((mtt_stack_entry_t**)((char*)pp[j] + sizeof(void*)));
                        break;
                    }
                }
            }
            json_write_leak_site_stdout(rep->cached_sites[i], se, client_fd);
        }
    }
    write(client_fd, "]}", 2);

    pthread_mutex_unlock(&rep->cache_lock);
}

/** 写入单个泄漏站点 JSON 到 client fd */
static void json_write_leak_site_stdout(mtt_leak_site_t *site,
                                         mtt_stack_entry_t *se, int fd)
{
    char buf[4096] = {0};
    int off = snprintf(buf, sizeof(buf),
        "{\"hash\":\"0x%llx\",\"count\":%zu,\"per_leak_size\":%zu,"
        "\"total_size\":%zu,\"first_seen\":%ld,\"last_seen\":%ld,\"stack\":[",
        (unsigned long long)site->stack_hash, site->count,
        site->per_leak_size, site->total_size,
        (long)site->first_seen, (long)site->last_seen);
    write(fd, buf, (size_t)off);

    if (se != NULL && se->is_resolved) {
        int first = 1;
        for (int j = 0; j < se->frame_count; j++) {
            const char *sym = se->resolved[j];
            if (sym == NULL || sym[0] == '\0'
                || strstr(sym, "libmemorytracetool") != NULL
                || strstr(sym, "mtt_") == sym
                || strstr(sym, "capture_stack") != NULL
                || strstr(sym, "backtrace") != NULL)
                continue;
            off = snprintf(buf, sizeof(buf), "%s\"", first ? "" : ",");
            write(fd, buf, (size_t)off);
            /* escape the symbol */
            write(fd, "\"", 1);
            for (const char *p = sym; *p != '\0'; p++) {
                if (*p == '"' || *p == '\\') write(fd, "\\", 1);
                write(fd, p, 1);
            }
            write(fd, "\"", 1);
            first = 0;
        }
    }
    write(fd, "]}", 2);
}

/**
 * 处理 GET /api/leaks — 返回完整泄漏站点列表。
 */
static void handle_api_leaks(int client_fd)
{
    mtt_reporter_t *rep = mtt_reporter_get();

    const char *header =
        "HTTP/1.0 200 OK\r\n"
        "Content-Type: application/json; charset=utf-8\r\n"
        "Cache-Control: no-cache\r\n"
        "Connection: close\r\n"
        "\r\n";
    write(client_fd, header, strlen(header));
    write(client_fd, "{\"leaks\":[", 10);

    pthread_mutex_lock(&rep->cache_lock);

    if (rep->cached_sites != NULL && rep->cached_site_count > 0) {
        for (size_t i = 0; i < rep->cached_site_count; i++) {
            if (i > 0) write(client_fd, ",", 1);
            mtt_stack_entry_t *se = NULL;
            if (rep->cached_pairs != NULL) {
                void **pp = rep->cached_pairs;
                for (size_t j = 0; j < rep->cached_site_count; j++) {
                    if (pp[j] == NULL) continue;
                    mtt_leak_site_t *ps = *(mtt_leak_site_t**)pp[j];
                    if (ps == rep->cached_sites[i]) {
                        se = *((mtt_stack_entry_t**)((char*)pp[j] + sizeof(void*)));
                        break;
                    }
                }
            }
            json_write_leak_site_stdout(rep->cached_sites[i], se, client_fd);
        }
    }

    pthread_mutex_unlock(&rep->cache_lock);
    write(client_fd, "]}", 2);
}

/**
 * 发送 404 响应。
 */
static void handle_404(int client_fd)
{
    const char *body = "{\"error\":\"not found\"}";
    char header[256] = {0};
    snprintf(header, sizeof(header),
        "HTTP/1.0 404 Not Found\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: %zu\r\n"
        "Connection: close\r\n"
        "\r\n", strlen(body));
    write(client_fd, header, strlen(header));
    write(client_fd, body, strlen(body));
}

/* ======================================================================== *
 *                        HTTP 工作线程                                        *
 * ======================================================================== */

/**
 * 简易 HTTP 请求解析：提取请求行中的路径。
 *
 * 只处理 "GET /path HTTP/1.x" 格式，其他返回 0。
 *
 * @param req     请求首行（null-terminated）
 * @param path    输出路径缓冲区
 * @param maxlen  路径缓冲区大小
 * @return        1=GET 请求, 0=非 GET
 */
static int parse_request(const char *req, char *path, size_t maxlen)
{
    if (req == NULL || path == NULL || maxlen == 0) return 0;
    if (strncmp(req, "GET ", 4) != 0) return 0;

    const char *start = req + 4;
    const char *end = strchr(start, ' ');
    if (end == NULL) return 0;

    size_t len = (size_t)(end - start);
    if (len >= maxlen) len = maxlen - 1;
    memcpy(path, start, len);
    path[len] = '\0';
    return 1;
}

/**
 * HTTP 服务器工作线程主函数。
 *
 * 使用 select + accept 处理并发连接（超时 1 秒），
 * 检测 running 标志以响应停止请求。
 * 非阻塞式设计：select 超时期间检查 running 标志。
 */
static void* http_thread_fn(void *arg)
{
    (void)arg;
    pthread_detach(pthread_self());

    /* HTTP 线程中的 raw_malloc 调用不受 g_in_hook 保护，
     * 但本模块中所有分配都使用标准 malloc（因为此线程不是 hook 路径）。
     * 注意：不要在此线程中调用 hook 版本的 malloc。 */

    char req_buf[MTT_HTTP_BUF_SIZE] = {0};
    char path[MTT_HTTP_MAX_PATH] = {0};

    while (atomic_load_explicit(&g_http_server.running, memory_order_acquire)) {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(g_http_server.listen_fd, &rfds);

        struct timeval tv = {1, 0}; /* 1 秒超时 */
        int ready = select(g_http_server.listen_fd + 1, &rfds, NULL, NULL, &tv);

        if (ready < 0) {
            if (errno == EINTR) continue;
            break; /* 严重错误，退出 */
        }
        if (ready == 0) continue; /* 超时，回到 running 检查 */

        if (!FD_ISSET(g_http_server.listen_fd, &rfds)) continue;

        /* accept 新连接 */
        struct sockaddr_in client_addr;
        socklen_t addr_len = sizeof(client_addr);
        int client_fd = accept(g_http_server.listen_fd,
                               (struct sockaddr*)&client_addr, &addr_len);
        if (client_fd < 0) {
            if (errno == EINTR || errno == EAGAIN) continue;
            break;
        }

        /* 读取请求首行（简单实现：只读首行，忽略 Header） */
        memset(req_buf, 0, sizeof(req_buf));
        ssize_t n = recv(client_fd, req_buf, sizeof(req_buf) - 1, 0);
        if (n <= 0) { close(client_fd); continue; }
        req_buf[n] = '\0';

        /* 提取首行 */
        char *crlf = strstr(req_buf, "\r\n");
        if (crlf != NULL) *crlf = '\0';

        /* 解析路径并路由 */
        memset(path, 0, sizeof(path));
        if (!parse_request(req_buf, path, sizeof(path))) {
            handle_404(client_fd);
            close(client_fd);
            continue;
        }

        if (strcmp(path, "/") == 0 || strcmp(path, "/index.html") == 0) {
            handle_root(client_fd);
        } else if (strcmp(path, "/api/data") == 0) {
            handle_api_data(client_fd);
        } else if (strcmp(path, "/api/leaks") == 0) {
            handle_api_leaks(client_fd);
        } else {
            handle_404(client_fd);
        }

        close(client_fd);
    }

    return NULL;
}

/* ======================================================================== *
 *                     公共接口                                              *
 * ======================================================================== */

/**
 * 启动 HTTP 服务器。
 *
 * 创建 socket → bind → listen → 启动后台线程处理请求。
 * bind 失败时尝试后续 5 个端口，全部失败则静默降级（不启动）。
 * 使用 SO_REUSEADDR 允许快速重启。
 *
 * @param port  期望监听端口（0=不启动）
 */
void mtt_http_server_start(uint16_t port)
{
    if (port == 0) return;

    /* 防止重复启动 */
    if (atomic_load_explicit(&g_http_server.running, memory_order_acquire))
        return;

    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) return;

    /* SO_REUSEADDR 允许快速重启（跳过 TIME_WAIT） */
    int reuse = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    /* 尝试绑定期望端口 + 后续 5 个端口 */
    int bound = 0;
    for (int try_port = port; try_port < (int)port + 6; try_port++) {
        addr.sin_port = htons((uint16_t)try_port);
        if (bind(listen_fd, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
            bound = 1;
            port = (uint16_t)try_port;
            break;
        }
    }
    if (!bound) {
        close(listen_fd);
        return;
    }

    if (listen(listen_fd, MTT_HTTP_BACKLOG) < 0) {
        close(listen_fd);
        return;
    }

    g_http_server.listen_fd = listen_fd;
    g_http_server.port = port;
    atomic_store_explicit(&g_http_server.running, 1, memory_order_release);

    pthread_t tid;
    if (pthread_create(&tid, NULL, http_thread_fn, NULL) != 0) {
        atomic_store_explicit(&g_http_server.running, 0, memory_order_release);
        close(listen_fd);
        return;
    }
    g_http_server.thread = tid;

    /* 输出实际监听端口（使用 write 避免 malloc） */
    char diag[128] = {0};
    int len = snprintf(diag, sizeof(diag),
        "[MTT] HTTP dashboard: http://0.0.0.0:%u/\n", (unsigned)port);
    if (len > 0 && len < (int)sizeof(diag))
        write(STDERR_FILENO, diag, (size_t)len);
}

/**
 * 停止 HTTP 服务器。
 *
 * 关闭 listen_fd，设置 running=0，线程在下次 select 超时后自行退出。
 */
void mtt_http_server_stop(void)
{
    atomic_store_explicit(&g_http_server.running, 0, memory_order_release);
    if (g_http_server.listen_fd > 0) {
        close(g_http_server.listen_fd);
        g_http_server.listen_fd = -1;
    }
}

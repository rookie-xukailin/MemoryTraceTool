/*
 * MemoryTraceTool — 嵌入式 HTTP 服务器模块实现。
 *
 * 轻量级 HTTP/1.0 服务器，运行在 detach 后台线程中，
 * 为 Web 仪表盘提供静态 HTML 和 JSON API。
 *
 * 零外部依赖：
 *   - HTTP 解析手写（仅支持 GET /path HTTP/1.0）
 *   - JSON 时间序列使用紧凑数组格式 [t,c,p,a,f,e] 代替冗长的键值对象
 *     （借鉴 heaptrack LineWriter 紧凑编码设计，减少约 50% 载荷大小）
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
"/* 手动主题切换（通过 toggleTheme() 按钮） */\n"
"[data-theme=\"dark\"] {\n"
"  --bg: #0d1117; --bg2: #161b22; --text: #c9d1d9; --border: #30363d;\n"
"  --accent: #58a6ff; --orange: #f0b755; --green: #3fb950;\n"
"  --warn: #f85149; --card: #161b22;\n"
"}\n"
"[data-theme=\"light\"] {\n"
"  --bg: #ffffff; --bg2: #f6f8fa; --text: #24292f; --border: #d0d7de;\n"
"  --accent: #0969da; --orange: #d97706; --green: #16a34a;\n"
"  --warn: #dc2626; --card: #ffffff;\n"
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
".toggles { display: flex; gap: 8px; float: right; }\n"
".toggle-btn { font-size: 0.75rem; padding: 3px 10px; border: 1px solid var(--border);\n"
"  border-radius: 4px; cursor: pointer; background: var(--bg2); color: var(--text); }\n"
".toggle-btn.active { background: var(--accent); color: #fff; border-color: var(--accent); }\n"
".filter-bar { display: flex; gap: 8px; margin-bottom: 12px; }\n"
".filter-btn { font-size: 0.78rem; padding: 4px 12px; border: 1px solid var(--border);\n"
"  border-radius: 4px; cursor: pointer; background: var(--bg2); color: var(--text); }\n"
".filter-btn.active { background: var(--accent); color: #fff; border-color: var(--accent); }\n"
".filter-btn.warn { border-color: var(--warn); color: var(--warn); }\n"
".filter-btn.warn.active { background: var(--warn); color: #fff; }\n"
".header-row { display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; }\n"
".chart-row { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }\n"
"@media (max-width: 800px) { .chart-row { grid-template-columns: 1fr; } }\n"
"</style>\n"
"</head>\n"
"<body>\n"
"<div class=\"container\">\n"
"<div class=\"header-row\">\n"
"  <div>\n"
"    <h1>MemoryTraceTool</h1>\n"
"    <div class=\"subtitle\" id=\"info\">加载中...</div>\n"
"  </div>\n"
"  <div class=\"toggles\">\n"
"    <button class=\"toggle-btn active\" id=\"refreshBtn\" onclick=\"toggleRefresh()\">自动刷新</button>\n"
"    <button class=\"toggle-btn\" id=\"themeBtn\" onclick=\"toggleTheme()\">暗色模式</button>\n"
"  </div>\n"
"</div>\n"
"<div class=\"card\">\n"
"  <h2>堆内存趋势 <span class=\"refresh\" id=\"refresh\">每 5 秒刷新</span></h2>\n"
"  <div class=\"stats\" id=\"stats\"></div>\n"
"  <div class=\"chart-row\">\n"
"    <canvas id=\"chart\" width=\"800\" height=\"400\" style=\"width:100%\"></canvas>\n"
"    <canvas id=\"histogram\" width=\"400\" height=\"400\" style=\"width:100%\"></canvas>\n"
"  </div>\n"
"  <div class=\"tooltip\" id=\"tip\"></div>\n"
"</div>\n"
"<div class=\"card\">\n"
"  <h2>泄漏站点排行（按占用大小降序）</h2>\n"
"  <div class=\"filter-bar\">\n"
"    <button class=\"filter-btn active\" id=\"fAll\" onclick=\"filterLeaks('all')\">全部泄漏</button>\n"
"    <button class=\"filter-btn warn\" id=\"fProb\" onclick=\"filterLeaks('probable')\">probable leak</button>\n"
"    <button class=\"filter-btn\" id=\"fPoss\" onclick=\"filterLeaks('possible')\">possible leak</button>\n"
"    <span style=\"font-size:0.75rem;color:var(--accent);margin-left:auto;align-self:center\" id=\"filterCount\"></span>\n"
"  </div>\n"
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
"/* 紧凑数组格式索引：[timestamp, current, peak, allocs, frees, entries] */\n"
"var IDX_T=0, IDX_CUR=1, IDX_PEAK=2, IDX_ALLOCS=3, IDX_FREES=4, IDX_ENTRIES=5;\n"
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
"  if (!data || !data.time_series || !Array.isArray(data.time_series) || data.time_series.length === 0) return;\n"
"  var W = chartCanvas.width, H = chartCanvas.height;\n"
"  /* 单数据点时 x 坐标固定为图表中央，避免除以 (ts.length-1)=0 产生 NaN */\n"
"  var singlePoint = data.time_series.length === 1;\n"
"  ctx.clearRect(0, 0, W, H);\n"
"  var pad = {top: 30, right: 30, bottom: 50, left: 80};\n"
"  var pw = W - pad.left - pad.right;\n"
"  var ph = H - pad.top - pad.bottom;\n"
"  var ts = data.time_series;\n"
"\n"
"  /* 防御：归一化缺失字段（紧凑数组格式: [t,c,p,a,f,e]） */\n"
"  for (var i = 0; i < ts.length; i++) {\n"
"    if (!Array.isArray(ts[i])) continue;\n"
"    if (!ts[i][IDX_PEAK]) ts[i][IDX_PEAK] = 0;\n"
"    if (!ts[i][IDX_CUR]) ts[i][IDX_CUR] = 0;\n"
"    if (!ts[i][IDX_ALLOCS]) ts[i][IDX_ALLOCS] = 0;\n"
"    if (!ts[i][IDX_FREES]) ts[i][IDX_FREES] = 0;\n"
"  }\n"
"\n"
"  var maxBytes = 0;\n"
"  for (var i = 0; i < ts.length; i++) {\n"
"    if (!Array.isArray(ts[i])) continue;\n"
"    if (ts[i][IDX_PEAK] > maxBytes) maxBytes = ts[i][IDX_PEAK];\n"
"    if (ts[i][IDX_CUR] > maxBytes) maxBytes = ts[i][IDX_CUR];\n"
"  }\n"
"  if (maxBytes === 0) maxBytes = 1;\n"
"\n"
"  function x(i) { return singlePoint ? pad.left + pw / 2 : pad.left + (i / (ts.length - 1)) * pw; }\n"
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
"  for (var i = 0; i < ts.length; i++) { if (!Array.isArray(ts[i])) continue; ctx.lineTo(x(i), y(ts[i][IDX_CUR])); }\n"
"  ctx.lineTo(x(ts.length - 1), pad.top + ph);\n"
"  ctx.closePath();\n"
"  ctx.fillStyle = 'rgba(9, 105, 218, 0.15)';\n"
"  ctx.fill();\n"
"\n"
"  /* cur line */\n"
"  ctx.beginPath();\n"
"  for (var i = 0; i < ts.length; i++) {\n"
"    if (!Array.isArray(ts[i])) continue;\n"
"    if (i === 0) ctx.moveTo(x(i), y(ts[i][IDX_CUR]));\n"
"    else ctx.lineTo(x(i), y(ts[i][IDX_CUR]));\n"
"  }\n"
"  ctx.strokeStyle = '#0969da'; ctx.lineWidth = 2;\n"
"  ctx.stroke();\n"
"\n"
"  /* peak line (dashed) */\n"
"  ctx.beginPath();\n"
"  ctx.setLineDash([4, 4]);\n"
"  for (var i = 0; i < ts.length; i++) {\n"
"    if (!Array.isArray(ts[i])) continue;\n"
"    if (i === 0) ctx.moveTo(x(i), y(ts[i][IDX_PEAK]));\n"
"    else ctx.lineTo(x(i), y(ts[i][IDX_PEAK]));\n"
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
"    var item = ts[idx];\n"
"    ctx.fillText(formatTime(Array.isArray(item) ? item[IDX_T] : item.ts), xx, H - pad.bottom + 20);\n"
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
"        var pt = ts[i];\n"
"        tip.style.display = 'block';\n"
"        tip.style.left = (e.clientX + 15) + 'px';\n"
"        tip.style.top = (e.clientY - 30) + 'px';\n"
"        var t = Array.isArray(pt) ? pt[IDX_T] : pt.ts;\n"
"        var c = Array.isArray(pt) ? pt[IDX_CUR] : pt.cur;\n"
"        var p = Array.isArray(pt) ? pt[IDX_PEAK] : pt.peak;\n"
"        var a = Array.isArray(pt) ? pt[IDX_ALLOCS] : pt.allocs;\n"
"        var f = Array.isArray(pt) ? pt[IDX_FREES] : pt.frees;\n"
"        tip.textContent = formatTime(t) + ' | cur: ' + formatBytes(c)\n"
"          + ' | peak: ' + formatBytes(p) + ' | allocs: ' + a + ' | frees: ' + f;\n"
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
"function addr2lineCmd(frame) {\n"
"  var m1 = frame.match(/\\((.+)\\)$/);\n"
"  var m2 = frame.match(/\\+(0x[0-9a-fA-F]+)/);\n"
"  if (m1 && m2) return 'addr2line -e ' + m1[1] + ' -f -C ' + m2[1];\n"
"  return '';\n"
"}\n"
"\n"
"var leakFilter = 'all';\n"
"var autoRefresh = true;\n"
"var refreshTimer = null;\n"
"\n"
"function toggleTheme() {\n"
"  var html = document.documentElement;\n"
"  if (html.hasAttribute('data-theme') && html.getAttribute('data-theme') === 'dark') {\n"
"    html.removeAttribute('data-theme');\n"
"    document.getElementById('themeBtn').textContent = '暗色模式';\n"
"  } else {\n"
"    html.setAttribute('data-theme', 'dark');\n"
"    document.getElementById('themeBtn').textContent = '亮色模式';\n"
"  }\n"
"}\n"
"\n"
"function toggleRefresh() {\n"
"  autoRefresh = !autoRefresh;\n"
"  var btn = document.getElementById('refreshBtn');\n"
"  if (autoRefresh) {\n"
"    btn.classList.add('active');\n"
"    btn.textContent = '自动刷新';\n"
"    refreshTimer = setInterval(refresh, 5000);\n"
"    refresh();\n"
"  } else {\n"
"    btn.classList.remove('active');\n"
"    btn.textContent = '手动刷新';\n"
"    if (refreshTimer) { clearInterval(refreshTimer); refreshTimer = null; }\n"
"  }\n"
"}\n"
"\n"
"function filterLeaks(mode) {\n"
"  leakFilter = mode;\n"
"  document.getElementById('fAll').classList.toggle('active', mode === 'all');\n"
"  document.getElementById('fProb').classList.toggle('active', mode === 'probable');\n"
"  document.getElementById('fPoss').classList.toggle('active', mode === 'possible');\n"
"  renderLeaks(data ? data.leaks : []);\n"
"}\n"
"\n"
"function drawHistogram() {\n"
"  var leaks = data && data.leaks ? data.leaks : [];\n"
"  var hCanvas = document.getElementById('histogram');\n"
"  if (!hCanvas) return;\n"
"  var hctx = hCanvas.getContext('2d');\n"
"  var W = hCanvas.width, H = hCanvas.height;\n"
"  hctx.clearRect(0, 0, W, H);\n"
"  if (leaks.length === 0) {\n"
"    hctx.fillStyle = getComputedStyle(document.documentElement).getPropertyValue('--text').trim();\n"
"    hctx.font = '14px sans-serif'; hctx.textAlign = 'center';\n"
"    hctx.fillText('暂无分配数据', W/2, H/2);\n"
"    return;\n"
"  }\n"
"  /* 按 per_leak_size 分桶（借鉴 heaptrack_gui HistogramWidget） */\n"
"  var buckets = [\n"
"    {label:'<1 KB', min:0, max:1024, count:0, bytes:0},\n"
"    {label:'1-4 KB', min:1024, max:4096, count:0, bytes:0},\n"
"    {label:'4-16 KB', min:4096, max:16384, count:0, bytes:0},\n"
"    {label:'16-64 KB', min:16384, max:65536, count:0, bytes:0},\n"
"    {label:'64-256 KB', min:65536, max:262144, count:0, bytes:0},\n"
"    {label:'256 KB-1 MB', min:262144, max:1048576, count:0, bytes:0},\n"
"    {label:'>1 MB', min:1048576, max:Infinity, count:0, bytes:0}\n"
"  ];\n"
"  for (var i = 0; i < leaks.length; i++) {\n"
"    var sz = leaks[i].per_leak_size || 0;\n"
"    for (var j = 0; j < buckets.length; j++) {\n"
"      if (sz >= buckets[j].min && sz < buckets[j].max) {\n"
"        buckets[j].count++;\n"
"        buckets[j].bytes += (leaks[i].total_size || 0);\n"
"        break;\n"
"      }\n"
"    }\n"
"  }\n"
"  var maxCount = 1;\n"
"  for (var j = 0; j < buckets.length; j++) {\n"
"    if (buckets[j].count > maxCount) maxCount = buckets[j].count;\n"
"  }\n"
"  var bw = (W - 120) / buckets.length;\n"
"  var barMaxH = H - 80;\n"
"  /* title */\n"
"  hctx.fillStyle = getComputedStyle(document.documentElement).getPropertyValue('--text').trim();\n"
"  hctx.font = 'bold 11px sans-serif'; hctx.textAlign = 'center';\n"
"  hctx.fillText('泄漏站点数 (按单次分配大小)', W/2, 16);\n"
"  /* bars */\n"
"  for (var j = 0; j < buckets.length; j++) {\n"
"    var barH = (buckets[j].count / maxCount) * barMaxH;\n"
"    var x = 60 + j * bw;\n"
"    var y = H - 50 - barH;\n"
"    /* gradient bar */\n"
"    var grad = hctx.createLinearGradient(x, y, x, H - 50);\n"
"    grad.addColorStop(0, '#0969da');\n"
"    grad.addColorStop(1, 'rgba(9,105,218,0.3)');\n"
"    hctx.fillStyle = grad;\n"
"    hctx.fillRect(x + 4, y, bw - 8, barH);\n"
"    /* count label */\n"
"    hctx.fillStyle = getComputedStyle(document.documentElement).getPropertyValue('--text').trim();\n"
"    hctx.font = '10px sans-serif'; hctx.textAlign = 'center';\n"
"    var countLabel = buckets[j].count > 0 ? buckets[j].count + '个站点' : '';\n"
"    if (buckets[j].count > 0) hctx.fillText(countLabel, x + bw/2, y - 4);\n"
"    /* bucket label */\n"
"    hctx.save();\n"
"    hctx.translate(x + bw/2, H - 32);\n"
"    hctx.font = '9px sans-serif';\n"
"    hctx.fillText(buckets[j].label, 0, 0);\n"
"    hctx.restore();\n"
"  }\n"
"  /* y axis */\n"
"  hctx.strokeStyle = getComputedStyle(document.documentElement).getPropertyValue('--border').trim();\n"
"  hctx.lineWidth = 0.5;\n"
"  hctx.beginPath();\n"
"  hctx.moveTo(56, 20);\n"
"  hctx.lineTo(56, H - 50);\n"
"  hctx.stroke();\n"
"}\n"
"\n"
"function renderLeaks(leaks) {\n"
"  var tbody = document.getElementById('leaks-tbody');\n"
"  /* 按 is_expired 过滤（借鉴 heaptrack 存活时间判定） */\n"
"  var filtered = leaks;\n"
"  if (leakFilter === 'probable') {\n"
"    filtered = leaks.filter(function(l) { return l.is_expired === 1; });\n"
"  } else if (leakFilter === 'possible') {\n"
"    filtered = leaks.filter(function(l) { return l.is_expired === 0; });\n"
"  }\n"
"  var fcEl = document.getElementById('filterCount');\n"
"  if (fcEl) fcEl.textContent = filtered.length + ' / ' + leaks.length + ' 条';\n"
"  if (!filtered || filtered.length === 0) {\n"
"    tbody.innerHTML = '<tr><td colspan=\"6\" style=\"text-align:center;color:#6e7681\">暂无匹配的泄漏数据</td></tr>';\n"
"    return;\n"
"  }\n"
"  var rows = '';\n"
"  for (var i = 0; i < filtered.length; i++) {\n"
"    var l = filtered[i];\n"
"    /* 置信度标签（借鉴 heaptrack 的 probable vs possible leak 概念） */\n"
"    var conf = '';\n"
"    if (l.is_expired) conf = ' <span style=\"color:var(--warn);font-size:0.7rem\">[probable]</span>';\n"
"    else conf = ' <span style=\"color:var(--orange);font-size:0.7rem\">[possible]</span>';\n"
"    var diff = '';\n"
"    if (l.diff_size && l.diff_size > 0) diff = ' class=\"diff-high\"';\n"
"    if (l.stack && l.stack.length > 0) {\n"
"      var stk = '<tr class=\"stack-row\" id=\"s'+i+'\"><td colspan=\"6\" class=\"stack-cell\">';\n"
"      for (var j = 0; j < l.stack.length; j++) {\n"
"        var cmd = addr2lineCmd(l.stack[j]);\n"
"        stk += '<div>' + (j===0?'<b>&rarr; ':'  ') + l.stack[j];\n"
"        if (cmd) stk += ' <code style=\"font-size:0.7rem;color:var(--accent)\">' + cmd + '</code>';\n"
"        stk += '</div>';\n"
"      }\n"
"      stk += '</td></tr>';\n"
"      rows += '<tr class=\"leak-row\"'+diff+' onclick=\"var s=document.getElementById(\\'s'+i+'\\');s.classList.toggle(\\'open\\')\">'\n"
"        + '<td>'+(i+1)+'</td><td>'+l.count.toLocaleString()+'</td>'\n"
"        + '<td>'+formatBytes(l.per_leak_size)+'</td><td><b>'+formatBytes(l.total_size)+'</b> '+conf+'</td>'\n"
"        + '<td>'+formatTime(l.first_seen)+'</td><td>'+formatTime(l.last_seen)+'</td></tr>'+stk;\n"
"    } else {\n"
"      rows += '<tr class=\"leak-row\"'+diff+'>'\n"
"        + '<td>'+(i+1)+'</td><td>'+l.count.toLocaleString()+'</td>'\n"
"        + '<td>'+formatBytes(l.per_leak_size)+'</td><td><b>'+formatBytes(l.total_size)+'</b> '+conf+'</td>'\n"
"        + '<td>'+formatTime(l.first_seen)+'</td><td>'+formatTime(l.last_seen)+'</td></tr>';\n"
"    }\n"
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
"    drawHistogram();\n"
"    renderLeaks(d.leaks || []);\n"
"    document.getElementById('refresh').textContent = '已刷新 — ' + new Date().toLocaleTimeString();\n"
"  }).catch(function(err) {\n"
"    console.error('fetch /api/data failed:', err);\n"
"    document.getElementById('refresh').textContent = '刷新失败，稍后重试';\n"
"  });\n"
"}\n"
"refresh();\n"
"refreshTimer = setInterval(refresh, 5000);\n"
"</script>\n"
"</body>\n"
"</html>\n";

/* ======================================================================== *
 *                       JSON 序列化辅助函数                                  *
 * ======================================================================== */

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

/* 前向声明：写入单个泄漏站点 JSON 到 client fd */
static void json_write_leak_site_stdout(mtt_leak_site_t *site,
                                         mtt_stack_entry_t *se, int fd);

/**
 * 处理 GET /api/data — 返回综合 JSON 数据。
 *
 * 包含：进程信息、统计摘要、时序数据（最近 360 点）、top 泄漏站点（最多 50 条）。
 * 从 reporter 缓存中读取，持 cache_lock 保护。
 */
static void handle_api_data(int client_fd)
{
    mtt_reporter_t *rep = mtt_reporter_get();

    /* Phase 1: 从时序数据环形缓冲区读取数据（使用 g_time_series.lock，
     * 必须在 cache_lock 之前完成，避免 cache_lock -> g_time_series.lock 的
     * ABBA 死锁：reporter 线程在 scan_and_report_locked Stage 0 中以
     * g_time_series.lock -> cache_lock 顺序加锁，若 HTTP 线程以相反顺序
     * 加锁会导致经典循环等待死锁。 */
    mtt_ts_point_t *fallback_pts = NULL;
    uint32_t       fallback_count = 0;
    const mtt_ts_point_t *src_pts = NULL;
    uint32_t       src_count = 0;

    if (mtt_ts_is_ready()) {
        fallback_pts = (mtt_ts_point_t*)raw_malloc(
            360 * sizeof(mtt_ts_point_t));
        if (fallback_pts != NULL) {
            memset(fallback_pts, 0, 360 * sizeof(mtt_ts_point_t));
            if (mtt_ts_get_range(0, fallback_pts, 360, &fallback_count) == 0
                && fallback_count > 0) {
                src_pts   = fallback_pts;
                src_count = fallback_count;
            }
        }
    }

    /* Phase 2: 读取 reporter 缓存（持缓存锁）。
     * 注意：cache_lock 在此处获取，时序数据已在 Phase 1 中完成读取，
     * 不会在持锁期间再次尝试获取 g_time_series.lock。 */
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

    static char buf[8192]; /* 静态分配：避免 ARM 嵌入式栈溢出（默认栈 8KB） */
    int len;

    len = snprintf(buf, sizeof(buf),
        "{\"pid\":%d,\"proc_name\":\"%s\",\"session_start\":%lld,\"last_scan\":%lld,"
        "\"stats\":{\"current_bytes\":%zu,\"peak_bytes\":%zu,\"alloc_count\":%zu,"
        "\"free_count\":%zu,\"leak_count\":%zu,\"total_allocated\":%zu}",
        (int)getpid(), proc_name,
        (long long)rep->session_start,
        (long long)time(NULL),
        cur_bytes, peak_bytes, allocs, frees, leak_count, total_alloc);
    write(client_fd, buf, (size_t)len);

    /* 时序数据 — 数据已在 Phase 1（cache_lock 前）从环形缓冲区读取完成，
     * 此处仅序列化 src_pts/src_count 中的数据点到 JSON 输出。
     * 优先使用环缓冲实时数据（cached 只在 60s 扫描时更新，太慢）。
     * 注意：不再在 cache_lock 内调用 mtt_ts_get_range（避免 ABBA 死锁）。 */
    write(client_fd, ",\"time_series\":[", 16);
    {
        if (src_pts != NULL && src_count > 0) {
            int wrote_first = 0;
            for (uint32_t i = 0; i < src_count; i++) {
                if (src_pts[i].timestamp == 0) continue;
                if (wrote_first) write(client_fd, ",", 1);
                wrote_first = 1;
                /* 紧凑数组格式 [timestamp, current, peak, allocs, frees, entries]
                 * 借鉴 heaptrack LineWriter 紧凑编码设计：
                 *   索引 0=t, 1=cur, 2=peak, 3=allocs, 4=frees, 5=entries
                 * 相比键值对象格式节省约 40-50% JSON 大小 */
                len = snprintf(buf, sizeof(buf),
                    "[%lld,%zu,%zu,%zu,%zu,%zu]",
                    (long long)src_pts[i].timestamp,
                    src_pts[i].current_bytes, src_pts[i].peak_bytes,
                    src_pts[i].alloc_count, src_pts[i].free_count,
                    src_pts[i].entry_count);
                write(client_fd, buf, (size_t)len);
            }
        }
    }
    write(client_fd, "]", 1);

    /* 泄漏站点（最多 50 条） */
    write(client_fd, ",\"leaks\":[", 10);
    if (rep->cached_sites != NULL && rep->cached_site_count > 0) {
        size_t show_count = rep->cached_site_count;
        if (show_count > 50) show_count = 50;
        int wrote_first = 0;
        for (size_t i = 0; i < show_count; i++) {
            /* 跳过分配失败的 NULL 条目（防御性编程） */
            if (rep->cached_sites[i] == NULL) continue;
            if (wrote_first) write(client_fd, ",", 1);
            wrote_first = 1;
            mtt_stack_entry_t *se = NULL;
            if (rep->cached_pairs != NULL) {
                site_stack_pair_t *pp = (site_stack_pair_t*)rep->cached_pairs;
                for (size_t j = 0; j < rep->cached_site_count; j++) {
                    if (pp[j].site == rep->cached_sites[i]) {
                        se = pp[j].stack_entry;
                        break;
                    }
                }
            }
            json_write_leak_site_stdout(rep->cached_sites[i], se, client_fd);
        }
    }
    write(client_fd, "]}", 2);

    pthread_mutex_unlock(&rep->cache_lock);

    /* Phase 3: 清理 Phase 1 中分配的回退缓冲区。
     * 必须在 cache_lock 释放后执行，避免持锁时间过长。 */
    if (fallback_pts != NULL && raw_free != NULL)
        raw_free(fallback_pts);
}

/** 写入单个泄漏站点 JSON 到 client fd */
static void json_write_leak_site_stdout(mtt_leak_site_t *site,
                                         mtt_stack_entry_t *se, int fd)
{
    if (site == NULL) return;

    static char buf[4096]; /* 静态分配：避免 ARM 栈溢出 */
    int off = snprintf(buf, sizeof(buf),
        "{\"hash\":\"0x%llx\",\"count\":%zu,\"per_leak_size\":%zu,"
        "\"total_size\":%zu,\"diff_size\":%zu,\"is_expired\":%d,"
        "\"first_seen\":%lld,\"last_seen\":%lld,\"stack\":[",
        (unsigned long long)site->stack_hash, site->count,
        site->per_leak_size, site->total_size,
        site->diff_size, site->is_expired,
        (long long)site->first_seen, (long long)site->last_seen);
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
            off = snprintf(buf, sizeof(buf), "%s", first ? "" : ",");
            write(fd, buf, (size_t)off);
            /* 写入 JSON 字符串引用 */
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
        int wrote_first = 0;
        for (size_t i = 0; i < rep->cached_site_count; i++) {
            if (rep->cached_sites[i] == NULL) continue;
            if (wrote_first) write(client_fd, ",", 1);
            wrote_first = 1;
            mtt_stack_entry_t *se = NULL;
            if (rep->cached_pairs != NULL) {
                site_stack_pair_t *pp = (site_stack_pair_t*)rep->cached_pairs;
                for (size_t j = 0; j < rep->cached_site_count; j++) {
                    if (pp[j].site == rep->cached_sites[i]) {
                        se = pp[j].stack_entry;
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

    static char req_buf[MTT_HTTP_BUF_SIZE]; /* 静态分配：避免 ARM 栈溢出 */
    static char path[MTT_HTTP_MAX_PATH];

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
        g_http_server.listen_fd = -1; /* 防止 mtt_http_server_stop() 重复 close */
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

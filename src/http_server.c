/*
 * MemoryTraceTool — 嵌入式 HTTP 服务器模块实现。
 *
 * 轻量级 HTTP/1.0 服务器，运行在 detach 后台线程中，
 * 为 Web 仪表盘提供静态 HTML 和 JSON API。
 *
 * 零外部依赖：纯 C 实现，HTTP 解析和 JSON 序列化全部手写。
 * HTML 仪表盘编译为 static const 字符串（存放在 .rodata 段）。
 */
#define _GNU_SOURCE
#include "http_server.h"
#include "reporter.h"
#include "stack_cache.h"
#include "time_series.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/** HTTP 服务器单例 */
static mtt_http_server_t g_http_server = {0};

/* ======================================================================== *
 *                    Web 仪表盘 HTML                                        *
 * ======================================================================== */

static const char g_dashboard_html[] =
"<!DOCTYPE html>\n"
"<html lang=\"zh\">\n"
"<head>\n"
"<meta charset=\"UTF-8\">\n"
"<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n"
"<meta http-equiv=\"Cache-Control\" content=\"no-cache\">\n"
"<title>MemoryTraceTool</title>\n"
"<style>\n"
":root{--bg:#fff;--bg2:#f6f8fa;--text:#24292f;--border:#d0d7de;--accent:#0969da;--orange:#d97706;--green:#16a34a;--warn:#dc2626}\n"
"@media(prefers-color-scheme:dark){:root{--bg:#0d1117;--bg2:#161b22;--text:#c9d1d9;--border:#30363d;--accent:#58a6ff;--orange:#f0b755;--green:#3fb950;--warn:#f85149}}\n"
"*{box-sizing:border-box;margin:0;padding:0}\n"
"body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;background:var(--bg);color:var(--text);line-height:1.5}\n"
".container{max-width:1200px;margin:0 auto;padding:20px}\n"
"h1{font-size:1.5rem;margin-bottom:4px}\n"
".subtitle{color:#6e7681;font-size:.85rem;margin-bottom:20px}\n"
".card{background:var(--bg);border:1px solid var(--border);border-radius:6px;padding:16px;margin-bottom:16px}\n"
".card h2{font-size:1.1rem;margin-bottom:12px;border-bottom:1px solid var(--border);padding-bottom:8px}\n"
".stats{display:flex;flex-wrap:wrap;gap:12px;margin-bottom:16px}\n"
".stat{background:var(--bg2);border-radius:6px;padding:10px 14px;min-width:130px}\n"
".stat .val{font-size:1.3rem;font-weight:600}\n"
".stat .lbl{font-size:.75rem;color:#6e7681}\n"
"canvas{width:100%;max-width:100%;display:block;border-radius:4px}\n"
"table{width:100%;border-collapse:collapse;font-size:.85rem}\n"
"th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--border)}\n"
"th{background:var(--bg2);position:sticky;top:0}\n"
"tr:hover{background:var(--bg2)}\n"
".stack-row{display:none;background:var(--bg2)}\n"
".stack-row.open{display:table-row}\n"
".stack-cell{padding:8px 10px 8px 30px;font-family:monospace;font-size:.78rem;white-space:pre-wrap;word-break:break-all}\n"
".stack-cell .cmd{font-size:.7rem;color:var(--accent);display:block;margin-top:2px}\n"
".leak-row{cursor:pointer}\n"
".diff-high{background:rgba(220,38,38,.08)}\n"
".tooltip{position:absolute;background:#1f2328;color:#fff;padding:4px 8px;border-radius:4px;font-size:.8rem;pointer-events:none;display:none;z-index:10}\n"
".refresh{font-size:.75rem;color:#6e7681;float:right}\n"
".toggle-btn{font-size:.75rem;padding:4px 10px;border:1px solid var(--border);border-radius:4px;background:var(--bg2);color:var(--text);cursor:pointer;margin-right:6px}\n"
".toggle-btn.active{background:var(--accent);color:#fff;border-color:var(--accent)}\n"
".stop-btn{font-size:.75rem;padding:4px 10px;border:1px solid var(--warn);border-radius:4px;background:var(--bg2);color:var(--warn);cursor:pointer}\n"
"</style>\n"
"</head>\n"
"<body>\n"
"<div class=\"container\">\n"
"<h1>MemoryTraceTool</h1>\n"
"<div class=\"subtitle\" id=\"info\">加载中...</div>\n"
"<div class=\"card\">\n"
"  <h2>堆内存趋势 <span class=\"refresh\" id=\"refreshLabel\">每 5 秒刷新</span></h2>\n"
"  <div class=\"stats\" id=\"stats\"></div>\n"
"  <canvas id=\"chart\" width=\"800\" height=\"400\"></canvas>\n"
"  <div class=\"tooltip\" id=\"tip\"></div>\n"
"</div>\n"
"<div class=\"card\">\n"
"  <h2>泄漏站点排行（按占用大小降序）</h2>\n"
"  <table>\n"
"    <thead><tr><th>#</th><th>次数</th><th>单次</th><th>总占用</th><th>置信度</th><th>首次</th><th>最后</th></tr></thead>\n"
"    <tbody id=\"leaks-tbody\"></tbody>\n"
"  </table>\n"
"</div>\n"
"</div>\n"
"<script>\n"
"var data=null,chartCanvas=document.getElementById('chart'),ctx=chartCanvas.getContext('2d'),tip=document.getElementById('tip');\n"
"function fb(b){if(b==null)return'0 B';if(b>=1048576)return(b/1048576).toFixed(2)+' MB';if(b>=1024)return(b/1024).toFixed(2)+' KB';return b+' B'}\n"
"function ft(t){if(!t||t<=0)return'N/A';return new Date(t*1000).toLocaleTimeString()}\n"
"function draw(){\n"
"  if(!data||!data.time_series||data.time_series.length===0)return;\n"
"  var ts=data.time_series,W=chartCanvas.width,H=chartCanvas.height;\n"
"  ctx.clearRect(0,0,W,H);\n"
"  var pad={top:30,right:30,bottom:50,left:70};\n"
"  var pw=W-pad.left-pad.right,ph=H-pad.top-pad.bottom;\n"
"  /* find max */\n"
"  var maxB=1;\n"
"  for(var i=0;i<ts.length;i++){var p=ts[i];if(p.peak>maxB)maxB=p.peak;if(p.cur>maxB)maxB=p.cur;}\n"
"  function x(i){return pad.left+(i/(ts.length-1))*pw}\n"
"  function y(v){return pad.top+ph-(v/maxB)*ph}\n"
"  /* grid */\n"
"  ctx.strokeStyle=getComputedStyle(document.documentElement).getPropertyValue('--border').trim();\n"
"  ctx.lineWidth=.5;\n"
"  for(var j=0;j<=4;j++){var val=(maxB/4)*j,yy=y(val);ctx.beginPath();ctx.moveTo(pad.left,yy);ctx.lineTo(W-pad.right,yy);ctx.stroke();ctx.fillStyle=getComputedStyle(document.documentElement).getPropertyValue('--text').trim();ctx.font='10px sans-serif';ctx.textAlign='right';ctx.fillText(fb(val),pad.left-6,yy+3)}\n"
"  /* area */\n"
"  ctx.beginPath();ctx.moveTo(x(0),pad.top+ph);\n"
"  for(var i=0;i<ts.length;i++)ctx.lineTo(x(i),y(ts[i].cur));\n"
"  ctx.lineTo(x(ts.length-1),pad.top+ph);ctx.closePath();\n"
"  ctx.fillStyle='rgba(9,105,218,.15)';ctx.fill();\n"
"  /* cur line */\n"
"  ctx.beginPath();\n"
"  for(var i=0;i<ts.length;i++){if(i===0)ctx.moveTo(x(i),y(ts[i].cur));else ctx.lineTo(x(i),y(ts[i].cur))}\n"
"  ctx.strokeStyle='#0969da';ctx.lineWidth=2;ctx.stroke();\n"
"  /* peak line */\n"
"  ctx.beginPath();ctx.setLineDash([4,4]);\n"
"  for(var i=0;i<ts.length;i++){if(i===0)ctx.moveTo(x(i),y(ts[i].peak));else ctx.lineTo(x(i),y(ts[i].peak))}\n"
"  ctx.strokeStyle='#d97706';ctx.lineWidth=1.5;ctx.stroke();ctx.setLineDash([]);\n"
"  /* legend */\n"
"  ctx.fillStyle='#0969da';ctx.fillRect(pad.left+10,10,12,12);\n"
"  ctx.fillStyle=getComputedStyle(document.documentElement).getPropertyValue('--text').trim();\n"
"  ctx.font='11px sans-serif';ctx.textAlign='left';\n"
"  ctx.fillText('current_bytes',pad.left+26,20);\n"
"  ctx.strokeStyle='#d97706';ctx.setLineDash([4,4]);\n"
"  ctx.beginPath();ctx.moveTo(pad.left+120,16);ctx.lineTo(pad.left+150,16);ctx.stroke();ctx.setLineDash([]);\n"
"  ctx.fillText('peak_bytes',pad.left+156,20);\n"
"  /* X labels */\n"
"  var steps=Math.min(10,ts.length);\n"
"  for(var i=0;i<=steps;i++){var idx=Math.floor((ts.length-1)*i/steps);if(idx>=ts.length)idx=ts.length-1;var xx=x(idx);ctx.fillStyle=getComputedStyle(document.documentElement).getPropertyValue('--text').trim();ctx.font='10px sans-serif';ctx.textAlign='center';ctx.fillText(ft(ts[idx].ts),xx,H-pad.bottom+20)}\n"
"  /* hover */\n"
"  chartCanvas.onmousemove=function(e){var r=chartCanvas.getBoundingClientRect();var sx=chartCanvas.width/r.width;var mx=(e.clientX-r.left)*sx;for(var i=0;i<ts.length;i++){if(Math.abs(mx-x(i))<5){var pt=ts[i];tip.style.display='block';tip.style.left=(e.clientX+15)+'px';tip.style.top=(e.clientY-30)+'px';tip.textContent=ft(pt.ts)+' | cur:'+fb(pt.cur)+' | peak:'+fb(pt.peak)+' | allocs:'+pt.allocs+' | frees:'+pt.frees;return}}tip.style.display='none'}\n"
"}\n"
"function renderStats(st){\n"
"  var s=st||{};\n"
"  document.getElementById('stats').innerHTML=\n"
"    '<div class=\"stat\"><div class=\"val\">'+fb(s.current_bytes||0)+'</div><div class=\"lbl\">当前未释放</div></div>'+\n"
"    '<div class=\"stat\"><div class=\"val\">'+fb(s.peak_bytes||0)+'</div><div class=\"lbl\">历史峰值</div></div>'+\n"
"    '<div class=\"stat\"><div class=\"val\">'+(s.alloc_count||0).toLocaleString()+'</div><div class=\"lbl\">累计分配</div></div>'+\n"
"    '<div class=\"stat\"><div class=\"val\">'+(s.free_count||0).toLocaleString()+'</div><div class=\"lbl\">累计释放</div></div>'+\n"
"    '<div class=\"stat\"><div class=\"val\">'+(s.leak_count||0).toLocaleString()+'</div><div class=\"lbl\">疑似泄漏</div></div>'+\n"
"    '<div class=\"stat\"><div class=\"val\">'+fb(s.total_allocated||0)+'</div><div class=\"lbl\">累计分配总量</div></div>';\n"
"}\n"
"function alCmd(frame){var m1=frame.match(/\\((.+)\\)$/);var m2=frame.match(/\\+(0x[0-9a-fA-F]+)/);if(m1&&m2)return'addr2line -e '+m1[1]+' -f -C '+m2[1];return''}\n"
"function renderLeaks(leaks){\n"
"  var tbody=document.getElementById('leaks-tbody');\n"
"  if(!leaks||leaks.length===0){tbody.innerHTML='<tr><td colspan=\"7\" style=\"text-align:center;color:#6e7681\">暂无泄漏数据</td></tr>';return}\n"
"  var rows='';\n"
"  for(var i=0;i<leaks.length;i++){\n"
"    var l=leaks[i],h=l.hash||'',conf=l.is_expired?'probable leak':'possible leak';\n"
"    var diff=l.diff_size>0?' class=\"diff-high\"':'';\n"
"    rows+='<tr class=\"leak-row\"'+diff+' onclick=\"var s=document.getElementById(\\'s'+i+'\\');s.classList.toggle(\\'open\\')\">'+\n"
"      '<td>'+(i+1)+'</td><td>'+l.count.toLocaleString()+'</td>'+\n"
"      '<td>'+fb(l.per_leak_size)+'</td><td><b>'+fb(l.total_size)+'</b></td>'+\n"
"      '<td>'+conf+'</td><td>'+ft(l.first_seen)+'</td><td>'+ft(l.last_seen)+'</td></tr>';\n"
"    if(l.stack&&l.stack.length>0){\n"
"      rows+='<tr class=\"stack-row\" id=\"s'+i+'\"><td colspan=\"7\" class=\"stack-cell\">';\n"
"      for(var j=0;j<l.stack.length;j++){\n"
"        var cmd=alCmd(l.stack[j]);\n"
"        rows+='<div>'+(j===0?'<b>&rarr; ':'  ')+l.stack[j]+'</div>';\n"
"        if(cmd)rows+='<div class=\"cmd\">'+cmd+'</div>';\n"
"      }\n"
"      rows+='</td></tr>';\n"
"    }\n"
"  }\n"
"  tbody.innerHTML=rows;\n"
"}\n"
"function refresh(){\n"
"  document.getElementById('refreshLabel').textContent='刷新中...';\n"
"  fetch('/api/data').then(function(r){return r.json()}).then(function(d){\n"
"    data=d;\n"
"    document.getElementById('info').textContent='PID: '+d.pid+' | '+d.proc_name+' | 会话: '+ft(d.session_start)+' | 上次扫描: '+ft(d.last_scan);\n"
"    renderStats(d.stats);draw();renderLeaks(d.leaks);\n"
"    document.getElementById('refreshLabel').textContent='已刷新 — '+new Date().toLocaleTimeString();\n"
"  }).catch(function(err){\n"
"    console.error('fetch failed:',err);\n"
"    document.getElementById('refreshLabel').textContent='刷新失败，稍后重试';\n"
"  })\n"
"}\n"
"refresh();setInterval(refresh,5000);\n"
"</script>\n"
"</body>\n"
"</html>\n";

/* ======================================================================== *
 *                        HTTP 请求处理器                                     *
 * ======================================================================== */

/**
 * 将字符串写入 fd，同时对 JSON 特殊字符（" \ 控制字符）进行转义。
 * 用于安全输出 proc_name 等可能包含特殊字符的字符串字段。
 *
 * @param fd   目标文件描述符
 * @param str  原始字符串
 */
static void write_json_string(int fd, const char *str)
{
    if (fd < 0 || str == NULL) return;
    write(fd, "\"", 1);
    for (const char *p = str; *p != '\0'; p++) {
        unsigned char c = (unsigned char)*p;
        if (c == '"' || c == '\\') {
            write(fd, "\\", 1);
            write(fd, p, 1);
        } else if (c < 0x20) {
            /* 控制字符：编码为 \\u00XX */
            char esc[8];
            int n = snprintf(esc, sizeof(esc), "\\u%04x", (unsigned)c);
            if (n > 0) write(fd, esc, (size_t)n);
        } else {
            write(fd, p, 1);
        }
    }
    write(fd, "\"", 1);
}

/** 处理 GET / — 返回仪表盘 HTML */
static void handle_root(int client_fd)
{
    const char *header =
        "HTTP/1.0 200 OK\r\n"
        "Content-Type: text/html; charset=utf-8\r\n"
        "Cache-Control: no-cache\r\n"
        "Connection: close\r\n"
        "\r\n";
    write(client_fd, header, strlen(header));
    write(client_fd, g_dashboard_html, strlen(g_dashboard_html));
}

/** 写入单个泄漏站点 JSON */
static void write_leak_json(mtt_leak_site_t *site, mtt_stack_entry_t *se, int fd)
{
    static char buf[4096];

    if (site == NULL) {
        /* 防御：调用者传入 NULL site，写入空对象 */
        write(fd, "{}", 2);
        return;
    }

    int off = snprintf(buf, sizeof(buf),
        "{\"hash\":\"0x%llx\",\"count\":%zu,\"per_leak_size\":%zu,"
        "\"total_size\":%zu,\"diff_size\":%zu,\"is_expired\":%d,"
        "\"first_seen\":%lld,\"last_seen\":%lld,\"stack\":[",
        (unsigned long long)site->stack_hash, site->count,
        site->per_leak_size, site->total_size,
        site->diff_size, site->is_expired,
        (long long)site->first_seen, (long long)site->last_seen);
    if (off < 0) off = 0; /* snprintf 编码错误时防御 */
    write(fd, buf, (size_t)off);

    int wrote_frame = 0;
    /* ARM32 QEMU 最后补救：若 reporter 线程未解析此栈条目（极端边界），
     * 在第一次 HTTP 访问时同步解析，确保 JSON 输出始终包含解析后的符号。
     * 调用方（handle_api_data / handle_api_leaks）持有 cache_lock，
     * 此时 reporter 线程不会并发修改同一栈条目（scan 已完成，cache 已更新）。 */
    if (se != NULL && !se->is_resolved) {
        mtt_stack_resolve(se);
    }
    if (se != NULL && se->is_resolved) {
        for (int j = 0; j < se->frame_count; j++) {
            const char *sym = se->resolved[j];
            if (sym == NULL || sym[0] == '\0'
                || strstr(sym, "libmemorytracetool") != NULL
                || strstr(sym, "mtt_") == sym
                || strstr(sym, "capture_stack") != NULL
                || strstr(sym, "backtrace") != NULL)
                continue;
            if (wrote_frame) write(fd, ",", 1);
            wrote_frame = 1;
            /* 写入引号包裹的符号字符串 */
            write(fd, "\"", 1);
            for (const char *p = sym; *p != '\0'; p++) {
                if (*p == '"' || *p == '\\') write(fd, "\\", 1);
                write(fd, p, 1);
            }
            write(fd, "\"", 1);
        }
    }

    /* 兜底：当所有已解析帧均被过滤时，输出原始帧地址作为后备，
     * 确保 ARM32 QEMU 等符号解析受限环境下仍能显示调用栈。
     * 仅跳过第 0 帧（mtt_capture_stack），保留其余所有帧的原始地址。 */
    if (!wrote_frame && se != NULL && se->frame_count > 0) {
        for (int j = 0; j < se->frame_count; j++) {
            /* 仅跳过第 0 帧（始终为 mtt_capture_stack，无诊断价值） */
            if (j == 0) continue;
            if (wrote_frame) {
                off = snprintf(buf, sizeof(buf), ",");
                if (off < 0) off = 0;
                write(fd, buf, (size_t)off);
            }
            wrote_frame = 1;
            off = snprintf(buf, sizeof(buf), "\"0x%lx\"",
                           (unsigned long)(uintptr_t)se->frames[j]);
            if (off < 0) off = 0;
            write(fd, buf, (size_t)off);
        }
    }

    write(fd, "]}", 2);
}

/** 处理 GET /api/data */
static void handle_api_data(int client_fd)
{
    mtt_reporter_t *rep = mtt_reporter_get();
    const char *header =
        "HTTP/1.0 200 OK\r\n"
        "Content-Type: application/json; charset=utf-8\r\n"
        "Cache-Control: no-cache\r\n"
        "Connection: close\r\n"
        "\r\n";
    write(client_fd, header, strlen(header));

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

    time_t session_ts = (rep != NULL) ? rep->session_start : 0;

    static char buf[8192];
    /* 先写 JSON 开头（到 proc_name 之前），再用 write_json_string 安全输出 proc_name */
    int len = snprintf(buf, sizeof(buf),
        "{\"pid\":%d,\"proc_name\":",
        (int)getpid());
    write(client_fd, buf, (size_t)len);
    write_json_string(client_fd, proc_name);

    len = snprintf(buf, sizeof(buf),
        ",\"session_start\":%lld,\"last_scan\":%lld,"
        "\"stats\":{\"current_bytes\":%zu,\"peak_bytes\":%zu,\"alloc_count\":%zu,"
        "\"free_count\":%zu,\"leak_count\":%zu,\"total_allocated\":%zu}",
        (long long)session_ts, (long long)time(NULL),
        cur_bytes, peak_bytes, allocs, frees, leak_count, total_alloc);
    write(client_fd, buf, (size_t)len);

    /* 时序数据 */
    write(client_fd, ",\"time_series\":[", 16);
    if (mtt_ts_is_ready() && raw_malloc != NULL) {
        mtt_ts_point_t *ts_buf = (mtt_ts_point_t*)raw_malloc(360 * sizeof(mtt_ts_point_t));
        if (ts_buf != NULL) {
            memset(ts_buf, 0, 360 * sizeof(mtt_ts_point_t));
            uint32_t ts_count = 0;
            mtt_ts_get_range(0, ts_buf, 360, &ts_count);
            int wrote_first = 0;
            for (uint32_t i = 0; i < ts_count; i++) {
                if (ts_buf[i].timestamp == 0) continue;
                if (wrote_first) write(client_fd, ",", 1);
                wrote_first = 1;
                len = snprintf(buf, sizeof(buf),
                    "{\"ts\":%lld,\"cur\":%zu,\"peak\":%zu,\"allocs\":%zu,\"frees\":%zu,\"entries\":%zu}",
                    (long long)ts_buf[i].timestamp, ts_buf[i].current_bytes,
                    ts_buf[i].peak_bytes, ts_buf[i].alloc_count,
                    ts_buf[i].free_count, ts_buf[i].entry_count);
                write(client_fd, buf, (size_t)len);
            }
            raw_free(ts_buf);
        }
    }
    write(client_fd, "]", 1);

    /* 泄漏站点 */
    write(client_fd, ",\"leaks\":[", 10);
    pthread_mutex_lock(&rep->cache_lock);
    if (rep->cached_sites != NULL && rep->cached_site_count > 0) {
        size_t show = rep->cached_site_count;
        if (show > 50) show = 50;
        int wrote_leak = 0;
        for (size_t i = 0; i < show; i++) {
            if (rep->cached_sites[i] == NULL) continue;
            if (wrote_leak) write(client_fd, ",", 1);
            wrote_leak = 1;
            mtt_stack_entry_t *se = NULL;
            if (rep->cached_pairs != NULL) {
                site_stack_pair_t *pp = (site_stack_pair_t*)rep->cached_pairs;
                for (size_t j = 0; j < rep->cached_site_count; j++) {
                    if (pp[j].site == rep->cached_sites[i]) {
                        se = pp[j].stack_entry; break;
                    }
                }
            }
            write_leak_json(rep->cached_sites[i], se, client_fd);
        }
    }
    pthread_mutex_unlock(&rep->cache_lock);
    write(client_fd, "]}", 2);
}

/** 处理 GET /api/leaks */
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
        int wrote_leak = 0;
        for (size_t i = 0; i < rep->cached_site_count; i++) {
            if (rep->cached_sites[i] == NULL) continue;
            if (wrote_leak) write(client_fd, ",", 1);
            wrote_leak = 1;
            mtt_stack_entry_t *se = NULL;
            if (rep->cached_pairs != NULL) {
                site_stack_pair_t *pp = (site_stack_pair_t*)rep->cached_pairs;
                for (size_t j = 0; j < rep->cached_site_count; j++) {
                    if (pp[j].site == rep->cached_sites[i]) {
                        se = pp[j].stack_entry; break;
                    }
                }
            }
            write_leak_json(rep->cached_sites[i], se, client_fd);
        }
    }
    pthread_mutex_unlock(&rep->cache_lock);
    write(client_fd, "]}", 2);
}

static void handle_404(int client_fd)
{
    const char *body = "{\"error\":\"not found\"}";
    char header[256];
    snprintf(header, sizeof(header),
        "HTTP/1.0 404 Not Found\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: %zu\r\n"
        "Connection: close\r\n\r\n", strlen(body));
    write(client_fd, header, strlen(header));
    write(client_fd, body, strlen(body));
}

/* ======================================================================== *
 *                        HTTP 工作线程                                        *
 * ======================================================================== */

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

static void* http_thread_fn(void *arg)
{
    (void)arg;
    pthread_detach(pthread_self());

    static char req_buf[MTT_HTTP_BUF_SIZE];
    static char path[MTT_HTTP_MAX_PATH];

    while (atomic_load_explicit(&g_http_server.running, memory_order_acquire)) {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(g_http_server.listen_fd, &rfds);
        struct timeval tv = {1, 0};
        int ready = select(g_http_server.listen_fd + 1, &rfds, NULL, NULL, &tv);
        if (ready < 0) {
            if (errno == EINTR || errno == EAGAIN) continue;
            break;
        }
        if (ready == 0) continue;
        if (!FD_ISSET(g_http_server.listen_fd, &rfds)) continue;

        struct sockaddr_in client_addr;
        socklen_t addr_len = sizeof(client_addr);
        int client_fd = accept(g_http_server.listen_fd, (struct sockaddr*)&client_addr, &addr_len);
        if (client_fd < 0) {
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) continue;
            break;
        }

        memset(req_buf, 0, sizeof(req_buf));
        ssize_t n = recv(client_fd, req_buf, sizeof(req_buf) - 1, 0);
        /* ARM32 QEMU: recv may spuriously return EAGAIN when data
         * has not yet been delivered by QEMU user-mode networking.
         * Retry up to 3 times with a 50ms wait between attempts. */
        if (n < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) {
            int retries = 0;
            do {
                struct timespec ts = {0, 50000000}; /* 50ms */
                nanosleep(&ts, NULL);
                n = recv(client_fd, req_buf, sizeof(req_buf) - 1, 0);
                retries++;
            } while (n < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) && retries < 3);
        }
        if (n <= 0) { close(client_fd); continue; }
        req_buf[n] = '\0';

        char *crlf = strstr(req_buf, "\r\n");
        if (crlf != NULL) *crlf = '\0';

        memset(path, 0, sizeof(path));
        if (!parse_request(req_buf, path, sizeof(path))) {
            handle_404(client_fd);
        } else if (strcmp(path, "/") == 0) {
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

void mtt_http_server_start(uint16_t port)
{
    if (port == 0) return;
    if (atomic_load_explicit(&g_http_server.running, memory_order_acquire)) return;

    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) return;
    int reuse = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    int bound = 0;
    for (int try_port = port; try_port < (int)port + 6; try_port++) {
        addr.sin_port = htons((uint16_t)try_port);
        if (bind(listen_fd, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
            bound = 1; port = (uint16_t)try_port; break;
        }
    }
    if (!bound) { close(listen_fd); return; }
    if (listen(listen_fd, MTT_HTTP_BACKLOG) < 0) { close(listen_fd); return; }

    g_http_server.listen_fd = listen_fd;
    g_http_server.port = port;
    atomic_store_explicit(&g_http_server.running, 1, memory_order_release);

    pthread_t tid;
    if (pthread_create(&tid, NULL, http_thread_fn, NULL) != 0) {
        atomic_store_explicit(&g_http_server.running, 0, memory_order_release);
        close(listen_fd); return;
    }
    g_http_server.thread = tid;

    char diag[128];
    int len = snprintf(diag, sizeof(diag), "[MTT] HTTP dashboard: http://0.0.0.0:%u/\n", (unsigned)port);
    if (len > 0 && len < (int)sizeof(diag))
        write(STDERR_FILENO, diag, (size_t)len);
}

void mtt_http_server_stop(void)
{
    atomic_store_explicit(&g_http_server.running, 0, memory_order_release);
    if (g_http_server.listen_fd > 0) {
        close(g_http_server.listen_fd);
        g_http_server.listen_fd = -1;
    }
}

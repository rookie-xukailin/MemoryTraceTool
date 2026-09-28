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
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <poll.h>

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
"<meta http-equiv=\"Cache-Control\" content=\"no-store, no-cache\">\n"
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
".tooltip{position:fixed;background:#1f2328;color:#fff;padding:4px 8px;border-radius:4px;font-size:.8rem;pointer-events:none;display:none;z-index:10;max-width:420px}\n"
".refresh{font-size:.75rem;color:#6e7681;float:right}\n"
".toggle-btn{font-size:.75rem;padding:4px 10px;border:1px solid var(--border);border-radius:4px;background:var(--bg2);color:var(--text);cursor:pointer;margin-right:6px}\n"
".toggle-btn.active{background:var(--accent);color:#fff;border-color:var(--accent)}\n"
".toggle-btn:disabled{opacity:.4;cursor:not-allowed}\n"
".unit-toggle{display:inline-flex;gap:2px;float:right;margin-right:14px;border:1px solid var(--border);border-radius:4px;overflow:hidden}\n"
".unit-toggle .unit-btn{font-size:.7rem;padding:3px 9px;border:none;background:var(--bg2);color:var(--text);cursor:pointer;border-right:1px solid var(--border)}\n"
".unit-toggle .unit-btn:last-child{border-right:none}\n"
".unit-toggle .unit-btn.active{background:var(--accent);color:#fff}\n"
".stop-btn{font-size:.75rem;padding:4px 10px;border:1px solid var(--warn);border-radius:4px;background:var(--bg2);color:var(--warn);cursor:pointer}\n"
".lg-bar{display:flex;gap:6px;flex-wrap:wrap;margin-bottom:8px}\n"
".lg-btn{font-size:.72rem;padding:3px 10px;border:1px solid var(--border);border-radius:10px;background:var(--bg2);color:var(--text);cursor:pointer}\n"
".lg-btn.on{color:var(--text);font-weight:600;box-shadow:inset 0 -2px 0 var(--lgc,var(--accent))}\n"
"th.sorth{cursor:pointer;user-select:none;white-space:nowrap}\n"
"th.sorth:hover{color:var(--accent)}\n"
".cf{font-size:.72rem;padding:1px 8px;border-radius:8px;border:1px solid var(--border);white-space:nowrap}\n"
".cf-probable{color:var(--warn);border-color:var(--warn)}\n"
".cf-possible{color:var(--orange);border-color:var(--orange)}\n"
".cf-session_scoped{color:var(--green);border-color:var(--green)}\n"
".cf-long_lived{color:#6e7681}\n"
".cf-nostack{color:#d29922;border-style:dashed}\n"
".fil-bar{display:flex;gap:6px;flex-wrap:wrap;align-items:center;margin-bottom:10px;font-size:.75rem;color:#6e7681}\n"
".chart-hint{margin-top:6px;font-size:.72rem;color:#6e7681}\n"
"</style>\n"
"</head>\n"
"<body>\n"
"<div class=\"container\">\n"
"<h1>MemoryTraceTool</h1>\n"
"<div class=\"subtitle\" id=\"info\">加载中...</div>\n"
"<div class=\"card\">\n"
"  <h2>堆内存趋势 <span class=\"unit-toggle\" id=\"unitToggle\"><button class=\"unit-btn\" data-unit=\"kb\">KB</button><button class=\"unit-btn\" data-unit=\"mb\">MB</button></span><span class=\"refresh\" id=\"refreshLabel\">每 5 秒刷新</span></h2>\n"
"  <div class=\"lg-bar\" id=\"legend\"></div>\n"
"  <div class=\"stats\" id=\"stats\"></div>\n"
"  <canvas id=\"chart\" width=\"800\" height=\"400\" style=\"cursor:default\"></canvas>\n"
"  <div class=\"chart-hint\">滚轮缩放（以光标为中心）· 按住拖拽平移 · 双击复位 <button class=\"toggle-btn\" id=\"resetViewBtn\" style=\"margin-left:8px\">复位视图</button> <span id=\"viewHint\" style=\"display:none;color:var(--orange)\">历史数据已被覆盖，已回到实时视图</span></div>\n"
"  <div class=\"tooltip\" id=\"tip\"></div>\n"
"</div>\n"
"<div class=\"card\">\n"
"  <h2>泄漏站点排行（点击列头排序）</h2>\n"
"  <div class=\"fil-bar\" id=\"leakFilters\">\n"
"    <span>最后发现：</span>\n"
"    <button class=\"toggle-btn\" data-ls=\"0\">全部</button>\n"
"    <button class=\"toggle-btn\" data-ls=\"300\">5分钟内</button>\n"
"    <button class=\"toggle-btn\" data-ls=\"900\">15分钟内</button>\n"
"    <button class=\"toggle-btn\" data-ls=\"3600\">1小时内</button>\n"
"    <span style=\"margin-left:12px\">分类：</span>\n"
"    <button class=\"toggle-btn\" data-cf=\"default\">默认</button>\n"
"    <button class=\"toggle-btn\" data-cf=\"all\">全部</button>\n"
"    <button class=\"toggle-btn\" data-cf=\"suspect\">疑似泄漏</button>\n"
"    <button class=\"toggle-btn\" data-cf=\"session\">周期作用域</button>\n"
"    <button class=\"toggle-btn\" data-cf=\"long\">长存活</button>\n"
"    <button class=\"toggle-btn\" data-gr=\"1\">仅看增长</button>\n"
"    <button class=\"toggle-btn\" data-ns=\"1\">仅看无栈</button>\n"
"  </div>\n"
"  <table>\n"
"    <thead><tr><th>#</th><th class=\"sorth\" onclick=\"sortBy('count')\">次数 <span id=\"si-count\"></span></th><th class=\"sorth\" onclick=\"sortBy('per_leak_size')\">单次 <span id=\"si-per_leak_size\"></span></th><th class=\"sorth\" onclick=\"sortBy('total_size')\">总占用 <span id=\"si-total_size\"></span></th><th class=\"sorth\" onclick=\"sortBy('diff_size')\">增长 <span id=\"si-diff_size\"></span></th><th class=\"sorth\" onclick=\"sortBy('conf')\">置信度 <span id=\"si-conf\"></span></th><th class=\"sorth\" onclick=\"sortBy('first_seen')\">首次 <span id=\"si-first_seen\"></span></th><th class=\"sorth\" onclick=\"sortBy('last_seen')\">最后 <span id=\"si-last_seen\"></span></th></tr></thead>\n"
"    <tbody id=\"leaks-tbody\"></tbody>\n"
"  </table>\n"
"  <div style=\"margin-top:12px;text-align:center;font-size:.85rem;color:#6e7681\">\n"
"    <button class=\"toggle-btn\" id=\"prevPageBtn\" onclick=\"changePage(-1)\">上一页</button>\n"
"    <span id=\"pageInfo\" style=\"margin:0 12px\"></span>\n"
"    <button class=\"toggle-btn\" id=\"nextPageBtn\" onclick=\"changePage(1)\">下一页</button>\n"
"  </div>\n"
"</div>\n"
"</div>\n"
"<script>\n"
"var data=null,chartCanvas=document.getElementById('chart'),ctx=chartCanvas.getContext('2d'),tip=document.getElementById('tip');\n"
"var expandedHashes=new Set(); /* 记录展开的泄漏站点 hash，刷新后恢复 */\n"
"var curPage=1, PAGE_SIZE=50, allLeaks=[], viewLeaksArr=[];\n"
"/* ---- 时间轴视窗（平移/缩放）与多曲线 ---- */\n"
"var PAD={top:28,right:28,bottom:48,left:64};\n"
"var view={t0:0,t1:0,follow:true}; /* follow=true 自动跟随最新（全量视图） */\n"
"var SERIES=[\n"
" {k:'talloc',c:'#22c55e',n:'累计分配',on:1,right:1},\n"
" {k:'cur',c:'#58a6ff',n:'当前未释放',on:1},\n"
" {k:'peak',c:'#d29922',n:'历史峰值',on:1},\n"
" {k:'rss',c:'#bc8cff',n:'RSS',on:0,right:1},\n"
" {k:'leak',c:'#f85149',n:'已识别泄漏',on:0}];\n"
"function fb(b){if(b==null)return'0 B';if(b>=1048576)return(b/1048576).toFixed(2)+' MB';if(b>=1024)return(b/1024).toFixed(2)+' KB';return b+' B'}\n"
"/* 千分位格式化:不用 toLocaleString()(旧版浏览器/嵌入式 webview 会输出\n    带 7 位小数的 0.0000000,导致 Y 轴刻度异常),自实现兼容 */\n"
"function fmtInt(n){n=Math.round(n);var s=String(n);return s.replace(/\\B(?=(\\d{3})+(?!\\d))/g,',')}\n"
"var yUnit=(function(){try{var u=localStorage.getItem('mtt_yunit');if(u!=='mb'&&u!=='kb')u='kb';return u}catch(e){return'kb'}})();\n"
"function fy(b){if(b==null||b<0)b=0;if(yUnit==='mb')return b>=1048576?(b/1048576).toFixed(2)+' MB':(b/1024).toFixed(1)+' KB';return b>=1024?fmtInt(b/1024)+' KB':fmtInt(b)+' B'}\n"
"(function(){var t=document.getElementById('unitToggle');if(!t)return;var btns=t.querySelectorAll('.unit-btn');btns.forEach(function(b){if(b.dataset.unit===yUnit)b.classList.add('active');b.onclick=function(){yUnit=b.dataset.unit;try{localStorage.setItem('mtt_yunit',yUnit)}catch(e){}btns.forEach(function(x){x.classList.toggle('active',x.dataset.unit===yUnit)});draw()}})})();\n"
"function ft(t){if(!t||t<=0)return'N/A';return new Date(t*1000).toLocaleTimeString()}\n"
"/* 图例：点击开关曲线（状态仅存内存，刷新页面恢复默认） */\n"
"function buildLegend(){\n"
"  var lg=document.getElementById('legend');if(!lg)return;var h='',i;\n"
"  for(i=0;i<SERIES.length;i++){var sr=SERIES[i];h+='<button class=\"lg-btn'+(sr.on?' on':'')+'\" data-i=\"'+i+'\" style=\"--lgc:'+sr.c+'\">'+sr.n+'</button>';}\n"
"  lg.innerHTML=h;\n"
"  var btns=lg.querySelectorAll('.lg-btn');\n"
"  for(i=0;i<btns.length;i++){(function(b){b.onclick=function(){var k=+b.getAttribute('data-i');SERIES[k].on=SERIES[k].on?0:1;buildLegend();draw();};})(btns[i]);}\n"
"}\n"
"/* 视窗夹紧：下限 60s 跨度，不超出数据时间范围（右端尽量吸住最新点） */\n"
"function clampView(ts){\n"
"  var lo=ts[0].ts,hi=ts[ts.length-1].ts;\n"
"  if(!view.follow&&view.t1<lo){/* 视窗滑出数据左界(环形覆盖)：回实时并提示 */\n"
"    view.follow=true;view.t0=lo;view.t1=hi;\n"
"    var hint=document.getElementById('viewHint');\n"
"    if(hint){hint.style.display='inline';setTimeout(function(){hint.style.display='none';},4000);}\n"
"  }\n"
"  var lo=ts[0].ts,hi=ts[ts.length-1].ts;\n"
"  if(view.t1-view.t0<60){view.t0=hi-60;view.t1=hi;}\n"
"  if(view.t0<lo){view.t1=Math.min(hi,view.t1+(lo-view.t0));view.t0=lo;}\n"
"  if(view.t1>hi){view.t0=Math.max(lo,view.t0-(view.t1-hi));view.t1=hi;}\n"
"}\n"
"function visSlice(ts){\n"
"  var a=[],i;\n"
"  if(view.t0>=view.t1){view.t0=ts[0].ts;view.t1=ts[ts.length-1].ts;}\n"
"  for(i=0;i<ts.length;i++){if(ts[i].ts>=view.t0&&ts[i].ts<=view.t1)a.push(ts[i]);}\n"
"  if(a.length===0)a=[ts[0],ts[ts.length-1]];\n"
"  return a;\n"
"}\n"
"function draw(){\n"
"  if(!data||!data.time_series||data.time_series.length===0)return;\n"
"  var ts=data.time_series;\n"
"  if(view.follow){view.t0=ts[0].ts;view.t1=ts[ts.length-1].ts;}\n"
"  clampView(ts);\n"
"  var vis=visSlice(ts);\n"
"  var W=chartCanvas.width,H=chartCanvas.height;\n"
"  ctx.clearRect(0,0,W,H);\n"
"  var pw=W-PAD.left-PAD.right,ph=H-PAD.top-PAD.bottom;\n"
"  var span=view.t1-view.t0;if(span<1)span=1;\n"
"  function x(t){return PAD.left+((t-view.t0)/span)*pw}\n"
"  /* 双 Y 轴：左轴=堆水位(cur/peak/leak)，右轴=大数量级(talloc/rss)。\n"
"   * 修走读 P1：GB 级 talloc/RSS 与 KB 级堆曲线共线时堆曲线被压成贴底直线 */\n"
"  var lMax=1,rMax=1,si,i;\n"
"  for(si=0;si<SERIES.length;si++){\n"
"    if(!SERIES[si].on)continue;\n"
"    for(i=0;i<vis.length;i++){\n"
"      var vv=vis[i][SERIES[si].k];if(vv==null)continue;\n"
"      if(SERIES[si].right){if(vv>rMax)rMax=vv;}else{if(vv>lMax)lMax=vv;}\n"
"    }\n"
"  }\n"
"  var maxL=lMax*1.2;if(maxL<1024)maxL=1024;\n"
"  var maxR=rMax*1.2;if(maxR<1024)maxR=1024;\n"
"  function y(v){return PAD.top+ph-(v/maxL)*ph}\n"
"  function yr(v){return PAD.top+ph-(v/maxR)*ph}\n"
"  function yOf(v,right){return right?yr(v):y(v)}\n"
"  var txtColor=getComputedStyle(document.documentElement).getPropertyValue('--text').trim();\n"
"  var borderColor=getComputedStyle(document.documentElement).getPropertyValue('--border').trim();\n"

"  /* grid: 极浅,不抢戏 */\n"
"  var rawL=maxL/4,magL=Math.pow(10,Math.floor(Math.log10(rawL))),stepL=magL;\n"
"  if(rawL/stepL>=5)stepL*=5;else if(rawL/stepL>=2)stepL*=2;\n"
"  var rawR=maxR/4,magR=Math.pow(10,Math.floor(Math.log10(rawR))),stepR=magR;\n"
"  if(rawR/stepR>=5)stepR*=5;else if(rawR/stepR>=2)stepR*=2;\n"
"  var rightOn=false;for(si=0;si<SERIES.length;si++){if(SERIES[si].on&&SERIES[si].right)rightOn=true;}\n"
"  ctx.strokeStyle=borderColor;ctx.globalAlpha=0.35;ctx.lineWidth=1;\n"
"  for(var v=0;v<=maxL;v+=stepL){var yy=y(v);ctx.beginPath();ctx.moveTo(PAD.left,yy);ctx.lineTo(W-PAD.right,yy);ctx.stroke()}\n"
"  ctx.globalAlpha=1;\n"
"  /* Y labels: 左轴(堆水位)按 yUnit 切换；右轴(大数量级)固定自适应字节 */\n"
"  ctx.fillStyle=txtColor;ctx.globalAlpha=0.65;ctx.font='10px -apple-system,BlinkMacSystemFont,sans-serif';ctx.textAlign='right';\n"
"  for(var v2=0;v2<=maxL;v2+=stepL){var yy2=y(v2);ctx.fillText(fy(v2),PAD.left-8,yy2+3)}\n"
"  if(rightOn){\n"
"    ctx.textAlign='right';\n"
"    for(var v3=0;v3<=maxR;v3+=stepR){var yy3=yr(v3);ctx.fillText(fb(v3),W-2,yy3+3)}\n"
"  }\n"
"  ctx.globalAlpha=1;\n"
"  /* 多曲线:cur/peak/rss/leak/talloc,按可见切片绘制 */\n"
"  for(si=0;si<SERIES.length;si++){\n"
"    if(!SERIES[si].on)continue;\n"
"    ctx.beginPath();var started=false;\n"
"    for(i=0;i<vis.length;i++){var val=vis[i][SERIES[si].k];if(val==null)continue;var xx=x(vis[i].ts),yyy=yOf(val,SERIES[si].right);if(!started){ctx.moveTo(xx,yyy);started=true;}else ctx.lineTo(xx,yyy);}\n"
"    if(started){ctx.strokeStyle=SERIES[si].c;ctx.lineWidth=1.6;ctx.lineJoin='round';ctx.lineCap='round';ctx.stroke();}\n"
"  }\n"
"  /* X labels: 按视窗时间均匀取 8 个刻度 */\n"
"  var steps=Math.min(8,Math.max(2,Math.round(span/60)+1));\n"
"  ctx.fillStyle=txtColor;ctx.globalAlpha=0.65;ctx.font='10px -apple-system,BlinkMacSystemFont,sans-serif';ctx.textAlign='center';\n"
"  for(i=0;i<=steps;i++){var tt=view.t0+span*i/steps;ctx.fillText(ft(tt),x(tt),H-PAD.bottom+18)}\n"
"  ctx.globalAlpha=1;\n"
"  /* hover: 可见切片内最近点,提示所有启用曲线的值 */\n"
"  chartCanvas.onmousemove=function(e){\n"
"    var r=chartCanvas.getBoundingClientRect();var sx=chartCanvas.width/r.width;var mx=(e.clientX-r.left)*sx;\n"
"    var best=null,bestD=1e9;\n"
"    for(var i2=0;i2<vis.length;i2++){var d=Math.abs(x(vis[i2].ts)-mx);if(d<bestD){bestD=d;best=vis[i2];}}\n"
"    if(best&&bestD<8){\n"
"      var parts=[ft(best.ts)];\n"
"      for(var s2=0;s2<SERIES.length;s2++){if(!SERIES[s2].on)continue;var pv=best[SERIES[s2].k];parts.push(SERIES[s2].n+':'+fb(pv!=null?pv:0));}\n"
"      tip.style.display='block';\n      var tx=e.clientX+15,ty=e.clientY-30;\n      if(tx+tip.offsetWidth+8>window.innerWidth)tx=e.clientX-tip.offsetWidth-15;\n      if(ty<4)ty=4;\n      tip.style.left=tx+'px';tip.style.top=ty+'px';tip.textContent=parts.join(' | ');return;\n"
"    }\n"
"    tip.style.display='none';\n"
"  };\n"
"}\n"
"/* ---- 平移/缩放交互（一次性绑定） ---- */\n"
"(function(){\n"
"  function evX(e){var r=chartCanvas.getBoundingClientRect();var sx=chartCanvas.width/r.width;return (e.clientX-r.left)*sx;}\n"
"  function evT(ex){var pw=chartCanvas.width-PAD.left-PAD.right;if(pw<=0)return view.t0;var f=(ex-PAD.left)/pw;if(f<0)f=0;if(f>1)f=1;return view.t0+f*(view.t1-view.t0);}\n"
"  chartCanvas.addEventListener('wheel',function(e){\n"
"    e.preventDefault();\n"
"    if(!data||!data.time_series||data.time_series.length<2)return;\n"
"    var ts=data.time_series;\n"
"    var t=evT(evX(e));\n"
"    /* 按量级缩放：鼠标齿轮一格一步；触控板轻扫(deltaY 小值连发)不再一步到底 */\n    var d=Math.max(-100,Math.min(100,e.deltaY));\n    var f=Math.exp(d*0.012);\n    if(f===1)f=e.deltaY>0?1.05:0.95;\n"
"    var nt0=t-(t-view.t0)*f,nt1=t+(view.t1-t)*f;\n"
"    var full=ts[ts.length-1].ts-ts[0].ts;\n"
"    if(nt1-nt0>=full){nt0=ts[0].ts;nt1=ts[ts.length-1].ts;}\n"
"    if(nt1-nt0<60){var m=(nt0+nt1)/2;nt0=m-30;nt1=m+30;}\n"
"    view.t0=nt0;view.t1=nt1;\n"
"    view.follow=(nt0<=ts[0].ts+1&&nt1>=ts[ts.length-1].ts-1);\n"
"    draw();\n"
"  },{passive:false});\n"
"  var dragging=false,startX=0,st0=0,st1=0;\n"
"  chartCanvas.addEventListener('mousedown',function(e){dragging=true;startX=evX(e);st0=view.t0;st1=view.t1;chartCanvas.style.cursor='grabbing';e.preventDefault();});\n"
"  window.addEventListener('mousemove',function(e){\n"
"    if(!dragging)return;\n"
"    var ex=evX(e);var pw=chartCanvas.width-PAD.left-PAD.right;if(pw<=0)return;\n"
"    var span2=st1-st0;var dt=-(ex-startX)/pw*span2;\n"
"    view.t0=st0+dt;view.t1=st1+dt;view.follow=false;draw();\n"
"  });\n"
"  window.addEventListener('mouseup',function(){if(dragging){dragging=false;chartCanvas.style.cursor='default';}});\n"
"  chartCanvas.addEventListener('dblclick',function(){view.follow=true;draw();});\n"
"  var rb=document.getElementById('resetViewBtn');if(rb)rb.onclick=function(){view.follow=true;draw();};\n"
"})();\n"
"function renderStats(st){\n"
"  var s=st||{};\n"
"  var p=(window.__lastData&&window.__lastData.pool)||{};\n"
"  var modeText = p.mode===1 ? 'POOL' : (p.mode===2 ? 'FALLBACK' : 'N/A');\n"
"  var modeColor = p.mode===1 ? '#3fb950' : (p.mode===2 ? '#f85149' : '#6e7681');\n"
"  var poolHtml='';\n"
"  if(p.mode===1){\n"
"    var pct = p.bytes_total>0 ? Math.round(p.bytes_used*100/p.bytes_total) : 0;\n"
"    var barColor = pct<60 ? '#3fb950' : (pct<85 ? '#d29922' : '#f85149');\n"
"    poolHtml='<div class=\"val\">'+fb(p.bytes_used||0)+' / '+fb(p.bytes_total||0)+'</div>'+\n"
"      '<div class=\"lbl\">工具内存池 <span style=\"color:'+modeColor+';font-weight:bold\">['+modeText+']</span></div>'+\n"
"      '<div style=\"margin-top:4px;height:6px;background:#21262d;border-radius:3px;overflow:hidden\"><div style=\"width:'+pct+'%;height:100%;background:'+barColor+'\"></div></div>'+\n"
"      '<div style=\"margin-top:2px;font-size:11px;color:#6e7681\">'+pct+'% | '+(p.used||0).toLocaleString()+' / '+(p.capacity||0).toLocaleString()+' entries</div>';\n"
"  } else if(p.mode===2){\n"
"    poolHtml='<div class=\"val\" style=\"color:'+modeColor+'\">降级模式</div>'+\n"
"      '<div class=\"lbl\">工具内存池 <span style=\"color:'+modeColor+';font-weight:bold\">['+modeText+']</span></div>'+\n"
"      '<div style=\"margin-top:4px;font-size:11px;color:#6e7681\">池子申请失败,按需 raw_malloc</div>';\n"
"  } else {\n"
"    poolHtml='<div class=\"val\">-</div><div class=\"lbl\">工具内存池</div>';\n"
"  }\n"
"  var skOvc=s.skipped_overcap||0,skSlot=s.skipped_slots||0;\n"
"  var warnHtml='';\n"
"  if(skOvc>0||skSlot>0){\n"
"    warnHtml='<div class=\"stat\" style=\"border-color:var(--warn)\"><div class=\"val\" style=\"color:var(--warn)\">'+fmtInt(skOvc+skSlot)+'</div><div class=\"lbl\">数据不完整 — 池耗尽:'+fmtInt(skOvc)+' 线程槽满:'+fmtInt(skSlot)+'</div></div>';\n"
"  }\n"
"  document.getElementById('stats').innerHTML=\n"
"    '<div class=\"stat\"><div class=\"val\">'+fb(s.current_bytes||0)+'</div><div class=\"lbl\">当前未释放</div></div>'+\n"
"    '<div class=\"stat\"><div class=\"val\">'+fb(s.peak_bytes||0)+'</div><div class=\"lbl\">历史峰值</div></div>'+\n"
"    '<div class=\"stat\"><div class=\"val\">'+(s.alloc_count||0).toLocaleString()+'</div><div class=\"lbl\">累计分配</div></div>'+\n"
"    '<div class=\"stat\"><div class=\"val\">'+(s.free_count||0).toLocaleString()+'</div><div class=\"lbl\">累计释放</div></div>'+\n"
"    '<div class=\"stat\"><div class=\"val\">'+(s.leak_count||0).toLocaleString()+'</div><div class=\"lbl\">疑似泄漏</div></div>'+\n"
"    '<div class=\"stat\"><div class=\"val\">'+fmtInt(s.late_free||0)+'</div><div class=\"lbl\">老化释放(周期证据)</div></div>'+\n"
"    '<div class=\"stat\"><div class=\"val\">'+fb(s.total_allocated||0)+'</div><div class=\"lbl\">累计分配总量</div></div>'+\n"
"    '<div class=\"stat\">'+poolHtml+'</div>'+\n"
"    warnHtml;\n"
"}\n"
"function alCmd(frame){var m=frame.match(/\\(([^()]+)\\+(0x[0-9a-fA-F]+)\\)$/);if(!m)return'';if(m[1]==='??')return'';return'addr2line -e '+m[1]+' -f -C '+m[2];}\n"
"/* ---- 泄漏表排序/筛选（状态跨刷新保持） ---- */\n"
"var sortKey='',sortDir=-1,filtLS=0,filtConf='default',filtGrow=false,filtNS=false;\n"
"(function(){try{\n"
"  var v=localStorage.getItem('mtt_sort');if(v)sortKey=v;\n"
"  var d=localStorage.getItem('mtt_sortdir');if(d==='1'||d==='-1')sortDir=parseInt(d,10);\n"
"  var f=localStorage.getItem('mtt_filt');\n"
"  if(f){var o=JSON.parse(f);filtLS=o.ls||0;filtConf=o.cf||'default';filtGrow=!!o.gr;\n"
"  var okCF=['default','all','suspect','session','long'];\n"
"  if(okCF.indexOf(filtConf)<0)filtConf='default';\n"
"  if([0,300,900,3600].indexOf(filtLS)<0)filtLS=0;filtNS=!!o.ns;}\n"
"}catch(e){}})();\n"
"function saveViewPref(){try{\n"
"  localStorage.setItem('mtt_sort',sortKey);\n"
"  localStorage.setItem('mtt_sortdir',String(sortDir));\n"
"  localStorage.setItem('mtt_filt',JSON.stringify({ls:filtLS,cf:filtConf,gr:filtGrow,ns:filtNS}));\n"
"}catch(e){}}\n"
"function confOf(l){return l.conf||(l.is_expired?'probable':'possible');}\n"
"function stackKindOf(l){if(typeof l.stack_kind==='number')return l.stack_kind;return (l.stack&&l.stack.length>0)?0:1;}\n"
"function stackKindLabel(k){\n"
"  if(k===1)return '<span class=\"cf cf-nostack\" title=\"抓栈失败：此站点是所有同尺寸分配的合计，不代表同一调用点\">⚠ 无栈·按大小聚合</span>';\n"
"  if(k===2)return '<span class=\"cf cf-nostack\" title=\"栈缓存(4096)已满，新栈不再缓存\">⚠ 无栈·缓存已满</span>';\n"
"  if(k===3)return '<span class=\"cf cf-nostack\">符号未解析</span>';\n"
"  return '';\n"
"}\n"
"var llSuspectBytes=1048576; /* 与后端 MTT_LONG_LIVED_SUSPECT_BYTES 默认值一致 */\n"
"function confLabel(l){\n"
"  if(l.conf==='long_lived'&&(l.total_size||0)>=llSuspectBytes&&l.late_free===0)return 'long-lived (SUSPECT)';\n"
"  var c=l.conf||'possible';\n"
"  return c==='probable'?'probable leak':c==='session_scoped'?'session-scoped':c==='long_lived'?'long-lived':'possible leak';\n"
"}\n"
"function viewLeaks(){\n"
"  var now=Math.floor(Date.now()/1000),arr=[],i;\n"
"  for(i=0;i<allLeaks.length;i++){\n"
"    var l=allLeaks[i],c=confOf(l);\n"
"    if(filtLS>0&&l.last_seen&&now-l.last_seen>filtLS)continue;\n"
"    if(filtConf==='default'&&c==='session_scoped')continue;\n"
"    if(filtConf==='suspect'&&c!=='probable'&&c!=='possible')continue;\n"
"    if(filtConf==='session'&&c!=='session_scoped')continue;\n"
"    if(filtConf==='long'&&c!=='long_lived')continue;\n"
"    if(filtGrow&&!(l.diff_size>0))continue;\n    if(filtNS&&stackKindOf(l)===0)continue;\n"
"    arr.push(l);\n"
"  }\n"
"  if(sortKey){\n"
"    var key=sortKey;\n"
"    arr.sort(function(a,b){\n"
"      var va,vb;\n"
"      if(key==='conf'){var rank={probable:3,possible:2,session_scoped:1,long_lived:0};va=rank[confOf(a)]||0;vb=rank[confOf(b)]||0;}\n"
"      else{va=a[key]||0;vb=b[key]||0;}\n"
"      if(va<vb)return -sortDir;\n"
"      if(va>vb)return sortDir;\n"
"      return 0;\n"
"    });\n"
"  }\n"
"  return arr;\n"
"}\n"
"function sortBy(k){\n"
"  if(sortKey===k)sortDir=-sortDir;\n"
"  else{sortKey=k;sortDir=-1;}\n"
"  saveViewPref();updateSortInd();curPage=1;renderLeaks(allLeaks);\n"
"}\n"
"function updateSortInd(){\n"
"  var ks=['count','per_leak_size','total_size','diff_size','conf','first_seen','last_seen'],i;\n"
"  for(i=0;i<ks.length;i++){\n"
"    var el=document.getElementById('si-'+ks[i]);\n"
"    if(el)el.textContent=(sortKey===ks[i])?(sortDir<0?'\\u25BC':'\\u25B2'):'';\n"
"  }\n"
"}\n"
"/* 筛选条交互 */\n"
"(function(){\n"
"  var bar=document.getElementById('leakFilters');if(!bar)return;\n"
"  var lsB=bar.querySelectorAll('[data-ls]'),cfB=bar.querySelectorAll('[data-cf]'),grB=bar.querySelector('[data-gr]'),nsB=bar.querySelector('[data-ns]');\n"
"  function paint(){\n"
"    var i;\n"
"    for(i=0;i<lsB.length;i++){lsB[i].className='toggle-btn'+(parseInt(lsB[i].getAttribute('data-ls'),10)===filtLS?' active':'');}\n"
"    for(i=0;i<cfB.length;i++){cfB[i].className='toggle-btn'+(cfB[i].getAttribute('data-cf')===filtConf?' active':'');}\n"
"    if(grB)grB.className='toggle-btn'+(filtGrow?' active':'');\n    if(nsB)nsB.className='toggle-btn'+(filtNS?' active':'');\n"
"  }\n"
"  function apply(){paint();saveViewPref();curPage=1;renderLeaks(allLeaks);}\n"
"  var i;\n"
"  for(i=0;i<lsB.length;i++){(function(b){b.onclick=function(){filtLS=parseInt(b.getAttribute('data-ls'),10);apply();};})(lsB[i]);}\n"
"  for(i=0;i<cfB.length;i++){(function(b){b.onclick=function(){filtConf=b.getAttribute('data-cf');apply();};})(cfB[i]);}\n"
"  if(grB)grB.onclick=function(){filtGrow=!filtGrow;apply();};\n  if(nsB)nsB.onclick=function(){filtNS=!filtNS;apply();};\n"
"  paint();\n"
"})();\n"
"function renderLeaks(leaks){\n"
"  allLeaks=leaks||[];\n"
"  viewLeaksArr=viewLeaks();\n"
"  var arr=viewLeaksArr;\n"
"  var total=Math.ceil(arr.length/PAGE_SIZE)||1;\n"
"  if(curPage>total)curPage=total;\n"
"  if(curPage<1)curPage=1;\n"
"  var tbody=document.getElementById('leaks-tbody');\n"
"  if(!allLeaks.length){tbody.innerHTML='<tr><td colspan=\"8\" style=\"text-align:center;color:#6e7681\">暂无泄漏数据</td></tr>';document.getElementById('pageInfo').textContent='';document.getElementById('prevPageBtn').disabled=document.getElementById('nextPageBtn').disabled=true;return}\n"
"  if(!arr.length){tbody.innerHTML='<tr><td colspan=\"8\" style=\"text-align:center;color:#6e7681\">当前筛选条件下无匹配站点</td></tr>';document.getElementById('pageInfo').textContent='0 / '+(allLeaks.length)+' 条';document.getElementById('prevPageBtn').disabled=document.getElementById('nextPageBtn').disabled=true;return}\n"
"  var startIdx=(curPage-1)*PAGE_SIZE, endIdx=Math.min(startIdx+PAGE_SIZE, arr.length);\n"
"  var rows='';\n"
"  for(var i=startIdx;i<endIdx;i++){\n"
"    var l=arr[i],h=l.hash||'',c=confOf(l);\n"
"    var diff=l.diff_size>0?' class=\"diff-high\"':'';\n"
"    var dim=(c==='session_scoped'||c==='long_lived')?';opacity:.55':'';\n"
"    var rowCls='leak-row'+(l.diff_size>0?' diff-high':'');\n"
"    rows+='<tr class=\"'+rowCls+'\" style=\"padding:0'+dim+'\" data-idx=\"'+i+'\">'+\n"
"      '<td>'+(i+1)+'</td><td>'+l.count.toLocaleString()+'</td>'+\n"
"      '<td>'+fb(l.per_leak_size)+'</td><td><b>'+fb(l.total_size)+'</b></td>'+\n"
"      '<td>'+(l.diff_size>0?'+'+fb(l.diff_size):'-')+'</td>'+\n"
"      '<td><span class=\"cf cf-'+c+'\">'+confLabel(l)+'</span> '+(stackKindOf(l)>0?stackKindLabel(stackKindOf(l)):'')+'</td>'+\n"
"      '<td>'+ft(l.first_seen)+'</td><td>'+ft(l.last_seen)+'</td></tr>';\n"
"    if(l.stack&&l.stack.length>0){\n"
"      rows+='<tr class=\"stack-row\" id=\"s'+i+'\"><td colspan=\"8\" class=\"stack-cell\">';\n"
"      var bizMarked=false;\n"
"      for(var j=0;j<l.stack.length;j++){\n"
"        var cmd=alCmd(l.stack[j]);\n"
"        // 首个业务帧加粗（跳过 operator new / STL 分配器帧，与报告 LEAK HERE 口径一致）\n"
"        var isShim=/^(operator new|operator delete|std::|__gnu_cxx::|__cxa_|_Znwm|_Znam|_ZdlPv)/.test(l.stack[j])||/_(M_create|M_mutate|M_append|M_construct)/.test(l.stack[j]);\n"
"        var mark=(!bizMarked&&!isShim)?'<b>&rarr; ':'  ';\n"
"        if(!bizMarked&&!isShim)bizMarked=true;\n"
"        rows+='<div>'+mark+l.stack[j]+'</div>';\n"
"        if(cmd)rows+='<div class=\"cmd\">'+cmd+'</div>';\n"
"      }\n"
"      rows+='</td></tr>';\n"
"    } else {\n"
"      var sk=stackKindOf(l);\n"
"      var skMsg=sk===1?'抓栈失败（本站点为所有 size='+l.per_leak_size+'B 分配的合计，不代表同一调用点）':(sk===2?'栈缓存已满（4096），此站点的新栈未再缓存':'符号未解析（stripped 或无 unwind 表）');\n"
"      rows+='<tr class=\"stack-row\" id=\"s'+i+'\"><td colspan=\"8\" class=\"stack-cell\"><div style=\"color:#d29922\">⚠ 无栈回溯（'+skMsg+'）— hash='+h+' count='+l.count+' conf='+c+(l.late_free?' late_free='+l.late_free:'')+'</div></td></tr>';\n"
"    }\n"
"  }\n"
"  tbody.innerHTML=rows;\n"
"  /* 分页控件 */\n"
"  document.getElementById('pageInfo').textContent='第 '+curPage+' / '+total+' 页 (筛选 '+(arr.length)+' / 共 '+allLeaks.length+' 条,当前 '+(endIdx-startIdx)+' 条)';\n"
"  document.getElementById('prevPageBtn').disabled=(curPage<=1);\n"
"  document.getElementById('nextPageBtn').disabled=(curPage>=total);\n"
"  /* 恢复展开状态 */\n"
"  var newHashes=new Set();\n"
"  for(var k=startIdx;k<endIdx;k++){var lh=arr[k].hash||'';if(expandedHashes.has(lh)){var sr=document.getElementById('s'+k);if(sr){sr.classList.add('open');newHashes.add(lh);}}}\n"
"  expandedHashes=newHashes;\n"
"}\n"
"/* 行点击展开（事件委托，兼容无 closest 的嵌入式 webview） */\n"
"(function(){\n"
"  var tbody=document.getElementById('leaks-tbody');if(!tbody)return;\n"
"  tbody.onclick=function(ev){\n"
"    var el=ev.target;\n"
"    while(el&&el!==tbody&&el.tagName!=='TR')el=el.parentNode;\n"
"    if(!el||el===tbody)return;\n"
"    var idxStr=el.getAttribute('data-idx');\n"
"    if(!idxStr)return;\n"
"    var idx=parseInt(idxStr,10);\n"
"    var sr=document.getElementById('s'+idx);\n"
"    if(!sr)return;\n"
"    var opened=sr.classList.toggle('open');\n"
"    var l=viewLeaksArr[idx];\n"
"    var hh=l&&l.hash?String(l.hash):'';\n"
"    if(opened&&hh)expandedHashes.add(hh);\n"
"    else if(hh)expandedHashes.delete(hh);\n"
"  };\n"
"})();\n"
"function changePage(delta){var total=Math.ceil(viewLeaksArr.length/PAGE_SIZE)||1;var np=curPage+delta;if(np<1||np>total)return;curPage=np;renderLeaks(allLeaks);}\n"
"function refresh(){\n"
"  document.getElementById('refreshLabel').textContent='刷新中...';\n"
"  fetch('/api/data?ts=3600').then(function(r){return r.json()}).then(function(d){\n"
"    data=d;window.__lastData=d;\n"
"    document.getElementById('info').textContent='PID: '+d.pid+' | '+d.proc_name+' | 会话: '+ft(d.session_start)+' | 上次扫描: '+ft(d.last_scan);\n"
"    renderStats(d.stats);draw();renderLeaks(d.leaks);updateSortInd();\n"
"    document.getElementById('refreshLabel').textContent='已刷新 — '+new Date().toLocaleTimeString();\n"
"  }).catch(function(err){\n"
"    console.error('fetch failed:',err);\n"
"    document.getElementById('refreshLabel').textContent='刷新失败，稍后重试';\n"
"  })\n"
"}\n"
"buildLegend();\n"
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
    MTT_DIAG_WRITE(fd, "\"", 1);
    for (const char *p = str; *p != '\0'; p++) {
        unsigned char c = (unsigned char)*p;
        if (c == '"' || c == '\\') {
            MTT_DIAG_WRITE(fd, "\\", 1);
            MTT_DIAG_WRITE(fd, p, 1);
        } else if (c < 0x20) {
            /* 控制字符：编码为 \\u00XX */
            char esc[8];
            int n = snprintf(esc, sizeof(esc), "\\u%04x", (unsigned)c);
            if (n > 0) MTT_DIAG_WRITE(fd, esc, (size_t)n);
        } else {
            MTT_DIAG_WRITE(fd, p, 1);
        }
    }
    MTT_DIAG_WRITE(fd, "\"", 1);
}

/** 处理 GET / — 返回仪表盘 HTML */
static void handle_root(int client_fd)
{
    const char *header =
        "HTTP/1.0 200 OK\r\n"
        "Content-Type: text/html; charset=utf-8\r\n"
        "Cache-Control: no-store, no-cache, max-age=0\r\n"
        "Connection: close\r\n"
        "\r\n";
    MTT_DIAG_WRITE(client_fd, header, strlen(header));
    MTT_DIAG_WRITE(client_fd, g_dashboard_html, strlen(g_dashboard_html));
}

/** 写入单个泄漏站点 JSON */
static void write_leak_json(mtt_leak_site_t *site, mtt_stack_entry_t *se, int fd)
{
    static char buf[4096];

    if (site == NULL) {
        /* 防御：调用者传入 NULL site，写入空对象 */
        MTT_DIAG_WRITE(fd, "{}", 2);
        return;
    }

    int off = snprintf(buf, sizeof(buf),
        "{\"hash\":\"0x%llx\",\"count\":%zu,\"per_leak_size\":%zu,"
        "\"total_size\":%zu,\"diff_size\":%zu,\"is_expired\":%d,"
        "\"conf\":\"%s\",\"late_free\":%u,\"stack_kind\":%d,"
        "\"first_seen\":%lld,\"last_seen\":%lld,\"stack\":[",
        (unsigned long long)site->stack_hash, site->count,
        site->per_leak_size, site->total_size,
        site->diff_size, site->is_expired,
        mtt_conf_str(site->conf), site->late_free_count,
        site->stack_kind,
        (long long)site->first_seen, (long long)site->last_seen);
    /* 防御：snprintf 可能返回 >= sizeof(buf)（truncation 情况），
     * cap 到 (sizeof(buf)-1) 避免读取 buf 越界。正常情况下输出远小于 4096。 */
    if (off < 0) off = 0;
    else if (off >= (int)sizeof(buf)) off = (int)sizeof(buf) - 1;
    MTT_DIAG_WRITE(fd, buf, (size_t)off);

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
            if (wrote_frame) MTT_DIAG_WRITE(fd, ",", 1);
            wrote_frame = 1;
            /* 写入引号包裹的符号字符串，同时转义 JSON 特殊字符。
             * 控制字符（< 0x20）编码为 \\u00XX，与 write_json_string 保持一致。
             * 确保 ARM32 QEMU 等环境下的符号即使包含特殊字节也不破坏 JSON 格式。 */
            MTT_DIAG_WRITE(fd, "\"", 1);
            for (const char *p = sym; *p != '\0'; p++) {
                unsigned char c = (unsigned char)*p;
                if (c == '"' || c == '\\') {
                    MTT_DIAG_WRITE(fd, "\\", 1);
                    MTT_DIAG_WRITE(fd, p, 1);
                } else if (c < 0x20) {
                    char esc[8];
                    int n = snprintf(esc, sizeof(esc), "\\u%04x", (unsigned)c);
                    if (n > 0) MTT_DIAG_WRITE(fd, esc, (size_t)n);
                } else {
                    MTT_DIAG_WRITE(fd, p, 1);
                }
            }
            MTT_DIAG_WRITE(fd, "\"", 1);
        }
    }

    /* 兜底：当所有已解析帧均被内部帧过滤器拦截时，回退输出不过滤的帧。
     * 同样跳过内部帧（mtt_/libmemorytracetool/capture_stack/backtrace），
     * 避免工具内部函数出现在页面。未解析帧降级为 hex 地址。 */
    if (!wrote_frame && se != NULL && se->frame_count > 0) {
        for (int j = 0; j < se->frame_count; j++) {
            if (j == 0) continue; /* 跳过 mtt_capture_stack 自身 */
            const char *fallback_sym = se->resolved[j];
            /* 过滤内部帧和未解析帧 */
            if (fallback_sym == NULL || fallback_sym[0] == '\0'
                || strstr(fallback_sym, "libmemorytracetool") != NULL
                || strstr(fallback_sym, "mtt_") == fallback_sym
                || strstr(fallback_sym, "capture_stack") != NULL
                || strstr(fallback_sym, "backtrace") != NULL)
                continue;
            if (wrote_frame) MTT_DIAG_WRITE(fd, ",", 1);
            wrote_frame = 1;
            /* 输出已解析符号，JSON 转义 */
            MTT_DIAG_WRITE(fd, "\"", 1);
            for (const char *p = fallback_sym; *p != '\0'; p++) {
                unsigned char c = (unsigned char)*p;
                if (c == '"' || c == '\\') {
                    MTT_DIAG_WRITE(fd, "\\", 1);
                    MTT_DIAG_WRITE(fd, p, 1);
                } else if (c < 0x20) {
                    char esc[8];
                    int n = snprintf(esc, sizeof(esc), "\\u%04x", (unsigned)c);
                    if (n > 0) MTT_DIAG_WRITE(fd, esc, (size_t)n);
                } else {
                    MTT_DIAG_WRITE(fd, p, 1);
                }
            }
            MTT_DIAG_WRITE(fd, "\"", 1);
        }
    }

    /* 第三级兜底：业务栈完全未捕获，所有帧都是工具内部（mtt_entry_new /
     * malloc hook 等）。常发生于 ARM32 -fomit-frame-pointer 路径上
     * backtrace 无法 unwind 业务调用栈，只剩工具自身调用链。
     * 此时输出全部未过滤帧，加 [INT] 前缀让用户识别为工具内部栈，
     * 至少能定位 hook 路径，避免页面显示空栈导致 onclick 无响应。
     * 注意：栈顶 j=0（mtt_capture_stack）始终跳过，无诊断价值。 */
    if (!wrote_frame && se != NULL && se->frame_count > 1) {
        for (int j = 1; j < se->frame_count; j++) {
            const char *raw_sym = se->resolved[j];
            if (wrote_frame) MTT_DIAG_WRITE(fd, ",", 1);
            wrote_frame = 1;
            MTT_DIAG_WRITE(fd, "\"[INT] ", 7);
            if (raw_sym != NULL && raw_sym[0] != '\0') {
                for (const char *p = raw_sym; *p != '\0'; p++) {
                    unsigned char c = (unsigned char)*p;
                    if (c == '"' || c == '\\') {
                        MTT_DIAG_WRITE(fd, "\\", 1);
                        MTT_DIAG_WRITE(fd, p, 1);
                    } else if (c < 0x20) {
                        char esc[8];
                        int n = snprintf(esc, sizeof(esc), "\\u%04x", (unsigned)c);
                        if (n > 0) MTT_DIAG_WRITE(fd, esc, (size_t)n);
                    } else {
                        MTT_DIAG_WRITE(fd, p, 1);
                    }
                }
            } else {
                off = snprintf(buf, sizeof(buf), "0x%lx",
                               (unsigned long)(uintptr_t)se->frames[j]);
                if (off < 0) off = 0;
                else if (off >= (int)sizeof(buf)) off = (int)sizeof(buf) - 1;
                MTT_DIAG_WRITE(fd, buf, (size_t)off);
            }
            MTT_DIAG_WRITE(fd, "\"", 1);
        }
    }

    MTT_DIAG_WRITE(fd, "]}", 2);
}

/** 处理 GET /api/data（可选 ?ts=N 指定时序点数，默认 360，上限 3600） */
static void handle_api_data(int client_fd, int ts_points)
{
    mtt_per_thread_t *ctx = mtt_thread_get();
    mtt_reporter_t *rep = mtt_reporter_get();
    const char *header =
        "HTTP/1.0 200 OK\r\n"
        "Content-Type: application/json; charset=utf-8\r\n"
        "Cache-Control: no-store, no-cache, max-age=0\r\n"
        "Connection: close\r\n"
        "\r\n";
    MTT_DIAG_WRITE(client_fd, header, strlen(header));

    mtt_state_t *s = mtt_state_get();
    size_t cur_bytes  = (s != NULL) ? atomic_load_explicit(&s->current_bytes, memory_order_relaxed) : 0;
    size_t peak_bytes = (s != NULL) ? atomic_load_explicit(&s->peak_bytes, memory_order_relaxed) : 0;
    size_t allocs     = (s != NULL) ? atomic_load_explicit(&s->alloc_count, memory_order_relaxed) : 0;
    size_t frees      = (s != NULL) ? atomic_load_explicit(&s->free_count, memory_order_relaxed) : 0;
    size_t total_alloc = (s != NULL) ? atomic_load_explicit(&s->total_bytes, memory_order_relaxed) : 0;
    size_t leak_count = (allocs > frees) ? (allocs - frees) : 0;
    size_t late_free_n = (s != NULL) ? atomic_load_explicit(&s->free_expired_count, memory_order_relaxed) : 0;
    size_t sk_ovc = (s != NULL) ? atomic_load_explicit(&s->skipped_overcap, memory_order_relaxed) : 0;
    size_t sk_slot = (s != NULL) ? atomic_load_explicit(&s->skipped_slots, memory_order_relaxed) : 0;

    /* entry 池指标（工具自身内存占用可视化） */
    size_t pool_used      = (s != NULL) ? atomic_load_explicit(&s->pool_used, memory_order_relaxed) : 0;
    size_t pool_capacity  = (s != NULL) ? s->pool_capacity : 0;
    size_t pool_bytes_total = (s != NULL) ? s->pool_raw_size : 0;
    size_t pool_bytes_used  = pool_used * sizeof(mtt_entry_t);
    int    pool_mode      = (s != NULL) ? atomic_load_explicit(&s->pool_mode, memory_order_relaxed) : MTT_POOL_MODE_NONE;
    /* 读取当前 RSS（近似值）。
     * fopen/fclose 内部触发 libc malloc，设 in_hook 防止被追踪为虚假泄漏。 */
    size_t rss_bytes = 0;
    if (ctx != NULL) {
        int saved_hook = ctx->in_hook;
        ctx->in_hook = 1;
        FILE *fp = fopen("/proc/self/statm", "r");
        if (fp != NULL) {
            long rss_pages = 0;
            if (fscanf(fp, "%*s %ld", &rss_pages) == 1 && rss_pages > 0)
                rss_bytes = (size_t)rss_pages * (size_t)sysconf(_SC_PAGESIZE);
            fclose(fp);
        }
        ctx->in_hook = saved_hook;
    }

    const char *proc_name = "unknown";
    if (s != NULL && s->proc_name_ready && s->proc_name[0] != '\0')
        proc_name = s->proc_name;

    time_t session_ts = (rep != NULL) ? rep->session_start : 0;

    static char buf[8192];
    /* 先写 JSON 开头（到 proc_name 之前），再用 write_json_string 安全输出 proc_name */
    int len = snprintf(buf, sizeof(buf),
        "{\"pid\":%d,\"proc_name\":",
        (int)getpid());
    if (len < 0) len = 0;
    else if (len >= (int)sizeof(buf)) len = (int)sizeof(buf) - 1;
    MTT_DIAG_WRITE(client_fd, buf, (size_t)len);
    write_json_string(client_fd, proc_name);

    len = snprintf(buf, sizeof(buf),
        ",\"session_start\":%lld,\"last_scan\":%lld,"
        "\"stats\":{\"current_bytes\":%zu,\"peak_bytes\":%zu,\"alloc_count\":%zu,"
        "\"free_count\":%zu,\"leak_count\":%zu,\"total_allocated\":%zu,"
        "\"rss_bytes\":%zu,\"late_free\":%zu,"
        "\"skipped_overcap\":%zu,\"skipped_slots\":%zu},"
        "\"pool\":{\"used\":%zu,\"capacity\":%zu,\"bytes_used\":%zu,\"bytes_total\":%zu,\"mode\":%d}",
        (long long)session_ts, (long long)time(NULL),
        cur_bytes, peak_bytes, allocs, frees, leak_count, total_alloc, rss_bytes,
        late_free_n, sk_ovc, sk_slot,
        pool_used, pool_capacity, pool_bytes_used, pool_bytes_total, pool_mode);
    if (len < 0) len = 0;
    else if (len >= (int)sizeof(buf)) len = (int)sizeof(buf) - 1;
    MTT_DIAG_WRITE(client_fd, buf, (size_t)len);

    /* 时序数据 */
    MTT_DIAG_WRITE(client_fd, ",\"time_series\":[", 16);
    if (mtt_ts_is_ready() && raw_malloc != NULL && ts_points > 0) {
        mtt_ts_point_t *ts_buf = (mtt_ts_point_t*)raw_malloc(
            (size_t)ts_points * sizeof(mtt_ts_point_t));
        if (ts_buf != NULL) {
            memset(ts_buf, 0, (size_t)ts_points * sizeof(mtt_ts_point_t));
            uint32_t ts_count = 0;
            mtt_ts_get_range(0, ts_buf, (uint32_t)ts_points, &ts_count);
            int wrote_first = 0;
            for (uint32_t i = 0; i < ts_count; i++) {
                if (ts_buf[i].timestamp == 0) continue;
                if (wrote_first) MTT_DIAG_WRITE(client_fd, ",", 1);
                wrote_first = 1;
                len = snprintf(buf, sizeof(buf),
                    "{\"ts\":%lld,\"cur\":%zu,\"peak\":%zu,\"allocs\":%zu,\"frees\":%zu,\"entries\":%zu,\"rss\":%zu,\"leak\":%zu,\"talloc\":%zu}",
                    (long long)ts_buf[i].timestamp, ts_buf[i].current_bytes,
                    ts_buf[i].peak_bytes, ts_buf[i].alloc_count,
                    ts_buf[i].free_count, ts_buf[i].entry_count,
                    ts_buf[i].rss_bytes, ts_buf[i].leak_bytes,
                    ts_buf[i].total_alloc_bytes);
                if (len < 0) len = 0;
                else if (len >= (int)sizeof(buf)) len = (int)sizeof(buf) - 1;
                MTT_DIAG_WRITE(client_fd, buf, (size_t)len);
            }
            raw_free(ts_buf);
        }
    }
    MTT_DIAG_WRITE(client_fd, "]", 1);

    /* 泄漏站点 — 返回全量(前端做分页,每页 50) */
    MTT_DIAG_WRITE(client_fd, ",\"leaks\":[", 10);
    pthread_mutex_lock(&rep->cache_lock);
    if (rep->cached_sites != NULL && rep->cached_site_count > 0) {
        int wrote_leak = 0;
        for (size_t i = 0; i < rep->cached_site_count; i++) {
            if (rep->cached_sites[i] == NULL) continue;
            if (wrote_leak) MTT_DIAG_WRITE(client_fd, ",", 1);
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
    MTT_DIAG_WRITE(client_fd, "]}", 2);
}

/** 处理 GET /api/leaks */
static void handle_api_leaks(int client_fd)
{
    mtt_reporter_t *rep = mtt_reporter_get();
    const char *header =
        "HTTP/1.0 200 OK\r\n"
        "Content-Type: application/json; charset=utf-8\r\n"
        "Cache-Control: no-store, no-cache, max-age=0\r\n"
        "Connection: close\r\n"
        "\r\n";
    MTT_DIAG_WRITE(client_fd, header, strlen(header));
    MTT_DIAG_WRITE(client_fd, "{\"leaks\":[", 10);

    pthread_mutex_lock(&rep->cache_lock);
    if (rep->cached_sites != NULL && rep->cached_site_count > 0) {
        int wrote_leak = 0;
        for (size_t i = 0; i < rep->cached_site_count; i++) {
            if (rep->cached_sites[i] == NULL) continue;
            if (wrote_leak) MTT_DIAG_WRITE(client_fd, ",", 1);
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
    MTT_DIAG_WRITE(client_fd, "]}", 2);
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
    MTT_DIAG_WRITE(client_fd, header, strlen(header));
    MTT_DIAG_WRITE(client_fd, body, strlen(body));
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

    /* 标记为工具内部线程:本线程的 malloc/free 都透传不追踪 */
    mtt_per_thread_t *ctx = mtt_thread_get();
    if (ctx != NULL) ctx->tool_internal = 1;

    static char req_buf[MTT_HTTP_BUF_SIZE];
    static char path[MTT_HTTP_MAX_PATH];

    while (atomic_load_explicit(&g_http_server.running, memory_order_acquire)) {
        /* 用 poll 替代 select:无 FD_SETSIZE 上限,glibc _FORTIFY_SOURCE 不会
         * 因 fd_set 越界 abort。某些 LD_PRELOAD 场景下 select 会触发
         * "bit out of range 0 - FD_SETSIZE" 误报,poll 完全规避。 */
        struct pollfd pfd;
        pfd.fd = g_http_server.listen_fd;
        pfd.events = POLLIN;
        int ready = poll(&pfd, 1, 1000); /* 1 秒超时 */
        if (ready < 0) {
            if (errno == EINTR || errno == EAGAIN) continue;
            break;
        }
        if (ready == 0) continue;
        if (!(pfd.revents & POLLIN)) continue;

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
        } else {
            /* 剥离 query string（?ts=N 等），路径匹配只看 ? 之前部分 */
            char *query = strchr(path, '?');
            if (query != NULL) {
                *query = '\0';
                query++;
            }
            if (strcmp(path, "/") == 0) {
                handle_root(client_fd);
            } else if (strcmp(path, "/api/data") == 0) {
                /* ?ts=N：时序点数，默认 360，范围 [60, 3600]（1Hz 环上限） */
                int ts_points = 360;
                if (query != NULL) {
                    const char *p = strstr(query, "ts=");
                    if (p != NULL) {
                        int v = atoi(p + 3);
                        if (v > 0) ts_points = v;
                    }
                }
                if (ts_points < 60) ts_points = 60;
                if (ts_points > 3600) ts_points = 3600;
                handle_api_data(client_fd, ts_points);
            } else if (strcmp(path, "/api/leaks") == 0) {
                handle_api_leaks(client_fd);
            } else {
                handle_404(client_fd);
            }
        }
        close(client_fd);
    }
    return NULL;
}

/* ======================================================================== *
 *                     公共接口                                              *
 * ======================================================================== */

uint16_t mtt_http_server_start(uint16_t port)
{
    if (port == 0) return 0;
    if (atomic_load_explicit(&g_http_server.running, memory_order_acquire)) return g_http_server.port;

    /* SIGPIPE 已在 mtt_ensure_init() 中通过 sigaction 全局忽略，
     * 无需在此重复设置。 */

    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) return 0;
    int reuse = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    /* bind 重试逻辑(解决 daemon fork 端口冲突):
     *
     * 场景:进程 fork 后父进程立即退出(daemon 化),子进程成为唯一存活
     * 进程。但子进程 init 在 fork 后立即触发(第一次 malloc),此时父进程
     * 可能还没退出,仍占用请求端口(如 8080) → 子进程 bind 失败。
     *
     * 策略:对请求端口重试若干次(间隔 0.5 秒),等父进程退出后端口释放。
     * 重试耗尽才退到 port+1~port+5 的 fallback 逻辑。
     *
     * 重试参数:4 次 × 0.5 秒 = 最多等 2 秒,足够父进程退出。
     * 用 nanosleep(不依赖 SIGALRM,不影响信号处理)。 */
    #define MTT_HTTP_BIND_RETRIES  4
    #define MTT_HTTP_BIND_RETRY_NS (500 * 1000 * 1000L)  /* 0.5 秒 */

    int bound = 0;

    /* 第一阶段:对请求端口重试(等父进程退出释放端口) */
    addr.sin_port = htons(port);
    for (int attempt = 0; attempt < MTT_HTTP_BIND_RETRIES && !bound; attempt++) {
        if (bind(listen_fd, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
            bound = 1;
            break;
        }
        /* bind 失败:等待 0.5 秒后重试(最后一次失败后不等待,直接进 fallback)。
         * 非 fork 场景(端口真空闲):attempt=0 就 bind 成功,不会等待。 */
        if (attempt < MTT_HTTP_BIND_RETRIES - 1) {
            struct timespec ts = { 0, MTT_HTTP_BIND_RETRY_NS };
            nanosleep(&ts, NULL);
        }
    }

    /* 第二阶段:重试耗尽,尝试 port+1 ~ port+5(fallback) */
    if (!bound) {
        for (int try_port = port + 1; try_port < (int)port + 6; try_port++) {
            addr.sin_port = htons((uint16_t)try_port);
            if (bind(listen_fd, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
                bound = 1; port = (uint16_t)try_port; break;
            }
        }
    }
    if (!bound) { close(listen_fd); return 0; }
    if (listen(listen_fd, MTT_HTTP_BACKLOG) < 0) { close(listen_fd); return 0; }

    g_http_server.listen_fd = listen_fd;
    g_http_server.port = port;
    atomic_store_explicit(&g_http_server.running, 1, memory_order_release);

    pthread_t tid;
    if (pthread_create(&tid, NULL, http_thread_fn, NULL) != 0) {
        atomic_store_explicit(&g_http_server.running, 0, memory_order_release);
        close(listen_fd); return 0;
    }
    g_http_server.thread = tid;

    /* 实际端口可能与请求端口不同(fork 场景:父进程占用了请求端口,
     * 子进程 bind 到 port+1 等)。用 INFO 等级输出,让用户知道实际地址。 */
    if (port != 0) {
        char diag[128];
        int len = snprintf(diag, sizeof(diag), "[MTT] HTTP dashboard: http://0.0.0.0:%u/\n", (unsigned)port);
        if (len > 0 && len < (int)sizeof(diag))
            MTT_LOG_INFO(diag, (size_t)len);
    }
    return port;
}

void mtt_http_server_stop(void)
{
    atomic_store_explicit(&g_http_server.running, 0, memory_order_release);
    if (g_http_server.listen_fd > 0) {
        close(g_http_server.listen_fd);
        g_http_server.listen_fd = -1;
    }
}

/**
 * fork 子进程后重置 HTTP server 状态。
 *
 * 由 tracker.c 的 mtt_fork_child 调用(async-signal-safe 上下文)。
 * 与 stop 的差异:重置 thread/port,让子进程下次 mtt_http_server_start
 * 重新走完整 socket/bind/listen 流程。
 */
void mtt_http_reset_for_fork(void)
{
    atomic_store_explicit(&g_http_server.running, 0, memory_order_release);
    if (g_http_server.listen_fd > 0) {
        close(g_http_server.listen_fd);
        g_http_server.listen_fd = -1;
    }
    g_http_server.thread = 0;
    g_http_server.port = 0;
}

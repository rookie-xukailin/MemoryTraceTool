/* page_functional_check.js — 仪表盘页面功能 17 项 checklist（平台无关）。
 * 在目标页面上下文 evaluate 执行，返回 {pass, fail, details} 汇总。
 * 使用方法：node repl 读取本文件内容作为 evaluate 参数。 */
(function () {
  var R = { pass: 0, fail: 0, items: {} };
  function ok(name, cond, detail) {
    R.items[name] = (cond ? 'PASS' : 'FAIL') + (detail ? ' | ' + detail : '');
    if (cond) R.pass++; else R.fail++;
  }

  /* 1. 加载/头部/统计卡片 */
  var stats = document.getElementById('stats');
  ok('01.load-stats', data !== null && stats && stats.children.length >= 8,
     'cards=' + (stats ? stats.children.length : 0));
  ok('01b.info-line', (document.getElementById('info').textContent || '').indexOf('PID:') >= 0);

  /* 2. 双 Y 轴渲染：画布有内容 + SERIES right 标记存在 */
  var cv = document.getElementById('chart');
  var ctx2 = cv.getContext('2d');
  var px = ctx2.getImageData(0, 0, cv.width, cv.height).data;
  var nonBlank = 0;
  for (var i = 3; i < px.length; i += 400) if (px[i] > 0) nonBlank++;
  var hasRight = false;
  for (var s = 0; s < SERIES.length; s++) if (SERIES[s].right) hasRight = true;
  ok('02.dual-axis', hasRight && nonBlank > 10,
     'rightFlag=' + hasRight + ' painted=' + nonBlank);

  /* 3. 图例开关 */
  var lgBtns = document.getElementById('legend').querySelectorAll('.lg-btn');
  var rssBefore = SERIES[3].on;
  lgBtns[3].click();
  var rssAfter = SERIES[3].on;
  lgBtns[3].click();
  lgBtns[3].click(); /* 保持开启供后续轴验证 */
  var rssFinal = SERIES[3].on;
  ok('03.legend-toggle', rssBefore !== rssAfter && rssFinal === true,
     'before=' + rssBefore + ' after=' + rssAfter);

  /* 4. KB/MB 切换 */
  var yuBefore = yUnit;
  var mbBtn = document.querySelector('.unit-btn[data-unit="mb"]');
  mbBtn.click();
  var yuAfter = yUnit;
  document.querySelector('.unit-btn[data-unit="kb"]').click();
  ok('04.unit-switch', yuBefore === 'kb' && yuAfter === 'mb');

  /* 5. 滚轮缩放（鼠标齿轮 deltaY=±120） */
  var r = cv.getBoundingClientRect();
  var cx = r.left + r.width / 2, cy = r.top + r.height / 2;
  var ts = data.time_series;
  var span0 = ts[ts.length - 1].ts - ts[0].ts;
  for (var w = 0; w < 5; w++)
    cv.dispatchEvent(new WheelEvent('wheel', { deltaY: -120, clientX: cx, clientY: cy, bubbles: true, cancelable: true }));
  var spanZoom = view.t1 - view.t0;
  ok('05.wheel-zoom', spanZoom < span0 && spanZoom >= 60,
     span0 + '->' + Math.round(spanZoom));

  /* 6. 触控板渐进（deltaY=3 连发，在小视图上应继续渐进或触底保持） */
  var before6 = view.t1 - view.t0;
  for (var w2 = 0; w2 < 10; w2++)
    cv.dispatchEvent(new WheelEvent('wheel', { deltaY: 3, clientX: cx, clientY: cy, bubbles: true, cancelable: true }));
  var after6 = view.t1 - view.t0;
  ok('06.touchpad-progressive', after6 >= 60 && after6 !== before6,
     before6 + '->' + Math.round(after6));

  /* 7. 拖拽平移 */
  var p0 = view.t0;
  cv.dispatchEvent(new MouseEvent('mousedown', { clientX: cx, clientY: cy, button: 0, bubbles: true }));
  window.dispatchEvent(new MouseEvent('mousemove', { clientX: cx - 150, clientY: cy, bubbles: true }));
  window.dispatchEvent(new MouseEvent('mouseup', { clientX: cx - 150, clientY: cy, bubbles: true }));
  ok('07.drag-pan', view.t0 !== p0, (view.t0 - p0).toFixed(1) + 's');

  /* 8. 双击复位 */
  cv.dispatchEvent(new MouseEvent('dblclick', { clientX: cx, clientY: cy, bubbles: true }));
  ok('08.dblclick-reset', view.follow === true);

  /* 9. 复位按钮 */
  cv.dispatchEvent(new WheelEvent('wheel', { deltaY: -120, clientX: cx, clientY: cy, bubbles: true, cancelable: true }));
  var shrunk = !view.follow;
  document.getElementById('resetViewBtn').click();
  ok('09.reset-btn', shrunk && view.follow === true);

  /* 10. tooltip + 内容 */
  cv.dispatchEvent(new MouseEvent('mousemove', { clientX: cx, clientY: cy, bubbles: true }));
  var tip = document.getElementById('tip');
  var tipOk = tip.style.display === 'block' && tip.textContent.length > 5;
  if (tipOk) {
    var tx = parseInt(tip.style.left) || 0;
    tipOk = tx >= 0 && tx + tip.offsetWidth <= window.innerWidth + 2;
  }
  ok('10.tooltip', tipOk, (tip.textContent || '').slice(0, 40));
  tip.style.display = 'none';

  /* 11. 排序 */
  var rows0 = document.querySelectorAll('#leaks-tbody tr.leak-row').length;
  sortBy('conf');
  var c1 = (document.querySelectorAll('#leaks-tbody tr.leak-row')[0] || {}).textContent || '';
  var confSorted = c1.indexOf('probable') >= 0 || c1.indexOf('possible') >= 0 || rows0 === 0;
  sortBy('count'); /* 恢复默认 */
  ok('11.sort-by-conf', confSorted, 'rows=' + rows0);

  /* 12. 筛选组按钮存在且默认激活 */
  var grp = document.querySelectorAll('#leakFilters [data-cf]');
  var grpNames = [];
  var activeFound = false;
  for (var g = 0; g < grp.length; g++) {
    grpNames.push(grp[g].getAttribute('data-cf'));
    if (grp[g].className.indexOf('active') >= 0) activeFound = true;
  }
  ok('12.filter-bar', grpNames.indexOf('default') >= 0 && grpNames.indexOf('session') >= 0 && activeFound,
     grpNames.join(','));

  /* 13. 分页控件 */
  ok('13.pagination', document.getElementById('prevPageBtn') && document.getElementById('nextPageBtn') && document.getElementById('pageInfo').textContent.length > 0);

  /* 14. 行展开 + addr2line 命令 */
  var rows = document.querySelectorAll('#leaks-tbody tr.leak-row');
  var expandOk = false, cmdOk = false;
  if (rows.length > 0) {
    rows[0].click();
    var idx = rows[0].getAttribute('data-idx');
    var sr = document.getElementById('s' + idx);
    expandOk = sr && sr.classList.contains('open');
    cmdOk = sr ? sr.innerHTML.indexOf('addr2line') >= 0 : false;
    rows[0].click();
  } else { expandOk = true; cmdOk = true; /* 无数据时跳过 */ }
  ok('14.row-expand-stack', expandOk);
  ok('14b.addr2line-cmd', cmdOk);

  /* 15. 徽标体系（四级 CSS 类存在即可，徽标按数据出现） */
  ok('15.badge-css', document.querySelector('.cf-probable') !== null ||
     document.querySelector('.cf-possible') !== null ||
     document.querySelector('.cf-long_lived') !== null);

  /* 16. session_scoped 默认隐藏（default 筛选激活时无 session 徽标行） */
  var sessVisible = false;
  for (var i2 = 0; i2 < rows.length; i2++) {
    var cf = rows[i2].querySelector('.cf');
    if (cf && cf.textContent.indexOf('session') >= 0) sessVisible = true;
  }
  ok('16.session-hidden-by-default', !sessVisible);

  /* 17. ?ts=N 参数（fetch 验证） */
  return fetch('/api/data?ts=60').then(function (resp) { return resp.json(); })
    .then(function (d60) {
      ok('17.ts-param', d60.time_series && d60.time_series.length <= 60,
         'points=' + d60.time_series.length);
      R.total = R.pass + R.fail;
      return R;
    });
})()

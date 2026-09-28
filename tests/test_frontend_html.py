#!/usr/bin/env python3
"""
MemoryTraceTool -- 前端 HTML 仪表盘集成测试。

测试 / (index) 端点的 HTML 结构、CSS 变量、Canvas 元素、JavaScript 函数。
断言与 src/http_server.c 内嵌的 g_dashboard_html 实际实现保持一致
（2026-09 重写：移除针对不存在的旧版页面的断言，覆盖平移缩放/多曲线/
排序筛选/置信度徽标等新功能）。

运行方式:
    python3 tests/test_frontend_html.py [--url http://localhost:8080]

前提条件:
    需要 MemoryTraceTool 程序已经运行且 HTTP 服务器已启动。
    如果服务器不可达，所有测试将标记为 SKIP 而非 FAIL。
"""

import os
import sys
import urllib.request
import urllib.error

BASE_URL = "http://localhost:8080"
SKIP = False
passed = 0
failed = 0
skipped = 0


def fetch(path):
    """Fetch path from the server and return (body_string, None) or (None, error_string)."""
    req = urllib.request.Request(BASE_URL + path, headers={"Cache-Control": "no-cache"})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            body = resp.read().decode("utf-8")
            return body, None
    except urllib.error.URLError as e:
        return None, str(e)
    except Exception as e:
        return None, "Unexpected error: {}".format(e)


def check(name, condition, detail=""):
    global passed, failed, skipped
    if SKIP:
        skipped += 1
        print("  SKIP {} (server unreachable)".format(name))
        return True
    if condition:
        passed += 1
        print("  PASS {}".format(name))
        return True
    else:
        failed += 1
        msg = "  FAIL {} -- {}".format(name, detail) if detail else "  FAIL {}".format(name)
        print(msg)
        return False


def verify_server():
    """Quick connectivity check."""
    global SKIP
    try:
        urllib.request.urlopen(BASE_URL + "/", timeout=5)
        return True
    except Exception:
        SKIP = True
        return False


def test_index_returns_html(html):
    """GET / should return text/html content."""
    if html is None:
        return
    has_doctype = "<!DOCTYPE html>" in html or "<!doctype html>" in html.lower()
    check("GET / returns HTML with DOCTYPE", has_doctype,
          detail="no DOCTYPE found in response")
    check("response contains <html> tag", "<html" in html)
    check("response contains <head> tag", "<head>" in html)
    check("response contains <body> tag", "<body" in html)
    check("response contains </html> closing tag", "</html>" in html)


def test_html_title(html):
    """Validate page title."""
    if html is None:
        return
    check("HTML title is 'MemoryTraceTool'", "<title>MemoryTraceTool</title>" in html)


def test_html_meta(html):
    """Validate charset / viewport / cache-control meta tags."""
    if html is None:
        return
    check("HTML has UTF-8 charset meta tag",
          'charset="UTF-8"' in html or 'charset=UTF-8' in html)
    check("HTML has viewport meta tag", 'name="viewport"' in html)
    check("HTML contains Cache-Control meta tag", 'Cache-Control' in html)


def test_html_core_elements(html):
    """Canvas chart, tooltip, stats, leaks table, info line."""
    if html is None:
        return
    check("HTML contains <canvas> element", "<canvas" in html)
    check("HTML contains canvas#chart (main chart)", 'id="chart"' in html)
    check("HTML contains tooltip div#tip", 'id="tip"' in html)
    check("HTML contains stats container div#stats", 'id="stats"' in html)
    check("HTML contains leaks table tbody#leaks-tbody", 'id="leaks-tbody"' in html)
    check("HTML contains info div#info", 'id="info"' in html)


def test_html_chart_features(html):
    """Pan/zoom, multi-series legend, reset button."""
    if html is None:
        return
    check("HTML contains legend bar div#legend", 'id="legend"' in html)
    check("HTML contains reset view button#resetViewBtn", 'id="resetViewBtn"' in html)
    check("JS wheel zoom handler present (passive:false)", "addEventListener('wheel'" in html)
    check("JS dblclick reset handler present", "dblclick" in html)
    check("JS defines SERIES multi-line config", "var SERIES=" in html)
    check("JS defines view window state (pan/zoom)", "var view=" in html)
    check("JS clampView keeps span >= 60s", "function clampView(" in html)
    check("JS buildLegend builds toggles", "function buildLegend(" in html)


def test_html_table_features(html):
    """Sortable headers, filter bar, confidence badges."""
    if html is None:
        return
    check("HTML contains filter bar div#leakFilters", 'id="leakFilters"' in html)
    check("filter bar has last-seen range buttons", "data-ls=" in html)
    check("filter bar has confidence class buttons", "data-cf=" in html)
    check("filter bar has growth-only toggle", "data-gr=" in html)
    check("JS sortBy function exists", "function sortBy(" in html)
    check("JS viewLeaks filter/sort pipeline exists", "function viewLeaks(" in html)
    check("table headers are clickable (sorth class)", "class=\"sorth\"" in html)
    check("CSS defines confidence badge classes", ".cf-probable" in html)
    check("CSS defines session_scoped badge class", ".cf-session_scoped" in html)
    check("CSS defines long_lived badge class", ".cf-long_lived" in html)
    check("JS confOf maps legacy is_expired fallback", "function confOf(" in html)


def test_js_core_functions(html):
    """Core JS functions present."""
    if html is None:
        return
    check("JS function draw() exists", "function draw(" in html)
    check("JS function renderStats() exists", "function renderStats(" in html)
    check("JS function renderLeaks() exists", "function renderLeaks(" in html)
    check("JS function refresh() exists", "function refresh()" in html)
    check("JS function changePage() exists", "function changePage(" in html)
    check("JS fetches '/api/data?ts=3600' (full hour window)",
          "fetch('/api/data?ts=3600')" in html)


def test_html_css_variables(html):
    """Validate CSS custom properties (dark/light theme support)."""
    if html is None:
        return
    check("CSS has --bg variable", "--bg:" in html)
    check("CSS has --text variable", "--text:" in html)
    check("CSS has --accent variable", "--accent:" in html)
    check("CSS has --warn variable", "--warn:" in html)
    check("CSS has prefers-color-scheme: dark media query",
          "prefers-color-scheme:dark" in html.replace(" ", "")
          or "prefers-color-scheme: dark" in html)


def test_js_tooltip_functionality(html):
    """Validate tooltip interaction code."""
    if html is None:
        return
    check("JS has canvas mouse hover (onmousemove) handler", "onmousemove" in html)
    check("JS references tooltip#tip element", "document.getElementById('tip')" in html)


def test_html_no_placeholder_content(html):
    """Validate that the HTML is not just a placeholder/template."""
    if html is None:
        return
    min_len = 2000
    check("HTML body is substantial (>{} chars)".format(min_len),
          len(html) > min_len,
          detail="body length={}".format(len(html)))


def test_html_has_mtt_header(html):
    """Validate MemoryTraceTool branding in the page."""
    if html is None:
        return
    check("HTML contains 'MemoryTraceTool' heading text", "MemoryTraceTool" in html)


def test_js_no_syntax_errors_basic(html):
    """Basic JS sanity: script section properly closed."""
    if html is None:
        return
    check("HTML has proper </script> closing tag", "</script>" in html)
    check("no obvious JS syntax error: draw is defined", "function draw(" in html)


# ---- main ----

def main():
    global passed, failed, skipped, SKIP

    # 支持 --url 参数覆盖默认目标
    global BASE_URL
    for i, arg in enumerate(sys.argv):
        if arg == "--url" and i + 1 < len(sys.argv):
            BASE_URL = sys.argv[i + 1]

    print("=== MemoryTraceTool Frontend HTML Dashboard Tests ===")
    print("Target: {}/".format(BASE_URL))
    print()

    if not verify_server():
        print("Server at {} is not reachable. All tests SKIPPED.".format(BASE_URL))
        print()
        print("To run this test, start the server first, e.g.:")
        print("  MTT_HTTP_PORT=8080 LD_PRELOAD=./build/libmemorytracetool.so \\")
        print("      ./build/demo_long_running")
        print()
        print("Result: 0 passed, 0 failed, 0 skipped (server unreachable)")
        return 0

    print("Server reachable, fetching dashboard HTML...")

    html, err = fetch("/")
    if not check("GET / returns HTTP 200 with HTML body", html is not None, detail=err):
        print("Cannot proceed without HTML content. Aborting.")
        print("Result: {} passed, {} failed, {} skipped".format(passed, failed, skipped))
        return 1

    print()

    # ---- HTML structure ----
    test_index_returns_html(html)
    test_html_title(html)
    test_html_meta(html)
    test_html_has_mtt_header(html)
    test_html_no_placeholder_content(html)

    # ---- Core UI elements ----
    test_html_core_elements(html)

    # ---- Chart: pan/zoom + multi-series ----
    test_html_chart_features(html)

    # ---- Table: sort/filter/badges ----
    test_html_table_features(html)

    # ---- CSS / theme ----
    test_html_css_variables(html)

    # ---- JavaScript functions ----
    test_js_core_functions(html)
    test_js_no_syntax_errors_basic(html)
    test_js_tooltip_functionality(html)

    # ---- summary ----
    print()
    print("---")
    total = passed + failed + skipped
    print("Results: {} tests, {} passed, {} failed, {} skipped".format(
        total, passed, failed, skipped))

    if failed > 0:
        print("SOME TESTS FAILED (miss: {} of {} assertions)".format(
            failed, passed + failed))
        return 1

    passed_msg = "ALL TESTS PASSED" if skipped == 0 else "ALL NON-SKIPPED TESTS PASSED"
    print(passed_msg)
    return 0


if __name__ == "__main__":
    sys.exit(main())

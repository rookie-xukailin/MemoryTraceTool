#!/usr/bin/env python3
"""
MemoryTraceTool -- 前端 HTML 仪表盘集成测试。

测试 / (index) 端点的 HTML 结构、CSS 变量、Canvas 元素、JavaScript 函数。

运行方式:
    python3 tests/test_frontend_html.py [--url http://localhost:8080]

前提条件:
    需要 MemoryTraceTool 程序已经运行且 HTTP 服务器已启动。
    如果服务器不可达，所有测试将标记为 SKIP 而非 FAIL。
"""

import json
import os
import re
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
    # The HTML is served from a static const string embedded in C code
    has_doctype = "<!DOCTYPE html>" in html or "<!doctype html>" in html.lower()
    check("GET / returns HTML with DOCTYPE", has_doctype,
          detail="no DOCTYPE found in response")

    has_html_tag = "<html" in html
    check("response contains <html> tag", has_html_tag)

    has_head_tag = "<head>" in html
    check("response contains <head> tag", has_head_tag)

    has_body_tag = "<body>" in html
    check("response contains <body> tag", has_body_tag)

    has_closing_html = "</html>" in html
    check("response contains </html> closing tag", has_closing_html)


def test_html_title(html):
    """Validate page title."""
    if html is None:
        return
    has_title = "<title>MemoryTraceTool</title>" in html
    check("HTML title is 'MemoryTraceTool'", has_title)


def test_html_meta_charset(html):
    """Validate charset meta tag."""
    if html is None:
        return
    has_charset = 'charset="UTF-8"' in html or "charset='UTF-8'" in html or \
                  'charset=UTF-8' in html
    check("HTML has UTF-8 charset meta tag", has_charset)


def test_html_has_viewport_meta(html):
    """Validate viewport meta tag for responsive design."""
    if html is None:
        return
    has_viewport = 'name="viewport"' in html
    check("HTML has viewport meta tag", has_viewport)


def test_html_has_canvas(html):
    """Validate that the page has a <canvas> element for the chart."""
    if html is None:
        return
    has_canvas = '<canvas' in html
    check("HTML contains <canvas> element", has_canvas)

    # Check for the main chart canvas specifically
    has_chart_canvas = 'id="chart"' in html
    check("HTML contains canvas#chart (main chart)", has_chart_canvas)

    # Check for histogram canvas
    has_histogram_canvas = 'id="histogram"' in html
    check("HTML contains canvas#histogram", has_histogram_canvas)


def test_html_has_tooltip(html):
    """Validate tooltip div for chart hover."""
    if html is None:
        return
    has_tooltip = 'id="tip"' in html
    check("HTML contains tooltip div#tip", has_tooltip)


def test_html_has_stats_container(html):
    """Validate stats display container."""
    if html is None:
        return
    has_stats = 'id="stats"' in html
    check("HTML contains stats container div#stats", has_stats)


def test_html_has_leaks_table(html):
    """Validate leaks table structure."""
    if html is None:
        return
    has_tbody = 'id="leaks-tbody"' in html
    check("HTML contains leaks table tbody#leaks-tbody", has_tbody)


def test_html_has_header_info(html):
    """Validate page header / info line."""
    if html is None:
        return
    has_info = 'id="info"' in html
    check("HTML contains info div#info", has_info)


def test_js_drawchart_function(html):
    """Validate that drawChart() JavaScript function is present."""
    if html is None:
        return
    has_fn = "function drawChart()" in html
    check("JS function drawChart() exists", has_fn,
          detail="drawChart function not found in HTML source")


def test_js_renderstats_function(html):
    """Validate renderStats function."""
    if html is None:
        return
    has_fn = "function renderStats(" in html
    check("JS function renderStats() exists", has_fn)


def test_js_renderleaks_function(html):
    """Validate renderLeaks function."""
    if html is None:
        return
    has_fn = "function renderLeaks(" in html
    check("JS function renderLeaks() exists", has_fn)


def test_js_refresh_function(html):
    """Validate refresh function that calls fetch('/api/data')."""
    if html is None:
        return
    has_fn = "function refresh()" in html
    check("JS function refresh() exists", has_fn)


def test_js_fetch_api_data(html):
    """Validate that JS fetches /api/data endpoint."""
    if html is None:
        return
    fetches_api = "fetch('/api/data')" in html or 'fetch("/api/data")' in html
    check("JS fetches '/api/data'", fetches_api,
          detail="no fetch('/api/data') call found")


def test_js_formatbytes_function(html):
    """Validate formatBytes utility function."""
    if html is None:
        return
    has_fn = "function formatBytes(" in html
    check("JS function formatBytes() exists", has_fn)


def test_html_css_variables(html):
    """Validate CSS custom properties (dark/light theme support)."""
    if html is None:
        return
    # Root variables for light theme
    has_bg_var = "--bg:" in html
    check("CSS has --bg variable", has_bg_var)

    has_text_var = "--text:" in html
    check("CSS has --text variable", has_text_var)

    has_accent_var = "--accent:" in html
    check("CSS has --accent variable", has_accent_var)


def test_html_dark_mode_support(html):
    """Validate dark mode CSS media query / data-theme support."""
    if html is None:
        return
    has_dark = "prefers-color-scheme: dark" in html
    check("CSS has prefers-color-scheme: dark media query", has_dark)

    has_data_theme = "[data-theme=" in html
    check("CSS has [data-theme] selectors for manual toggle", has_data_theme)


def test_html_has_refresh_toggle(html):
    """Validate auto-refresh toggle button."""
    if html is None:
        return
    has_btn = 'id="refreshBtn"' in html
    check("HTML has refresh toggle button#refreshBtn", has_btn)

    has_fn = "function toggleRefresh()" in html
    check("JS function toggleRefresh() exists", has_fn)


def test_html_has_theme_toggle(html):
    """Validate theme toggle button."""
    if html is None:
        return
    has_btn = 'id="themeBtn"' in html
    check("HTML has theme toggle button#themeBtn", has_btn)

    has_fn = "function toggleTheme()" in html
    check("JS function toggleTheme() exists", has_fn)


def test_html_has_filter_bar(html):
    """Validate leak filter functionality."""
    if html is None:
        return
    has_fn = "function filterLeaks(" in html
    check("JS function filterLeaks() exists", has_fn)

    has_btn = 'id="fAll"' in html
    check("HTML has filter button#fAll", has_btn)


def test_js_no_syntax_errors_basic(html):
    """Basic JS sanity: no unmatched script tags or empty function bodies that would obviously crash."""
    if html is None:
        return
    # The script section should be properly closed
    has_script_close = "</script>" in html
    check("HTML has proper </script> closing tag", has_script_close)

    # No stray "undefined" object references (common paste errors)
    # This is a weak check; real JS validation would need a headless browser
    check("no obvious JS syntax error: drawChart is defined", "function drawChart()" in html)


def test_html_no_placeholder_content(html):
    """Validate that the HTML is not just a placeholder/template."""
    if html is None:
        return
    # The embedded HTML should be substantial (not a stub)
    min_len = 2000  # The real dashboard is >10000 chars
    check("HTML body is substantial (>{} chars)".format(min_len),
          len(html) > min_len,
          detail="body length={}".format(len(html)))


def test_html_has_mtt_header(html):
    """Validate MemoryTraceTool branding in the page."""
    if html is None:
        return
    has_h1 = "MemoryTraceTool" in html
    check("HTML contains 'MemoryTraceTool' heading text", has_h1)


def test_html_cache_control(html):
    """Validate the embedded HTML includes Cache-Control: no-cache meta."""
    if html is None:
        return
    # The meta tag in the head
    has_meta = 'Cache-Control' in html
    check("HTML contains Cache-Control meta tag", has_meta)


def test_js_tooltip_functionality(html):
    """Validate tooltip interaction code."""
    if html is None:
        return
    # Check for onmousemove handler on the canvas
    has_mousemove = "onmousemove" in html or "addEventListener('mousemove'" in html
    check("JS has canvas mouse hover (onmousemove) handler", has_mousemove)

    has_tooltip_ref = "document.getElementById('tip')" in html
    check("JS references tooltip#tip element", has_tooltip_ref)


def test_js_compact_array_format(html):
    """Validate JS references the compact time_series array format [t,c,p,a,f,e]."""
    if html is None:
        return
    # The JS defines index constants
    has_idx = "IDX_T=" in html
    check("JS defines IDX_T index constant", has_idx)

    has_idx_cur = "IDX_CUR=" in html
    check("JS defines IDX_CUR index constant", has_idx_cur)

    has_idx_peak = "IDX_PEAK=" in html
    check("JS defines IDX_PEAK index constant", has_idx_peak)

    has_idx_allocs = "IDX_ALLOCS=" in html
    check("JS defines IDX_ALLOCS index constant", has_idx_allocs)


def test_js_histogram_drawing(html):
    """Validate histogram drawing code."""
    if html is None:
        return
    has_fn = "function drawHistogram()" in html
    check("JS function drawHistogram() exists", has_fn)


# ---- main ----

def main():
    global passed, failed, skipped, SKIP

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

    # Fetch the page
    html, err = fetch("/")
    if not check("GET / returns HTTP 200 with HTML body", html is not None, detail=err):
        print("Cannot proceed without HTML content. Aborting.")
        print("Result: {} passed, {} failed, {} skipped".format(passed, failed, skipped))
        return 1

    print()

    # ---- HTML structure ----
    test_index_returns_html(html)
    test_html_title(html)
    test_html_meta_charset(html)
    test_html_has_viewport_meta(html)
    test_html_has_mtt_header(html)
    test_html_cache_control(html)
    test_html_no_placeholder_content(html)

    # ---- Canvas and UI elements ----
    test_html_has_canvas(html)
    test_html_has_tooltip(html)
    test_html_has_stats_container(html)
    test_html_has_leaks_table(html)
    test_html_has_header_info(html)
    test_html_has_refresh_toggle(html)
    test_html_has_theme_toggle(html)
    test_html_has_filter_bar(html)

    # ---- CSS / theme ----
    test_html_css_variables(html)
    test_html_dark_mode_support(html)

    # ---- JavaScript functions ----
    test_js_drawchart_function(html)
    test_js_renderstats_function(html)
    test_js_renderleaks_function(html)
    test_js_refresh_function(html)
    test_js_fetch_api_data(html)
    test_js_formatbytes_function(html)
    test_js_no_syntax_errors_basic(html)
    test_js_tooltip_functionality(html)
    test_js_compact_array_format(html)
    test_js_histogram_drawing(html)

    # ---- summary ----
    print()
    print("---")
    total = passed + failed + skipped
    print("Results: {} tests, {} passed, {} failed, {} skipped".format(
        total, passed, failed, skipped))

    if failed > 0:
        found_msg = "SOME TESTS FAILED (miss: {} of {} assertions)".format(
            failed, passed + failed)
        print(found_msg)
        return 1

    passed_msg = "ALL TESTS PASSED" if skipped == 0 else "ALL NON-SKIPPED TESTS PASSED"
    print(passed_msg)
    return 0


if __name__ == "__main__":
    sys.exit(main())

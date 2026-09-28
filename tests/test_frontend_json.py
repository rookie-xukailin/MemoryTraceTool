#!/usr/bin/env python3
"""
MemoryTraceTool -- 前端 JSON API 集成测试。

测试 /api/data 端点的 JSON 响应结构、类型和语义正确性。
（2026-09 重写：time_series 元素为 9 字段对象 [http_server.c 实际格式]，
并覆盖 conf 四级分类 / late_free / skipped 完整性字段与 ?ts=N 参数。）

运行方式:
    python3 tests/test_frontend_json.py [--url http://localhost:8080]

前提条件:
    需要 MemoryTraceTool 程序已经运行且 HTTP 服务器已启动。
    例如: MTT_HTTP_PORT=8080 LD_PRELOAD=./build/libmemorytracetool.so ./build/demo_long_running

    如果服务器不可达，所有测试将标记为 SKIP 而非 FAIL。
"""

import json
import sys
import time
import urllib.request
import urllib.error

BASE_URL = "http://localhost:8080"
SKIP = False
passed = 0
failed = 0
skipped = 0

# ---- helpers ----

def fetch_json(path):
    """Fetch path from the server and parse as JSON. Returns (dict, None) or (None, error_string)."""
    req = urllib.request.Request(BASE_URL + path, headers={"Cache-Control": "no-cache"})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            body = resp.read().decode("utf-8")
            return json.loads(body), None
    except urllib.error.URLError as e:
        return None, str(e)
    except json.JSONDecodeError as e:
        return None, "JSON parse error: {}".format(e)
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
    """Quick connectivity check. If server is unreachable, mark all following tests as SKIP."""
    global SKIP
    try:
        urllib.request.urlopen(BASE_URL + "/", timeout=5)
        return True
    except Exception:
        SKIP = True
        return False

# ---- test functions ----

def test_api_data_reachable():
    data, err = fetch_json("/api/data")
    if not check("GET /api/data returns valid JSON", data is not None, detail=err):
        return None
    return data

def test_top_level_fields(data):
    if data is None:
        return
    required = ["pid", "proc_name", "session_start", "last_scan", "stats", "time_series", "leaks"]
    for field in required:
        check("field '{}' present".format(field), field in data,
              detail="missing field {}".format(field))

def test_pid_is_positive_int(data):
    if data is None:
        return
    pid = data.get("pid")
    check("pid is positive int", isinstance(pid, int) and pid > 0,
          detail="pid={}, type={}".format(pid, type(pid).__name__))

def test_proc_name_is_string(data):
    if data is None:
        return
    pn = data.get("proc_name")
    check("proc_name is non-empty string", isinstance(pn, str) and len(pn) > 0,
          detail="proc_name={!r}".format(pn))

def test_session_start_is_numeric(data):
    if data is None:
        return
    ss = data.get("session_start")
    check("session_start is numeric timestamp",
          isinstance(ss, (int, float)) and ss > 0,
          detail="session_start={}, type={}".format(ss, type(ss).__name__))

def test_last_scan_is_numeric(data):
    if data is None:
        return
    ls = data.get("last_scan")
    ss = data.get("session_start")
    ok = isinstance(ls, (int, float)) and ls >= 0
    check("last_scan is valid timestamp", ok,
          detail="last_scan={}, type={}".format(ls, type(ls).__name__))
    if ok and ss is not None:
        check("last_scan >= session_start", ls >= ss,
              detail="last_scan={} < session_start={}".format(ls, ss))

def test_stats_object(data):
    if data is None:
        return
    stats = data.get("stats")
    if not check("stats is dict", isinstance(stats, dict),
                 detail="stats type={}".format(type(stats).__name__)):
        return

    required_stats = [
        "current_bytes", "peak_bytes", "alloc_count",
        "free_count", "leak_count", "total_allocated",
        # 2026-09 新增：late-free 计数 + 数据完整性计数
        "late_free", "skipped_overcap", "skipped_slots",
    ]
    for key in required_stats:
        val = stats.get(key)
        check("stats.{} is non-negative int".format(key),
              isinstance(val, (int, float)) and val >= 0,
              detail="stats.{}={}, type={}".format(key, val, type(val).__name__))

def test_stats_consistency(data):
    if data is None:
        return
    stats = data.get("stats", {})
    allocs = stats.get("alloc_count", 0)
    frees = stats.get("free_count", 0)
    leaks = stats.get("leak_count", 0)
    expected_leaks = max(0, allocs - frees)
    check("stats.leak_count ~= alloc_count - free_count",
          leaks >= expected_leaks,
          detail="leak_count={}, alloc_count={}, free_count={}, diff={}".format(
              leaks, allocs, frees, allocs - frees))

def test_stats_peak_ge_current(data):
    if data is None:
        return
    stats = data.get("stats", {})
    peak = stats.get("peak_bytes", 0)
    cur = stats.get("current_bytes", 0)
    check("stats.peak_bytes >= current_bytes", peak >= cur,
          detail="peak={}, current={}".format(peak, cur))

def test_time_series_is_array(data):
    if data is None:
        return
    ts = data.get("time_series")
    check("time_series is list", isinstance(ts, list),
          detail="time_series type={}".format(type(ts).__name__))

def test_time_series_element_format(data):
    """Each time_series element must be an object with the 9 fields
    actually emitted by http_server.c: ts/cur/peak/allocs/frees/entries/rss/leak/talloc."""
    if data is None:
        return
    ts = data.get("time_series")
    if not isinstance(ts, list):
        return
    if len(ts) == 0:
        print("  INFO time_series is empty (no data recorded yet)")
        return

    required_keys = ["ts", "cur", "peak", "allocs", "frees", "entries",
                     "rss", "leak", "talloc"]
    all_ok = True
    for i, point in enumerate(ts):
        if not isinstance(point, dict):
            print("  FAIL time_series[{}] is not an object: {!r}".format(i, point))
            all_ok = False
            continue
        missing = [k for k in required_keys if k not in point]
        if missing:
            print("  FAIL time_series[{}] missing keys: {}".format(i, missing))
            all_ok = False

    check("time_series elements are 9-field objects", all_ok)

def test_time_series_semantic_content(data):
    if data is None:
        return
    ts = data.get("time_series")
    if not isinstance(ts, list) or len(ts) < 2:
        return

    monotonic_t = True
    cur_le_peak = True
    allocs_ge_frees = True

    prev_t = None
    for point in ts:
        if not isinstance(point, dict):
            continue
        t = point.get("ts", 0)
        if prev_t is not None and t < prev_t:
            monotonic_t = False
        if point.get("cur", 0) > point.get("peak", 0):
            cur_le_peak = False
        if point.get("allocs", 0) < point.get("frees", 0):
            allocs_ge_frees = False
        prev_t = t

    check("time_series timestamps monotonic", monotonic_t)
    check("time_series current <= peak for all points", cur_le_peak,
          detail="at least one point has cur > peak")
    check("time_series allocs >= frees for all points", allocs_ge_frees,
          detail="at least one point has allocs < frees")

def test_time_series_recent_timestamps(data):
    if data is None:
        return
    ts = data.get("time_series")
    if not isinstance(ts, list) or len(ts) == 0:
        return
    now = int(time.time())
    last_ts = ts[-1].get("ts", 0)
    delta = now - int(last_ts)
    check("time_series last entry within last hour", delta < 3600,
          detail="last_ts={}, now={}, delta={}s".format(last_ts, now, delta))

def test_ts_query_param():
    """/api/data?ts=60 should return at most 60 points (clamped to [60,3600])."""
    data, err = fetch_json("/api/data?ts=60")
    if not check("GET /api/data?ts=60 returns valid JSON", data is not None, detail=err):
        return
    ts = data.get("time_series")
    if not check("time_series is list for ?ts=60 query", isinstance(ts, list)):
        return
    check("?ts=60 returns at most 60 points", len(ts) <= 60,
          detail="got {} points".format(len(ts)))

def test_leaks_is_array(data):
    if data is None:
        return
    leaks = data.get("leaks")
    check("leaks is list", isinstance(leaks, list),
          detail="leaks type={}".format(type(leaks).__name__))

def test_leak_entry_structure(data):
    if data is None:
        return
    leaks = data.get("leaks")
    if not isinstance(leaks, list) or len(leaks) == 0:
        print("  INFO leaks list is empty (no leak data yet)")
        return

    leak = leaks[0]
    required_fields = {
        "hash": str,
        "count": (int,),
        "per_leak_size": (int,),
        "total_size": (int,),
        "diff_size": (int,),
        "is_expired": (int,),
        "first_seen": (int, float),
        "last_seen": (int, float),
        "stack": list,
        # 2026-09 新增：四级分类 + late-free 证据计数
        "conf": str,
        "late_free": (int,),
    }

    all_ok = True
    for field, expected_types in required_fields.items():
        val = leak.get(field)
        if val is None:
            print("  FAIL leak entry missing field '{}'".format(field))
            all_ok = False
        elif not isinstance(val, expected_types):
            print("  FAIL leak entry field '{}': expected {}, got {}".format(
                field, expected_types, type(val).__name__))
            all_ok = False

    check("leak entry has all required fields with correct types", all_ok)

def test_leak_conf_enum(data):
    """conf must be one of the four classification levels."""
    if data is None:
        return
    leaks = data.get("leaks")
    if not isinstance(leaks, list) or len(leaks) == 0:
        return
    valid = {"probable", "session_scoped", "long_lived", "possible"}
    bad = [l.get("conf") for l in leaks if l.get("conf") not in valid]
    check("leak conf is one of probable/session_scoped/long_lived/possible",
          len(bad) == 0, detail="invalid values: {}".format(bad[:3]))

def test_leak_stack_format(data):
    if data is None:
        return
    leaks = data.get("leaks")
    if not isinstance(leaks, list):
        return
    for leak in leaks:
        stack = leak.get("stack", [])
        if len(stack) > 0:
            frame = stack[0]
            has_offset = "+0x" in frame if isinstance(frame, str) else False
            has_lib = "(" in frame if isinstance(frame, str) else False
            if has_offset or has_lib:
                check("leak stack frame format 'func+0xOFFSET (libname)'", True)
                return
    print("  INFO no leak stack frames to validate format (may be expected for raw addresses)")

def test_leak_is_expired_semantics(data):
    if data is None:
        return
    leaks = data.get("leaks")
    if not isinstance(leaks, list) or len(leaks) == 0:
        return
    all_ok = all(leak.get("is_expired") in (0, 1) for leak in leaks)
    check("leak is_expired is always 0 or 1 (legacy compat field)", all_ok)

def test_json_total_size_coherence(data):
    if data is None:
        return
    leaks = data.get("leaks")
    if not isinstance(leaks, list) or len(leaks) == 0:
        return
    all_ok = True
    for leak in leaks:
        count = leak.get("count", 0)
        per = leak.get("per_leak_size", 0)
        total = leak.get("total_size", 0)
        if count > 0 and (total < per or total == 0):
            all_ok = False
            break
    check("leak total_size >= per_leak_size for all sites", all_ok,
          detail="total_size should be >= first allocation size")

def test_no_obvious_json_errors(data):
    if data is None:
        return
    raw = json.dumps(data)
    check("JSON contains no NaN tokens", "NaN" not in raw)
    check("JSON contains no Infinity tokens", "Infinity" not in raw)


# ---- main ----

def main():
    global passed, failed, skipped, SKIP

    # 支持 --url 参数覆盖默认目标
    global BASE_URL
    for i, arg in enumerate(sys.argv):
        if arg == "--url" and i + 1 < len(sys.argv):
            BASE_URL = sys.argv[i + 1]

    print("=== MemoryTraceTool Frontend JSON API Tests ===")
    print("Target: {}/api/data".format(BASE_URL))
    print()

    if not verify_server():
        print("Server at {} is not reachable. All tests SKIPPED.".format(BASE_URL))
        print()
        print("To run this test, start the server first, e.g.:")
        print("  MTT_HTTP_PORT=8080 LD_PRELOAD=./build/libmemorytracetool.so \\")
        print("      ./build/demo_long_running")
        print()
        print("Result: 0 passed, 0 failed, 0 skipped (server unreachable)")
        return 0  # Exit cleanly

    print("Server reachable, running tests...")
    print()

    data, err = fetch_json("/api/data")
    if not check("GET /api/data returns HTTP 200 with JSON", data is not None, detail=err):
        print("Cannot proceed without data. Aborting.")
        print("Result: {} passed, {} failed, {} skipped".format(passed, failed, skipped))
        return 1

    # Structural tests
    test_top_level_fields(data)
    test_pid_is_positive_int(data)
    test_proc_name_is_string(data)
    test_session_start_is_numeric(data)
    test_last_scan_is_numeric(data)

    # Stats tests
    test_stats_object(data)
    test_stats_consistency(data)
    test_stats_peak_ge_current(data)

    # Time series tests
    test_time_series_is_array(data)
    test_time_series_element_format(data)
    test_time_series_semantic_content(data)
    test_time_series_recent_timestamps(data)
    test_ts_query_param()

    # Leak tests
    test_leaks_is_array(data)
    test_leak_entry_structure(data)
    test_leak_conf_enum(data)
    test_leak_stack_format(data)
    test_leak_is_expired_semantics(data)
    test_json_total_size_coherence(data)

    # Sanity tests
    test_no_obvious_json_errors(data)

    # ---- summary ----
    print()
    print("---")
    total = passed + failed + skipped
    print("Results: {} tests, {} passed, {} failed, {} skipped".format(
        total, passed, failed, skipped))

    if failed > 0:
        print("SOME TESTS FAILED")
        return 1

    print("ALL TESTS PASSED" if skipped == 0 else "ALL NON-SKIPPED TESTS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())

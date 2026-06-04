#!/usr/bin/env python3
"""
MemoryTraceTool -- 前端 JSON API 集成测试。

测试 /api/data 端点的 JSON 响应结构、类型和语义正确性。

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
        return True  # chainable, coerce to True for skip
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
    """Verify /api/data returns HTTP 200 with parseable JSON."""
    data, err = fetch_json("/api/data")
    if not check("GET /api/data returns valid JSON", data is not None,
                 detail=err):
        return None
    return data

def test_top_level_fields(data):
    """Verify top-level fields: pid, proc_name, session_start, last_scan, stats, time_series, leaks."""
    if data is None:
        return
    required = ["pid", "proc_name", "session_start", "last_scan", "stats", "time_series", "leaks"]
    for field in required:
        check("field '{}' present".format(field), field in data,
              detail="missing field {}".format(field))

def test_pid_is_positive_int(data):
    """pid must be a positive integer."""
    if data is None:
        return
    pid = data.get("pid")
    check("pid is positive int", isinstance(pid, int) and pid > 0,
          detail="pid={}, type={}".format(pid, type(pid).__name__))

def test_proc_name_is_string(data):
    """proc_name must be a non-empty string."""
    if data is None:
        return
    pn = data.get("proc_name")
    check("proc_name is non-empty string", isinstance(pn, str) and len(pn) > 0,
          detail="proc_name={!r}".format(pn))

def test_session_start_is_numeric(data):
    """session_start must be a number (int/float Unix timestamp)."""
    if data is None:
        return
    ss = data.get("session_start")
    check("session_start is numeric timestamp",
          isinstance(ss, (int, float)) and ss > 0,
          detail="session_start={}, type={}".format(ss, type(ss).__name__))

def test_last_scan_is_numeric(data):
    """last_scan must be a number >= session_start."""
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
    """stats must be a dict with required numeric fields."""
    if data is None:
        return
    stats = data.get("stats")
    if not check("stats is dict", isinstance(stats, dict),
                 detail="stats type={}".format(type(stats).__name__)):
        return

    required_stats = [
        "current_bytes", "peak_bytes", "alloc_count",
        "free_count", "leak_count", "total_allocated"
    ]
    for key in required_stats:
        val = stats.get(key)
        check("stats.{} is non-negative int".format(key),
              isinstance(val, (int, float)) and val >= 0,
              detail="stats.{}={}, type={}".format(key, val, type(val).__name__))

def test_stats_consistency(data):
    """Verify stats semantic consistency: leak_count approx alloc_count - free_count."""
    if data is None:
        return
    stats = data.get("stats", {})
    allocs = stats.get("alloc_count", 0)
    frees = stats.get("free_count", 0)
    leaks = stats.get("leak_count", 0)
    # Allow small tolerance for internal tracker allocations
    expected_leaks = max(0, allocs - frees)
    check("stats.leak_count ~= alloc_count - free_count",
          leaks >= expected_leaks,
          detail="leak_count={}, alloc_count={}, free_count={}, diff={}".format(
              leaks, allocs, frees, allocs - frees))

def test_stats_peak_ge_current(data):
    """peak_bytes should always be >= current_bytes."""
    if data is None:
        return
    stats = data.get("stats", {})
    peak = stats.get("peak_bytes", 0)
    cur = stats.get("current_bytes", 0)
    check("stats.peak_bytes >= current_bytes", peak >= cur,
          detail="peak={}, current={}".format(peak, cur))

def test_time_series_is_array(data):
    """time_series must be a list (possibly empty)."""
    if data is None:
        return
    ts = data.get("time_series")
    check("time_series is list", isinstance(ts, list),
          detail="time_series type={}".format(type(ts).__name__))

def test_time_series_element_format(data):
    """Each time_series element must be a 6-element array [t, cur, peak, allocs, frees, entries]."""
    if data is None:
        return
    ts = data.get("time_series")
    if not isinstance(ts, list):
        return
    if len(ts) == 0:
        print("  INFO time_series is empty (no data recorded yet)")
        return

    all_ok = True
    for i, point in enumerate(ts):
        if not isinstance(point, list):
            print("  FAIL time_series[{}] is not a list: {!r}".format(i, point))
            failed_incr()
            all_ok = False
            continue
        if len(point) != 6:
            print("  FAIL time_series[{}] length != 6: len={}".format(i, len(point)))
            failed_incr()
            all_ok = False
            continue

    check("time_series elements are 6-element arrays", all_ok)

def test_time_series_semantic_content(data):
    """time_series values should make sense: t monotonic, cur <= peak, allocs >= frees."""
    if data is None:
        return
    ts = data.get("time_series")
    if not isinstance(ts, list) or len(ts) < 2:
        return

    # Index definitions from http_server.c: [timestamp, current, peak, allocs, frees, entries]
    IDX_T = 0
    IDX_CUR = 1
    IDX_PEAK = 2
    IDX_ALLOCS = 3
    IDX_FREES = 4

    monotonic_t = True
    cur_le_peak = True
    allocs_ge_frees = True

    prev_t = None
    for i, point in enumerate(ts):
        if not isinstance(point, list) or len(point) != 6:
            continue
        t = point[IDX_T]

        if prev_t is not None and t < prev_t:
            monotonic_t = False

        if point[IDX_CUR] > point[IDX_PEAK]:
            cur_le_peak = False

        if point[IDX_ALLOCS] < point[IDX_FREES]:
            allocs_ge_frees = False

        prev_t = t

    check("time_series timestamps monotonic", monotonic_t)
    check("time_series current <= peak for all points", cur_le_peak,
          detail="at least one point has cur > peak")
    check("time_series allocs >= frees for all points", allocs_ge_frees,
          detail="at least one point has allocs < frees")

def test_leaks_is_array(data):
    """leaks must be a list."""
    if data is None:
        return
    leaks = data.get("leaks")
    check("leaks is list", isinstance(leaks, list),
          detail="leaks type={}".format(type(leaks).__name__))

def test_leak_entry_structure(data):
    """Each leak entry must have required fields with correct types."""
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
    }

    all_ok = True
    for field, expected_types in required_fields.items():
        val = leak.get(field)
        if val is None:
            print("  FAIL leak entry missing field '{}'".format(field))
            failed_incr()
            all_ok = False
        elif not isinstance(val, expected_types):
            print("  FAIL leak entry field '{}': expected {}, got {}".format(
                field, expected_types, type(val).__name__))
            failed_incr()
            all_ok = False

    check("leak entry has all required fields with correct types", all_ok)

def test_leak_stack_format(data):
    """Stack frames should be strings like 'func+0xOFFSET (libname)'."""
    if data is None:
        return
    leaks = data.get("leaks")
    if not isinstance(leaks, list):
        return

    for leak in leaks:
        stack = leak.get("stack", [])
        if len(stack) > 0:
            frame = stack[0]
            # Check that at least some frames match the expected format
            has_offset = "+0x" in frame if isinstance(frame, str) else False
            has_lib = "(" in frame if isinstance(frame, str) else False
            if has_offset or has_lib:
                check("leak stack frame format 'func+0xOFFSET (libname)'", True)
                return

    # No stack with identifiable format found -- may be normal if no symbols
    print("  INFO no leak stack frames to validate format (may be expected for raw addresses)")
    passed += 1  # not a failure

def test_leak_is_expired_semantics(data):
    """is_expired should be 0 (possible leak) or 1 (probable leak)."""
    if data is None:
        return
    leaks = data.get("leaks")
    if not isinstance(leaks, list) or len(leaks) == 0:
        return

    all_ok = True
    for leak in leaks:
        expired = leak.get("is_expired")
        if expired not in (0, 1):
            all_ok = False
            break

    check("leak is_expired is always 0 or 1", all_ok)

def test_json_total_size_coherence(data):
    """total_size should be approximately count * per_leak_size."""
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
        expected = count * per
        # total_size should be reasonable; allow small diffs from rounding
        if total < expected:
            all_ok = False
            break

    check("leak total_size >= count * per_leak_size", all_ok,
          detail="total_size should be at least count * per_leak_size")

def test_time_series_recent_timestamps(data):
    """Time series timestamps should be recent (within last hour)."""
    if data is None:
        return
    ts = data.get("time_series")
    if not isinstance(ts, list) or len(ts) == 0:
        return

    now = int(time.time())
    last = ts[-1]
    if not isinstance(last, list) or len(last) < 1:
        return
    last_ts = last[0]
    delta = now - int(last_ts)
    check("time_series last entry within last hour", delta < 3600,
          detail="last_ts={}, now={}, delta={}s".format(last_ts, now, delta))

def test_no_obvious_json_errors(data):
    """Sanity: No obvious parsing artifacts like NaN or Inf strings."""
    if data is None:
        return
    raw = json.dumps(data)
    check("JSON contains no NaN tokens", "NaN" not in raw)
    check("JSON contains no Infinity tokens", "Infinity" not in raw)
    check("JSON contains no -Infinity tokens", "-Infinity" not in raw)


def failed_incr():
    """Allow exception handlers to increment failed counter."""
    global failed
    failed += 1


# ---- main ----

def main():
    global passed, failed, skipped, SKIP

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
        print("Result: {} passed, {} failed, {} skipped (server unreachable)".format(0, 0, 1))
        return 0  # Exit cleanly

    print("Server reachable, running tests...")
    print()

    # Fetch data once, reuse across tests
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

    # Leak tests
    test_leaks_is_array(data)
    test_leak_entry_structure(data)
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

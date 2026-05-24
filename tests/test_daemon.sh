#!/bin/bash
#
# 守护进程 / Web 看板 API 功能测试。
#
# 启动 mttd → 测试 HTTP API 端点 → 关闭 mttd → 报告结果。
#
# 用法: make test_daemon  或直接  bash tests/test_daemon.sh
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJ_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
MTTD="$PROJ_DIR/build/mttd"

# 自动选择可用端口
pick_port() {
    local p
    for p in 18080 18081 18082 19080 19081; do
        if ! ss -ltn 2>/dev/null | grep -q ":$p "; then
            echo "$p"
            return 0
        fi
    done
    echo $((RANDOM % 10000 + 20000))
}

PASS=0
FAIL=0
TOTAL=0

pass() { PASS=$((PASS + 1)); TOTAL=$((TOTAL + 1)); printf "  %-45s PASS\n" "$1"; }
fail() { FAIL=$((FAIL + 1)); TOTAL=$((TOTAL + 1)); printf "  %-45s FAIL: %s\n" "$1" "$2"; }

PORT=$(pick_port)
BASE="http://localhost:$PORT"
MTTD_PID=""

cleanup() {
    if [ -n "${MTTD_PID:-}" ] && kill -0 "$MTTD_PID" 2>/dev/null; then
        kill "$MTTD_PID" 2>/dev/null || true
        wait "$MTTD_PID" 2>/dev/null || true
    fi
    # 确保端口释放
    local leftover
    leftover=$(ss -ltnp 2>/dev/null | grep ":$PORT " | awk '{print $NF}' | grep -oP 'pid=\K\d+' || true)
    if [ -n "${leftover:-}" ]; then
        kill "$leftover" 2>/dev/null || true
    fi
}
trap cleanup EXIT

echo "=== MemoryTraceTool 守护进程 / 看板 API 测试 ==="
echo ""

# ---- 1. 启动守护进程 ----
echo "[启动] 启动 mttd 在端口 $PORT ..."
"$MTTD" "$PORT" &
MTTD_PID=$!
sleep 1

# 确认进程存活
if ! kill -0 "$MTTD_PID" 2>/dev/null; then
    fail "daemon startup" "mttd 进程未成功启动"
    echo ""
    echo "Results: $PASS/$TOTAL tests passed"
    exit 1
fi

# 等待端口就绪（最多 3 秒）
for i in $(seq 1 30); do
    if curl -s -o /dev/null --max-time 1 "$BASE/" 2>/dev/null; then
        break
    fi
    if [ "$i" -eq 30 ]; then
        fail "daemon startup" "端口 $PORT 在 3 秒内未就绪"
        echo ""
        echo "Results: $PASS/$TOTAL tests passed"
        exit 1
    fi
    sleep 0.1
done
pass "daemon startup (pid=$MTTD_PID, port=$PORT)"

# ---- 2. GET / → 返回 HTML 看板页面 ----
HTTP_CODE=$(curl -s -o /tmp/mtt_test_index.html -w '%{http_code}' --max-time 3 "$BASE/")
if [ "$HTTP_CODE" = "200" ] && grep -qi '<html\|<!DOCTYPE' /tmp/mtt_test_index.html; then
    pass "GET / returns HTML dashboard"
else
    fail "GET / returns HTML dashboard" "HTTP $HTTP_CODE"
fi

# ---- 3. GET /api/data → 返回合法 JSON ----
DATA=$(curl -s --max-time 3 "$BASE/api/data")
if echo "$DATA" | python3 -c "import sys,json; d=json.load(sys.stdin); assert 'nprocs' in d; assert 'procs' in d" 2>/dev/null; then
    pass "GET /api/data returns valid JSON"
else
    fail "GET /api/data returns valid JSON" "response: ${DATA:0:120}"
fi

# ---- 4. GET /api/reset → 返回 status ok ----
RESET=$(curl -s --max-time 3 "$BASE/api/reset")
if echo "$RESET" | python3 -c "import sys,json; d=json.load(sys.stdin); assert d.get('status')=='ok'" 2>/dev/null; then
    pass "GET /api/reset returns status ok"
else
    fail "GET /api/reset returns status ok" "response: ${RESET:0:120}"
fi

# ---- 5. GET /api/injected → 返回合法 JSON ----
INJ=$(curl -s --max-time 3 "$BASE/api/injected")
if echo "$INJ" | python3 -c "import sys,json; json.load(sys.stdin)" 2>/dev/null; then
    pass "GET /api/injected returns valid JSON"
else
    fail "GET /api/injected returns valid JSON" "response: ${INJ:0:120}"
fi

# ---- 6. GET /api/addr2line → 用 /bin/ls 的偏移 0 测试 ----
# /bin/ls 通常没有调试符号，返回 ?? 也算正常
ADDR2=$(curl -s --max-time 3 "$BASE/api/addr2line?bin=/bin/ls&off=0x0")
if echo "$ADDR2" | python3 -c "import sys,json; d=json.load(sys.stdin); assert 'result' in d" 2>/dev/null; then
    pass "GET /api/addr2line returns result field"
else
    fail "GET /api/addr2line returns result field" "response: ${ADDR2:0:120}"
fi

# ---- 7. 未知路径返回 HTML（SPA fallback，预期行为） ----
UNKNOWN=$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 "$BASE/nonexistent")
if [ "$UNKNOWN" = "200" ]; then
    pass "GET /nonexistent SPA fallback (expected)"
else
    fail "GET /nonexistent SPA fallback (expected)" "HTTP $UNKNOWN"
fi

# ---- 8. 健康检查：多次请求 /api/data 不崩溃 ----
STABLE=1
for i in $(seq 1 5); do
    if ! curl -s --max-time 3 "$BASE/api/data" >/dev/null; then
        STABLE=0
        break
    fi
done
if [ "$STABLE" -eq 1 ]; then
    pass "5 consecutive GET /api/data stable"
else
    fail "5 consecutive GET /api/data stable" "request $i failed"
fi

# ---- 9. Content-Type 头检查 ----
CT=$(curl -s -o /dev/null -w '%{content_type}' --max-time 3 "$BASE/api/data")
if echo "$CT" | grep -q 'application/json'; then
    pass "Content-Type is application/json"
else
    fail "Content-Type is application/json" "got: $CT"
fi

# ---- 清理 ----
cleanup
rm -f /tmp/mtt_test_index.html

echo ""
echo "---"
echo "Results: $PASS/$TOTAL tests passed"

[ "$FAIL" -eq 0 ] && exit 0 || exit 1

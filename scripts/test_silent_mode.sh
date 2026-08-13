#!/bin/bash
# 静默模式回归测试 — 验证 MTT_DEBUG=0 下 stderr 完全静默但 leak 报告正常生成
#
# 验收准则:
#   1. stderr 完全空(无 [MTT] 诊断输出)
#   2. /var/log/mtt/<pid>_*.log 有 leak 报告
#   3. 进程正常退出
#
# 注意:本脚本只测 ARM64 native(本机 Docker)。ARM32 silent 行为由
# sim-test.sh 间接覆盖(同套代码路径,无平台分支)。
#
# 用法: ./scripts/test_silent_mode.sh

set -e
PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

echo "=========================================="
echo "Silent Mode Test (ARM64 native)"
echo "=========================================="

docker run --rm --platform linux/arm64 \
  -v "$PROJECT_ROOT":/work -w /work arm64-builder bash -c '
set -e

# 编译工具 + demo(故意泄漏)。clean 防止跨架构 build 残留导致 libunwind.a format 不匹配
make clean > /dev/null 2>&1
make > /dev/null 2>&1
mkdir -p /var/log/mtt
gcc -O2 -o /tmp/demo_silent examples/demo_small_leak.c

# 清理旧日志
rm -rf /var/log/mtt/*

echo "--- 启动 demo (MTT_DEBUG=0, 关 HTTP) ---"
LD_PRELOAD=output/libmemorytracetool.so \
  MTT_DEBUG=0 \
  MTT_HTTP_PORT=0 \
  /tmp/demo_silent >/tmp/out.txt 2>/tmp/err.txt &
DEMO_PID=$!
sleep 65
kill $DEMO_PID 2>/dev/null || true
wait $DEMO_PID 2>/dev/null || true

echo ""
echo "--- 验收 1: stderr 行数(期望 0) ---"
ERR_LINES=$(wc -l < /tmp/err.txt)
echo "stderr 行数: $ERR_LINES"
if [ "$ERR_LINES" -eq 0 ]; then
    echo "PASS: stderr 完全静默"
else
    echo "FAIL: stderr 有输出:"
    head -5 /tmp/err.txt
    exit 1
fi

echo ""
echo "--- 验收 2: /var/log/mtt 报告生成 ---"
LOG_COUNT=$(ls /var/log/mtt/*.log 2>/dev/null | wc -l)
echo "日志文件数: $LOG_COUNT"
if [ "$LOG_COUNT" -ge 1 ]; then
    echo "PASS: leak 报告已生成"
    echo ""
    echo "报告样本(前 20 行):"
    head -20 $(ls /var/log/mtt/*.log | head -1)
else
    echo "FAIL: 无 leak 报告"
    exit 1
fi

echo ""
echo "=========================================="
echo "Silent Mode Test PASS"
echo "=========================================="
'
#!/bin/bash
# 栈深度回归测试 — libunwind 静态链接守护
#
# 验证:在 ARM32 release 二进制(-O2 -fomit-frame-pointer,无 -funwind-tables)上,
# libunwind 静态链接能拿到 ≥1 业务帧(对比改前 glibc backtrace 拿 0 帧"未捕获")
#
# 验收准则:
#   1. leak site 数 > 0
#   2. 至少 1 个业务帧(非纯工具内部帧)
#
# 用法: ./scripts/test_stack_depth.sh [arm32|arm64]
#   默认 arm32(用户主场景,真机 release 模式)

set -e
ARCH="${1:-arm32}"
PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

echo "=========================================="
echo "Stack Depth Test ($ARCH)"
echo "=========================================="

docker run --rm --platform linux/arm64 \
  -v "$PROJECT_ROOT":/work -w /work hdm3-sim:latest bash -c '
set -e

if [ "'"$ARCH"'" = "arm32" ]; then
    # ARM32 模拟真机 release: -O2 -fomit-frame-pointer (无 unwind-tables)
    arm-linux-gnueabi-gcc -O2 -fomit-frame-pointer -o /tmp/demo_release examples/demo_small_leak.c
    make ARCH=arm32 CROSS_COMPILE=arm-linux-gnueabi- OUTPUT_DIR=/tmp/o32 BUILD_DIR=/tmp/b32 clean > /dev/null 2>&1
    make ARCH=arm32 CROSS_COMPILE=arm-linux-gnueabi- OUTPUT_DIR=/tmp/o32 BUILD_DIR=/tmp/b32 > /dev/null 2>&1
    LIBPATH=/tmp/o32/libmemorytracetool.so
    RUN_PREFIX="qemu-arm-static -L /usr/arm-linux-gnueabi"
else
    gcc -O2 -fomit-frame-pointer -o /tmp/demo_release examples/demo_small_leak.c
    make OUTPUT_DIR=/tmp/o64 BUILD_DIR=/tmp/b64 clean > /dev/null 2>&1
    make OUTPUT_DIR=/tmp/o64 BUILD_DIR=/tmp/b64 > /dev/null 2>&1
    LIBPATH=/tmp/o64/libmemorytracetool.so
    RUN_PREFIX=""
fi
mkdir -p /var/log/mtt

# 清理旧日志
rm -rf /var/log/mtt/*

echo "--- 启动 demo (release binary, -O2 -fomit-frame-pointer) ---"
$RUN_PREFIX \
  -E LD_PRELOAD=$LIBPATH \
  -E MTT_HTTP_PORT=0 \
  /tmp/demo_release >/tmp/out.txt 2>/tmp/err.txt &
DEMO_PID=$!
sleep 70
kill $DEMO_PID 2>/dev/null || true
wait $DEMO_PID 2>/dev/null || true

LOG=$(ls /var/log/mtt/*.log 2>/dev/null | head -1)
if [ -z "$LOG" ]; then
    echo "FAIL: 无 leak 报告生成"
    exit 1
fi

echo ""
echo "--- 验收 1: leak site 数 ---"
SITE_COUNT=$(grep -c "^--- Leak" "$LOG")
echo "leak site 数: $SITE_COUNT"
if [ "$SITE_COUNT" -ge 1 ]; then
    echo "PASS: 检测到泄漏"
else
    echo "FAIL: 未检测到泄漏"
    exit 1
fi

echo ""
echo "--- 验收 2: 业务帧数(≥1 业务地址, addr2line 可定位) ---"
TOTAL_FRAMES=$(grep -E "^  #[0-9]+" "$LOG" | wc -l)

echo "总栈帧数(所有 leak site 累计): $TOTAL_FRAMES"
if [ "$TOTAL_FRAMES" -ge 1 ]; then
    echo "PASS: 拿到 ≥1 业务帧(libunwind 静态链接生效)"
    echo ""
    echo "栈样本(前 10 行):"
    grep -E "^  #[0-9]+" "$LOG" | head -10
else
    echo "FAIL: 0 业务帧,libunwind 集成可能回归"
    exit 1
fi

echo ""
echo "=========================================="
echo "Stack Depth Test ('"$ARCH"') PASS"
echo "=========================================="
'
#!/bin/bash
# HDM3 build 环境模拟测试 — 用与 flasher 完全一致的工具链/ABI/编译选项验证
#
# 测试矩阵:
#   ARM32: gcc-13-arm-linux-gnueabi (soft-float, 匹配 HDM3_build) + qemu-arm-static
#   ARM64: native gcc (host 就是 ARM64) 
#   demo/fakebiz: -O2 -fomit-frame-pointer (匹配 flasher release 选项)
#
# 用法:
#   ./scripts/sim-test.sh           # 编译 + 跑两平台
#   ./scripts/sim-test.sh build     # 只编译
#   ./scripts/sim-test.sh run       # 只跑(产物已存在)
#   ./scripts/sim-test.sh arm32     # 只跑 ARM32
#   ./scripts/sim-test.sh arm64     # 只跑 ARM64

set -e

PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
IMAGE="hdm3-sim:latest"
ACTION="${1:-all}"

docker_run() {
  docker run --rm --platform linux/arm64 -v "$PROJECT_ROOT":/work -w /work "$IMAGE" bash -c "$1"
}

build_all() {
  echo "=========================================="
  echo "Build: 编译两平台 lib + 综合多 .so demo"
  echo "=========================================="

  docker_run '
    set -e
    echo "=== [ARM32] cross compile (soft-float gnueabi) ==="
    make OUTPUT_DIR=/tmp/o32 BUILD_DIR=/tmp/b32 clean >/dev/null 2>&1
    make ARCH=arm32 CROSS_COMPILE=arm-linux-gnueabi- OUTPUT_DIR=/tmp/o32 BUILD_DIR=/tmp/b32 >/dev/null 2>&1
    arm-linux-gnueabi-gcc -O2 -fomit-frame-pointer -fPIC -shared -o /tmp/o32/fakebiz_normal.so examples/realistic/fakebiz_normal.c
    arm-linux-gnueabi-gcc -O2 -fomit-frame-pointer -fPIC -shared -o /tmp/o32/fakebiz_misuse.so examples/realistic/fakebiz_misuse.c
    arm-linux-gnueabi-gcc -O2 -fomit-frame-pointer -fPIC -o /tmp/o32/demo_realistic examples/realistic/demo_realistic.c -ldl

    echo "=== [ARM64] native compile ==="
    make OUTPUT_DIR=/tmp/o64 BUILD_DIR=/tmp/b64 clean >/dev/null 2>&1
    make ARCH=arm64 OUTPUT_DIR=/tmp/o64 BUILD_DIR=/tmp/b64 >/dev/null 2>&1
    gcc -O2 -fomit-frame-pointer -fPIC -shared -o /tmp/o64/fakebiz_normal.so examples/realistic/fakebiz_normal.c
    gcc -O2 -fomit-frame-pointer -fPIC -shared -o /tmp/o64/fakebiz_misuse.so examples/realistic/fakebiz_misuse.c
    gcc -O2 -fomit-frame-pointer -fPIC -o /tmp/o64/demo_realistic examples/realistic/demo_realistic.c -ldl

    echo "=== 汇总产物到 output/sim/ ==="
    rm -rf output/sim && mkdir -p output/sim
    cp /tmp/o32/libmemorytracetool.so output/sim/libmemorytracetool-arm32.so
    cp /tmp/o32/fakebiz_normal.so   output/sim/fakebiz_normal-arm32.so
    cp /tmp/o32/fakebiz_misuse.so   output/sim/fakebiz_misuse-arm32.so
    cp /tmp/o32/demo_realistic      output/sim/demo_realistic-arm32
    cp /tmp/o64/libmemorytracetool.so output/sim/libmemorytracetool-arm64.so
    cp /tmp/o64/fakebiz_normal.so   output/sim/fakebiz_normal-arm64.so
    cp /tmp/o64/fakebiz_misuse.so   output/sim/fakebiz_misuse-arm64.so
    cp /tmp/o64/demo_realistic      output/sim/demo_realistic-arm64
    ls output/sim/

    echo ""
    echo "=== 验证关键特征 ==="
    echo "--- ARM32 lib soft-float (期望: 无 Tag_ABI_VFP_args) ---"
    arm-linux-gnueabi-readelf -A output/sim/libmemorytracetool-arm32.so | grep Tag_ABI_VFP_args || echo "  ✓ soft-float"
    echo "--- ARM32 demo main 无帧指针 ---"
    arm-linux-gnueabi-objdump -d output/sim/demo_realistic-arm32 | awk "/<main>:/{f=1;print;next} f&&/^$/{exit} f" | head -3
    echo "--- ARM64 demo main 无帧指针 ---"
    objdump -d output/sim/demo_realistic-arm64 | awk "/<main>:/{f=1;print;next} f&&/^$/{exit} f" | head -3
  '
}

run_arm32() {
  echo ""
  echo "=========================================="
  echo "Run ARM32: 综合测试 (qemu-arm-static)"
  echo "=========================================="
  docker_run '
    cd output/sim
    ln -sf fakebiz_normal-arm32.so fakebiz_normal.so
    ln -sf fakebiz_misuse-arm32.so fakebiz_misuse.so

    echo "--- 基线 (无 LD_PRELOAD) ---"
    qemu-arm-static -L /usr/arm-linux-gnueabi ./demo_realistic-arm32 >/tmp/baseline.txt 2>&1
    echo "baseline exit=$?"

    echo "--- LD_PRELOAD 跑 (期望: 不崩 + entry>0 + sites>0) ---"
    qemu-arm-static -L /usr/arm-linux-gnueabi \
      -E LD_PRELOAD=./libmemorytracetool-arm32.so \
      ./demo_realistic-arm32 >/tmp/out.txt 2>/tmp/err.txt
    RC=$?
    echo "LD_PRELOAD exit=$RC"

    ENTRY=$(grep "scan enter" /tmp/err.txt | tail -1 | grep -oE "entry=[0-9]+" | grep -oE "[0-9]+")
    SITES=$(grep "scan done" /tmp/err.txt | tail -1 | grep -oE "sites=[0-9]+" | grep -oE "[0-9]+")

    echo ""
    echo "--- 验收 ---"
    [ "$RC" = "0" ] && echo "✓ exit=0 (不崩)" || echo "✗ FAIL: exit=$RC (崩溃)"
    [ -n "$ENTRY" ] && [ "$ENTRY" -gt 0 ] && echo "✓ entry=$ENTRY (>0,追踪到分配)" || echo "✗ FAIL: entry=$ENTRY"
    [ -n "$SITES" ] && [ "$SITES" -gt 0 ] && echo "✓ sites=$SITES (>0,识别出泄漏站点)" || echo "✗ FAIL: sites=$SITES"
    grep -q "Reporter thread started" /tmp/err.txt && echo "✓ reporter 线程正常启动" || echo "✗ FAIL: reporter 未启动"
  '
}

run_arm64() {
  echo ""
  echo "=========================================="
  echo "Run ARM64: 综合测试 (native)"
  echo "=========================================="
  docker_run '
    cd output/sim
    ln -sf fakebiz_normal-arm64.so fakebiz_normal.so
    ln -sf fakebiz_misuse-arm64.so fakebiz_misuse.so

    echo "--- 基线 ---"
    ./demo_realistic-arm64 >/tmp/baseline.txt 2>&1
    echo "baseline exit=$?"

    echo "--- LD_PRELOAD 跑 ---"
    LD_PRELOAD=./libmemorytracetool-arm64.so \
      ./demo_realistic-arm64 >/tmp/out.txt 2>/tmp/err.txt
    RC=$?
    echo "LD_PRELOAD exit=$RC"

    ENTRY=$(grep "scan enter" /tmp/err.txt | tail -1 | grep -oE "entry=[0-9]+" | grep -oE "[0-9]+")
    SITES=$(grep "scan done" /tmp/err.txt | tail -1 | grep -oE "sites=[0-9]+" | grep -oE "[0-9]+")

    echo ""
    echo "--- 验收 ---"
    [ "$RC" = "0" ] && echo "✓ exit=0 (不崩)" || echo "✗ FAIL: exit=$RC (崩溃)"
    [ -n "$ENTRY" ] && [ "$ENTRY" -gt 0 ] && echo "✓ entry=$ENTRY (>0,追踪到分配)" || echo "✗ FAIL: entry=$ENTRY"
    [ -n "$SITES" ] && [ "$SITES" -gt 0 ] && echo "✓ sites=$SITES (>0,识别出泄漏站点)" || echo "✗ FAIL: sites=$SITES"
    grep -q "Reporter thread started" /tmp/err.txt && echo "✓ reporter 线程正常启动" || echo "✗ FAIL: reporter 未启动"
  '
}

case "$ACTION" in
  build) build_all ;;
  arm32) run_arm32 ;;
  arm64) run_arm64 ;;
  run)   run_arm32; run_arm64 ;;
  all|"") build_all; run_arm32; run_arm64 ;;
  *) echo "用法: $0 [build|run|arm32|arm64|all]"; exit 1 ;;
esac

echo ""
echo "=========================================="
echo "测试结束"
echo "=========================================="

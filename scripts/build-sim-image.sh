#!/bin/bash
# 一键构建 HDM3 build 模拟环境 (hdm3-sim:latest)
#
# 镜像内容:
#   - Ubuntu 24.04 ARM64 (匹配 Colima arch)
#   - gcc-13-arm-linux-gnueabi (ARM32 cross, soft-float, 与 HDM3_build ABI 一致)
#   - native gcc (ARM64 host 直接编)
#   - qemu-arm-static (跑 ARM32 binary)
#
# 用法:
#   ./scripts/build-sim-image.sh           # 构建
#   ./scripts/build-sim-image.sh --force   # 强制重建(不使用缓存)

set -e
PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$PROJECT_ROOT"

EXTRA_ARGS=""
if [ "$1" = "--force" ]; then
    EXTRA_ARGS="--no-cache"
fi

echo "Building hdm3-sim:latest ..."
docker build --platform linux/arm64 -f Dockerfile.hdm3-sim -t hdm3-sim:latest $EXTRA_ARGS .

echo ""
echo "Build 完成。验证:"
docker run --rm --platform linux/arm64 hdm3-sim:latest bash -c '
    echo "  Native ARM64: $(gcc --version | head -1)"
    echo "  ARM32 cross:  $(arm-linux-gnueabi-gcc --version | head -1)"
    echo "  qemu-arm:     $(qemu-arm-static --version | head -1)"
    ls /usr/arm-linux-gnueabi/lib/libc.so.6 > /dev/null && echo "  ARM32 sysroot: OK"
'
echo ""
echo "现在可以跑 ./scripts/sim-test.sh 做两平台综合测试"

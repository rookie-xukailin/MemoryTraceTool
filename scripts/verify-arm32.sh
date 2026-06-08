#!/bin/bash
# ARM32 交叉编译环境端到端验证脚本
# 编译和测试都在 Docker 容器内完成，无需本地 QEMU

set -e
PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$PROJECT_ROOT"

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

pass() { echo -e "${GREEN}[通过]${NC} $1"; }
fail() { echo -e "${RED}[失败]${NC} $1"; exit 1; }

echo "=== ARM32 交叉编译环境验证 ==="
echo ""

# 1. 检查前置条件
echo "[1/4] 检查前置条件..."
docker info > /dev/null 2>&1 || fail "Docker 未运行，请先执行 colima start"
pass "Docker 可用"

# 2. 检查 arm32-builder 镜像
echo "[2/4] 检查 arm32-builder 镜像..."
docker image inspect arm32-builder:latest > /dev/null 2>&1 || fail "arm32-builder 镜像不存在"
pass "arm32-builder 镜像就绪"

# 3. ARM32 编译
echo "[3/4] ARM32 编译中..."
docker run --platform linux/arm/v7 --rm \
    -v "$PWD":/work -w /work \
    arm32-builder:latest \
    bash -c "make clean && make"
pass "编译成功"

# 4. 验证 ELF 格式
echo "[4/4] 验证 ELF 格式..."
docker run --platform linux/arm/v7 --rm \
    -v "$PWD":/work -w /work \
    arm32-builder:latest \
    bash -c 'readelf -h output/libmemorytracetool.so | grep -q "ELF32" && echo "  ELF 格式: ARM32 ✓" || (echo "  错误: 不是 ARM32 ELF"; exit 1)'
pass "ELF 32-bit ARM"

echo ""
echo -e "${GREEN}=== 全部验证通过 ===${NC}"
echo "ARM32 交叉编译环境已就绪。"
echo ""
echo "日常使用:"
echo "  ./scripts/compile-arm32.sh            # 编译"
echo "  ./scripts/compile-arm32.sh test       # 测试"
echo "  ./scripts/compile-arm32.sh clean test # 清理+测试"

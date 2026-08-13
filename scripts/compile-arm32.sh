#!/bin/bash
# ARM32 交叉编译脚本（复用 arm32-builder Docker 镜像）
# 用法: ./scripts/compile-arm32.sh [make 目标...]
#   ./scripts/compile-arm32.sh              # 编译共享库
#   ./scripts/compile-arm32.sh test         # 编译并运行测试
#   ./scripts/compile-arm32.sh clean test   # 清理并测试

set -e
PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
docker run --platform linux/arm/v7 --rm \
  -v "$PROJECT_ROOT":/work -w /work \
  arm32-builder:latest \
  make "$@"

#!/bin/bash
# ARM64 原生编译脚本（复用 arm64-builder Docker 镜像）
# 用法: ./scripts/compile-arm64.sh [make 目标...]
#   ./scripts/compile-arm64.sh              # 编译共享库
#   ./scripts/compile-arm64.sh test         # 编译并运行测试
#   ./scripts/compile-arm64.sh clean test   # 清理并测试

set -e
PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
docker run --rm \
  -v "$PROJECT_ROOT":/work -w /work \
  arm64-builder:latest \
  make "$@"

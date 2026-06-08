# MemoryTraceTool - C/C++ Memory Leak Detector

## Build

```bash
make          # 编译静态库和动态库
make test     # 编译并运行测试
make clean    # 清理构建产物
```

## Workflow

编码完成后必须遵循以下流程：

1. **编辑代码** — 修改 `.c`/`.h` 文件
2. **ARM64 编译+测试** — 立即运行 `./scripts/compile-arm64.sh clean test`，确保编译通过且 36 个测试全部通过
3. **ARM32 交叉编译+测试** — 运行 `./scripts/compile-arm32.sh clean test`，确保 ARM32 环境下编译通过且 36 个测试全部通过
4. **两个平台全部通过** → 直接主动提交，无需询问用户
5. **任一平台失败** → 修复错误，回到步骤 2，**禁止在编译失败或测试不通过时提交**

每次编辑源文件后，必须主动跑两个平台的编译+测试验证，不需要等用户提醒。
两个平台都通过后，直接主动提交，无需询问用户。

**macOS 环境特殊规则**：不执行 `git push`，推送到远端由用户在终端手动完成。

## 编码规范

1. **每个函数都要有函数头（doxygen 风格 `/** ... */`）**，说明用途、参数、返回值
2. **必要的注释必须添加**，解释性内容必须用中文
3. 结构体成员、宏定义、关键算法逻辑旁边应有简短中文注释说明意图

## 重要规则

**禁止破坏已有功能** — 修改任何代码前必须确认受影响的功能范围，改动后逐项验证已有功能仍完好。编译通过 + 测试通过不等于功能正确。

## ARM32 交叉编译（Docker）

### 前置条件（一次性）

```bash
# 启动 Colima（若未运行）
colima start --arch aarch64 --cpu 4 --memory 4
```

### 日常流程（反复执行）

```bash
# 编译
./scripts/compile-arm32.sh

# 编译 + 运行测试
./scripts/compile-arm32.sh test

# 清理 + 编译 + 测试（推荐）
./scripts/compile-arm32.sh clean test
```

每次都是 `docker run --rm -v $PWD:/work arm32-builder make <目标>`，容器内原生 ARM32 GCC 编译，不进入交互式会话，命令全程在 macOS 侧可控。

### 验证环境

```bash
./scripts/verify-arm32.sh
```

### 环境架构

- **Colima** — 后台常驻 Docker 服务（`brew services start colima` 开机自启）
- **arm32-builder 镜像** — 基于 `arm32v7/ubuntu:22.04`，预装 build-essential（`Dockerfile.arm32`）
- **sysroot/arm32/** — ARM32 共享库（供 QEMU 用户模式使用，当前不需要）
- 代码通过 `-v` 挂载，Docker 不拉代码、不管理版本

## ARM64 编译（Docker，原生架构）

Colima 虚拟机本身就是 ARM64，Docker 默认 `linux/arm64` 是原生指令集，无需交叉编译。

### 日常流程

```bash
# 编译
./scripts/compile-arm64.sh

# 编译 + 运行测试（推荐）
./scripts/compile-arm64.sh clean test
```

### 环境架构

- **arm64-builder 镜像** — 基于 `ubuntu:22.04`，预装 build-essential（`Dockerfile.arm64`）
- 无需 `--platform` 参数，无需 QEMU 模拟，原生速度

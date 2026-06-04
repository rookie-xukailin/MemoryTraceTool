# MemoryTraceTool — C/C++ 内存泄漏检测工具

轻量级内存泄漏检测，**无需修改代码**即可监控任意 C/C++ 程序的堆分配，通过 Web 看板实时查看泄漏报告和调用栈。

## 30 秒上手

> 以下所有命令都在项目根目录 `MemoryTraceTool/` 下执行。

```bash
# 1. 编译（在 MemoryTraceTool/ 目录下）
make

# 2. 编译示例程序 + 启动监控（HTTP 仪表盘内嵌在 lib 中）
make demo_long_running
MTT_HTTP_PORT=8080 LD_PRELOAD=./build/libmemorytracetool.so ./build/demo_long_running &

# 3. 浏览器打开
# http://localhost:8080
```

复制上面命令到终端，浏览器打开看板页面，完成。HTTP 服务器内嵌在动态库中，无需单独的守护进程。

## 监控你的程序

还是在 `MemoryTraceTool/` 目录下，用 `LD_PRELOAD` 启动你的程序（**不需要改一行代码**）：

```bash
LD_PRELOAD=./build/libmemorytracetool.so ./your_app
```

程序运行时，泄漏数据会**实时推送到 Web 看板**。打开 `http://localhost:8080` 就能看到：
- 进程列表、泄漏数量、泄漏字节数
- 每个泄漏点的完整调用栈（函数名 + 偏移 + 库名）
- 调用树视图（带方向箭头，直观展示调用关系）
- 泄漏趋势曲线图

如果是常驻服务不会退出，发送信号触发报告：

```bash
kill -USR1 <pid>
```

## 两种集成模式

| 模式 | 是否改代码 | 源码位置 | 适用场景 |
|------|-----------|---------|---------|
| **LD_PRELOAD** | 不需要 | 显示为 `Preload` 标签 | 快速排查，无源码侵入 |
| **Macro** | 需要 `#include` 头文件 | 显示文件名:行号 | 开发阶段，精确定位 |

### LD_PRELOAD 模式（推荐，零侵入）

```bash
# 在 MemoryTraceTool/ 目录下执行
LD_PRELOAD=./build/libmemorytracetool.so ./your_app
```

调用栈可通过看板的一键 `addr2line` 解析还原应用层函数名。

### Macro 模式（精确到行号）

```c
#define MEMORYTRACETOOL_ENABLE
#include "memorytracetool/memorytracetool.h"

// malloc / calloc / realloc / free / strdup 自动被宏替换
// 每个分配点记录 __FILE__ 和 __LINE__
```

```bash
# 在 MemoryTraceTool/ 目录下执行
gcc -Iinclude -o myapp myapp.c build/libmemorytracetool.so -lpthread -ldl
```

## 运行时注入（高级）

对于已经在跑的进程，无需重启，直接注入动态库：

> 运行时注入能力计划中，当前版本请使用 LD_PRELOAD 模式。
> 注入功能实现后，将支持：在 Web 看板输入 PID，一键注入监控。

## 交叉编译

支持交叉编译到 ARM 32/64 位等目标平台。设置 `CROSS_COMPILE` 环境变量后直接 `make`：

```bash
# ARM 32-bit（Cortex-A 系列）
export CROSS_COMPILE=arm-linux-gnueabihf-
make

# ARM 64-bit（Cortex-A53/A72）
export CROSS_COMPILE=aarch64-linux-gnu-
make

# 或直接在命令行指定
make CROSS_COMPILE=arm-linux-gnueabihf-
```

设置 `CROSS_COMPILE` 后自动使用对应的交叉编译器。产物 `libmemorytracetool.so` 为对应架构的二进制。

如需自定义编译选项（如 sysroot）：

```bash
make CROSS_COMPILE=arm-linux-gnueabihf- \
     CFLAGS="-Wall -Wextra -g -O1 -fPIC --sysroot=/opt/sdk/sysroot" \
     LDFLAGS="-lpthread -ldl --sysroot=/opt/sdk/sysroot"
```

## API

| 端点 | 说明 |
|------|------|
| `GET /` | Web 看板页面 |
| `GET /api/data` | JSON 格式的综合泄漏数据（统计 + 时序 + 泄漏站点） |
| `GET /api/leaks` | JSON 格式的完整泄漏站点列表（无统计/时序） |

## 环境变量

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `MTT_DISABLE` | 0 | 设为 1 完全禁用追踪 |
| `MTT_SAMPLE` | 0 | 旧模式：每 N 次 alloc 记录 1 次 |
| `MTT_SAMPLE_RATE` | 0 | 字节采样率：2^N 字节平均采样一次（0=全量追踪） |
| `MTT_HTTP_PORT` | 0 | Web 仪表盘端口（0=禁用） |
| `MTT_LEAK_THRESHOLD_SEC` | 300 | 存活超过此秒数→probable leak |
| `MTT_SKIP_STARTUP_SEC` | 0 | 启动后跳过 N 秒不追踪 |
| `MTT_LIB_BLACKLIST` | 未设置 | 逗号分隔的库黑名单（如 `libc.so,libfoo.so`） |

## 测试

```bash
# 在 MemoryTraceTool/ 目录下执行
make test
```

## 清理

```bash
# 在 MemoryTraceTool/ 目录下执行
make clean         # 清理构建产物
```

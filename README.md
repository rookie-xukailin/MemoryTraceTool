# MemoryTraceTool — C/C++ 内存泄漏检测工具

轻量级内存泄漏检测，**无需修改代码**即可监控任意 C/C++ 程序的堆分配，通过 Web 看板实时查看泄漏报告和调用栈。

## 30 秒上手

> 以下所有命令都在项目根目录 `MemoryTraceTool/` 下执行。

```bash
# 1. 编译（在 MemoryTraceTool/ 目录下）
make

# 2. 启动 Web 看板（守护进程）
./build/mttd 8080 &

# 3. 浏览器打开
# http://localhost:8080
```

复制上面三行命令到终端，浏览器打开看板页面，完成。

## 监控你的程序

还是在 `MemoryTraceTool/` 目录下，用 `LD_PRELOAD` 启动你的程序（**不需要改一行代码**）：

```bash
LD_PRELOAD=./lib/libmemorytracetool.so ./your_app
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
LD_PRELOAD=./lib/libmemorytracetool.so ./your_app
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
gcc -Iinclude -o myapp myapp.c lib/libmemorytracetool.a -lpthread -ldl
```

## 运行时注入（高级）

对于已经在跑的进程，无需重启，直接注入动态库：

```bash
# 在 MemoryTraceTool/ 目录下执行
sudo setcap cap_sys_ptrace+ep ./build/mttd

# 在 Web 看板页面输入 PID，点击 Inject 即可
```

> 注意：需要 `ptrace_scope=0` 或 root 权限。

## API

| 端点 | 说明 |
|------|------|
| `GET /` | Web 看板页面 |
| `GET /api/data` | JSON 格式的泄漏数据 |
| `GET /api/addr2line?bin=<path>&off=<hex>` | 解析函数名 |
| `GET /api/injected` | 注入状态列表 |

## 测试

```bash
# 在 MemoryTraceTool/ 目录下执行
make test
```

## 清理

```bash
# 在 MemoryTraceTool/ 目录下执行
make clean         # 清理构建产物
make stop_daemon   # 停止守护进程
```

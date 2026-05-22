# MemoryTraceTool — C/C++ 内存泄漏检测工具

MemoryTraceTool 是一个轻量级 C/C++ 内存泄漏检测工具，支持两种集成模式：
- **Macro 模式**：通过宏替换，记录每次分配的文件名和行号
- **LD_PRELOAD 模式**：无需修改代码，通过动态库注入拦截所有堆分配

特别适用于**常驻进程**（后台服务、嵌入式设备）的内存泄漏监控，支持信号触发的在线报告和 Web 看板。

## 快速开始

```bash
# 编译
make

# 运行测试（7 个单元测试）
make test

# 清理构建产物
make clean
```

## 两种集成模式

### 1. Macro 模式（推荐，有文件:行号信息）

在源文件中 `#define MEMORYTRACETOOL_ENABLE` 并包含头文件，链接静态库：

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MEMORYTRACETOOL_ENABLE
#include "memorytracetool/memorytracetool.h"

int main() {
    char* buf = malloc(1024);  // 自动替换为 mtt_malloc(1024, __FILE__, __LINE__)
    // ... 忘记 free(buf) → 泄漏被记录
    return 0;  // 程序退出时自动输出报告
}
```

编译：
```bash
gcc -Iinclude -o myapp myapp.c lib/libmemorytracetool.a -lpthread -ldl
```

程序退出时自动输出泄漏报告到 stderr。

### 2. LD_PRELOAD 模式（无需修改代码）

直接通过环境变量注入：

```bash
LD_PRELOAD=lib/libmemorytracetool.so ./myapp
```

程序退出时自动输出泄漏报告。由于没有源码信息，文件标记为 `?`，行号为 `0`，但会记录完整的调用栈。

## 常驻进程监控（核心功能）

对于不会退出的常驻进程（如服务器、嵌入式设备），通过 **SIGUSR1 信号** 随时触发在线泄漏报告。

### 完整工作流程

```
+----------------+     SIGUSR1 / atexit     +------------+     HTTP      +-------------+
|  被监控进程     |  ──────────────────────>  |  mttd 守护  |  ─────────>  |  浏览器看板  |
| (长运行服务)    |    Unix Socket IPC       |  进程      |  :8080       |             |
+----------------+                          +------------+              +-------------+
```

### 步骤 1：编译

```bash
make
```

### 步骤 2：启动守护进程

```bash
build/mttd 8080 &
```

守护进程监听两个端口：
- Unix Socket：`/tmp/mttd.sock`（接收被监控进程的报告）
- TCP：`0.0.0.0:8080`（提供 Web 看板和 JSON API）

### 步骤 3：启动被监控的常驻进程

**Macro 模式**（有文件:行号）：
```bash
LD_LIBRARY_PATH=lib build/demo_long_running &
```

**LD_PRELOAD 模式**（无需修改代码）：
```bash
LD_PRELOAD=lib/libmemorytracetool.so build/demo_long_running_preload &
```

程序输出示例：
```
=== MemoryTraceTool — Long-Running Server Demo ===

PID: 7201
This process simulates a server that slowly leaks memory.
Send SIGUSR1 to trigger a leak report:
  kill -USR1 7201
Send SIGINT  to stop:
  kill -INT  7201

Signal handler installed (SIGUSR1 -> report to daemon if available).

--- Cycle 1 ---
  [login]  user=alice, token allocated (0x5c6a5d2653f0)
  [login]  user=bob, token allocated (0x5c6a5d2666a0)
  ...
```

### 步骤 4：在线查看泄漏报告

发送 SIGUSR1 信号触发一次在线报告：

```bash
kill -USR1 7201
```

然后打开浏览器访问 `http://<IP>:8080`，即可看到：

- **总览卡片**：监控的进程数、总泄漏数、总泄漏字节
- **进程列表**：PID、名称、状态（ACTIVE/DONE）、泄漏数、最后报告时间、栈顶帧
- **Top Suspect Leaks**：按泄漏大小排序，展开查看完整调用栈

页面每 3 秒自动刷新。

### 步骤 5：分析报告

#### Web 看板

看板显示每个进程的泄漏详情：

| PID | Name | Status | Leaks | Bytes | Last Seen | Top Frame |
|-----|------|--------|-------|-------|-----------|-----------|
| 7201 | demo_long_running | ACTIVE | 15 | 3.9 KB | 00:36:09 | build/demo_long_running(+0x2ca6) |

每个泄漏点展开后可看到完整调用栈（8 帧）。

#### JSON API

直接获取原始数据：

```bash
curl -s http://localhost:8080/api/data | python3 -m json.tool
```

返回结构：
```json
{
  "nprocs": 1,
  "total_leaks": 15,
  "total_bytes": 3972,
  "procs": [
    {
      "pid": 7201,
      "name": "demo_long_running",
      "active": true,
      "leak_count": 15,
      "total_leaked": 3972,
      "last_seen": 1779467769,
      "top_stack": "build/demo_long_running(+0x2ca6) [0x...]",
      "leaks": [
        {
          "size": 256,
          "file": "demo_long_running.c",
          "line": 32,
          "nframes": 8,
          "frames": [
            "build/demo_long_running(+0x2ca6) [0x...]",
            ...
          ]
        }
      ]
    }
  ]
}
```

### 步骤 6：反复检查

可以多次发送 SIGUSR1 来观察内存变化趋势：

```bash
# 第一次检查
kill -USR1 7201
curl -s http://localhost:8080/api/data | python3 -c "import sys,json; d=json.load(sys.stdin); print(f'Leaks: {d[\"total_leaks\"]}, Bytes: {d[\"total_bytes\"]}')"

# 等待一段时间...

# 第二次检查（泄漏是否增加了？）
kill -USR1 7201
curl -s http://localhost:8080/api/data | python3 -c "import sys,json; d=json.load(sys.stdin); print(f'Leaks: {d[\"total_leaks\"]}, Bytes: {d[\"total_bytes\"]}')"
```

每次 SIGUSR1 报告都会**覆蓋**该进程的上一次数据（守护进程自动识别 PID 并刷新）。

### 步骤 7：停止

```bash
# 停止被监控进程（自动发送最终报告）
kill -INT 7201

# 停止守护进程
make stop_daemon
```

## 嵌入式设备使用指南

### 场景：设备上的常驻服务疑似泄漏

**1. 交叉编译**

修改 Makefile 中的 CC 为交叉编译器：
```makefile
CC = arm-linux-gnueabihf-gcc
```

确保目标设备支持 pthread 和 dl。

**2. 部署到设备**

```bash
# 拷贝动态库
scp lib/libmemorytracetool.so root@device:/usr/lib/

# 启动守护进程（可选，如果设备有 HTTP 访问能力）
scp build/mttd root@device:/tmp/
ssh root@device "/tmp/mttd 8080 &"
```

**3. 注入监控**

```bash
# 在设备上以 LD_PRELOAD 启动服务
ssh root@device "LD_PRELOAD=/usr/lib/libmemorytracetool.so /usr/bin/my_service &"
```

**4. 触发报告**

```bash
# 发送 SIGUSR1 获取在线报告
ssh root@device "kill -USR1 \$(pidof my_service)"
```

**5. 查看结果**

如果守护进程在运行，浏览器访问 `http://<设备IP>:8080`。
如果无法运行守护进程，修改代码使用 `mtt_report()` 输出到 stderr 或调用 `mtt_report_to_fd()` 写入文件。

### 资源受限设备建议

- 修改 `src/internal.h` 中的限制：
  - `MTT_MAX_LEAKS_PER_PROC`：从 2048 降到 256
  - `MTT_BUCKETS`：从 4096 降到 1024
  - `MTT_STACK_DEPTH`：从 16 降到 8

- 守护进程也有限制（`src/daemon.h`）：
  - `MTT_MAX_PROCS`：64 → 16
  - `MTT_MAX_LEAKS`：128 → 32

## API 参考

### 公共 API（`memorytracetool/memorytracetool.h`）

| 函数 | 说明 |
|------|------|
| `void mtt_init(void)` | 初始化（自动在首次分配时调用） |
| `void mtt_report(void)` | 输出当前泄漏报告到 stderr |
| `void mtt_report_to_fd(int fd)` | 输出报告到指定文件描述符 |
| `void mtt_report_to_daemon(void)` | 发送报告到守护进程 |
| `void mtt_install_signal_handler(void)` | 安装 SIGUSR1 信号处理器（自动调用） |
| `void mtt_client_report(void)` | 发送在线报告到守护进程（不含 BYE，进程继续运行） |

### 统计查询

| 函数 | 说明 |
|------|------|
| `size_t mtt_get_alloc_count(void)` | 总分配次数 |
| `size_t mtt_get_free_count(void)` | 总释放次数 |
| `size_t mtt_get_leak_count(void)` | 当前泄漏数 |
| `size_t mtt_get_current_usage(void)` | 当前分配字节数 |
| `size_t mtt_get_peak_usage(void)` | 峰值分配字节数 |
| `size_t mtt_get_total_allocated(void)` | 累计分配字节数 |

## 模拟泄漏场景说明

项目包含 4 个 demo 程序，模拟不同的泄漏场景：

| Demo | 模式 | 说明 |
|------|------|------|
| `demo` | Macro | 静态链接，exit 时输出报告 |
| `demo_preload` | LD_PRELOAD | 动态注入，exit 时输出报告 |
| `demo_daemon` | LD_PRELOAD | 注入 + 报告到守护进程 |
| `demo_macro_daemon` | Macro | 宏 + 报告到守护进程 |
| `demo_long_running` | Macro | 常驻进程，SIGUSR1 在线报告 |
| `demo_long_running_preload` | LD_PRELOAD | 常驻进程，SIGUSR1 在线报告 |

模拟的泄漏类型：
- **令牌泄漏**（`handle_login`）：分配 session token 后未存储指针，无法释放
- **缓存覆盖**（`handle_query`）：重新分配缓存而不释放旧缓存（累积泄漏）
- **strdup 泄漏**（`handle_config_reload`）：strdup 后未释放

## Makefile 目标

```bash
make                      # 编译所有（静态库、动态库、守护进程）
make test                 # 编译并运行单元测试（7 个）
make demo                 # 编译 Macro 模式 demo
make demo_preload         # 编译 LD_PRELOAD demo
make demo_daemon          # 编译守护进程 demo（LD_PRELOAD）
make demo_macro_daemon    # 编译 Macro + 守护进程 demo
make demo_long_running    # 编译常驻进程 demo（Macro 模式）
make demo_long_running_preload  # 编译常驻进程 demo（LD_PRELOAD）
make run_demo             # 运行 Macro demo
make run_demo_preload     # 运行 LD_PRELOAD demo
make run_demo_daemon      # 一键启动守护进程 + 运行 demo
make run_demo_long_running # 一键启动守护进程 + 常驻 demo
make stop_daemon          # 停止守护进程
make clean                # 清理构建产物
```

## 架构

```
src/
├── memorytracetool.c     # 核心：分配追踪、报告生成、信号处理
├── hooks.c               # LD_PRELOAD 钩子（malloc/calloc/realloc/free）
├── client.c              # Unix Socket 客户端（发送报告到守护进程）
├── daemon.c              # 守护进程（HTTP 看板 + Unix Socket 服务端）
├── daemon.h              # IPC 协议数据结构
└── internal.h            # 内部数据结构和常量

include/memorytracetool/
└── memorytracetool.h     # 公共 API 头文件

examples/
├── demo.c                # Macro 模式基础 demo
├── demo_preload.c        # LD_PRELOAD 基础 demo
├── demo_daemon.c         # 守护进程 demo（LD_PRELOAD）
├── demo_macro_daemon.c   # 守护进程 demo（Macro）
├── demo_long_running.c   # 常驻进程 demo（Macro）
└── demo_long_running_preload.c  # 常驻进程 demo（LD_PRELOAD）

tests/
└── test_basic.c          # 单元测试
```

## 注意事项

1. **Macro 模式的头文件包含顺序**：系统头文件必须放在 `#define MEMORYTRACETOOL_ENABLE` 之前
   ```c
   // 正确顺序
   #include <stdlib.h>   // 先包含系统头文件
   #include <string.h>
   #define MEMORYTRACETOOL_ENABLE
   #include "memorytracetool/memorytracetool.h"
   ```

2. **LD_PRELOAD 的假阳性**：glibc 内部的一些分配（如 `backtrace`）可能会出现在泄漏列表中，标记为文件 `?`、行号 `0`。Macro 模式不会出现此问题。

3. **守护进程未运行时的行为**：如果守护进程未启动，SIGUSR1 报告会自动降级为输出到 stderr。

4. **重入保护**：工具内部使用 `raw_malloc`/`raw_free` 绕过自身的钩子，使用 thread-local 标志防止 `backtrace` 无限递归。

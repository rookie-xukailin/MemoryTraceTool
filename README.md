# MemoryTraceTool

轻量级 C/C++ 内存泄漏检测工具，**零代码侵入**，单 `.so` 部署。
通过 `LD_PRELOAD` 拦截 malloc/free，Web 仪表盘实时展示堆内存趋势和泄漏调用栈。

## 30 秒上手

```bash
# 1. 编译（ARM32）
make PLATFORM=arm32

# 2. 编译 demo + 启动监控
make PLATFORM=arm32 demo_controlled_leak
LD_PRELOAD=./build/libmemorytracetool.so MTT_HTTP_PORT=8080 ./build/demo_controlled_leak &

# 3. 浏览器打开 http://localhost:8080
```

## 多平台编译

```bash
make                    # x86_64 原生编译
make PLATFORM=arm32     # ARM32 (arm-linux-gnueabihf)
make PLATFORM=arm64     # ARM64 (aarch64-linux-gnu)
make PLATFORM=x86       # x86_64（等于默认）
```

产物：`build/libmemorytracetool.so`

## 监控你的程序

```bash
LD_PRELOAD=./build/libmemorytracetool.so ./your_app
```

程序运行时打开 `http://localhost:8080`，实时看到：
- 堆内存趋势图（Canvas 大图，current_bytes 面积 + peak_bytes 虚线）
- 泄漏站点排行（按 total_size 降序，可展开看完整调用栈）
- 统计卡片（当前未释放 / 历史峰值 / 累计分配 / 累计释放 / 疑似泄漏）
- 每帧格式 `func+0xOFFSET (libname)`，直接用于 `addr2line` 定位源码行

发送信号触发即时报告（不用等 60 秒扫描间隔）：

```bash
kill -USR1 <pid>
```

## 架构

```
LD_PRELOAD → hooks.c (malloc/free/calloc/realloc 拦截)
  → tracker.c   (哈希表 4096 桶 + 64 分段锁 + 栈捕获 + 采样)
  → stack_cache.c (xxHash64 + dladdr 符号解析 + 懒缓存)
  → time_series.c (环形缓冲区 3600 点，1Hz 采集)
  → reporter.c  (后台线程，60s 周期扫描 + atexit 最终扫描)
  → flamegraph.c (collapsed stacks 输出，兼容 flamegraph.pl)
  → http_server.c (嵌入式 HTTP/1.0，仪表盘 HTML + JSON API)
```

单 `.so` 零外部依赖。`MTT_HTTP_PORT=8080` 开启 Web 仪表盘（默认禁用）。

## API

| 端点 | 说明 |
|------|------|
| `GET /` | Web 仪表盘 HTML |
| `GET /api/data` | JSON：统计摘要 + 时序数据 + top 50 泄漏站点（含栈回溯） |
| `GET /api/leaks` | JSON：完整泄漏站点列表 |

## 火焰图

每次扫描同时输出 collapsed stacks 文件（兼容 Brendan Gregg 的 flamegraph.pl）：

```bash
flamegraph.pl /var/log/mtt/<pid>_<name>.folded > flame.svg
```

## 环境变量

| 变量 | 默认 | 说明 |
|------|------|------|
| `MTT_DISABLE` | 0 | 设为 1 完全禁用追踪 |
| `MTT_SAMPLE` | 0 | 旧模式：每 N 次 alloc 记录 1 次 |
| `MTT_SAMPLE_RATE` | 0 | 字节采样率：2^N 字节平均采样一次（0=全量追踪，>=1MB 必追踪） |
| `MTT_HTTP_PORT` | 0 | Web 仪表盘端口（0=禁用） |
| `MTT_LEAK_THRESHOLD_SEC` | 300 | 存活超过此秒数 → probable leak |
| `MTT_SKIP_STARTUP_SEC` | 0 | 进程启动后跳过 N 秒不追踪 |
| `MTT_LIB_BLACKLIST` | 无 | 逗号分隔的库黑名单（如 `libc.so,libfoo.so`） |

## 借鉴的成熟方案

| 特性 | 来源 |
|------|------|
| 统计字节采样（大分配必追踪） | gperftools + jemalloc |
| 新高水位自动扫描（peak_updated 秒级触发） | jemalloc `prof_gdump` |
| 差值报告（Growth 增量、diff 高亮） | jemalloc `--base` |
| 存活时间泄漏判定（probable / possible leak） | libleak `LEAK_EXPIRE` |
| 延迟释放追踪（free_expired 计数） | libleak late-free |
| 库黑名单 `MTT_LIB_BLACKLIST` | libleak |
| 跳过启动阶段 `MTT_SKIP_STARTUP_SEC` | libleak `LEAK_AFTER` |
| 信号触发即时报告（SIGUSR1） | heaptrack + gperftools |
| 临时分配检测（<1s 释放计数） | heaptrack |
| Collapsed stacks（兼容 flamegraph.pl） | heaptrack |

## 测试

```bash
make PLATFORM=arm32 test       # test_basic (36 用例)
make PLATFORM=arm32 test_all   # test_basic + test_stability (18 cases)

# 前端测试（需先启动 HTTP 服务器）
python3 tests/test_frontend_json.py    # JSON 结构和语义验证 (20 项)
python3 tests/test_frontend_html.py    # HTML/JS/CSS 结构验证 (27 项)
```

## 验证状态

| 里程碑 | ARM32 | ARM64 | x86_64 |
|--------|-------|-------|--------|
| 编译 | 通过 | 通过 | 通过 |
| test_basic 36/36 | PASS | — | PASS |
| LD_PRELOAD + HTTP | PASS | — | PASS |
| 栈回溯（函数名+偏移） | PASS | — | PASS |
| 火焰图 collapsed stacks | PASS | — | PASS |

ARM32 验证环境：QEMU user 模式 (`qemu-arm-static -L /usr/arm-linux-gnueabihf`)

## 部署到 ARM 设备

```bash
# 1. 编译（本机 WSL）
make PLATFORM=arm32

# 2. 复制到设备
scp build/libmemorytracetool.so root@<device>:/tmp/

# 3. 在设备上运行
LD_PRELOAD=/tmp/libmemorytracetool.so MTT_HTTP_PORT=8080 ./your_daemon
```

## 已知限制

- `backtrace()` 是 glibc 扩展，musl / bionic 上栈回溯不可用（仍按大小统计）
- 哈希表最大 65536 条活跃分配，超出静默跳过（可通过修改 `MTT_MAX_ENTRIES` 调整）
- ARM32 需链接 `-latomic`（64-bit 原子操作依赖）
- `/proc/self/exe` 不可用时进程名显示 "unknown"（回退到 `prctl(PR_GET_NAME)`）
- `time_t` 在 ARM32 上为 4 字节（2038 年问题）

## 清理

```bash
make clean
```

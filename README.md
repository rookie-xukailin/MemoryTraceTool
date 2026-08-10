# MemoryTraceTool

轻量级 C/C++ 内存泄漏检测工具，**零代码侵入**，单 `.so` 部署。
通过 `LD_PRELOAD` 拦截 malloc/free，Web 仪表盘实时展示堆内存趋势和泄漏调用栈。
专为 **ARM32/ARM64 嵌入式 BMC 守护进程**设计，栈深度 32 帧穿透闭源库追踪。

## 30 秒上手

```bash
# 1. 编译（ARM32，Docker 交叉编译，已含 libunwind 静态链接）
./scripts/compile-arm32.sh

# 2. 编译 demo + 启动监控
make demo_controlled_leak
LD_PRELOAD=./output/libmemorytracetool.so MTT_HTTP_PORT=8080 ./output/demo_controlled_leak &

# 3. 浏览器打开 http://localhost:8080
```

## 多平台编译

```bash
make                    # 本机架构原生编译
make ARCH=arm32         # ARM32 (arm-linux-gnueabihf)
make ARCH=arm64         # ARM64 (aarch64-linux-gnu)
```

Docker 一键编译（推荐，免装交叉工具链）：
```bash
./scripts/compile-arm32.sh           # ARM32 编译
./scripts/compile-arm64.sh           # ARM64 编译
./scripts/compile-arm32.sh clean test  # 清理 + 编译 + 跑测试
```

工具已**内置 libunwind**（vendored 在 `open/libunwind/`），单 `.so` 交付，目标机无需 `apt install libunwind8`，内网编译无需联网。

产物在 `output/` 目录下（`.o` 中间文件自动清理于 `build/`）。

## 监控你的程序

```bash
LD_PRELOAD=./output/libmemorytracetool.so ./your_app
```

程序运行时打开 `http://localhost:8080`，实时看到：
- 堆内存趋势图（Canvas 大图，current_bytes 面积 + peak_bytes 虚线 + RSS 进程内存）
- 泄漏站点排行（按 total_size 降序，可展开看完整调用栈，32 帧深度）
- 统计卡片（当前未释放 / 历史峰值 / 累计分配 / 累计释放 / 疑似泄漏 / RSS）
- 每帧格式 `func+0xOFFSET (libname)`，直接用于 `addr2line` 定位源码行

发送信号触发即时报告（不用等 60 秒扫描间隔）：

```bash
kill -USR1 <pid>
```

## 架构

```
LD_PRELOAD → hooks.c (malloc/free/calloc/realloc 拦截)
  → tracker.c   (哈希表 4096 桶 + 64 分段锁 + 栈捕获 32 帧 + 采样)
  → stack_cache.c (xxHash64 + dladdr 符号解析 + C++ 反修饰 + 懒缓存)
  → time_series.c (环形缓冲区 3600 点 @ 1Hz + RSS 进程内存)
  → reporter.c  (后台线程，60s 周期扫描 + SIGUSR1 即时报告)
  → flamegraph.c (collapsed stacks 输出，兼容 flamegraph.pl)
  → http_server.c (嵌入式 HTTP/1.0，仪表盘 HTML + JSON API)
```

单 `.so` 零外部依赖。`MTT_HTTP_PORT=8080` 开启 Web 仪表盘（默认禁用）。

## API

| 端点 | 说明 |
|------|------|
| `GET /` | Web 仪表盘 HTML |
| `GET /api/data` | JSON：统计摘要（含 RSS）+ 时序数据（含 RSS）+ top 50 泄漏站点（含栈回溯） |
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
| `MTT_POOL_ENTRIES` | 16384 | 工具自身 entry 池容量（控制预占用内存，[1024, 65536]，约 600B/entry） |
| `MTT_DEBUG` | 1 | 诊断日志开关（0=静默,屏蔽所有 stderr 诊断,只保留 leak 报告 + heartbeat） |
| `MTT_MAX_STACK_FRAMES` | 8 | 栈回溯深度（每次 malloc 最多回溯几帧，[1, 64]）。调大获更深栈（定位更深调用链）但回溯更慢；调小降低 CPU。性能敏感场景建议 4-8 |
| `MTT_UNWINDER` | auto | 栈回溯方式：`auto`（libunwind 优先，崩溃自动降级）/ `libunwind` / `backtrace`。HDM3 等 libunwind 崩溃环境可设 `backtrace` 绕过 |
| `MTT_UNWIND_PARALLEL` | 1 | libunwind 栈回溯并行模式开关（unwind-parallel 改造）。`1`=并行(默认,TLS 上下文+无 mutex,多核发挥)；`0`=串行 fallback(全局 mutex,TLS 不可靠设备兜底)。BMC 多线程业务 CPU 飙升 / RPC 长尾超时默认即生效,有问题设 0 一键回退 |

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
| RSS 进程内存跟踪 | heaptrack |

## 测试

```bash
# 基础功能(36 个):alloc/free 统计、栈回溯、计数原子性
make test
./scripts/compile-arm64.sh clean test   # ARM64 Docker
./scripts/compile-arm32.sh clean test   # ARM32 Docker

# 并发压力(18 个):60s 长稳 + pool_lock per-stripe + 各种 race
make test_stability

# 综合场景:HDM3 build 模拟环境(ARM32 soft-float + ARM64 + C++ 异常)
./scripts/sim-test.sh

# 静默模式回归:验证 MTT_DEBUG=0 下 stderr 完全静默但 leak 报告正常
./scripts/test_silent_mode.sh

# 栈深度回归:验证 libunwind 静态链接在 -O2 -fomit-frame-pointer 上能拿到业务帧
./scripts/test_stack_depth.sh arm32     # ARM32 主场景
./scripts/test_stack_depth.sh arm64     # ARM64 对比

# 前端测试（需先启动 HTTP 服务器）
python3 tests/test_frontend_json.py    # JSON 结构和语义验证
python3 tests/test_frontend_html.py    # HTML/JS/CSS 结构验证
```

## 关键指标

| 指标 | 数值 |
|------|------|
| 栈回溯深度 | **32 帧**（闭源库穿透） |
| 堆内存入口上限 | 65536 条目 |
| 哈希桶 / 分段锁 | 4096 / 64 |
| 时序容量 | 3600 点（1 小时 @ 1Hz） |
| 内存占用（ARM32） | ~12MB 峰值 |
| 后台线程数 | 3（reporter + HTTP + signal） |

## 里程碑

| # | 提交 | 内容 |
|---|------|------|
| M1 | `7760a15` | 三大 Bug 修复：符号解析 `main+0x460` + use-after-free + 时序数据 |
| M2 | `5d4091f` | ARM32 QEMU 12/12 PASS + x86_64 120s 长稳零崩溃 |
| M3 | `a08e059` | HTTP JSON 合法化 + 时序数据实时读取 |
| M4 | `e339d5a` | 借鉴 heaptrack 四大改进：符号缓存/C++反修饰/compact TS/仪表盘增强 |
| M5 | `0f66af5` | ARM32 QEMU LD_PRELOAD+HTTP+栈回溯 全链路 PASS |
| M6 | `73c8a3d` | 编译零警告：MTT_DIAG_WRITE 宏根治 48 个 warn_unused_result |
| M7 | `e004c6a` | test_stability 7→17 用例：并发配对/同桶竞争/读写并发/竞态初始化/realloc 压力 |
| M8 | `e7d14fe` | 产物分离：output/ 最终产物 + build/ 中间 .o |
| M9 | `c0bb2c4` | **栈深度 16→32** + RSS 进程内存跟踪 + GDB 运行时注入 + ARM32 栈溢出修复 |
| M10 | `32aec7f` | **libunwind v1.8.2 vendored 静态链接** + 性能优化(pool_lock per-stripe + CLOCK_REALTIME_COARSE),单 .so 内置 unwind,目标机零依赖 |
| M11 | `779fbd3` | **addr2line 行号解析修复**:alCmd 命令格式修正(-e 不再带 +offset)+ 非 PIE 主程序帧地址修正(读 ELF e_type 判定,主程序帧输出运行时地址,libc/.so 帧保持 file_off)。HDM3 storageManager 主进程泄漏点可正确解析 `func at file.c:line` |

## 验证状态

| 指标 | ARM32 | ARM64 | x86_64 |
|------|-------|-------|--------|
| 编译警告 | 0 | 0 | 0 |
| test_basic | 36/36 PASS | — | 36/36 PASS |
| test_stability | 17/17 PASS | — | 17/17 PASS |
| LD_PRELOAD + HTTP | PASS | — | PASS |
| 栈回溯（函数名+偏移） | PASS | — | PASS |
| **addr2line 行号解析（PIE + 非 PIE）** | PASS | PASS | — |
| RSS 进程内存 | PASS | — | PASS |
| 火焰图 collapsed stacks | PASS | — | PASS |

## 验证状态

| 指标 | ARM32 | ARM64 | x86_64 |
|------|-------|-------|--------|
| 编译警告 | 0 | 0 | 0 |
| test_basic | 36/36 PASS | — | 36/36 PASS |
| test_stability | 17/17 PASS | — | 17/17 PASS |
| LD_PRELOAD + HTTP | PASS | — | PASS |
| 栈回溯（函数名+偏移） | PASS | — | PASS |
| RSS 进程内存 | PASS | — | PASS |
| 火焰图 collapsed stacks | PASS | — | PASS |

ARM32 验证环境：QEMU user 模式 (`qemu-arm-static -L /usr/arm-linux-gnueabihf`)

## BMC 守护进程部署流程

```bash
# 1. 开发机交叉编译
./scripts/compile-arm32.sh clean
scp output/libmemorytracetool.so root@<bmc>:/tmp/

# 2. BMC 上重启守护进程 + 注入监控
ssh root@<bmc>
systemctl stop <daemon>
LD_PRELOAD=/tmp/libmemorytracetool.so \
  MTT_HTTP_PORT=8080 \
  MTT_LEAK_THRESHOLD_SEC=300 \
  <daemon_path> &

# 3. 浏览器查看仪表盘
# http://<bmc-ip>:8080/

# 4. 或在 BMC 上用 curl 查看
curl -s http://localhost:8080/api/data | python3 -m json.tool | head -80
# Growth > 0 → 正在泄漏
# is_expired = 1 → probable leak

# 5. 即时报告（无需等 60s 扫描周期）
kill -USR1 $(pidof <daemon>)

# 6. 离线火焰图分析
scp root@<bmc>:/var/log/mtt/*.folded ./
flamegraph.pl *.folded > flame.svg

# 7. 源码定位
addr2line -e /path/to/daemon.debug -f -C 0x460
```

### 无需重启的方案（运行时注入）

```bash
# GDB 脚本注入（需目标进程链接 libdl）
./scripts/inject.sh $(pidof <daemon>) MTT_HTTP_PORT=8080
```

## 部署到 ARM 设备

```bash
# 1. 编译（本机 WSL / Docker）
./scripts/compile-arm32.sh

# 2. 复制到设备
scp output/libmemorytracetool.so root@<device>:/tmp/

# 3. 在设备上运行
LD_PRELOAD=/tmp/libmemorytracetool.so MTT_HTTP_PORT=8080 ./your_daemon
```

## 已知限制

- 内置 libunwind 仍受目标二进制 unwind 信息约束：业务用 `-O2 -fomit-frame-pointer` 但**未加** `-funwind-tables` 时，ARM32 上仍只能拿到 1-2 帧（vs 5+ 帧需要 `-funwind-tables`）
- 哈希表最大 65536 条活跃分配，超出静默跳过（可通过修改 `MTT_MAX_ENTRIES` 调整）
- ARM32 需链接 `-latomic`（64-bit 原子操作依赖）
- `/proc/self/exe` 不可用时进程名显示 "unknown"（回退到 `prctl(PR_GET_NAME)`）
- `time_t` 在 ARM32 上为 4 字节（2038 年问题）
- 运行时注入依赖 GDB（目标需有 gdb/gdbserver）

## 栈回溯深度优化（重要）

若你发现泄漏点的栈回溯只有 2-3 帧、无法定位业务调用方，**99% 是目标二进制的编译选项导致**。按效力排序的解决方案：

### 方案 A（最有效，零工具侧改动）：重建目标二进制

在目标工程的 CFLAGS / LDFLAGS 加上：
```makefile
CFLAGS += -funwind-tables -fno-omit-frame-pointer
```

- `-funwind-tables`：强制为每个函数生成 `.ARM.exidx` unwind 表，glibc `backtrace()` 由此能完整回溯
- `-fno-omit-frame-pointer`：保留帧指针链作为兜底
- 体积开销：典型 `.text` 增大 <2%，对 release 二进制几乎无感

### 方案 B（工具侧，已内置）：libunwind 静态链接

工具已**内置 libunwind v1.8.2**（vendored 在 `open/libunwind/`，静态链入 `.so`），自动多策略 unwind（`.ARM.exidx` → DWARF → FP chain → stack scan），在 `-fomit-frame-pointer` 二进制上能拿到比 glibc `backtrace()` 更深的栈。

实测效果（ARM32 demo_nofp `-O2 -fomit-frame-pointer`）：
- 仅 glibc `backtrace()`：0-2 帧，业务栈基本丢失
- 内置 libunwind：业务栈能拿到至少 1 帧定位（如 `flasher+0x654`，可用 `addr2line` 精确定位）；目标加 `-funwind-tables` 后可达 5+ 帧

目标机**无需 `apt install libunwind8`**，部署就跟之前一样：单 `.so` 文件 + `LD_PRELOAD`。

### 方案 C（运行时观测）：浅栈警告

工具在扫描时若发现 >20% 分配的栈回溯少于 4 帧，会一次性输出 stderr 警告：
```
[MTT] WARNING: 120/150 (80%) allocations have <4 frames.
       Rebuild target with -funwind-tables -fno-omit-frame-pointer
```
即便 `MTT_DEBUG=0` 静默模式也会输出（属于关键诊断信息）。

### 为什么 ARM32 容易出现浅栈

ARM EABI 的 `glibc backtrace()` 依赖 `.ARM.exidx` 段，遇到标记 `CANTUNWIND` 的条目立即终止。`-O2 -fomit-frame-pointer` 配合下，叶子函数常无栈帧、尾调用覆盖 LR、静态函数被内联，三者叠加导致 unwind 表不完整 → 2-3 帧就被截断。ARM64 上 `glibc backtrace()` 用 DWARF，对此类优化更鲁棒。

## 性能优化（已落地，对业务透明）

工具通过 `LD_PRELOAD` 拦截 malloc/free，每次 hook 都要打时间戳、操作 entry 池、回溯栈。多线程高频 alloc 场景下，热路径任何一处锁竞争或系统调用都会被放大。已落地的优化：

| 优化点 | 改动 | 效果 |
|--------|------|------|
| **pool_lock per-stripe** | 单锁 → 64 把独立锁 + 64 桶 free_list，按 ptr/entry 地址分散 | 多线程高频 alloc 锁竞争降低 ~64x |
| **CLOCK_REALTIME_COARSE** | `time(NULL)` 系统调用 → VDSO 无 syscall 实现 | 每次时间戳开销 ~1-2μs → 接近 0 |
| **延迟符号解析** | dladdr/backtrace_symbols 移到 reporter 后台线程 | 热路径不做符号解析 |
| **entry 对象池** | 启动时一次性 raw_malloc 大块,entry 复用槽位 | 热路径不调 libc malloc |
| **64 段 stripe_lock** | 哈希桶链表 64 分段锁,缓存行对齐 | 多线程并发读写无伪共享 |
| **libunwind 并行化(unwind-parallel)** | 全局 `g_unwind_mutex` + `g_unwind_jmp` → `__thread` TLS sigjmp 上下文 + sigaction 一次性安装 + handler chain + reporter 60s 监控补偿 | 多线程 malloc 多核并行,4 线程实测加速比 3.7~6.2x(commit `839821a` 的 SIGSEGV 保护零回归) |

业务接口变慢时的排查路径：
1. 先 `MTT_DEBUG=0 MTT_HTTP_PORT=0` 关诊断 + Web 仪表盘,排除 IO 开销
2. 仍慢 → 业务二进制加 `-funwind-tables -fno-omit-frame-pointer` 重编(降低 unwind 复杂度)
3. 极端场景 → 启用采样 `MTT_SAMPLE_RATE=15`(约每 32KB 采一次,跳过 99% 小分配的栈回溯)

## 清理

```bash
make clean         # 清除 build/ + output/
make vendor-clean  # 单独清 libunwind 构建产物(build/libunwind-*)
make distclean     # clean + 清 sysroot/
```

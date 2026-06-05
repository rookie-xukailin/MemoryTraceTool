# MemoryTraceTool — 项目记忆

## 定位

C/C++ LD_PRELOAD 内存泄漏检测共享库，目标平台 ARM32/ARM64 嵌入式 Linux。
单 .so 部署，零外部依赖。测试同学只需 LD_PRELOAD + 环境变量即可运行。

## 编译规则（核心）

**每次编辑源文件后，必须运行 `make clean && make` 验证编译。编译不通过禁止提交。**

交叉编译：
```bash
CROSS_COMPILE=arm-linux-gnueabihf- make    # ARM32
CROSS_COMPILE=aarch64-linux-gnu- make      # ARM64
make                                        # x86_64 native
```

当前 Windows 开发环境无 GCC（VM 会崩溃），仅做静态代码走查。代码提交后由用户在有编译环境处验证。

## 架构概览

```
LD_PRELOAD →
  hooks.c (malloc/free/calloc/realloc 拦截)
    → tracker.c (哈希表 + 栈捕获 + 采样 + 状态管理)
    → reporter.c (后台线程，60s 周期扫描 + atexit 最终扫描)
    → stack_cache.c (xxHash64 + dladdr 符号解析 + 懒缓存)
    → time_series.c (环形缓冲区 3600 点，1Hz 堆内存趋势采集)
    → flamegraph.c (collapsed stacks 输出，兼容 flamegraph.pl)
    → http_server.c (嵌入式 HTTP/1.0，Web 仪表盘 + JSON API)
```

## 测试套件

| 文件 | 覆盖范围 | 用例数 |
|------|---------|--------|
| tests/test_basic.c | malloc/free/calloc/realloc 各种大小和边界 | 36 |
| tests/test_stability.c | 60 秒长稳 + 并发配对/同桶竞争/读写并发/竞态初始化/realloc压力/边界并发/current_bytes原子/峰值CAS/混合操作/线程搅动 | 17 |
| tests/test_frontend_json.py | /api/data JSON 结构和语义验证（含 rss_bytes 字段） | 20 |
| tests/test_frontend_html.py | / 仪表盘 HTML/JS/CSS 结构验证 | 27 |
| scripts/inject.sh | GDB 运行时注入脚本（无需重启守护进程） | — |

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
| M9 | `c0bb2c4` | 栈深度 16→32 + RSS 进程内存跟踪 + GDB 运行时注入 + ARM32 栈溢出修复 |

运行：`make test_all`（编译 + C 测试，Python 测试需先启动 HTTP 服务器）

## 部署流程

1. 交叉编译：`CROSS_COMPILE=arm-linux-gnueabihf- make`
2. 复制到设备：`scp build/libmemorytracetool.so root@device:/tmp/`
3. 启动监控：
```bash
MTT_HTTP_PORT=8080 MTT_LEAK_THRESHOLD_SEC=300 \
LD_PRELOAD=/tmp/libmemorytracetool.so ./my_daemon
```
4. 查看 Web 仪表盘：`http://<device_ip>:8080`
5. 查看报告日志：`/var/log/mtt/<pid>_<name>.log`
6. 信号触发即时报告：`kill -USR1 <pid>`
7. 火焰图：`flamegraph.pl /var/log/mtt/<pid>_<name>.folded > flame.svg`

## 环境变量一览

| 变量 | 默认值 | 说明 |
|------|--------|------|
| MTT_DISABLE | 0 | 设为 1 完全禁用追踪 |
| MTT_SAMPLE | 0 | 旧模式：每 N 次 alloc 记录 1 次 |
| MTT_SAMPLE_RATE | 0 | 字节采样率：2^N 字节平均采样一次（0=全量追踪） |
| MTT_HTTP_PORT | 0 | Web 仪表盘端口（0=禁用） |
| MTT_LEAK_THRESHOLD_SEC | 300 | 存活超过此秒数→probable leak |
| MTT_SKIP_STARTUP_SEC | 0 | 启动后跳过 N 秒不追踪 |

## 已知限制

- backtrace() 是 glibc 扩展，musl/bionic 上栈回溯不可用（仍按大小统计）
- 哈希表最大 65536 条活跃分配，超出静默跳过
- ARM32 需要 -latomic（64-bit 原子操作）
- /proc/self/exe 不可用时进程名显示 "unknown"
- HTTP 服务器仅支持 GET 请求，不支持并发连接（单线程 accept）
- time_t 在 ARM32 上为 4 字节（2038 年问题）

## 线程模型

- Application threads: 并发 alloc/free，64 分段锁
- Reporter thread: 1 个 detach 线程，g_in_hook=1 全程
- HTTP thread: 1 个 detach 线程，select+accept，1 秒超时
- Signal thread: 1 个 detach 线程，sigwait 阻塞 SIGUSR1
- Atexit handler: main 线程退出时串行执行最终扫描

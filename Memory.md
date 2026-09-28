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
| MTT_LEAK_THRESHOLD_SEC | 300 | 老化阈值：存活超过此秒数→进入四级分类候选 |
| MTT_SKIP_STARTUP_SEC | 0 | 启动后跳过 N 秒不追踪 |
| MTT_CLASSIC_LEAK | 0 | 设为 1 回退纯时间两级判定（新旧行为 A/B 对比） |
| MTT_LONG_LIVED_SUSPECT_BYTES | 1MB | long_lived 嫌疑阈值（0=禁用），超限保留嫌疑区全栈显示 |
| MTT_TAKEOVER_USR1 | 1 | 0=跳过 SIGUSR1 接管（业务自带 handler 时用） |
| MTT_ARCHIVE | 1 | 扫描历史 JSONL 归档开关（/var/log/mtt/<pid>_<name>.archive.jsonl） |
| MTT_MAX_STACK_FRAMES | 64 | 栈回溯深度 [1, 64] |
| MTT_UNWINDER | auto | auto / libunwind / backtrace |
| MTT_POOL_ENTRIES | 自动 | entry 池容量 [1024, 131072]，默认按 20MB 反推 |
| MTT_LIB_BLACKLIST / MTT_LIB_BLACKLIST_FAST | 无 | 符号过滤 / 地址范围跳过抓栈 |

## 已知限制

- 泄漏判定为四级分类（probable / session_scoped / long_lived / possible），
  综合老化 + 跨扫描存活数趋势 + late-free 证据；一次性泄漏与单例缓存
  无法在事件层面区分，归入 long_lived 人工复核
- 栈回溯优先 libunwind（已内嵌静态链接 v1.8.2），glibc backtrace 兜底；
  musl/bionic 无 backtrace 时降级 FP chain
- 哈希表最大 131072 条活跃分配（池受 MTT_POOL_ENTRIES 约束），
  超出跳过并计入 Skipped (overflow)，报告头/心跳/仪表盘可见
- ARM32 需要 -latomic（64-bit 原子操作）
- /proc/self/exe 不可用时进程名显示 "unknown"
- HTTP 服务器仅支持 GET 请求，不支持并发连接（单线程 accept）
- time_t 在 ARM32 上为 4 字节（2038 年问题）

## 测试纪律（2026-09 与用户约定，永久有效）

1. **所有修改必须页面实测**：前端/交互改动一律真实打开页面（浏览器自动化
   登录 + 截图 + 视觉确认），禁止只跑 node/静态检查就宣布通过。
2. **addr2line 必须找回原文**：栈回溯验收标准——报告中的帧必须能通过
   `addr2line -e <bin> -f -C <off>` 解析出函数名（有 -g 时含源码行），
   找不回原文 = 失败。固化于 `make test_addr2line`（全平台套件共用）。
3. **编译参数固定**（对齐真实工程参数表）：
   - sensorhub-c（纯 C）: `-O2 -g -Wall -Werror -fsigned-char -fgnu89-inline
     -funwind-tables -std=gnu11` + 链接 `-Wl,--export-dynamic`
   - devmgr-cpp（纯 C++）: `-Os -Wall -std=c++17`（无 unwind 显式参数，平台隐式）
   - gateway-mixed（C++调C .so）: C `-Os -Wall -Werror -fPIC -fsigned-char`，
     C++ `-Os -Wall -fPIC -std=c++17`
   - 其余参数交给平台默认；测试前必须 `make clean && make`（防产物架构污染）

## 测试套件（2026-09 更新）

| 目标 | 用例数 | 覆盖 |
|------|-------|------|
| make test | 36 | 基础 API/计数 |
| make test_stability | 18 | 60s 并发压力 |
| make test_leak_class | 4+3 | 四级分类(智能+classic 回退) |
| make test_integrity | 2 | 池耗尽计数可见性 |
| make test_archive | 5 | JSONL 归档 |
| make test_addr2line | 逐帧 | 栈→addr2line→源码找回(全平台门禁) |
| test_frontend_html/json.py | 52/42 | 仪表盘 HTML/JSON API |

## 线程模型

- Application threads: 并发 alloc/free，64 分段锁
- Reporter thread: 1 个 detach 线程，g_in_hook=1 全程
- HTTP thread: 1 个 detach 线程，select+accept，1 秒超时
- Signal thread: 1 个 detach 线程，sigwait 阻塞 SIGUSR1
- Atexit handler: main 线程退出时串行执行最终扫描

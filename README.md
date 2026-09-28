# MemoryTraceTool

轻量级 C/C++ 内存泄漏检测工具，**零代码侵入**，单 `.so` 部署。
通过 `LD_PRELOAD` 拦截 malloc/free，Web 仪表盘实时展示堆内存趋势和泄漏调用栈。
面向 ARM32/ARM64 嵌入式 BMC 守护进程，栈回溯最深 64 帧。

## 编译

```bash
make                    # 本机架构
make ARCH=arm32         # ARM32
make ARCH=arm64         # ARM64
make ARCH=riscv64       # RISC-V64（自定义工具链加 CROSS_COMPILE=<完整路径前缀>）
make -n ARCH=...        # 检查编译：只打印命令行，不产出二进制
```

- 内置 libunwind（vendored 在 `open/libunwind/`），产物为单 `.so`，位于 `output/`，目标机零依赖
- 当前 Windows 开发机无 GCC/Docker，日常用 `make -n` 检查编译，完整编译 + 测试在有编译环境的机器执行（ARM32/ARM64/x86_64 历史实测通过，RISC-V64 待真机验证）
- Docker 交叉编译（可选）：先 `docker build -f Dockerfile.arm32 -t arm32-builder .`，再 `./scripts/compile-arm32.sh [clean] [test]`
- 清理：`make clean`（build + output）/ `make vendor-clean`（libunwind 产物）/ `make distclean`

## 使用（LD_PRELOAD）

```bash
# 编译机上拷贝到目标机
scp output/libmemorytracetool.so root@<bmc>:/tmp/

# 目标机：启动守护进程时预加载
MTT_HTTP_PORT=8080 LD_PRELOAD=/tmp/libmemorytracetool.so <daemon_path> &
```

- 浏览器打开 `http://<bmc-ip>:8080`：堆内存趋势图（累计分配/当前未释放/峰值/RSS/已识别泄漏五条曲线，滚轮缩放、拖拽平移、双击复位）、泄漏站点排行（可展开完整调用栈，表头点击排序、按最后发现时间/置信度/增长筛选）、统计卡片（含数据完整性告警）
- `kill -USR1 $(pidof <daemon>)` 触发即时报告，不用等 60s 扫描周期
- 每帧格式 `func+0xOFFSET (libname)`，用 `addr2line -e <daemon>.debug -f -C 0xOFFSET` 定位源码行
- `Growth > 0` → 正在泄漏；置信度见下方"泄漏四级分类"

## 泄漏四级分类（2026-09 起）

判定不再只看"活得久"，而是综合**老化（单调时钟，免疫 NTP 跳变）+ 跨扫描存活数趋势 + 该站点是否观察到过释放**：

| 分类 | 含义 | 判定依据 |
|------|------|---------|
| `probable` | 真泄漏特征 | 已老化且存活数超过历史峰值（只增不减），从未释放 |
| `session_scoped` | 周期作用域，**非泄漏** | 观察到过"超阈值后释放"（如收到主机重启 RPC 信号后释放），当前存活数不超过历史峰值 |
| `long_lived` | 长存活稳定，信息级 | 已老化但数量稳定、从未观察到释放（单例/缓存；一次性泄漏与此无法区分，人工复核） |
| `possible` | 待观察 | 未老化，或首次出现在扫描中（首扫不判 probable，压掉周期开头的误报） |

- 压测场景收益：重启主机压力测试中"申请后长期持有、收到重启 RPC 信号才释放"的内存，确认周期作用域后**从页面完全移除**（默认视图/嫌疑区/信息区都不出现，"周期作用域"筛选按钮可主动查看），文本报告只留一行汇总计数
- 报告/JSON/仪表盘中 `conf` 字段为上述四级；`late_free` 为该站点观察到的老化释放次数（周期作用域证据）；`stack_kind` 标识无栈成因（1=按大小聚合/2=栈缓存满/3=未解析——"数量涨但栈空"时可诊断）
- **`is_expired` 语义迁移（外部脚本必读）**：旧版 `is_expired==1` 即泄漏；新版它只表示"存活超阈值（老化）"，`long_lived` 站点也是 1。是否泄漏以 `conf` 为准，统计泄漏请用 `conf=='probable'`
- `MTT_LONG_LIVED_SUSPECT_BYTES`（默认 1MB，0=禁用）：长存活且从未释放、字节数超阈值的站点保留嫌疑区全栈显示并标 SUSPECT——防止平台期真泄漏被分类放走
- `MTT_TAKEOVER_USR1=0`：业务进程自带 SIGUSR1 handler（如日志轮转）时跳过接管，工具即时报告随之不可用（周期扫描不受影响）；接管已有 handler 时工具会打 WARN
- `MTT_CLASSIC_LEAK=1` 回退旧的纯时间两级判定（存活超阈值一律 probable），用于新旧行为 A/B 对比
- 扫描历史：`/var/log/mtt/<pid>_<name>.archive.jsonl` 每次扫描追加一行站点级快照（count/size/conf/late_free/增长），覆盖写报告只保留最新一次，归档让数小时压测后可回溯每一轮；单文件 8MB 轮转保留 2 代，`MTT_ARCHIVE=0` 关闭

## 延时敏感场景（RPC 等）：建议开启采样

默认全量追踪，每次 malloc 都要抓栈（微秒级），RPC 等对延时敏感的场景可能被拖慢。这类场景建议开启字节采样，**牺牲小对象的采集密度，换取业务延时不受影响**：

```bash
MTT_SAMPLE_RATE=15 LD_PRELOAD=/tmp/libmemorytracetool.so <daemon_path>
```

- 机制：小于 1KB 的分配按字节累加，**攒满 2^N 字节才采集一次**，其余跳过抓栈，大幅降低 CPU 开销
- 兜底：>=1KB 的分配不受采样影响，仍然全量追踪，中等/大对象泄漏不会漏检
- N 越大越省 CPU：15 ≈ 每 32KB 采一次，20 ≈ 每 1MB 采一次
- 代价：小对象泄漏的调用量和精确字节数是采样估算值，看趋势和热点站点够用

## 环境变量

| 变量 | 默认 | 说明 |
|------|------|------|
| `MTT_HTTP_PORT` | 0 | Web 仪表盘端口（0=禁用） |
| `MTT_DISABLE` | 0 | 设为 1 完全禁用追踪 |
| `MTT_LEAK_THRESHOLD_SEC` | 300 | 老化阈值：存活超过此秒数 → 进入分类候选（判定见"泄漏四级分类"） |
| `MTT_CLASSIC_LEAK` | 0 | 设为 1 回退纯时间两级判定（超阈值一律 probable） |
| `MTT_ARCHIVE` | 1 | 扫描历史 JSONL 归档（0=关闭）。`/var/log/mtt/<pid>_<name>.archive.jsonl`，8MB 轮转×2 代 |
| `MTT_SKIP_STARTUP_SEC` | 0 | 进程启动后跳过 N 秒不追踪 |
| `MTT_MAX_STACK_FRAMES` | 64 | 栈回溯深度 [1, 64]。调大栈更深但更慢，性能敏感场景建议 4-8 |
| `MTT_UNWINDER` | auto | `auto`（libunwind 优先，崩溃自动降级）/ `libunwind` / `backtrace` |
| `MTT_SAMPLE_RATE` | 0 | 字节采样率：2^N 字节平均采样一次（0=全量追踪）。>=1KB 必追踪，只对 <1KB 小对象采样 |
| `MTT_LIB_BLACKLIST` | 无 | 逗号分隔库名，reporter 按符号过滤，只影响 leak 报告显示 |
| `MTT_LIB_BLACKLIST_FAST` | 无 | 库地址范围快速黑名单：命中跳过抓栈省 CPU（该库内调用链不可见）。适合 lmdb/XML 等库内海量 malloc 拖慢业务的场景 |
| `MTT_POOL_ENTRIES` | 自动 | 工具自身 entry 池容量，默认按 20MB 目标内存反推，可设 [1024, 131072]。entry 增加 8B 单调时间戳后容量约降 1.4%，可用此变量调回 |
| `MTT_DEBUG` | 1 | 0=静默（只留 leak 报告 + heartbeat），2=全量调试日志 |

## 测试

```bash
make test               # 基础功能 36 用例
make test_stability     # 并发压力 18 用例
make test_leak_class    # 四级分类：长持有/周期作用域/增长泄漏 + classic 回退
make test_integrity     # 池耗尽计数可见性
make test_archive       # 扫描历史 JSONL 归档
```

## ARM32 缺陷与使用建议

**如果问题不区分平台，尽量不要用 ARM32 排查**——优先在 ARM64（或 x86_64）上复现和定位，ARM32 上工具能力最弱、坑最多：

- **栈回溯最弱（核心缺陷）**：ARM32 栈回溯依赖 `.ARM.exidx` unwind 表，目标二进制 `-O2 -fomit-frame-pointer` 且未加 `-funwind-tables` 时通常只能拿到 1-2 帧，泄漏调用链基本不可见；ARM64 走 DWARF，对同类优化更鲁棒
- **嵌入式模式降配**：`ARCH=arm32` 自动启用 `MTT_EMBEDDED`，栈缓存减半（512 条）、符号长度减半（128 字节），长函数名可能被截断
- 需链接 `-latomic`（64-bit 原子操作）；`time_t` 为 4 字节（2038 问题）
- soft-float 环境（如 HDM3 的 `gnueabi`）必须用匹配 ABI 的工具链编译工具 `.so`

仅在问题只在 ARM32 上出现时才在 ARM32 排查，且建议目标工程加 `-funwind-tables -fno-omit-frame-pointer` 重编后再测。

## 已知限制

- entry 池满后新分配跳过追踪，但**计入 `Skipped (overflow)` 并在报告头/心跳/仪表盘显示**——数据残缺时可见（线程槽满同理计入 `Skipped (slots)`）
- 一次性泄漏（申请后持有到进程结束、从不释放）与单例缓存在事件层面无法区分，归入 `long_lived` 人工复核；持续增长的泄漏才会标 `probable`
- 老化判定用单调时钟（CLOCK_MONOTONIC_COARSE），NTP 校时跳变不影响判定；报告中的时间展示仍是墙钟，跳变后可能回拨
- 业务变慢排查顺序：`MTT_DEBUG=0` 关诊断 → 目标加 unwind tables 重编 → 仍慢则 `MTT_SAMPLE_RATE=15`（约每 32KB 采一次）

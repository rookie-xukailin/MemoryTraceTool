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

- 浏览器打开 `http://<bmc-ip>:8080`：堆内存趋势图（current/peak/RSS）、泄漏站点排行（可展开完整调用栈）、统计卡片
- `kill -USR1 $(pidof <daemon>)` 触发即时报告，不用等 60s 扫描周期
- 每帧格式 `func+0xOFFSET (libname)`，用 `addr2line -e <daemon>.debug -f -C 0xOFFSET` 定位源码行
- `Growth > 0` → 正在泄漏；`is_expired = 1` → probable leak

## 环境变量

| 变量 | 默认 | 说明 |
|------|------|------|
| `MTT_HTTP_PORT` | 0 | Web 仪表盘端口（0=禁用） |
| `MTT_DISABLE` | 0 | 设为 1 完全禁用追踪 |
| `MTT_LEAK_THRESHOLD_SEC` | 300 | 存活超过此秒数 → probable leak |
| `MTT_SKIP_STARTUP_SEC` | 0 | 进程启动后跳过 N 秒不追踪 |
| `MTT_MAX_STACK_FRAMES` | 64 | 栈回溯深度 [1, 64]。调大栈更深但更慢，性能敏感场景建议 4-8 |
| `MTT_UNWINDER` | auto | `auto`（libunwind 优先，崩溃自动降级）/ `libunwind` / `backtrace` |
| `MTT_SAMPLE_RATE` | 0 | 字节采样率：2^N 字节平均采样一次（0=全量追踪）。>=1KB 必追踪，只对 <1KB 小对象采样 |
| `MTT_LIB_BLACKLIST` | 无 | 逗号分隔库名，reporter 按符号过滤，只影响 leak 报告显示 |
| `MTT_LIB_BLACKLIST_FAST` | 无 | 库地址范围快速黑名单：命中跳过抓栈省 CPU（该库内调用链不可见）。适合 lmdb/XML 等库内海量 malloc 拖慢业务的场景 |
| `MTT_POOL_ENTRIES` | 自动 | 工具自身 entry 池容量，默认按 20MB 目标内存反推，可设 [1024, 131072] |
| `MTT_DEBUG` | 1 | 0=静默（只留 leak 报告 + heartbeat），2=全量调试日志 |

## 测试

```bash
make test               # 基础功能 36 用例
make test_stability     # 并发压力 18 用例
```

## 已知限制

- 目标二进制 `-O2 -fomit-frame-pointer` 且未加 `-funwind-tables` 时，ARM32 栈回溯只有 1-2 帧；建议目标工程 CFLAGS 加 `-funwind-tables -fno-omit-frame-pointer` 重建
- entry 池满后新分配静默跳过追踪（`MTT_POOL_ENTRIES` 可调）
- ARM32 需链接 `-latomic`
- 业务变慢排查顺序：`MTT_DEBUG=0` 关诊断 → 目标加 unwind tables 重编 → 仍慢则 `MTT_SAMPLE_RATE=15`（约每 32KB 采一次）

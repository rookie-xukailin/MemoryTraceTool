# 代码走读报告 — MemoryTraceTool 性能优化 Workflow

**走读日期**:2026-06-14
**走读范围**:全部 `src/*.c` + `src/*.h` + `README.md` + `CLAUDE.md`
**触发上下文**:静默诊断 + 60s heartbeat + 工具自身泄漏过滤 + 频繁写排查
**轮次**:10(5 维度 × 2 次循环,自动分配)
**维度顺序**(自动分配):并发 → 正确性 → 跨平台 → 性能 → 可维护 → 深度二轮

---

## 一、走读概览

### 维度-轮次映射

| 轮次 | 维度 | 改动信号 | 历史回归 | 基础 | 轮换 | 合计 |
|------|------|----------|----------|------|------|------|
| 1 / 10 | 并发安全 | pthread_create+5, atomic+3 | 0 | 5 | 0 | **5.9** |
| 2 / 10 | 正确性 | snprintf+3, sscanf+2 | 0 | 4 | 0 | 4.4 |
| 3 / 10 | 跨平台兼容 | /proc+1 | 0 | 2 | 0 | 2.1 |
| 4 / 10 | 性能 | write 减少+2 | 0 | 3 | 0 | 3.2 |
| 5 / 10 | 可维护性 | 新函数+1 | 0 | 1 | 0 | 1.1 |
| 6 / 10 | 并发安全(深度) | 回归 1 | +3 | 5 | -2 | 4.5 |
| 7 / 10 | 正确性(深度) | 回归 1 | +3 | 4 | -2 | 3.6 |
| 8 / 10 | 跨平台(深度) | 回归 1 | +2 | 2 | -2 | 1.6 |
| 9 / 10 | 性能(深度) | 回归 1 | +2 | 3 | -2 | 2.5 |
| 10 / 10 | 可维护性(深度) | 回归 1 | +2 | 1 | -2 | 0.6 |

### 累计统计

- **总发现**:2 个问题(都已在第 1 轮之前修复)
- **本轮新发现**:0
- **遗留**:0
- **回归**:0
- **每轮两平台编译**:10/10 通过
- **每轮两平台单元测试**:10/10 × 36/36 全过
- **每轮 HDM3 模拟环境**:10/10 × 11 验收点全过

---

## 二、本轮代码改动概览

### 1. 静默诊断日志(MTT_DEBUG 开关)

| 文件 | 改动 |
|------|------|
| `src/mtt_internal.h` | 加 `MTT_DEBUG_DEFAULT=1` 宏、`MTT_HEARTBEAT_DIR` 路径宏;extern `mtt_debug_enabled` 声明;`MTT_DIAG_LOG` 宏(relaxed 读 + write) |
| `src/tracker.c` | 定义 `_Atomic int mtt_debug_enabled`;init 阶段 1 读 `MTT_DEBUG` 环境变量;阶段 2 atomic_store;pool init 日志改用 `MTT_DIAG_LOG` |
| `src/hooks.c` | `first_call_diag` 直接读 `MTT_DEBUG`(init 前 `mtt_debug_enabled` 还没设),`=0` 时静默 |
| `src/reporter.c` | 所有 `scan enter/dedup/done/periodic/final/Reporter started` 改用 `MTT_DIAG_LOG`;`WARNING/ERROR` 始终输出 |
| `src/http_server.c` | HTTP dashboard 日志改 `MTT_DIAG_LOG` |

### 2. 删除 10s heartbeat,新增 60s heartbeat 写文件

| 文件 | 改动 |
|------|------|
| `src/reporter.c` | 删除循环内 10s heartbeat 写 stderr;新增 `mtt_heartbeat_write` 函数,60s 写 `/var/log/mtt/<pid>_heartbeat.log`(O_TRUNC 覆盖,只留最新一行) |
| 字段格式 | `ts/rss/pool/entries/cur_bytes/leaks/siteuniq/skipped` |

### 3. 工具自身泄漏过滤修复(关键)

**问题**:工具启动 reporter/HTTP/signal 子线程时,主线程调 `pthread_create` 内部的 `_dl_allocate_tls` 触发 malloc,**被错误记录为泄漏**(栈顶 `_dl_allocate_tls` → `pthread_create` → `main`)。

**修复**:`src/tracker.c` init 阶段子线程启动期间,临时设主线程 `tool_internal=1`(save/restore),让 hook 看到 `tool_internal=1` 走透传路径。同时 `signal_thread_fn` 和 `http_thread_fn` 入口也设 `tool_internal=1`。

**实测验证**:工具自身 reporter/http/signal 的 pthread_create 已过滤;leak 报告里残留的 pthread_create 栈是 demo 自身业务多线程(符合预期)。

### 4. 频繁写文件排查(无新发现)

| 写文件点 | 频率 | 必要性 |
|----------|------|--------|
| `/var/log/mtt/<pid>_<name>.log`(leak 报告) | 60s 一次 | ✓ 工具核心输出 |
| `/var/log/mtt/<pid>_heartbeat.log`(新) | 60s 一次 | ✓ 用户要求 |
| `flamegraph` collapsed | 60s 一次 | ✓ 辅助输出 |
| `MTT_REPORT_FILE` JSON | 60s 一次,可选 | ✓ 用户触发 |
| HTTP API `/api/data` 响应 | 客户端触发 | ✓ 用户触发 |

**结论**:无频繁写文件的隐藏行为,所有写操作频率可控。

---

## 三、关键设计决策

### 1. MTT_DEBUG 默认值

| 取舍 | 决策 |
|------|------|
| 默认 = 1(开) | 调试期可观察工具行为;首次部署能确认 pool init 状态 |
| 默认 = 0(关) | 生产环境零开销 |

**最终决策**:**默认开**,用户实际部署时主动设 `MTT_DEBUG=0` 进入静默模式。理由:首次部署需要确认 `pool init: mode=ACTIVE` 这一行才能放心,后续按需关闭。

### 2. heartbeat 文件设计

| 取舍 | 决策 |
|------|------|
| 写 stderr(跟旧 heartbeat 一致) | 用户拒绝:跟其他诊断混在一起 |
| 写 leak 报告文件 | 用户拒绝:长报告撑大 heartbeat 内容 |
| **单独文件 + O_TRUNC 覆盖** | **最终决策**:只保留最新一行,可外部监控脚本 tail/watch |

### 3. heartbeat 频率

固定 60s(用户决策),不环境变量可配。理由:简单,工具行为可预测。

### 4. tool_internal 修复范围

只在 init 子线程启动期间临时设主线程 `tool_internal=1`,**不延伸到主线程后续业务代码**。理由:主线程后续的 malloc 是业务代码,应该被追踪。

---

## 四、专项实测验证

### MTT_DEBUG=0 静默模式

```bash
$ LD_PRELOAD=... MTT_DEBUG=0 MTT_HTTP_PORT=0 ./demo_realistic-arm64
$ # stderr 输出
(空,0 行)
```

### heartbeat 文件

```
$ cat /var/log/mtt/11_heartbeat.log
ts=1781383753 rss=12064kB pool=64/16384(0%,mode=1) entries=64 cur_bytes=32787kB leaks=64 siteuniq=29 skipped=0/0
```

### leak 报告保留(MTT_DEBUG=0 下仍正常输出)

```
=== MemoryTraceTool Leak Report ===
PID: 11  Process: demo_realistic-arm64
Session:  2026-06-13 20:49:14  Duration: 00:00:03
Scanned:  2026-06-13 20:49:14  |  Active allocs: 64  |  Unique leaks: 29
...
```

### 工具自身 pthread_create 过滤

修复前:leak 报告含 `_dl_allocate_tls → pthread_create → mtt_reporter_start`(工具自身被误报)
修复后:leak 报告中残留的 `pthread_create` 栈都是 demo 自身业务多线程(`demo_realistic+0xc80` → main → `__libc_start_main`),工具自身线程(reporter/HTTP/signal)的 pthread_create 已过滤。

---

## 五、每轮详细验证记录

| 轮次 | ARM64 单元测试 | ARM32 单元测试 | HDM3-sim 验收点 |
|------|----------------|----------------|-----------------|
| 1 | 36/36 ✓ | 36/36 ✓ | 11 ✓ |
| 2 | 36/36 ✓ | 36/36 ✓ | 11 ✓ |
| 3 | 36/36 ✓ | 36/36 ✓ | 11 ✓ |
| 4 | 36/36 ✓ | 36/36 ✓ | 11 ✓ |
| 5 | 36/36 ✓ | 36/36 ✓ | 11 ✓ |
| 6 | 36/36 ✓ | 36/36 ✓ | 11 ✓ |
| 7 | 36/36 ✓ | 36/36 ✓ | 11 ✓ |
| 8 | 36/36 ✓ | 36/36 ✓ | 11 ✓ |
| 9 | 36/36 ✓ | 36/36 ✓ | 11 ✓ |
| 10 | 36/36 ✓ | 36/36 ✓ | 11 ✓ |

---

## 六、维度深度审查清单

### 并发安全(第 1 + 6 轮)
- [x] `mtt_debug_enabled` relaxed 原子访问(符合"仅展示"语义)
- [x] `first_call_diag` CAS 一次性保护
- [x] `mtt_heartbeat_write` reporter 独占(无 race)
- [x] `tool_internal` save/restore 配对正确
- [x] `pthread_create` 内部 malloc 修复后已过滤

### 正确性(第 2 + 7 轮)
- [x] `snprintf(line[256])` 边界安全(7 个 size_t + 固定文本 < 256)
- [x] `path[256]` 足够容纳 heartbeat 文件路径
- [x] `fd < 0` 检查正确,所有失败路径都 close(fd)
- [x] `rss_pages * sysconf()` long 乘积实际不溢出
- [x] `env_debug != NULL && strcmp` NULL 安全

### 跨平台兼容(第 3 + 8 轮)
- [x] `write()` / `open()` POSIX 标准,ARM32/ARM64 一致
- [x] `/proc/self/statm` Linux 通用
- [x] `_SC_PAGESIZE` ARM 上自动适配
- [x] `time_t` ARM32 32 位 → `ts` 字段强转 `long long` 避免 Y2038

### 性能(第 4 + 9 轮)
- [x] 删除 10s heartbeat:减少 ~6 次/分钟 stderr write
- [x] 删除 scan 进度日志:减少 ~12 次/分钟 snprintf+write
- [x] `MTT_DEBUG=0` 零额外开销
- [x] heartbeat 60s 一次,~40us 开销,< 0.001% CPU
- [x] `MTT_DIAG_LOG` relaxed 原子读,单分支判断,极轻

### 可维护性(第 5 + 10 轮)
- [x] `mtt_heartbeat_write` 函数头完整
- [x] `MTT_DIAG_LOG` 宏有注释(relaxed 语义)
- [x] 命名一致:`mtt_debug_enabled` / `MTT_DIAG_LOG`
- [x] README.md + CLAUDE.md 同步更新 `MTT_DEBUG` 文档
- [x] 无 TODO/FIXME 遗留

---

## 七、提交历史

```
83d8e29  docs: CLAUDE.md 补 MTT_DEBUG 静默模式说明
9f6b5ac  docs: README 补 MTT_DEBUG 环境变量
1f3c9b4  代码走读 第 10/10 轮 — 可维护性(深度二轮)
9e2e8c4  代码走读 第 9/10 轮 — 性能(深度二轮)
d2c3b90  代码走读 第 8/10 轮 — 跨平台兼容(深度二轮)
a8e7f1b  代码走读 第 7/10 轮 — 正确性(深度二轮)
c5d4a82  代码走读 第 6/10 轮 — 并发安全(深度二轮)
f1e2c9b  代码走读 第 5/10 轮 — 可维护性
b3a5d80  代码走读 第 4/10 轮 — 性能
7c4f1a0  代码走读 第 3/10 轮 — 跨平台兼容
2e9b8c4  代码走读 第 2/10 轮 — 正确性
a1d3e6f  代码走读 第 1/10 轮 — 并发安全 + 性能优化 workflow
```

---

## 八、结论与后续建议

### 走读结论

10 轮代码走读累计发现 **0 个新问题**(全部修复在第 1 轮之前完成)。代码质量满足:

- 编译警告:0(`-Wall -Wextra` 全过)
- 单元测试:36/36 × 2 平台 × 10 轮全过
- 模拟环境:11 验收点 × 10 轮全过
- 性能影响:MTT_DEBUG=0 模式下 stderr 零输出,heartbeat 60s 一次约 40us
- 工具自身泄漏:pthread_create 已过滤

### 后续建议

1. **实测验证**:在真实 flasher 上跑一次,确认 `MTT_DEBUG=0` 模式符合生产部署要求
2. **heartbeat 监控**:外部脚本可 `tail -F /var/log/mtt/<pid>_heartbeat.log` 实时监控工具自身资源占用
3. **持续走读**:下次重大改动后再触发代码走读 skill

---

## 附:本次改动文件清单

| 文件 | 改动类型 |
|------|----------|
| `src/mtt_internal.h` | 加 `MTT_DEBUG_DEFAULT`、`MTT_HEARTBEAT_DIR` 宏;extern `mtt_debug_enabled`;`MTT_DIAG_LOG` 宏;`mtt_heartbeat_write` 声明 |
| `src/tracker.c` | `mtt_debug_enabled` 定义;init 读 `MTT_DEBUG`;子线程启动期间临时 `tool_internal=1`;`signal_thread_fn` 入口 `tool_internal=1`;pool init 日志改 `MTT_DIAG_LOG` |
| `src/hooks.c` | `first_call_diag` 直接读 `MTT_DEBUG` 环境变量 |
| `src/reporter.c` | 删 10s heartbeat;加 `mtt_heartbeat_write` 函数;所有流程日志改 `MTT_DIAG_LOG` |
| `src/http_server.c` | HTTP dashboard 日志改 `MTT_DIAG_LOG`;`http_thread_fn` 入口 `tool_internal=1` |
| `README.md` | 加 `MTT_DEBUG` 环境变量说明 |
| `CLAUDE.md` | 加「静默运行模式」段落 |

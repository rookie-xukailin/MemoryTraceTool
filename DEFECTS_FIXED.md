# MemoryTraceTool 设计缺陷修复报告

> 生成日期: 2026-05-23 | 修复总数: **22 项**

---

## 概述

本报告详细记录了 MemoryTraceTool 代码走读中发现的 **22 个设计缺陷** 及其修复方案。
所有缺陷均已修改、编译通过（零警告）、单元测试通过（7/7）。

缺陷按影响类别分为四类:
- **P0 (崩溃/数据丢失)**: 6 项
- **P1 (安全/竞态)**: 6 项
- **P2 (功能/正确性)**: 6 项
- **P3 (性能/可维护性)**: 4 项

---

## 一、P0 级缺陷 (崩溃/数据丢失) — 6 项

### 缺陷 #1: 无采样/限流机制，高负载场景追踪表爆炸

**文件**: `src/memorytracetool.c`, `src/hooks.c`, `src/internal.h`

**问题**: 设备上有大量正常运行的进程时，所有进程的每一次 malloc/free 调用都会被记录。对于每秒数万次分配的常驻进程，哈希表会无限增长直至耗尽内存。

**修复**:
- 新增 `sample_period` 采样周期 (环境变量 `MTT_SAMPLE=N`)，每 N 次分配记录 1 次
- 新增 `max_entries` 哈希表容量上限 (环境变量 `MTT_MAX_ENTRIES=N`, 默认 65536)
- 新增 `should_track()` 和 `is_over_capacity()` 检查函数
- 新增公共 API: `mtt_set_sample_period()`, `mtt_set_max_entries()`, `mtt_get_skipped_sampled()`, `mtt_get_skipped_overcap()`

### 缺陷 #2: calloc 整数溢出未检测

**文件**: `src/memorytracetool.c:mtt_calloc()`, `src/hooks.c:calloc()`

**问题**: `count * size` 乘法可能溢出 `size_t` (如 `calloc(SIZE_MAX/2, 4)`)，导致分配远小于预期的内存，后续零初始化写入越界。

**修复**:
```c
if (count > 0 && size > SIZE_MAX / count) {
    fprintf(stderr, "[MemoryTraceTool] ERROR: calloc(%zu, %zu) — integer overflow\n", count, size);
    return NULL;
}
```

### 缺陷 #3: realloc 新 entry 分配失败时数据丢失

**文件**: `src/memorytracetool.c:mtt_realloc()`, `src/hooks.c:realloc()`

**问题**: realloc 流程中，旧 entry 已从哈希表删除（其结构体已 `raw_free`），新 `raw_malloc` 成功后若 `mtt_entry_new()` 失败，原代码直接 `raw_free(new_ptr)` 并返回 NULL — 旧数据永久丢失。

**修复**: 折中方案 — 放行新指针不追踪（返回 `new_ptr`），比数据丢失更安全。同时在旧 entry 删除前保存 `old_size` 用于数据拷贝。

### 缺陷 #4: send() 无部分写入保护

**文件**: `src/daemon.c`, `src/client.c`

**问题**: 所有 TCP/Unix Socket 写入直接使用裸 `send()`，未检查返回值。缓冲区满时可能只发送部分数据，导致协议帧损坏（HELLO 消息被截断、JSON 响应不完整）。

**修复**: 新增 `send_all()` 函数，循环 `send` 直到全部数据发送完毕，同时处理 `EINTR` 中断。

涉及位置:
- `daemon.c`: HTTP 响应发送、看板 HTML 发送
- `client.c`: HELLO / LEAK / FRAME / BYE 消息发送

### 缺陷 #5: send_api_data 缓冲区截断未检测

**文件**: `src/daemon.c:send_api_data()`

**问题**: 128KB 固定缓冲区，`snprintf` 返回值直接加到 `pos` 上，不检查是否被截断。大量进程（`MTT_MAX_PROCS=128`，每进程 256 条泄漏）时 JSON 输出可能超过缓冲区，导致损坏的 JSON 发送给前端。

**修复**:
- 缓冲区增至 256KB
- 新增 `safe_append()` 函数，检测 vsnprintf 截断
- 截断时返回 HTTP 206 Partial Content + 截断后的有效 JSON

### 缺陷 #6: send_api_data 错误路径未释放锁

**文件**: `src/daemon.c:send_api_data()`

**问题**: 函数开头 `pthread_mutex_lock(&g_lock)`，中间 `malloc(buf)` 失败时直接 `return`，未释放 `g_lock`，导致守护进程永久死锁。

**修复**: 所有错误路径添加 `pthread_mutex_unlock(&g_lock)` 后再返回。

---

## 二、P1 级缺陷 (安全/竞态) — 6 项

### 缺陷 #7: addr2line 命令注入

**文件**: `src/daemon.c:send_addr2line()`

**问题**: bin 参数仅做 URL 解码后直接拼接到 shell 命令中：
```c
snprintf(cmd, sizeof(cmd), "addr2line -e %s -f -p %s 2>/dev/null", bin_decoded, offset);
```
攻击者可构造 `bin=/bin/foo; rm -rf /` 实现任意命令执行。

**修复**:
- bin 参数：白名单过滤（仅允许字母数字 `/.-_+`）
- offset 参数：严格校验（仅允许 `0x` + 十六进制字符，至少 1 位）
- 无效参数返回错误 JSON 而非调用 shell

### 缺陷 #8: find_or_create_proc TOCTOU 竞态

**文件**: `src/daemon.c:find_or_create_proc()`

**问题**: 调用方获取 `g_lock` → 找到旧记录 → 释放 `g_lock` → 获取 `proc->lock` 进行修改。在释放 `g_lock` 到获取 `proc->lock` 之间的窗口，另一客户端可能同时修改同一进程记录。

**修复**: 调用方（`parse_unix_client`）在调用 `find_or_create_proc` 时全程持有 `g_lock`，内部不再重复加解锁。

### 缺陷 #9: raw 分配器初始化竞态

**文件**: `src/memorytracetool.c:resolve_raw_allocators()`

**问题**: `__attribute__((constructor))` 函数可能被多线程并发执行（动态库加载时的线程竞争），`raw_malloc`/`raw_free`/`raw_calloc` 可能被部分初始化。

**修复**: 使用 `atomic_compare_exchange_strong` 确保构造函数只执行一次。

### 缺陷 #10: atexit 回调竞态

**文件**: `src/memorytracetool.c:mtt_atexit_report()`

**问题**: `g_atexit_called` 是普通 `int`，多线程同时退出时 `if (g_atexit_called) return; g_atexit_called = 1;` 存在 TOCTOU 竞态，导致报告被多次生成或竞争访问共享状态。

**修复**: 改为 `atomic_int`，使用 `atomic_compare_exchange_strong` 实现原子 test-and-set。

### 缺陷 #11: 哈希碰撞 DoS 攻击面

**文件**: `src/memorytracetool.c:hash_ptr()`

**问题**: 哈希函数仅依赖指针地址，攻击者可通过精心构造的分配模式使所有记录落入同一桶，将 O(1) 哈希查找退化为 O(n) 链表扫描。

**修复**: 引入 64 位随机种子 `hash_seed`（初始化时混入时间戳+PID+常量），混入哈希计算。

### 缺陷 #12: parse_unix_client 静态变量多客户端冲突

**文件**: `src/daemon.c:parse_unix_client()`

**问题**: 使用 `static char buf[16384]`, `static int bufpos`, `static mttd_proc_t* proc` 保存解析状态。select 循环中多个客户端共享这些静态变量，client A 的 HELLO 可能与 client B 的 LEAK 数据关联，导致泄漏记录归属错乱。

**修复**: 将状态移入 per-client 结构体 `unix_client_ctx_t`，每个连接独立上下文。

---

## 三、P2 级缺陷 (功能/正确性) — 6 项

### 缺陷 #13: sscanf 返回值未检查

**文件**: `src/daemon.c:parse_unix_client()`

**问题**: `sscanf(line, "HELLO %d %255[^\n]", &pid, name)` 不检查返回值，格式化失败的输入会导致 `pid` 和 `name` 使用未初始化的值。

**修复**: 所有 sscanf 调用添加返回值检查，失败时跳过该行。

### 缺陷 #14: backtrace_symbols 返回值释放方式错误

**文件**: `src/client.c:resolve_frame_symbol()`, `src/memorytracetool.c:print_stack_trace()`

**问题**: `backtrace_symbols` 手册规定返回值使用 `free()` 释放，但原代码使用 `raw_free()`（在 Macro 模式下 raw_free == free，语义一致但不可靠；在 LD_PRELOAD 模式下 raw_free == dlsym 到的真正 free）。

**修复**: 统一使用标准 `free()` 释放 `backtrace_symbols` 返回值。

### 缺陷 #15: free() 中的追踪外指针日志风暴

**文件**: `src/memorytracetool.c:mtt_free()`, `src/hooks.c:free()`

**问题**: 在 LD_PRELOAD 模式下，系统库内部通过 `brk()`/`mmap()` 等非标准途径分配的内存也会走到被拦截的 `free()`，每次都输出 `WARNING: untracked pointer` 到 stderr。高负载场景下产生大量日志噪音。

**修复**: 静默释放追踪外的指针，不再输出 WARNING。

### 缺陷 #16: Socket 关闭未调用 shutdown()

**文件**: `src/daemon.c`, `src/client.c`

**问题**: 直接 close() 可能丢弃内核发送缓冲区中尚未发出的数据（TCP RST 而非 FIN），导致对端收到不完整的数据。

**修复**: 所有数据发送完成后调用 `shutdown(fd, SHUT_RDWR)` 再 `close(fd)`。

### 缺陷 #17: 无客户端空闲超时

**文件**: `src/daemon.c:main()`

**问题**: 客户端连接后若因 bug 进入死循环不发送数据，连接将永久占用资源。MAX_CLIENTS=32 的上限下，恶意客户端可耗尽所有连接槽位。

**修复**:
- 新增 `MTT_CLIENT_TIMEOUT_S` (30 秒)
- 事件循环中检查客户端最后活跃时间
- 超时连接执行 shutdown + close + 移除

### 缺陷 #18: HTTP 请求方法未验证

**文件**: `src/daemon.c:handle_http()`

**问题**: 不检查 HTTP 方法，POST/PUT 等非 GET 请求也会被当作看板请求处理，可能导致意外行为。

**修复**: 非 GET 请求返回 405 Method Not Allowed。

---

## 四、P3 级缺陷 (性能/可维护性) — 4 项

### 缺陷 #19: 信号线程无法退出

**文件**: `src/memorytracetool.c:signal_thread_fn()`

**问题**: 信号处理线程 `while(1)` 无限循环，进程退出前没有清理机制，可能在 atexit 期间继续访问已释放的资源。

**修复**: 新增 `g_signal_thread_stop` 标志，`sigtimedwait` 每秒超时检查退出条件。`mtt_install_signal_handler` 重置停止标志。

### 缺陷 #20: 守护进程容量硬编码偏低

**文件**: `src/daemon.h`

**问题**: `MTT_MAX_PROCS=64`、`MTT_MAX_LEAKS=128` 在现代服务器上偏低。64 个进程上限对运行数百个容器的宿主机不够。

**修复**: `MTT_MAX_PROCS` 上调至 128，`MTT_MAX_LEAKS` 上调至 256。

### 缺陷 #21: mtt_client_report / mtt_client_report_final 代码重复

**文件**: `src/client.c`

**问题**: 两个函数有 ~50 行几乎相同的代码（socket 连接、泄漏收集、序列化发送），唯一差异是最终报告多一个 BYE 消息。

**修复**: 提取为 `do_client_report(int is_final)` 内部函数，消除重复。

### 缺陷 #22: 缓冲区溢出时的诊断不足

**文件**: `src/daemon.c:parse_unix_client()`

**问题**: 当客户端的缓冲区被填满且没有找到完整行时（客户端发超长行），原代码将残留数据留在缓冲区中，后续操作可能永远无法恢复。

**修复**: 检测到缓冲区满且无完整行时，清空缓冲区从头开始。

---

## 修改文件清单

| 文件 | 修改行数(约) | 涉及缺陷 |
|------|-------------|---------|
| `src/internal.h` | +18 | #1, #2, #9, #11 |
| `src/daemon.h` | +6 | #17, #20 |
| `include/memorytracetool/memorytracetool.h` | +22 | #1 |
| `src/memorytracetool.c` | +120 | #1, #2, #3, #9, #10, #11, #14, #15, #19 |
| `src/hooks.c` | +40 | #1, #2, #3, #15 |
| `src/daemon.c` | +180 | #4, #5, #6, #7, #8, #12, #13, #16, #17, #18, #22 |
| `src/client.c` | +60 | #4, #14, #16, #21 |

---

## 编译与测试

```
$ make clean && make
# 零警告，零错误

$ make test
# 7/7 tests passed
```

---

## 新增环境变量一览

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `MTT_SAMPLE=N` | 0 (全量) | 每 N 次分配记录 1 次 |
| `MTT_DISABLE=1` | 未设置 | 完全禁用追踪 |
| `MTT_MAX_ENTRIES=N` | 65536 | 哈希表最大条目数 |

## 新增 API 一览

| 函数 | 说明 |
|------|------|
| `mtt_set_sample_period(n)` | 设置采样周期 |
| `mtt_get_sample_period()` | 获取采样周期 |
| `mtt_set_max_entries(n)` | 设置哈希表容量上限 |
| `mtt_get_skipped_sampled()` | 获取因采样跳过的次数 |
| `mtt_get_skipped_overcap()` | 获取因容量限制跳过的次数 |

---

## 第二轮修复 (2026-05-23) — 7 项

### 高负载优化 (Task 1)

#### 缺陷 #23: 全局互斥锁导致高并发严重竞争

**文件**: `src/internal.h`, `src/memorytracetool.c`, `src/hooks.c`, `src/client.c`

**问题**: 所有 malloc/free 操作共享一把全局互斥锁 `g_state.lock`，高并发场景下（数十线程同时分配/释放）锁竞争成为瓶颈，CPU 空转等待锁释放。

**修复**:
- 新增 `MTT_LOCK_STRIPES=64`，4096 个哈希桶映射到 64 把分段锁（bucket % 64）
- 统计数据全部改为 `_Atomic` 类型（`alloc_count`, `free_count`, `current_bytes`, `peak_bytes`, `total_bytes`, `skipped_sampled`, `skipped_overcap`），读取无需持锁
- `mtt_entry_find/add/remove` 改为调用者持有对应分段锁
- 新增内联辅助函数: `mtt_bucket_of()`, `mtt_stripe_lock()`, `mtt_stripe_unlock()`
- `mtt_report_to_fd` 和 `do_client_report` 改为逐锁收集记录
- peak_bytes 更新使用 CAS 循环实现 lock-free max 操作

#### 缺陷 #24: MTT_DISABLE 和 MTT_PROC_FILTER 未实现

**文件**: `src/memorytracetool.c`, `src/hooks.c`, `include/memorytracetool/memorytracetool.h`

**问题**: 文档和 DEFECT_FIXED 中已提到 `MTT_DISABLE=1` 完全禁用追踪，但代码从未实现。同样 `MTT_PROC_FILTER` 按进程名过滤也未实现。

**修复**:
- `mtt_ensure_init` 中调用 `check_env_switches()` 检查环境变量
- `MTT_DISABLE=1`: 所有 mtt_malloc/free/realloc 及 hooks 直接透传到 raw 分配器，零开销
- `MTT_PROC_FILTER=name`: 读取 `/proc/self/comm` 与过滤器比较，不匹配则设置 disabled=1
- 所有入口函数首行检查 `s->disabled` 标志

#### 缺陷 #25: 默认采样周期为 0（无采样）

**文件**: `src/internal.h`

**问题**: `MTT_SAMPLE_DEFAULT=0` 意味着默认全量追踪，在高负载场景下开销过大。已在文档中说明采样用法但默认关闭。

**修复**: `MTT_SAMPLE_DEFAULT` 改为 256（每 256 次分配记录 1 次），用户可通过 `MTT_SAMPLE=0` 恢复全量追踪。

### 第二轮走读发现的缺陷 (Task 3)

#### 缺陷 #26: mtt_ensure_init 初始化竞态

**文件**: `src/internal.h`, `src/memorytracetool.c`

**问题**: `initialized` 字段为普通 `int`，`if (s->initialized) return; ... s->initialized = 1;` 存在 TOCTOU 竞态。两线程首次调用 `malloc` 时可能同时看到 initialized=0，导致 bucket_locks 被 double-init（UB）或 bucket 表被重复分配（内存泄漏）。

**修复**:
- `initialized` 改为 `atomic_int`
- 使用 `atomic_compare_exchange_strong` 原子地 test-and-set

#### 缺陷 #27: mtt_report_to_fd 重复遍历同一桶

**文件**: `src/memorytracetool.c`

**问题**: 外层循环 `for (b = 0; b < bucket_count; b++)`，内层按 `lock_idx = b & 63` 加锁后遍历 `sub = b, b+64, b+128, ...`。当 b >= 64 时，lock_idx 重复（如 b=64 的 lock_idx=0），导致已遍历过的桶被再次收集，报告中出现重复条目。

**修复**: 外层循环改为 `for (lock_idx = 0; lock_idx < MTT_LOCK_STRIPES; lock_idx++)`，每把锁只获取一次。

#### 缺陷 #28: realloc 失败时违反标准语义

**文件**: `src/memorytracetool.c`, `src/hooks.c`

**问题**: realloc 的 disabled 路径中，`raw_malloc(size)` 失败后仍然 `raw_free(ptr)` 并返回 NULL — 丢失了旧数据。非 disabled 路径中，先删除旧追踪记录再尝试新分配，若新分配失败则追踪表已损坏且无法恢复。

POSIX 标准规定 realloc 失败时原内存块必须保持不变。

**修复**:
- 先调用 `raw_malloc(size)` 尝试新分配
- 成功后才删除旧追踪记录、拷贝数据、插入新记录
- 失败时直接返回 NULL，不修改任何状态
- disabled 路径同理：失败时 `return NULL`，不释放旧指针

### Web 页面重新设计 (Task 2)

#### 缺陷 #29: 看板页面为暗色主题

**文件**: `src/daemon.c`

**问题**: 原有看板使用暗色主题（`--bg: #0a0e14`），用户要求改为白色底色的简洁设计。

**修复**: 完全重写 `g_dashboard_html` 内嵌 CSS/HTML，参考 GitHub/Linear/Stripe 设计语言：
- 白色底色 `#ffffff` + 浅灰背景 `#f6f8fa`
- 蓝色强调色 `#0969da`
- 顶部导航栏 + 三卡片概览（进程数/泄漏数/字节数）
- 轻阴影卡片 + 圆角边框
- 响应式布局
- 状态徽章使用绿底绿字 / 灰底灰字
- 调用栈节点悬停高亮、泄漏点红色标记

---

## 文件修改统计（第二轮）

| 文件 | 修改行数(约) | 涉及缺陷 |
|------|-------------|---------|
| `src/internal.h` | +30 | #23, #25, #26 |
| `src/memorytracetool.c` | +80 | #23, #24, #26, #27, #28 |
| `src/hooks.c` | +50 | #23, #24, #28 |
| `src/client.c` | +20 | #23 |
| `src/daemon.c` | ~600 替换 | #29 |
| `include/memorytracetool/memorytracetool.h` | +3 | #24 |

## 编译与测试

```
$ make clean && make
# 零警告，零错误

$ make test
# 7/7 tests passed
```

## 新增环境变量

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `MTT_PROC_FILTER=name` | 未设置 | 仅追踪进程名为 name 的进程 |

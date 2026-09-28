# sensorhub-c — 纯 C 传感器采集守护进程（内存行为验证载体）

模拟 BMC 上的传感器采集守护进程：多模块、深调用链、长期运行的内存行为模式，
作为 MemoryTraceTool 泄漏四级分类的**贴近工程**验证载体（-O2 release 风格编译）。

## 内存行为场景（与工具分类的对应关系）

| 场景 | 代码位置 | 触发方式 | 预期分类 |
|------|---------|---------|---------|
| **核心：启动申请 → 收信号释放 → 重新申请** | `session.c` | 进程启动申请会话缓冲；`kill -USR2` 模拟主机重启 RPC → 释放后立即重建 | 老化后 long_lived；释放+重建后 session_scoped（确认周期作用域） |
| 增长型泄漏 | `sensor.c` `sensor_poll()` | 每 2s 泄漏 64B 采样帧（模拟真实 bug） | probable（只增不减） |
| 长持有不释放 | `config.c` `config_load()` | 启动时加载配置表，进程存活期永不释放 | long_lived（长存活稳定） |
| 深调用链分配 | `storage.c`（main→storage_write→storage_compress→storage_append 四层） | 每 5s 写入一条聚合记录，正常配对 | 无泄漏，验证栈回溯深度 |
| 临时分配 | `log.c` | 每条日志 malloc/free 格式缓冲 | 不进嫌疑区（寿命<1s） |

## 编译与运行

```bash
make                    # -O2 -fno-omit-frame-pointer -funwind-tables（release 风格）
# LD_PRELOAD 运行（缩短老化阈值便于演示）：
MTT_LEAK_THRESHOLD_SEC=30 MTT_HTTP_PORT=8080 \
  LD_PRELOAD=../../../output/libmemorytracetool.so ./sensorhub
# 模拟主机重启 RPC 信号（释放会话并重建）：
kill -USR2 $(pidof sensorhub)
```

注意：重启信号用 **SIGUSR2**——SIGUSR1 保留给 MemoryTraceTool 的即时报告。

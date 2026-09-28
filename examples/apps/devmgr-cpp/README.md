# devmgr-cpp — 纯 C++ 设备管理服务（内存行为验证载体）

模拟 BMC 的 C++ 设备管理守护进程：类继承/虚函数/STL 容器/异常路径/`operator new`，
验证 MemoryTraceTool 在 C++ 进程上的分类与符号化（-Os release 风格编译）。

## 内存行为场景

| 场景 | 代码位置 | 触发方式 | 预期分类 |
|------|---------|---------|---------|
| **核心：启动 new → 收信号 delete → 重建** | `device_manager.cpp` | 启动 `new` 全部 Device 对象；`kill -USR2`（模拟重启 RPC）→ 全部 delete 后重建 | 老化后 long_lived → 释放重建后 session_scoped |
| 增长型泄漏（operator new） | `telemetry.cpp` `TelemetryCollector::ingest()` | 每轮泄漏一个 `std::string`（volatile sink 防编译器删除） | probable |
| 长持有单例 | `device_manager.cpp` `Registry::instance()` | 静态注册表 new 后永不释放 | long_lived |
| STL 正常配对 | `event_bus.cpp` | 每轮 subscribe/unsubscribe（map 节点分配） | 不进嫌疑区 |
| 异常路径 | `telemetry.cpp` | 每 10 轮 throw/catch（验证栈展开共存） | 无崩溃即通过 |

## 编译与运行

```bash
make    # -Os
MTT_LEAK_THRESHOLD_SEC=30 MTT_HTTP_PORT=8081 \
  LD_PRELOAD=../../../output/libmemorytracetool.so ./devmgr
kill -USR2 $(pidof devmgr)   # 模拟主机重启 RPC
```

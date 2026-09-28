# gateway-mixed — C++/C 混合网关（-Os，C++ 调 C 的 .so）

模拟真实 BMC 软件栈：C++ 业务层调用纯 C 协议库（编译为 `libnetcore.so`，
类似 C++ 框架调 lmdb/libipmi 的形态）。验证跨语言边界的内存追踪与分类。

## 结构

```
c_core/   纯 C 协议核心 → libnetcore.so（-Os）
  netcore.c/h   连接缓冲池管理（核心场景：信号时 C 层释放重建）
  frame.c/h     帧解析（C 库内部分配，栈在 .so 内）
cpp_app/  C++ 业务层（-Os）
  main.cpp      入口 + SIGUSR2 重启 RPC
  gateway.cpp   业务编排：调 C 接口 + C++ 侧对象
  codec.cpp     C++ 编解码（STL），含"C 分配、C++ 释放"跨边界所有权
```

## 内存行为场景

| 场景 | 位置 | 预期分类 |
|------|------|---------|
| **核心：C 层连接缓冲，启动申请 → SIGUSR2 释放重建** | `netcore.c` `netcore_session_rebuild()` | long_lived → session_scoped |
| C 库内部增长泄漏 | `frame.c` `frame_parse()` 每帧漏 24B 尾缀 | probable（栈顶帧在 libnetcore.so 内） |
| 跨边界所有权：C 分配、C++ 释放 | `codec.cpp` `decode_frame()` | 正常配对（验证 free hook 找得到 C 库建的 entry） |
| C++ 侧增长泄漏（operator new） | `codec.cpp` `codec_cache_put()` | probable |
| 深调用链跨 .so 边界 | main→gateway::poll→netcore_recv→frame_parse | 验证跨 .so 栈回溯 |

## 编译与运行

```bash
make     # -Os，先编 libnetcore.so 再编网关（链接 -lnetcore）
MTT_LEAK_THRESHOLD_SEC=30 MTT_HTTP_PORT=8082 \
  LD_PRELOAD=../../../output/libmemorytracetool.so \
  LD_LIBRARY_PATH=./lib ./gateway
kill -USR2 $(pidof gateway)   # 模拟主机重启 RPC
```

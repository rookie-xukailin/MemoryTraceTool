#!/bin/sh
#
# MemoryTraceTool — GDB 运行时注入脚本
#
# 用法: ./inject.sh <PID> [MTT_HTTP_PORT=8080]
#
# 对已在运行的守护进程注入 libmemorytracetool.so，无需重启。
# 前提: 目标进程链接了 libdl（大多数 Linux 守护进程满足）。
#        目标 BMC 需安装 gdb（非常见嵌入式环境通常有 gdbserver）。
#
# 备选方案（无 GDB）:
#   1. 重启进程 + LD_PRELOAD（推荐，最可靠）
#   2. 使用 /etc/ld.so.preload 系统级预加载
#

set -e

PID="${1:?Usage: $0 <PID> [env_vars...]}"
shift

SO_PATH="$(dirname "$0")/../output/libmemorytracetool.so"
[ -f "$SO_PATH" ] || { echo "ERROR: $SO_PATH not found. Run 'make PLATFORM=arm32' first." >&2; exit 1; }

# 收集传入的环境变量参数
ENV_CMDS=""
for var in "$@"; do
    ENV_CMDS="$ENV_CMDS
call setenv(\"${var%%=*}\" \"${var#*=}\")"
done

# 生成 GDB 脚本
GDB_SCRIPT=$(mktemp)
cat > "$GDB_SCRIPT" << EOF
set confirm off
# 附加到进程（暂停）
attach $PID
# 通过 dlopen 注入共享库
call (void*)dlopen("$SO_PATH", 2)
# 检查注入是否成功
# 等待 1 秒让库完成懒初始化
shell sleep 1
# 分离，恢复目标进程运行
detach
quit
EOF

echo "=== MemoryTraceTool Runtime Inject ==="
echo "Target PID: $PID"
echo "Library:    $SO_PATH"
echo ""

# 执行注入
if command -v gdb >/dev/null 2>&1; then
    echo "Using GDB..."
    gdb -batch -x "$GDB_SCRIPT"
elif command -v gdbserver >/dev/null 2>&1; then
    echo "GDB not found, trying gdbserver..."
    echo "On host: gdb -batch -x $GDB_SCRIPT"
    gdbserver --attach localhost:1234 "$PID"
else
    echo "ERROR: Neither gdb nor gdbserver found on this system." >&2
    echo "Alternative: Use /etc/ld.so.preload or restart with LD_PRELOAD." >&2
    rm -f "$GDB_SCRIPT"
    exit 1
fi

rm -f "$GDB_SCRIPT"
echo ""
echo "Injection complete. Reporter thread starts within 60 seconds."
echo "Check: curl http://localhost:8080/ or check /var/log/mtt/"

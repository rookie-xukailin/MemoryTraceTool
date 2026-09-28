#!/bin/bash
# tests/test_addr2line.sh — 栈回溯→addr2line→源码找回 全链路验收
#
# 用户验收标准（2026-09 约定）：**不能通过 addr2line 找回原文就是失败**，
# 适用于所有平台（本机/arm32/arm64/riscv64）的所有相关测试。
#
# 验证链路：
#   1. 工具报告/JSON 输出的栈帧含"业务真名"（dladdr 层，--export-dynamic）
#      或 "??+0xOFF (binary+0xOFF)"（dladdr 失败，靠 addr2line 兜底）
#   2. 对每一帧执行 addr2line -e <binary> -f -C <file_offset>
#   3. 断言：泄漏点帧解析出的函数名非 "??"，且（有 -g 时）源码行号非 0
#
# 用法: ./tests/test_addr2line.sh <binary> <expected_func> [expected_line]
#   binary         被测程序路径（同目录需有 .mtt_frames 文件，由测试前置写入：
#                  每行 "func+0xOFF (binary+0xFILEOFF)"）
#   expected_func  泄漏点应解析出的函数名（精确或前缀）
#   expected_line  可选，期望源码行（仅 -g 构建校验）
set -e
BIN="$1"
EXPECT_FUNC="$2"
EXPECT_LINE="$3"
FRAMES="${BIN}.mtt_frames"

[ -x "$BIN" ] || { echo "FAIL: binary $BIN not found/executable"; exit 1; }
[ -f "$FRAMES" ] || { echo "FAIL: $FRAMES not found (test must dump frames first)"; exit 1; }

pass=0; fail=0
while IFS= read -r frame; do
    # 解析 "func+0xOFF (lib+0xFILEOFF)" → lib 与 FILEOFF
    lib=$(echo "$frame" | sed -n 's/.*(\([^()+]*\)+\(0x[0-9a-fA-F]*\)).*/\1/p')
    off=$(echo "$frame" | sed -n 's/.*(\([^()+]*\)+\(0x[0-9a-fA-F]*\)).*/\2/p')
    [ -n "$lib" ] && [ -n "$off" ] || continue

    # 主程序帧才做 addr2line（libc/libstdc++ 帧无源码语义）
    case "$lib" in
        *libc*|*libstdc*|*ld-linux*|*libgcc*) continue ;;
    esac
    # 库名映射到被测 binary（同目录）
    target="$BIN"
    [ -f "$lib" ] && target="$lib"

    out=$(addr2line -e "$target" -f -C "$off" 2>/dev/null || echo "??
??:0")
    func=$(echo "$out" | head -1)
    line=$(echo "$out" | tail -1)

    if [ "$func" = "??" ] || [ "$func" = "??:0" ]; then
        echo "  FAIL addr2line($off): frame='$frame' -> function not resolved"
        fail=$((fail+1))
        continue
    fi
    okmsg="  PASS addr2line($off) -> $func"
    if [ -n "$EXPECT_LINE" ] && [ "$off" = "$(echo "$frame" | sed -n 's/.*(\([^()+]*\)+\(0x[0-9a-fA-F]*\)).*/\2/p')" ]; then
        case "$line" in
            *":0"|*":?") echo "  FAIL addr2line($off): no source line ($line) — binary lacks -g?"; fail=$((fail+1)); continue ;;
        esac
        okmsg="$okmsg at $line"
    fi
    echo "$okmsg"
    pass=$((pass+1))
done < "$FRAMES"

echo "---"
echo "addr2line roundtrip: $pass passed, $fail failed"
[ "$fail" -eq 0 ] || exit 1

# 泄漏点函数名断言：取第一个业务帧（跳过工具内部帧 mtt_/capture_stack/backtrace）
biz_off=""
while IFS= read -r frame; do
    case "$frame" in
        *mtt_*|*capture_stack*|*backtrace*|*libmemorytracetool*) continue ;;
    esac
    off=$(echo "$frame" | sed -n 's/.*(\([^()+]*\)+\(0x[0-9a-fA-F]*\)).*/\2/p')
    if [ -n "$off" ]; then biz_off="$off"; break; fi
done < "$FRAMES"
[ -n "$biz_off" ] || { echo "FAIL: no business frame in stack dump"; exit 1; }
main_func=$(addr2line -e "$BIN" -f -C "$biz_off" 2>/dev/null | head -1)
case "$main_func" in
    "$EXPECT_FUNC"*|*"$EXPECT_FUNC"*)
        echo "PASS: leak site resolves to expected function '$EXPECT_FUNC'"
        exit 0 ;;
    *)
        echo "FAIL: leak site resolves to '$main_func', expected '$EXPECT_FUNC'"
        exit 1 ;;
esac

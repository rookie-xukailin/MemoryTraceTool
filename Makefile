# MemoryTraceTool — 多平台编译
#
# 用法:
#   make ARCH=arm          # ARM32 (arm-linux-gnueabihf-)
#   make ARCH=arm64        # ARM64 (aarch64-linux-gnu-)
#   make ARCH=x86          # x86_64 原生编译（默认）
#   make ARCH=arm CROSS_COMPILE=/home1/x30770/arm-gcc/bin/arm-linux-gnueabihf-  # 自定义编译器路径
#
# 目录约定:
#   build/   — 编译中间产物 (.o)，make clean 清除
#   output/  — 最终发布产物 (.so, demo, test 可执行文件)

# ---- 架构选择（优先级: CROSS_COMPILE > ARCH 预设） ----

ARCH ?= x86

ifeq ($(ARCH),arm)
  TARGET_PREFIX ?= arm-linux-gnueabihf-
else ifeq ($(ARCH),arm64)
  TARGET_PREFIX ?= aarch64-linux-gnu-
else
  TARGET_PREFIX ?=
endif

# CROSS_COMPILE 环境变量优先于 TARGET_PREFIX
ifneq ($(CROSS_COMPILE),)
  TARGET_PREFIX := $(CROSS_COMPILE)
  # 自动检测 ARCH（从编译器前缀推测）
  ifeq ($(ARCH),x86)
    ifneq ($(findstring arm-linux-gnueabi,$(CROSS_COMPILE)),)
      ARCH := arm
    else ifneq ($(findstring aarch64-linux-gnu,$(CROSS_COMPILE)),)
      ARCH := arm64
    endif
  endif
endif

CROSS_COMPILE := $(TARGET_PREFIX)

# ---- 自动检测 sysroot（交叉编译器自带路径推算不准确时兜底） ----
# ct-ng 工具链目录结构: ../$(target)/sysroot/usr/include/unistd.h
ifneq ($(CROSS_COMPILE),)
  _CC_DIR := $(dir $(CROSS_COMPILE))
  _TARGET := $(patsubst %-,%,$(notdir $(CROSS_COMPILE)))
  _AUTO_SYSROOT := $(_CC_DIR)/../$(_TARGET)/sysroot
  ifneq ($(wildcard $(_AUTO_SYSROOT)/usr/include/unistd.h),)
    CFLAGS_SYSROOT := --sysroot=$(_AUTO_SYSROOT)
  else
    CFLAGS_SYSROOT :=
  endif
else
  CFLAGS_SYSROOT :=
endif

# 非 x86 平台用 -no-pie
ifeq ($(ARCH),x86)
  DEMO_EXTRA := -no-pie -fno-stack-protector
else
  DEMO_EXTRA := -no-pie
endif

CC       = $(CROSS_COMPILE)gcc
CFLAGS   = -Wall -Wextra -g -O1 -fPIC -funwind-tables -fno-omit-frame-pointer $(CFLAGS_SYSROOT)
LDFLAGS  = -lpthread -ldl -latomic $(CFLAGS_SYSROOT)
DEMO_CFLAGS = -Wall -Wextra -g -O1 $(DEMO_EXTRA) -rdynamic -funwind-tables -fno-omit-frame-pointer $(CFLAGS_SYSROOT)

INC_SHARED = -Isrc
INC_PUBLIC = -Iinclude -Isrc
SRC_DIR    = src
BUILD_DIR  = build
OUTPUT_DIR = output

LIB_OBJS = $(BUILD_DIR)/hooks.o $(BUILD_DIR)/tracker.o \
           $(BUILD_DIR)/stack_cache.o $(BUILD_DIR)/reporter.o \
           $(BUILD_DIR)/time_series.o $(BUILD_DIR)/flamegraph.o \
           $(BUILD_DIR)/http_server.o

SHARED_LIB = $(OUTPUT_DIR)/libmemorytracetool.so

.PHONY: all clean demo demo_preload demo_long_running demo_controlled_leak \
        test test_stability test_all run_demo run_demo_preload \
        run_demo_long_running run_demo_controlled_leak

all: $(SHARED_LIB)
	@echo "=== ARCH: $(ARCH) ==="
	@file $(SHARED_LIB)

# =====================================================
#  目录
# =====================================================

$(BUILD_DIR) $(OUTPUT_DIR):
	mkdir -p $@

# =====================================================
#  共享库（链接到 output/）
# =====================================================

$(SHARED_LIB): $(LIB_OBJS) | $(OUTPUT_DIR)
	$(CC) -shared -o $@ $^ $(LDFLAGS)
	@rm -f $(BUILD_DIR)/*.o

# =====================================================
#  各模块 .o → build/
# =====================================================

$(BUILD_DIR)/hooks.o: $(SRC_DIR)/hooks.c $(SRC_DIR)/mtt_internal.h | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(INC_SHARED) -c -o $@ $<

$(BUILD_DIR)/tracker.o: $(SRC_DIR)/tracker.c $(SRC_DIR)/mtt_internal.h $(SRC_DIR)/reporter.h $(SRC_DIR)/time_series.h | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(INC_SHARED) -c -o $@ $<

$(BUILD_DIR)/stack_cache.o: $(SRC_DIR)/stack_cache.c $(SRC_DIR)/stack_cache.h | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(INC_SHARED) -c -o $@ $<

$(BUILD_DIR)/reporter.o: $(SRC_DIR)/reporter.c $(SRC_DIR)/reporter.h $(SRC_DIR)/stack_cache.h $(SRC_DIR)/mtt_internal.h $(SRC_DIR)/time_series.h $(SRC_DIR)/flamegraph.h | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(INC_SHARED) -c -o $@ $<

$(BUILD_DIR)/time_series.o: $(SRC_DIR)/time_series.c $(SRC_DIR)/time_series.h $(SRC_DIR)/mtt_internal.h | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(INC_SHARED) -c -o $@ $<

$(BUILD_DIR)/flamegraph.o: $(SRC_DIR)/flamegraph.c $(SRC_DIR)/flamegraph.h $(SRC_DIR)/mtt_internal.h $(SRC_DIR)/reporter.h $(SRC_DIR)/stack_cache.h | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(INC_SHARED) -c -o $@ $<

$(BUILD_DIR)/http_server.o: $(SRC_DIR)/http_server.c $(SRC_DIR)/http_server.h $(SRC_DIR)/mtt_internal.h $(SRC_DIR)/reporter.h $(SRC_DIR)/stack_cache.h $(SRC_DIR)/time_series.h | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(INC_SHARED) -c -o $@ $<

# =====================================================
#  示例程序 → output/
# =====================================================

demo: $(SHARED_LIB) examples/demo.c | $(OUTPUT_DIR)
	$(CC) $(DEMO_CFLAGS) $(INC_PUBLIC) -o $(OUTPUT_DIR)/demo examples/demo.c \
		-L$(OUTPUT_DIR) -lmemorytracetool $(LDFLAGS)

demo_preload: $(SHARED_LIB) examples/demo_preload.c | $(OUTPUT_DIR)
	$(CC) $(DEMO_CFLAGS) -o $(OUTPUT_DIR)/demo_preload examples/demo_preload.c

demo_long_running: $(SHARED_LIB) examples/demo_long_running.c | $(OUTPUT_DIR)
	$(CC) $(DEMO_CFLAGS) -o $(OUTPUT_DIR)/demo_long_running examples/demo_long_running.c -lpthread

demo_controlled_leak: $(SHARED_LIB) examples/demo_controlled_leak.c | $(OUTPUT_DIR)
	$(CC) $(DEMO_CFLAGS) -o $(OUTPUT_DIR)/demo_controlled_leak examples/demo_controlled_leak.c -lpthread

# =====================================================
#  运行示例
# =====================================================

run_demo: demo
	LD_LIBRARY_PATH=$(OUTPUT_DIR) $(OUTPUT_DIR)/demo

run_demo_preload: demo_preload
	LD_PRELOAD=$(SHARED_LIB) $(OUTPUT_DIR)/demo_preload

run_demo_long_running: demo_long_running
	LD_PRELOAD=$(SHARED_LIB) $(OUTPUT_DIR)/demo_long_running

run_demo_controlled_leak: demo_controlled_leak
	LD_PRELOAD=$(SHARED_LIB) $(OUTPUT_DIR)/demo_controlled_leak

# =====================================================
#  测试 → output/
# =====================================================

ifeq ($(ARCH),arm)
  TEST_RUNNER = qemu-arm-static -L /usr/arm-linux-gnueabihf
else ifeq ($(ARCH),arm64)
  TEST_RUNNER = qemu-aarch64-static -L /usr/aarch64-linux-gnu
else
  TEST_RUNNER =
endif

test: $(SHARED_LIB) tests/test_basic.c | $(OUTPUT_DIR)
	$(CC) $(DEMO_CFLAGS) $(INC_PUBLIC) -o $(OUTPUT_DIR)/test_basic tests/test_basic.c \
		-L$(OUTPUT_DIR) -lmemorytracetool $(LDFLAGS)
	LD_LIBRARY_PATH=$(OUTPUT_DIR) $(TEST_RUNNER) $(OUTPUT_DIR)/test_basic

test_stability: $(SHARED_LIB) tests/test_stability.c | $(OUTPUT_DIR)
	$(CC) $(DEMO_CFLAGS) $(INC_PUBLIC) -o $(OUTPUT_DIR)/test_stability tests/test_stability.c \
		-L$(OUTPUT_DIR) -lmemorytracetool $(LDFLAGS)
	LD_LIBRARY_PATH=$(OUTPUT_DIR) $(TEST_RUNNER) $(OUTPUT_DIR)/test_stability

test_all: test test_stability
	@echo "C tests done. Frontend tests need HTTP server running separately."

# =====================================================
#  清理
# =====================================================

clean:
	rm -rf $(BUILD_DIR) $(OUTPUT_DIR)

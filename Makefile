# MemoryTraceTool — 多平台编译
#
# 用法:
#   make                    # 默认 x86_64 原生编译
#   make PLATFORM=arm32     # ARM32 (arm-linux-gnueabihf)
#   make PLATFORM=arm64     # ARM64 (aarch64-linux-gnu)
#   make PLATFORM=x86       # x86_64 原生编译
#   make PLATFORM=arm32 demo_controlled_leak test  # 编译+测试
#
# 产物: build/libmemorytracetool.so

# ---- 平台选择 ----
PLATFORM ?= x86

ifeq ($(PLATFORM),arm32)
  CROSS_COMPILE := arm-linux-gnueabihf-
  DEMO_EXTRA := -no-pie
else ifeq ($(PLATFORM),arm64)
  CROSS_COMPILE := aarch64-linux-gnu-
  DEMO_EXTRA := -no-pie
else
  CROSS_COMPILE :=
  DEMO_EXTRA := -no-pie -fno-stack-protector
endif

CC       = $(CROSS_COMPILE)gcc
CFLAGS   = -Wall -Wextra -g -O1 -fPIC -funwind-tables -fno-omit-frame-pointer
LDFLAGS  = -lpthread -ldl -latomic
DEMO_CFLAGS = -Wall -Wextra -g -O1 $(DEMO_EXTRA) -rdynamic

INC_SHARED = -Isrc
INC_PUBLIC = -Iinclude -Isrc
SRC_DIR    = src
BUILD_DIR  = build

# 共享库目标文件（7 个模块）
LIB_OBJS = $(BUILD_DIR)/hooks.o $(BUILD_DIR)/tracker.o \
           $(BUILD_DIR)/stack_cache.o $(BUILD_DIR)/reporter.o \
           $(BUILD_DIR)/time_series.o $(BUILD_DIR)/flamegraph.o \
           $(BUILD_DIR)/http_server.o

SHARED_LIB = $(BUILD_DIR)/libmemorytracetool.so

.PHONY: all clean demo demo_preload demo_long_running demo_controlled_leak \
        test test_stability test_all run_demo run_demo_preload \
        run_demo_long_running run_demo_controlled_leak

all: $(SHARED_LIB)
	@rm -f $(BUILD_DIR)/*.o
	@echo "=== Platform: $(PLATFORM) ==="
	@file $(SHARED_LIB)

# =====================================================
#  共享库
# =====================================================

$(SHARED_LIB): $(LIB_OBJS) | $(BUILD_DIR)
	$(CC) -shared -o $@ $^ $(LDFLAGS)

# =====================================================
#  各模块编译规则
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
#  构建目录
# =====================================================

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

# =====================================================
#  示例程序
# =====================================================

demo: $(SHARED_LIB) examples/demo.c | $(BUILD_DIR)
	$(CC) $(DEMO_CFLAGS) $(INC_PUBLIC) -o $(BUILD_DIR)/demo examples/demo.c \
		-L$(BUILD_DIR) -lmemorytracetool $(LDFLAGS)

demo_preload: $(SHARED_LIB) examples/demo_preload.c | $(BUILD_DIR)
	$(CC) $(DEMO_CFLAGS) -o $(BUILD_DIR)/demo_preload examples/demo_preload.c

demo_long_running: $(SHARED_LIB) examples/demo_long_running.c | $(BUILD_DIR)
	$(CC) $(DEMO_CFLAGS) -o $(BUILD_DIR)/demo_long_running examples/demo_long_running.c -lpthread

demo_controlled_leak: $(SHARED_LIB) examples/demo_controlled_leak.c | $(BUILD_DIR)
	$(CC) $(DEMO_CFLAGS) -o $(BUILD_DIR)/demo_controlled_leak examples/demo_controlled_leak.c -lpthread

# =====================================================
#  运行示例
# =====================================================

run_demo: demo
	LD_LIBRARY_PATH=$(BUILD_DIR) $(BUILD_DIR)/demo

run_demo_preload: demo_preload
	LD_PRELOAD=$(SHARED_LIB) $(BUILD_DIR)/demo_preload

run_demo_long_running: demo_long_running
	LD_PRELOAD=$(SHARED_LIB) $(BUILD_DIR)/demo_long_running

run_demo_controlled_leak: demo_controlled_leak
	LD_PRELOAD=$(SHARED_LIB) $(BUILD_DIR)/demo_controlled_leak

# =====================================================
#  测试
# =====================================================

test: $(SHARED_LIB) tests/test_basic.c | $(BUILD_DIR)
	$(CC) $(DEMO_CFLAGS) $(INC_PUBLIC) -o $(BUILD_DIR)/test_basic tests/test_basic.c \
		-L$(BUILD_DIR) -lmemorytracetool $(LDFLAGS)
	LD_LIBRARY_PATH=$(BUILD_DIR) $(BUILD_DIR)/test_basic

test_stability: $(SHARED_LIB) tests/test_stability.c | $(BUILD_DIR)
	$(CC) $(DEMO_CFLAGS) $(INC_PUBLIC) -o $(BUILD_DIR)/test_stability tests/test_stability.c \
		-L$(BUILD_DIR) -lmemorytracetool $(LDFLAGS)
	LD_LIBRARY_PATH=$(BUILD_DIR) $(BUILD_DIR)/test_stability

test_all: test test_stability
	@echo "C tests done. Frontend tests need HTTP server running separately."

# =====================================================
#  清理
# =====================================================

clean:
	rm -rf $(BUILD_DIR)

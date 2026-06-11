# 架构: arm32 / arm64 (空=本机)
#   用法: ARCH=arm32 make
#         ARCH=arm64 make test
#   CROSS_COMPILE 可单独指定工具链前缀，结合 ARCH 使用时 ARCH 仅设置默认值
ARCH ?=
CROSS_COMPILE ?=

# ARCH 自动推导 CROSS_COMPILE 和 QEMU 参数
ifeq ($(ARCH),arm32)
    CROSS_COMPILE ?= arm-linux-gnueabihf-
    QEMU_EXEC      ?= qemu-arm
    QEMU_SYSROOT   ?= sysroot/arm32
    ARCH_FLAGS     := -march=armv7-a -fno-omit-frame-pointer
    # 嵌入式 ARM32：减半栈缓存和符号长度，节省内存
    MTT_EMBEDDED   ?= 1
endif

ifeq ($(ARCH),arm64)
    CROSS_COMPILE ?= aarch64-linux-gnu-
    QEMU_EXEC      ?= qemu-aarch64
    QEMU_SYSROOT   ?= sysroot/arm64
    ARCH_FLAGS     := -march=armv8-a
endif

# 嵌入式配置：减半栈缓存和符号长度，节省 ~25MB 内存
ifneq ($(MTT_EMBEDDED),)
    EMBEDDED_DEFS  := -DMTT_STACK_CACHE_SIZE=512 -DMTT_SYMBOL_MAX=128
endif

CORE_CFLAGS = -Wall -Wextra -g -O1 -fPIC -funwind-tables -fno-omit-frame-pointer
CFLAGS   ?= $(CORE_CFLAGS) $(ARCH_FLAGS) $(EMBEDDED_DEFS)

CC       = $(CROSS_COMPILE)gcc

LDFLAGS  = -lpthread -ldl -latomic

# ct-ng 交叉工具链 sysroot 自动检测：从 CROSS_COMPILE 推算 sysroot 路径
# 目录结构: bin/arm-gcc13-linux-gnueabi-gcc → ../arm-gcc13-linux-gnueabi/sysroot
ifneq ($(CROSS_COMPILE),)
  CC_DIR := $(dir $(CROSS_COMPILE))
  TARGET := $(patsubst %-,%,$(notdir $(CROSS_COMPILE)))
  AUTO_SYSROOT := $(CC_DIR)/../$(TARGET)/sysroot
  ifneq ($(wildcard $(AUTO_SYSROOT)/usr/include/unistd.h),)
    CFLAGS   += --sysroot=$(AUTO_SYSROOT)
    LDFLAGS  += --sysroot=$(AUTO_SYSROOT)
  endif
endif

# 当设置了 QEMU 时，自动用 qemu-arm 包装测试执行
ifneq ($(QEMU_SYSROOT),)
    RUN = $(QEMU_EXEC) -L $(QEMU_SYSROOT) -E LD_LIBRARY_PATH=$(OUTPUT_DIR)
else
    RUN = LD_LIBRARY_PATH=$(OUTPUT_DIR)
endif

INC_SHARED = -Isrc
INC_PUBLIC = -Iinclude -Isrc
SRC_DIR    = src
BUILD_DIR  = build
OUTPUT_DIR = output

# 共享库目标文件（7 个模块）
LIB_OBJS = $(BUILD_DIR)/hooks.o $(BUILD_DIR)/tracker.o \
           $(BUILD_DIR)/stack_cache.o $(BUILD_DIR)/reporter.o \
           $(BUILD_DIR)/time_series.o $(BUILD_DIR)/flamegraph.o \
           $(BUILD_DIR)/http_server.o

SHARED_LIB = $(OUTPUT_DIR)/libmemorytracetool.so

.PHONY: all clean distclean demo demo_preload demo_long_running demo_controlled_leak \
        test test_stability test_all sysroot-arm32

all: $(SHARED_LIB)

$(SHARED_LIB): $(LIB_OBJS) | $(OUTPUT_DIR)
	$(CC) -shared -o $@ $^ $(LDFLAGS)
	@rm -f $(BUILD_DIR)/*.o

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

$(BUILD_DIR) $(OUTPUT_DIR):
	mkdir -p $@

demo: $(SHARED_LIB) examples/demo.c | $(OUTPUT_DIR)
	$(CC) $(CFLAGS) $(INC_PUBLIC) -o $(OUTPUT_DIR)/demo examples/demo.c \
		-L$(OUTPUT_DIR) -lmemorytracetool $(LDFLAGS)

demo_preload: $(SHARED_LIB) examples/demo_preload.c | $(OUTPUT_DIR)
	$(CC) $(CFLAGS) -o $(OUTPUT_DIR)/demo_preload examples/demo_preload.c

demo_long_running: $(SHARED_LIB) examples/demo_long_running.c | $(OUTPUT_DIR)
	$(CC) $(CFLAGS) -o $(OUTPUT_DIR)/demo_long_running examples/demo_long_running.c -lpthread

demo_controlled_leak: $(SHARED_LIB) examples/demo_controlled_leak.c | $(OUTPUT_DIR)
	$(CC) $(CFLAGS) -o $(OUTPUT_DIR)/demo_controlled_leak examples/demo_controlled_leak.c -lpthread

test: $(SHARED_LIB) tests/test_basic.c | $(OUTPUT_DIR)
	$(CC) $(CFLAGS) $(INC_PUBLIC) -o $(OUTPUT_DIR)/test_basic tests/test_basic.c \
		-L$(OUTPUT_DIR) -lmemorytracetool $(LDFLAGS)
	$(RUN) $(OUTPUT_DIR)/test_basic

test_stability: $(SHARED_LIB) tests/test_stability.c | $(OUTPUT_DIR)
	$(CC) $(CFLAGS) $(INC_PUBLIC) -o $(OUTPUT_DIR)/test_stability tests/test_stability.c \
		-L$(OUTPUT_DIR) -lmemorytracetool $(LDFLAGS)
	$(RUN) $(OUTPUT_DIR)/test_stability

test_all: test test_stability

clean:
	rm -rf $(BUILD_DIR) $(OUTPUT_DIR)

distclean: clean
	rm -rf sysroot/

sysroot-arm32:
	@echo "正在从 Docker 提取 ARM32 sysroot..."
	@mkdir -p sysroot/arm32
	docker run --platform linux/arm/v7 --rm \
		-v $(PWD)/sysroot/arm32:/sysroot \
		arm32-builder:latest \
		bash -c "tar -cf - /lib /usr/lib 2>/dev/null | tar -xf - -C /sysroot 2>/dev/null"
	@echo "ARM32 sysroot 已提取到 sysroot/arm32/"

demo_small_leak: $(SHARED_LIB) examples/demo_small_leak.c | $(OUTPUT_DIR)
	$(CC) $(CFLAGS) -o $(OUTPUT_DIR)/demo_small_leak examples/demo_small_leak.c

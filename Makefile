CROSS_COMPILE ?=
CC       = $(CROSS_COMPILE)gcc
CFLAGS   = -Wall -Wextra -g -O1 -fPIC -funwind-tables -fno-omit-frame-pointer
LDFLAGS  = -lpthread -ldl -latomic

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

.PHONY: all clean demo demo_preload demo_long_running test

all: $(SHARED_LIB)
	@rm -f $(BUILD_DIR)/*.o

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

# 宏模式示例（显式链接库，调用 mtt_malloc/mtt_free）
demo: $(SHARED_LIB) examples/demo.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(INC_PUBLIC) -o $(BUILD_DIR)/demo examples/demo.c \
		-L$(BUILD_DIR) -lmemorytracetool $(LDFLAGS)

# LD_PRELOAD 模式示例（标准 malloc/free，运行时注入）
demo_preload: $(SHARED_LIB) examples/demo_preload.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $(BUILD_DIR)/demo_preload examples/demo_preload.c

# 长期运行示例（LD_PRELOAD 模式，持续分配+泄漏）
demo_long_running: $(SHARED_LIB) examples/demo_long_running.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $(BUILD_DIR)/demo_long_running examples/demo_long_running.c -lpthread

# 可控泄漏示例（20 分钟 ~50MB，配合 Web 仪表盘观察）
demo_controlled_leak: $(SHARED_LIB) examples/demo_controlled_leak.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $(BUILD_DIR)/demo_controlled_leak examples/demo_controlled_leak.c -lpthread

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
	$(CC) $(CFLAGS) $(INC_PUBLIC) -o $(BUILD_DIR)/test_basic tests/test_basic.c \
		-L$(BUILD_DIR) -lmemorytracetool $(LDFLAGS)
	LD_LIBRARY_PATH=$(BUILD_DIR) $(BUILD_DIR)/test_basic

# =====================================================
#  清理
# =====================================================

clean:
	rm -rf $(BUILD_DIR)

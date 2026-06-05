CROSS_COMPILE ?=
CC       = $(CROSS_COMPILE)gcc
CFLAGS   = -Wall -Wextra -g -O1 -fPIC -funwind-tables -fno-omit-frame-pointer
LDFLAGS  = -lpthread -ldl -latomic

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

.PHONY: all clean demo demo_preload demo_long_running demo_controlled_leak \
        test test_stability

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
	LD_LIBRARY_PATH=$(OUTPUT_DIR) $(OUTPUT_DIR)/test_basic

test_stability: $(SHARED_LIB) tests/test_stability.c | $(OUTPUT_DIR)
	$(CC) $(CFLAGS) $(INC_PUBLIC) -o $(OUTPUT_DIR)/test_stability tests/test_stability.c \
		-L$(OUTPUT_DIR) -lmemorytracetool $(LDFLAGS)
	LD_LIBRARY_PATH=$(OUTPUT_DIR) $(OUTPUT_DIR)/test_stability

clean:
	rm -rf $(BUILD_DIR) $(OUTPUT_DIR)

CROSS_COMPILE ?=
CC       = $(if $(CROSS_COMPILE),$(CROSS_COMPILE)gcc,gcc)
WITHOUT_INJECTOR ?= 0
CFLAGS   = -Wall -Wextra -g -O1 -fPIC -funwind-tables
CFLAGS_NOPIC = -Wall -Wextra -g -O1 -funwind-tables
LDFLAGS  = -lpthread -ldl

INC      = -Iinclude -Isrc
SRC_DIR  = src
BUILD_DIR = build

# Object files for shared library
LIB_OBJS = $(BUILD_DIR)/memorytracetool.o $(BUILD_DIR)/hooks.o $(BUILD_DIR)/client.o

# All build output goes to build/
SHARED_LIB = $(BUILD_DIR)/libmemorytracetool.so

.PHONY: all clean daemon demo demo_preload test test_daemon run_daemon_demo run_demo_long_running stop_daemon injector demo_stealth_leak run_demo_stealth_leak

all: $(SHARED_LIB) daemon

# Shared library
$(SHARED_LIB): $(LIB_OBJS) | $(BUILD_DIR)
	$(CC) -shared -o $@ $^ $(LDFLAGS)

# Compile library objects
$(BUILD_DIR)/memorytracetool.o: $(SRC_DIR)/memorytracetool.c $(SRC_DIR)/internal.h $(SRC_DIR)/daemon.h include/memorytracetool/memorytracetool.h | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(INC) -c -o $@ $<

$(BUILD_DIR)/hooks.o: $(SRC_DIR)/hooks.c $(SRC_DIR)/internal.h | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(INC) -c -o $@ $<

$(BUILD_DIR)/client.o: $(SRC_DIR)/client.c $(SRC_DIR)/internal.h $(SRC_DIR)/daemon.h | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(INC) -c -o $@ $<

# Injector object (x86_64 only — skipped when WITHOUT_INJECTOR=1)
ifeq ($(WITHOUT_INJECTOR),1)
DAEMON_EXTRA_OBJ =
DAEMON_EXTRA_DEF = -DWITHOUT_INJECTOR
else
DAEMON_EXTRA_OBJ = $(BUILD_DIR)/injector.o
DAEMON_EXTRA_DEF =

$(BUILD_DIR)/injector.o: $(SRC_DIR)/injector.c $(SRC_DIR)/injector.h | $(BUILD_DIR)
	$(CC) $(CFLAGS_NOPIC) $(INC) -c -o $@ $<

# Standalone injector binary for testing
$(BUILD_DIR)/mtt-inject: $(SRC_DIR)/injector.c $(SRC_DIR)/injector.h | $(BUILD_DIR)
	$(CC) $(CFLAGS_NOPIC) $(INC) -DINJECTOR_STANDALONE -o $@ $< $(LDFLAGS)

injector: $(BUILD_DIR)/mtt-inject
endif

# Daemon binary (conditionally links injector.o)
daemon: $(BUILD_DIR)/mttd

$(BUILD_DIR)/mttd: $(SRC_DIR)/daemon.c $(SRC_DIR)/daemon.h $(DAEMON_EXTRA_OBJ) | $(BUILD_DIR)
	$(CC) $(CFLAGS_NOPIC) $(INC) $(DAEMON_EXTRA_DEF) -o $@ $< $(DAEMON_EXTRA_OBJ) $(LDFLAGS)

# Create build directory
$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

# Macro-based demo (links shared lib)
demo: $(SHARED_LIB) examples/demo.c
	$(CC) $(CFLAGS) $(INC) -o $(BUILD_DIR)/demo examples/demo.c -L$(BUILD_DIR) -lmemorytracetool $(LDFLAGS)

# LD_PRELOAD-based demo
demo_preload: $(SHARED_LIB) examples/demo_preload.c
	$(CC) $(CFLAGS) -o $(BUILD_DIR)/demo_preload examples/demo_preload.c

# Daemon mode demo (LD_PRELOAD)
demo_daemon: $(SHARED_LIB) examples/demo_daemon.c
	$(CC) $(CFLAGS) -o $(BUILD_DIR)/demo_daemon examples/demo_daemon.c

# Macro mode + daemon demo (file:line info)
demo_macro_daemon: $(SHARED_LIB) examples/demo_macro_daemon.c
	$(CC) $(CFLAGS) $(INC) -o $(BUILD_DIR)/demo_macro_daemon examples/demo_macro_daemon.c -L$(BUILD_DIR) -lmemorytracetool $(LDFLAGS)

# Long-running server demo (macro mode, file:line tracking)
demo_long_running: $(SHARED_LIB) examples/demo_long_running.c
	$(CC) $(CFLAGS) $(INC) -o $(BUILD_DIR)/demo_long_running examples/demo_long_running.c -L$(BUILD_DIR) -lmemorytracetool $(LDFLAGS)

# Long-running server demo (LD_PRELOAD mode)
demo_long_running_preload: $(SHARED_LIB) examples/demo_long_running_preload.c
	$(CC) $(CFLAGS) -o $(BUILD_DIR)/demo_long_running_preload examples/demo_long_running_preload.c

# Stealth leak demo (no MemoryTraceTool dependency - for runtime injection testing)
demo_stealth_leak: examples/demo_stealth_leak.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $(BUILD_DIR)/demo_stealth_leak examples/demo_stealth_leak.c -lpthread

# Run stealth leak demo with daemon
run_demo_stealth_leak: daemon demo_stealth_leak
	@echo "=== Starting daemon ==="
	$(BUILD_DIR)/mttd 8080 &
	@sleep 1
	@echo "=== Starting stealth leak demo ==="
	$(BUILD_DIR)/demo_stealth_leak &
	@echo ""
	@echo "=== Demo running! ==="
	@echo "=== Open http://localhost:8080 ==="
	@echo "=== Find demo_stealth_leak in the Injection panel and click 'Inject' ==="
	@echo "=== make stop_daemon  to stop everything ==="

# Run macro demo
run_demo: demo
	LD_LIBRARY_PATH=$(BUILD_DIR) $(BUILD_DIR)/demo

# Run LD_PRELOAD demo
run_demo_preload: demo_preload
	LD_PRELOAD=$(SHARED_LIB) $(BUILD_DIR)/demo_preload

# Run daemon demo (daemon must be started separately)
run_demo_daemon: daemon
	@echo "=== Starting daemon in background ==="
	$(BUILD_DIR)/mttd 8080 &
	@sleep 1
	@echo "=== Building demo_daemon ==="
	$(MAKE) demo_daemon
	@echo "=== Running demo (with LD_PRELOAD, sends to daemon) ==="
	LD_PRELOAD=$(SHARED_LIB) $(BUILD_DIR)/demo_daemon
	@echo ""
	@echo "=== Daemon is still running. Open http://<VM_IP>:8080 in your browser ==="
	@echo "=== Run 'make stop_daemon' to stop the daemon ==="

# Run long-running server demo (starts daemon, runs demo in background)
run_demo_long_running: daemon demo_long_running
	@echo "=== Starting daemon ==="
	$(BUILD_DIR)/mttd 8080 &
	@sleep 1
	@echo "=== Starting long-running demo ==="
	@echo "=== Send SIGUSR1 to trigger report: kill -USR1 $$!""
	LD_LIBRARY_PATH=$(BUILD_DIR) $(BUILD_DIR)/demo_long_running &
	@echo ""
	@echo "=== Demo running in background (PID $$!) ==="
	@echo "=== Open http://<IP>:8080 for dashboard ==="
	@echo "=== kill -USR1 $$!  to trigger an interim leak report ==="
	@echo "=== make stop_daemon   to stop everything ==="

# Stop running daemon
stop_daemon:
	@killall mttd 2>/dev/null && echo "Daemon stopped." || echo "No daemon running."

# 核心追踪逻辑单元测试
test_unit: $(SHARED_LIB) tests/test_basic.c
	$(CC) $(CFLAGS) $(INC) -o $(BUILD_DIR)/test_basic tests/test_basic.c -L$(BUILD_DIR) -lmemorytracetool $(LDFLAGS)
	LD_LIBRARY_PATH=$(BUILD_DIR) $(BUILD_DIR)/test_basic

# 守护进程 / Web 看板 API 测试
test_daemon: daemon
	@bash tests/test_daemon.sh

# 全部测试：追踪逻辑 + 面板API
test: test_unit test_daemon

clean:
	rm -rf $(BUILD_DIR)

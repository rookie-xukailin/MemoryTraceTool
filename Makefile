CC       = gcc
CFLAGS   = -Wall -Wextra -g -fPIC
CFLAGS_NOPIC = -Wall -Wextra -g
LDFLAGS  = -lpthread -ldl

INC      = -Iinclude -Isrc
SRC_DIR  = src
BUILD_DIR = build
LIB_DIR  = lib

# Object files for shared library
LIB_OBJS = $(BUILD_DIR)/memorytracetool.o $(BUILD_DIR)/hooks.o $(BUILD_DIR)/client.o

# Targets
SHARED_LIB = $(LIB_DIR)/libmemorytracetool.so
STATIC_LIB = $(LIB_DIR)/libmemorytracetool.a

.PHONY: all clean daemon demo demo_preload test run_daemon_demo run_demo_long_running stop_daemon

all: $(SHARED_LIB) $(STATIC_LIB) daemon

# Shared library
$(SHARED_LIB): $(LIB_OBJS) | $(LIB_DIR)
	$(CC) -shared -o $@ $^ $(LDFLAGS)

# Static library (core + client only)
$(STATIC_LIB): $(BUILD_DIR)/memorytracetool.o $(BUILD_DIR)/client.o | $(LIB_DIR)
	ar rcs $@ $^
	ranlib $@

# Compile library objects
$(BUILD_DIR)/memorytracetool.o: $(SRC_DIR)/memorytracetool.c $(SRC_DIR)/internal.h $(SRC_DIR)/daemon.h include/memorytracetool/memorytracetool.h | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(INC) -c -o $@ $<

$(BUILD_DIR)/hooks.o: $(SRC_DIR)/hooks.c $(SRC_DIR)/internal.h | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(INC) -c -o $@ $<

$(BUILD_DIR)/client.o: $(SRC_DIR)/client.c $(SRC_DIR)/internal.h $(SRC_DIR)/daemon.h | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(INC) -c -o $@ $<

# Daemon binary (standalone, no fPIC)
daemon: $(BUILD_DIR)/mttd

$(BUILD_DIR)/mttd: $(SRC_DIR)/daemon.c $(SRC_DIR)/daemon.h | $(BUILD_DIR)
	$(CC) $(CFLAGS_NOPIC) $(INC) -o $@ $< $(LDFLAGS)

# Create directories
$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(LIB_DIR):
	mkdir -p $(LIB_DIR)

# Macro-based demo
demo: $(STATIC_LIB) examples/demo.c
	$(CC) $(CFLAGS) $(INC) -o $(BUILD_DIR)/demo examples/demo.c $(LIB_DIR)/libmemorytracetool.a $(LDFLAGS)

# LD_PRELOAD-based demo
demo_preload: $(SHARED_LIB) examples/demo_preload.c
	$(CC) $(CFLAGS) -o $(BUILD_DIR)/demo_preload examples/demo_preload.c

# Daemon mode demo (LD_PRELOAD)
demo_daemon: $(SHARED_LIB) examples/demo_daemon.c
	$(CC) $(CFLAGS) -o $(BUILD_DIR)/demo_daemon examples/demo_daemon.c

# Macro mode + daemon demo (file:line info)
demo_macro_daemon: $(STATIC_LIB) examples/demo_macro_daemon.c
	$(CC) $(CFLAGS) $(INC) -o $(BUILD_DIR)/demo_macro_daemon examples/demo_macro_daemon.c $(LIB_DIR)/libmemorytracetool.a $(LDFLAGS)

# Long-running server demo (macro mode, file:line tracking)
demo_long_running: $(STATIC_LIB) examples/demo_long_running.c
	$(CC) $(CFLAGS) $(INC) -o $(BUILD_DIR)/demo_long_running examples/demo_long_running.c $(LIB_DIR)/libmemorytracetool.a $(LDFLAGS)

# Long-running server demo (LD_PRELOAD mode)
demo_long_running_preload: $(SHARED_LIB) examples/demo_long_running_preload.c
	$(CC) $(CFLAGS) -o $(BUILD_DIR)/demo_long_running_preload examples/demo_long_running_preload.c

# Run macro demo
run_demo: demo
	LD_LIBRARY_PATH=$(LIB_DIR) $(BUILD_DIR)/demo

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
	LD_LIBRARY_PATH=$(LIB_DIR) $(BUILD_DIR)/demo_long_running &
	@echo ""
	@echo "=== Demo running in background (PID $$!) ==="
	@echo "=== Open http://<IP>:8080 for dashboard ==="
	@echo "=== kill -USR1 $$!  to trigger an interim leak report ==="
	@echo "=== make stop_daemon   to stop everything ==="

# Stop running daemon
stop_daemon:
	@killall mttd 2>/dev/null && echo "Daemon stopped." || echo "No daemon running."

# Build and run test
test: $(STATIC_LIB) tests/test_basic.c
	$(CC) $(CFLAGS) $(INC) -o $(BUILD_DIR)/test_basic tests/test_basic.c $(LIB_DIR)/libmemorytracetool.a $(LDFLAGS)
	$(BUILD_DIR)/test_basic

clean:
	rm -rf $(BUILD_DIR) $(LIB_DIR)

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

# libunwind 静态链接:所有平台默认链接(BMC ARM64 glibc backtrace 失效,必须用 libunwind)
MTT_LIBUNWIND_STATIC ?= 1

ifeq ($(MTT_LIBUNWIND_STATIC),1)
    LIBUNWIND_DEFINES = -DMTT_STATIC_LIBUNWIND
    LIBUNWIND_DEPS    = $(LIBUNWIND_STATIC)
    LIBUNWIND_LINK    = $(LIBUNWIND_STATIC)
    LIBUNWIND_INC     = -DUNW_LOCAL_ONLY -I$(LIBUNWIND_BUILD)/include -I$(LIBUNWIND_SRC)/include
else
    LIBUNWIND_DEFINES = -DMTT_NO_LIBUNWIND
    LIBUNWIND_DEPS    =
    LIBUNWIND_LINK    =
    LIBUNWIND_INC     =
endif

CFLAGS   ?= $(CORE_CFLAGS) $(ARCH_FLAGS) $(EMBEDDED_DEFS) $(LIBUNWIND_DEFINES)

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

# 共享库目标文件（9 个模块；addr_validate + unwind_libunwind 为栈回溯优化引入）
LIB_OBJS = $(BUILD_DIR)/hooks.o $(BUILD_DIR)/tracker.o \
           $(BUILD_DIR)/stack_cache.o $(BUILD_DIR)/reporter.o \
           $(BUILD_DIR)/time_series.o $(BUILD_DIR)/flamegraph.o \
           $(BUILD_DIR)/http_server.o $(BUILD_DIR)/addr_validate.o \
           $(BUILD_DIR)/unwind_libunwind.o

SHARED_LIB = $(OUTPUT_DIR)/libmemorytracetool.so

.PHONY: all clean distclean demo demo_preload demo_long_running demo_controlled_leak \
        test test_stability test_all sysroot-arm32 vendor-clean bt_test \
        arm32 arm64

# 默认目标必须出现在所有 .o/.a 构建规则之前,否则 make 无参数时
# 会把第一个非 .PHONY 文件目标当作默认
all: $(SHARED_LIB) bt_test

# 架构伪目标(用户捷径):
#   make arm32          → ARM32 编译(链接 libunwind + 嵌入式优化)
#   make arm64          → ARM64 编译(不链接 libunwind)
#   make                → 本机默认编译(不链接 libunwind)
#
# 不强制设 ARCH(避免与工具链默认 -march/-mfloat-abi 冲突),让 CROSS_COMPILE
# 指定的工具链自己决定目标架构。仅设 MTT_LIBUNWIND_STATIC + MTT_EMBEDDED。
#
# 用户用法:
#   export CROSS_COMPILE=arm-linux-gnueabihf-   # 或其他 ARM32 工具链前缀
#   make arm32                                   # 编译 ARM32 + libunwind
#   make arm64                                   # 编译 ARM64 + 纯 glibc backtrace
arm32:
	$(MAKE) MTT_LIBUNWIND_STATIC=1 MTT_EMBEDDED=1

arm64:
	$(MAKE) MTT_LIBUNWIND_STATIC=

# ---- libunwind 静态库构建 ----
# open/libunwind 是 vendored libunwind v1.8.2 源码(MIT 许可,随项目分发)。
# configure 等脚本已预生成并 commit,运行时无需 autotools。
# 在独立 build 目录跑 configure + make,产出 libunwind.a 链入我们的 .so。
# 目标机零依赖:不需要预装 libunwind8,内网编译无需联网。
LIBUNWIND_SRC    := open/libunwind
LIBUNWIND_BUILD  := $(BUILD_DIR)/libunwind-$(or $(ARCH),host)
LIBUNWIND_STATIC := $(LIBUNWIND_BUILD)/src/.libs/libunwind.a
# --host 三元组从 CROSS_COMPILE 推导:arm-linux-gnueabihf- → arm-linux-gnueabihf
# 必须用 $(notdir ...) 剥掉目录前缀,否则 CROSS_COMPILE 是全路径时
# (如 /home1/x/.../bin/arm-gcc13-linux-gnueabi-)
# --host 会收到整条路径,config.sub 报 "more than four components"。
# 本机编译时 CROSS_COMPILE 为空,--host 留空,configure 自动检测
LIBUNWIND_HOST   := $(patsubst %-,%,$(notdir $(CROSS_COMPILE)))

# libunwind 静态库构建目标:
#   在独立 build 目录跑 configure(--host 交叉编译 / --enable-static / --disable-shared)
#   + make 产出 libunwind.a。
# 注意:cd 进入 build 目录后,$(LIBUNWIND_SRC)/configure 相对路径会失效,
# 必须用 $(CURDIR) 锚定到项目根。
$(LIBUNWIND_STATIC): $(LIBUNWIND_SRC)/configure
	@mkdir -p $(LIBUNWIND_BUILD)
	@# 暴力自愈: core.autocrlf=true 的环境会把 configure 检出成 CRLF,
	@# 导致 "/bin/sh^M: bad interpreter"。检测到就 strip,无需用户手动 sed。
	@if file $(LIBUNWIND_SRC)/configure | grep -q 'CRLF'; then \
	    echo "[MTT] libunwind autotools 文件含 CRLF,暴力 strip..."; \
	    find $(LIBUNWIND_SRC) -type f \
	        \( -name 'configure' -o -name '*.in' -o -name '*.m4' -o -name 'aclocal.m4' \) \
	        -exec perl -i -pe 's/\r$$//' {} +; \
	    find $(LIBUNWIND_SRC)/config -type f -exec perl -i -pe 's/\r$$//' {} +; \
	fi
	cd $(LIBUNWIND_BUILD) && \
	    $(CURDIR)/$(LIBUNWIND_SRC)/configure \
	        $(if $(LIBUNWIND_HOST),--host=$(LIBUNWIND_HOST)) \
	        --enable-static --disable-shared \
	        --disable-tests \
	        --disable-coredump \
	        --disable-ptrace \
	        --disable-setjmp \
	        --disable-nto \
	        --disable-cxx-exceptions \
	        --disable-minidebuginfo \
	        --disable-zlibdebuginfo \
	        --disable-documentation \
	        --disable-weak-backtrace \
	        CC="$(CC)" CFLAGS="$(ARCH_FLAGS) -O2 -fPIC -fno-omit-frame-pointer"
	$(MAKE) -C $(LIBUNWIND_BUILD) -j4 V=0

$(SHARED_LIB): $(LIB_OBJS) $(LIBUNWIND_DEPS) | $(OUTPUT_DIR)
	$(CC) -shared -o $@ $(LIB_OBJS) $(LIBUNWIND_LINK) \
	    -Wl,--exclude-libs,ALL $(LDFLAGS)
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

$(BUILD_DIR)/addr_validate.o: $(SRC_DIR)/addr_validate.c $(SRC_DIR)/addr_validate.h $(SRC_DIR)/mtt_internal.h | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(INC_SHARED) -c -o $@ $<

$(BUILD_DIR)/unwind_libunwind.o: $(SRC_DIR)/unwind_libunwind.c $(SRC_DIR)/unwind_libunwind.h $(SRC_DIR)/mtt_internal.h $(LIBUNWIND_DEPS) | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(INC_SHARED) $(LIBUNWIND_INC) -c -o $@ $<

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

# 库地址范围黑名单验证测试(MTT_LIB_BLACKLIST_FAST)
test_blacklist_fast: $(SHARED_LIB) tests/test_blacklist_fast.c | $(OUTPUT_DIR)
	$(CC) $(CFLAGS) $(INC_PUBLIC) -o $(OUTPUT_DIR)/test_blacklist_fast tests/test_blacklist_fast.c \
		-L$(OUTPUT_DIR) -lmemorytracetool $(LDFLAGS)
	$(RUN) $(OUTPUT_DIR)/test_blacklist_fast

# fork handler 验证测试(Type=forking 路径)
test_fork: $(SHARED_LIB) tests/test_fork.c | $(OUTPUT_DIR)
	$(CC) $(CFLAGS) $(INC_PUBLIC) -o $(OUTPUT_DIR)/test_fork tests/test_fork.c \
		-L$(OUTPUT_DIR) -lmemorytracetool $(LDFLAGS) -lpthread
	$(RUN) $(OUTPUT_DIR)/test_fork

test_all: test test_stability test_blacklist_fast test_fork

clean:
	rm -rf $(BUILD_DIR) $(OUTPUT_DIR)

distclean: clean
	rm -rf sysroot/

# 清理 libunwind 构建产物(独立于 clean,避免普通 clean 触发完整 rebuild)
vendor-clean:
	rm -rf $(BUILD_DIR)/libunwind-*
	@cd $(LIBUNWIND_SRC) && git clean -fdx 2>/dev/null || true

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

# bt_test:综合 backtrace 诊断(纯单线程,7 场景遍历)
bt_test: examples/bt_test.c | $(OUTPUT_DIR)
	$(CC) $(CFLAGS) -o $(OUTPUT_DIR)/bt_test examples/bt_test.c

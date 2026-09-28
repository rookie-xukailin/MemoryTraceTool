# gateway-mixed — C++/C 混合网关（-Os，C++ 调 C 的 libnetcore.so）
# 平台约定同根 Makefile：make / ARCH=arm64 / ARCH=arm32 / ARCH=riscv64
ARCH ?=
# 注意：不能写 "CROSS_COMPILE ?=" 空值预定义 —— ?= 只在变量未定义时赋值，
# 空值预定义会让后面分支里的 ?= 全部失效（交叉工具链永远不生效）。
ifeq ($(ARCH),arm32)
    CROSS_COMPILE ?= arm-linux-gnueabihf-
    ARCH_FLAGS := -march=armv7-a
else ifeq ($(ARCH),arm64)
    CROSS_COMPILE ?= aarch64-linux-gnu-
    ARCH_FLAGS := -march=armv8-a
else ifeq ($(ARCH),riscv64)
    CROSS_COMPILE ?= riscv64-linux-gnu-
endif

CC      := $(CROSS_COMPILE)gcc
CXX     := $(CROSS_COMPILE)g++
CFLAGS  := -Os -Wall -Werror -fPIC -fsigned-char -std=gnu11 $(ARCH_FLAGS)
CXXFLAGS := -Os -Wall -fPIC -std=c++17 $(ARCH_FLAGS) -Ic_core
LDFLAGS  := -lpthread

BUILD := build
LIB   := $(BUILD)/libnetcore.so

CSRC := c_core/netcore.c c_core/frame.c
COBJ := $(CSRC:.c=.o)
CXXSRC := cpp_app/main.cpp cpp_app/gateway.cpp cpp_app/codec.cpp
CXXOBJ := $(CXXSRC:.cpp=.o)

all: $(BUILD)/gateway

$(LIB): $(COBJ)
	mkdir -p $(BUILD)
	$(CC) -shared -o $@ $(COBJ)

$(BUILD)/gateway: $(CXXOBJ) $(LIB)
	mkdir -p $(BUILD)
	$(CXX) -o $@ $(CXXOBJ) -L$(BUILD) -lnetcore \
		-Wl,-rpath,'$$ORIGIN' $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c -o $@ $<

clean:
	rm -rf $(BUILD) $(COBJ) $(CXXOBJ)

.PHONY: all clean

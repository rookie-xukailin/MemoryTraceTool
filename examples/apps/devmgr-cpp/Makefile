# devmgr-cpp — 纯 C++ 设备管理服务（-Os）
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

CXX     := $(CROSS_COMPILE)g++
CXXFLAGS := -Os -Wall -Wextra -fno-omit-frame-pointer -funwind-tables -std=c++17 $(ARCH_FLAGS)
LDFLAGS  := -lpthread

SRC := src/main.cpp src/device.cpp src/device_manager.cpp src/event_bus.cpp src/telemetry.cpp
OBJ := $(SRC:.cpp=.o)

devmgr: $(OBJ)
	$(CXX) -o $@ $(OBJ) $(LDFLAGS)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c -o $@ $<

clean:
	rm -f devmgr $(OBJ)

.PHONY: clean

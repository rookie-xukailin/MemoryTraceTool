# sensorhub-c — 纯 C 传感器采集守护进程（-O2）
# 与项目根 Makefile 同款平台约定：
#   make                  # 本机（容器内原生架构）
#   ARCH=arm64 make       # aarch64 交叉
#   ARCH=arm32 make       # armv7 交叉（gnueabihf）
#   ARCH=riscv64 make     # riscv64 交叉
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
CFLAGS  := -O2 -g -Wall -Werror -fsigned-char -fgnu89-inline -funwind-tables -std=gnu11 $(ARCH_FLAGS)
# --export-dynamic: 对齐 STORAGE，主程序符号导出后 dladdr 可解析业务帧（栈回溯可读）
LDFLAGS := -lpthread -Wl,--export-dynamic

SRC := src/main.c src/config.c src/session.c src/sensor.c src/storage.c src/log.c
OBJ := $(SRC:.c=.o)

sensorhub: $(OBJ)
	$(CC) -o $@ $(OBJ) $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f sensorhub $(OBJ)

.PHONY: clean

# Android GKI 6.1内核模块编译
obj-m += rwProcMem_module.o

KDIR ?= /path/to/kernel-source  # GitHub Actions中会自动设置
ARCH ?= arm64
CROSS_COMPILE ?= aarch64-linux-android-
CC := $(CROSS_COMPILE)gcc
LD := $(CROSS_COMPILE)ld

PWD := $(shell pwd)

EXTRA_CFLAGS += -I$(KDIR)/include
EXTRA_CFLAGS += -Wno-error=incompatible-pointer-types
EXTRA_CFLAGS += -Wno-error=implicit-function-declaration
EXTRA_CFLAGS += -Wno-error=format-security
EXTRA_CFLAGS += -Wno-error=pointer-sign
EXTRA_CFLAGS += -Wno-error=unused-function

# 禁用模块签名（GKI内核可能需要）
CONFIG_MODULE_SIG := n

# 默认目标：编译模块
all:
	$(MAKE) ARCH=$(ARCH) CROSS_COMPILE=$(CROSS_COMPILE) -C $(KDIR) M=$(PWD) modules

# 清理
clean:
	$(MAKE) ARCH=$(ARCH) CROSS_COMPILE=$(CROSS_COMPILE) -C $(KDIR) M=$(PWD) clean

# 安装（可能需要root权限）
install: all
	sudo insmod rwProcMem_module.ko

# 卸载
uninstall:
	sudo rmmod rwProcMem_module

# 查看内核日志
log:
	dmesg | tail -20
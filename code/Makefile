# Android GKI 6.1内核模块编译
obj-m += rwProcMem_module.o

KDIR ?= /path/to/kernel-source  # 替换为实际内核路径
ARCH ?= arm64
CROSS_COMPILE ?= aarch64-linux-android-
CC := $(CROSS_COMPILE)gcc
LD := $(CROSS_COMPILE)ld

PWD := $(shell pwd)

EXTRA_CFLAGS += -I$(KDIR)/include
EXTRA_CFLAGS += -Wno-error=incompatible-pointer-types
EXTRA_CFLAGS += -Wno-error=implicit-function-declaration

CONFIG_MODULE_SIG := n

all:
	$(MAKE) ARCH=$(ARCH) CROSS_COMPILE=$(CROSS_COMPILE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) ARCH=$(ARCH) CROSS_COMPILE=$(CROSS_COMPILE) -C $(KDIR) M=$(PWD) clean
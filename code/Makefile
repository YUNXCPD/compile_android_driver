# 外部内核模块标准 Makefile
# 用法: make KDIR=/path/to/kernel/source

KDIR ?= $(PWD)/kernel_source

obj-m += yunwu.o

all:
	$(MAKE) -C $(KDIR) ARCH=arm64 LLVM=1 M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) ARCH=arm64 LLVM=1 M=$(PWD) clean

CC := $(AX_ARCH)-linux-gnu-gcc
STRIP := $(AX_ARCH)-linux-gnu-strip

all: init init_static

init: init.c
	$(CC) $< -o $@
	$(STRIP) $@

init_static: init.c
	$(CC) -static $< -o $@
	$(STRIP) $@

#riscv64-linux-gnu-gcc -static ./main1.c -o hello1 -L/home/cloud/study/glibc-2.36-riscv/build/

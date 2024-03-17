CC := $(AX_ARCH)-linux-gnu-gcc
STRIP := $(AX_ARCH)-linux-gnu-strip

all: init init_static

init: init.c
	$(CC) $< -o $@
	$(STRIP) $@

init_static: init.c
	$(CC) -static $< -o $@
	$(STRIP) $@

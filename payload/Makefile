CC := $(AX_ARCH)-linux-gnu-gcc
STRIP := $(AX_ARCH)-linux-gnu-strip

all: init

init: init.c
	$(CC) -static $< -o $@
	$(STRIP) $@

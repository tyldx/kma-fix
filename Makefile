CROSS ?= aarch64-linux-gnu-
KP_DIR ?= KernelPatch

CC := $(CROSS)gcc
LD := $(CROSS)ld

CFLAGS := -Wall -O2 -nostdinc
CFLAGS += -mgeneral-regs-only -mno-outline-atomics
CFLAGS += -fno-pic -fno-PIC -fno-pie -fno-stack-protector
CFLAGS += -fno-asynchronous-unwind-tables -fno-unwind-tables -fno-exceptions

INCLUDE_DIRS := . include patch/include linux/include linux/arch/arm64/include linux/tools/arch/arm64/include
INCLUDE_FLAGS := $(foreach dir,$(INCLUDE_DIRS),-I$(KP_DIR)/kernel/$(dir))

all: kma-fix.kpm

kma-fix.kpm: fix.o
	$(LD) -r -o $@ $^

fix.o: fix.c fix.lds
	$(CC) $(CFLAGS) $(INCLUDE_FLAGS) -Tfix.lds -c -o $@ fix.c

clean:
	rm -f fix.o kma-fix.kpm

.PHONY: all clean

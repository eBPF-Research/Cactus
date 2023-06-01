
all: build-go
.PHONY: clean

CLANG := clang-14
SHELL := /bin/bash
SRCARCH := x86

UNAME_RELEASE = $(shell uname -r)
objtree := /lib/modules/$(UNAME_RELEASE)/build

USERINCLUDE := \
	-isystem$(objtree)/arch/$(SRCARCH)/include/uapi \
	-isystem$(objtree)/arch/$(SRCARCH)/include/generated/uapi \
	-isystem$(objtree)/include/uapi \
	-isystem$(objtree)/include/generated/uapi

LINUXINCLUDE := \
	-isystem$(objtree)/arch/$(SRCARCH)/include \
	-isystem$(objtree)/arch/$(SRCARCH)/include/generated \
	-isystem$(objtree)/include \
	$(USERINCLUDE)

LLC ?= llc
CLANG ?= clang

CLANG_FLAGS := \
	-D__KERNEL__ \
	-D__BPF_TRACING__ \
	-DCONFIG_64BIT \
	-D__TARGET_ARCH_$(SRCARCH) \
	-Wno-unused-value \
	-Wno-pointer-sign \
	-Wno-compare-distinct-pointer-types \
	-Wunused \
	-Wall \
	-Werror

CLANG_CMD := $(CLANG) $(CLANG_FLAGS) \
	$(LINUXINCLUDE) \
	-Iebpf \
	-include include/asm_goto_workaround.h \
	-O2 -emit-llvm

LLC_CMD := $(LLC) -march=bpf -filetype=obj

build-bpf: ebpf/tc/*.h ebpf/xdp/*.h ebpf/main.c
	mkdir -p pkg/eshuffler/bin
	$(CLANG_CMD) ebpf/main.c -c -o - | $(LLC_CMD) -o pkg/eshuffler/bin/bpf.o
	llvm-objdump pkg/eshuffler/bin/bpf.o -d -S > pkg/eshuffler/bin/bpf.o.dump

build-go: build-bpf
	mkdir -p bin
	go build -o bin/ ./cmd/*

run:
	source scripts/setdir.sh && bash scripts/basic_test.sh

clean:
	rm -rf bin/
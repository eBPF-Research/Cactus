
all: build-go
.PHONY: clean

CLANG := clang-14
SHELL := /bin/bash

build-bpf: ebpf/tc/*.h ebpf/xdp/*.h ebpf/main.c
	mkdir -p pkg/ebpf/bin
	$(CLANG) -D__KERNEL__ -DCONFIG_64BIT -D__ASM_SYSREG_H -D__x86_64__ -DUSE_SYSCALL_WRAPPER=1 -D__BPF_TRACING__ -DKBUILD_MODNAME=\"eshuffler\" \
		-Wno-unused-value \
		-Wno-pointer-sign \
		-Wno-compare-distinct-pointer-types \
		-Wunused \
		-Wall \
		-Werror \
		-I/lib/modules/$$(uname -r)/build/include \
		-I/lib/modules/$$(uname -r)/build/include/uapi \
		-I/lib/modules/$$(uname -r)/build/include/generated/uapi \
		-I/lib/modules/$$(uname -r)/build/arch/x86/include \
		-I/lib/modules/$$(uname -r)/build/arch/x86/include/uapi \
		-I/lib/modules/$$(uname -r)/build/arch/x86/include/generated \
		-Iebpf/ \
		-c -O2 -g -target bpf \
		ebpf/main.c \
		-o pkg/ebpf/bin/bpf.o

build-go: build-bpf
	mkdir -p bin
	go build -o bin/ ./cmd/*

run:
	source scripts/conf.sh && bash scripts/basic_test.sh

clean:
	rm -rf bin/

all: build-go
.PHONY: clean

CLANG := clang-14
SHELL := /bin/bash

build-bpf: ebpf/tc/*.h ebpf/xdp/*.h ebpf/main.c
	mkdir -p pkg/eshuffler/bin
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
		-o pkg/eshuffler/bin/bpf.o -ftime-trace 
	llvm-objdump pkg/eshuffler/bin/bpf.o -d > pkg/eshuffler/bin/bpf.o.dump

build-go: build-bpf
	mkdir -p bin
	go build -o bin/ ./cmd/*

run:
	source scripts/setdir.sh && bash scripts/basic_test.sh

clean:
	rm -rf bin/
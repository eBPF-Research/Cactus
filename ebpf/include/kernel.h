#ifndef KERNEL_H_
#define KERNEL_H_


#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Waddress-of-packed-member"
#pragma clang diagnostic ignored "-Warray-bounds"
#pragma clang diagnostic ignored "-Wunused-label"
#pragma clang diagnostic ignored "-Wgnu-variable-sized-type-not-at-end"
#pragma clang diagnostic ignored "-Wframe-address"

#include <linux/kconfig.h>
// include asm/compiler.h to fix `error: expected string literal in 'asm'` compilation error coming from mte-kasan.h
// this was fixed in https://github.com/torvalds/linux/commit/b859ebedd1e730bbda69142fca87af4e712649a1
#ifdef CONFIG_HAVE_ARCH_COMPILER_H
#include <asm/compiler.h>
#endif

#include <linux/version.h>
// #include <uapi/linux/ptrace.h>
// #include <uapi/linux/bpf_perf_event.h>

#define KBUILD_MODNAME "test"

// XDP and TC
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/bpf.h>
#include <linux/in.h>

#pragma clang diagnostic pop

#endif

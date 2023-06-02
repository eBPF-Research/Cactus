/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright (c) 2020
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#ifndef _ALL_H__
#define _ALL_H__

// 当前禁用 CO-RE
// #define USE_CO_RE
#ifdef USE_CO_RE

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Waddress-of-packed-member"
#pragma clang diagnostic ignored "-Warray-bounds"
#pragma clang diagnostic ignored "-Wunused-label"
#pragma clang diagnostic ignored "-Wunknown-attributes"
#pragma clang diagnostic ignored "-Wgnu-variable-sized-type-not-at-end"
#pragma clang diagnostic ignored "-Wframe-address"


#include "vmlinux.h"
#include "tc_xdp_co_re.h"

#pragma clang diagnostic pop

#else
// not use CO-RE， import kernel head from uapi and linux headers
#include "kernel.h"
#endif // USE_CO_RE

#include "bpf_core_read.h"
#include "bpf_endian.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"
#include <errno.h>
#include "mydef.h"

#endif
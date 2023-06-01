#ifndef _TC_H_
#define _TC_H_

#include "bpf_helpers.h"

// https://elixir.bootlin.com/linux/v5.3.8/source/include/uapi/linux/if_ether.h#L71
#define ETH_P_IP	0x0800		/* Internet Protocol packet	*/
#define ETH_P_8021Q	0x8100          /* 802.1Q VLAN Extended Header  */
#define ETH_P_8021AD	0x88A8          /* 802.1ad Service VLAN		*/
#define ETH_ALEN	6		/* Octets in one ethernet addr	 */


// https://elixir.bootlin.com/linux/v5.3.8/source/include/linux/socket.h#L165
#define AF_INET		2	/* Internet IP Protocol 	*/

// https://elixir.bootlin.com/linux/v4.5/source/include/uapi/linux/pkt_cls.h#L107

#define TC_ACT_UNSPEC	(-1)
#define TC_ACT_OK		0
#define TC_ACT_RECLASSIFY	1
#define TC_ACT_SHOT		2
#define TC_ACT_PIPE		3
#define TC_ACT_STOLEN		4
#define TC_ACT_QUEUED		5
#define TC_ACT_REPEAT		6
#define TC_ACT_REDIRECT		7
#define TC_ACT_JUMP		0x10000000

// /* https://elixir.bootlin.com/linux/v5.3.8/source/include/uapi/linux/swab.h
// */
// #define ___constant_swab16(x) ((__u16)(				\
// 	(((__u16)(x) & (__u16)0x00ffU) << 8) |			\
// 	(((__u16)(x) & (__u16)0xff00U) >> 8)))

// #define ___constant_swab32(x) ((__u32)(				\
// 	(((__u32)(x) & (__u32)0x000000ffUL) << 24) |		\
// 	(((__u32)(x) & (__u32)0x0000ff00UL) <<  8) |		\
// 	(((__u32)(x) & (__u32)0x00ff0000UL) >>  8) |		\
// 	(((__u32)(x) & (__u32)0xff000000UL) >> 24)))

// #define ___constant_swab64(x) ((__u64)(				\
// 	(((__u64)(x) & (__u64)0x00000000000000ffULL) << 56) |	\
// 	(((__u64)(x) & (__u64)0x000000000000ff00ULL) << 40) |	\
// 	(((__u64)(x) & (__u64)0x0000000000ff0000ULL) << 24) |	\
// 	(((__u64)(x) & (__u64)0x00000000ff000000ULL) <<  8) |	\
// 	(((__u64)(x) & (__u64)0x000000ff00000000ULL) >>  8) |	\
// 	(((__u64)(x) & (__u64)0x0000ff0000000000ULL) >> 24) |	\
// 	(((__u64)(x) & (__u64)0x00ff000000000000ULL) >> 40) |	\
// 	(((__u64)(x) & (__u64)0xff00000000000000ULL) >> 56)))

// #define ___constant_swahw32(x) ((__u32)(			\
// 	(((__u32)(x) & (__u32)0x0000ffffUL) << 16) |		\
// 	(((__u32)(x) & (__u32)0xffff0000UL) >> 16)))

// #define ___constant_swahb32(x) ((__u32)(			\
// 	(((__u32)(x) & (__u32)0x00ff00ffUL) << 8) |		\
// 	(((__u32)(x) & (__u32)0xff00ff00UL) >> 8)))


// /* copy from
// https://elixir.bootlin.com/linux/v5.3.8/source/tools/testing/selftests/bpf/bpf_endian.h#L45
// */
// #if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
// # define __bpf_ntohs(x)			__builtin_bswap16(x)
// # define __bpf_htons(x)			__builtin_bswap16(x)
// # define __bpf_constant_ntohs(x)	___constant_swab16(x)
// # define __bpf_constant_htons(x)	___constant_swab16(x)
// # define __bpf_ntohl(x)			__builtin_bswap32(x)
// # define __bpf_htonl(x)			__builtin_bswap32(x)
// # define __bpf_constant_ntohl(x)	___constant_swab32(x)
// # define __bpf_constant_htonl(x)	___constant_swab32(x)
// #elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
// # define __bpf_ntohs(x)			(x)
// # define __bpf_htons(x)			(x)
// # define __bpf_constant_ntohs(x)	(x)
// # define __bpf_constant_htons(x)	(x)
// # define __bpf_ntohl(x)			(x)
// # define __bpf_htonl(x)			(x)
// # define __bpf_constant_ntohl(x)	(x)
// # define __bpf_constant_htonl(x)	(x)
// #else
// # error "Fix your compiler's __BYTE_ORDER__?!"
// #endif

// #define bpf_htons(x)				\
// 	(__builtin_constant_p(x) ?		\
// 	 __bpf_constant_htons(x) : __bpf_htons(x))
// #define bpf_ntohs(x)				\
// 	(__builtin_constant_p(x) ?		\
// 	 __bpf_constant_ntohs(x) : __bpf_ntohs(x))
// #define bpf_htonl(x)				\
// 	(__builtin_constant_p(x) ?		\
// 	 __bpf_constant_htonl(x) : __bpf_htonl(x))
// #define bpf_ntohl(x)				\
// 	(__builtin_constant_p(x) ?		\
// 	 __bpf_constant_ntohl(x) : __bpf_ntohl(x))

#endif
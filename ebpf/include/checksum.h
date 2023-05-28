#ifndef CHECKSUM_H_
#define CHECKSUM_H_

#include "include/all.h"

static __always_inline u32 from64to32(u64 x)
{
	x = (x & 0xffffffff) + (x >> 32);
	x = (x & 0xffffffff) + (x >> 32);
	return (u32)x;
}

static __always_inline u16 from32to16(u32 x) {
	x = (x & 0xffff) + (x >> 16);
	x = (x & 0xffff) + (x >> 16);
	return x;
}

static __always_inline __sum16 csum_fold(__wsum csum)
{
	u32 sum = (u32)csum;

	sum = (sum & 0xffff) + (sum >> 16);
	sum = (sum & 0xffff) + (sum >> 16);
	return (__sum16)~sum;
}

static __always_inline
__wsum csum_tcpudp_nofold(__be32 saddr, __be32 daddr,
			  __u32 len, __u8 proto, __wsum sum)
{
	unsigned long long s = (u32)sum;

	s += (u32)saddr;
	s += (u32)daddr;
#ifdef __BIG_ENDIAN__
	s += proto + len;
#else
	s += (proto + len) << 8;
#endif
	return (__wsum)from64to32(s);
}

static __always_inline 
__sum16 csum_tcpudp_magic(__be32 saddr, __be32 daddr, __u32 len,
		  __u8 proto, __wsum sum)
{
	return csum_fold(csum_tcpudp_nofold(saddr, daddr, len, proto, sum));
}

static __always_inline 
u16 udp_csum(u32 saddr, u32 daddr, u32 len, u8 proto, u16 *udp_pkt, void* data_end)
{
	u32 csum = 0;
	u32 cnt = 0;
	u16* pkt = udp_pkt;

	#pragma unroll
	for (; cnt < 1500; cnt += 2) {
		if (pkt + 1 > data_end || cnt + 2 > len) {
			break;
		}
		csum += *pkt;
		pkt += 1;
	}

	if ((void*)pkt + 1 <= data_end && cnt + 1 <= len) {
		csum += *(u8*)pkt;
	}

	return csum_tcpudp_magic(saddr, daddr, len, proto, csum);
}

#endif /* CHECKSUM_H_ */

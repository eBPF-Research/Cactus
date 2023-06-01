#ifndef XDP_OP_H_
#define XDP_OP_H_

#include "net/checksum.h"
#include "net/parsing_helpers.h"
#include "xdp_states.h"


#define PERCENT(x) (__UINT32_MAX__ / 100 * (x))

#define COPY_MAC(dst, src) \
	dst[0] = src[0]; \
	dst[1] = src[1]; \
	dst[2] = src[2]; \
	dst[3] = src[3]; \
	dst[4] = src[4]; \
	dst[5] = src[5];

static __always_inline bool roll(u32 percentile) {
	u32 rand_u = bpf_get_prandom_u32() % 100 + 1;
	// u32 thresh = PERCENT(percentile);
	// return rand_u < thresh;
	return rand_u <= percentile;
}

static __always_inline u16 modify_csums(u16 csum, u16 old, u16 new) {
	u32 tmp = csum;
	tmp += old;
	tmp += (~new & 0xffff);
	return from32to16(tmp);
}

static __always_inline u16 modify_csuml(u16 csum, u32 old, u32 new) {
	u32 tmp = csum;
	tmp += (old & 0xffff) + (old >> 16) + (~new & 0xffff) + (~new >> 16);
	return from32to16(tmp);
}

// OP-2
// execute the following command first
// sysctl -w net.ipv4.ip_forward=1
SEC("xdp/dummy_packet")
int xdp_op2_dummy_packet(struct xdp_md *ctx) {
	u32 action = XDP_PASS;

	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct hdr_cursor nh;
	struct ethhdr *eth;
	struct iphdr *iphdr;
	struct tcphdr *tcphdr;
	int eth_type;
	int ip_type;
	int tcp_len;

	// 只开启一种算法
	int one_op = use_one_op();
	if (one_op) {
		xdp_stats_record_op(ctx, XDP_OP_DEFAULT);	
		// bpf_printk("choose op: %d %d\n", one_op, __LINE__);
	}

	nh.pos = data;
	u32 p = get_belta_p();

	eth_type = parse_ethhdr(&nh, data_end, &eth);
	if (eth_type == bpf_htons(ETH_P_IP)) {
		ip_type = parse_iphdr(&nh, data_end, &iphdr);
		if (ip_type < 0) {
			action = XDP_ABORTED;
			goto out;
		}
		if (ip_type == IPPROTO_TCP) {
			tcp_len = parse_tcphdr(&nh, data_end, &tcphdr);
			if (tcp_len < 0) {
				action = XDP_ABORTED;
				goto out;
			}
			if (!tcphdr->ack || !roll(p)) {
				goto out;
			}

			u32 saddr = iphdr->saddr;
			iphdr->saddr = iphdr->daddr;
			iphdr->daddr = saddr;

			u16 sport = tcphdr->source;
			tcphdr->source = tcphdr->dest;
			tcphdr->dest = sport;
			u32 seq = tcphdr->seq;
			tcphdr->seq = bpf_htonl(bpf_ntohl(tcphdr->ack_seq) - 100);
			tcphdr->check = modify_csuml(tcphdr->check, seq, tcphdr->seq);

			struct bpf_fib_lookup fib_params = {};
			fib_params.family	= AF_INET;
			fib_params.tos		= iphdr->tos;
			fib_params.l4_protocol	= iphdr->protocol;
			fib_params.sport	= 0;
			fib_params.dport	= 0;
			fib_params.tot_len	= bpf_ntohs(iphdr->tot_len);
			fib_params.ipv4_src	= iphdr->saddr;
			fib_params.ipv4_dst	= iphdr->daddr;
			fib_params.ifindex = ctx->ingress_ifindex;

			int rc = bpf_fib_lookup(ctx, &fib_params, sizeof(fib_params), 0);
			switch (rc) {
			case BPF_FIB_LKUP_RET_SUCCESS:         /* lookup successful */
				// COPY_MAC(eth->h_dest, fib_params.dmac);
				// COPY_MAC(eth->h_source, fib_params.smac);
				// 为了过verifier，只能加一行对h_dest的修改
				eth->h_dest[0] = fib_params.dmac[0];
				__builtin_memcpy(eth->h_dest, fib_params.dmac, ETH_ALEN);
				__builtin_memcpy(eth->h_source, fib_params.smac, ETH_ALEN);
				action = bpf_redirect(fib_params.ifindex, 0);
				xdp_stats_record_op(ctx, XDP_OP_2);
				break;
			case BPF_FIB_LKUP_RET_BLACKHOLE:    /* dest is blackholed; can be dropped */
			case BPF_FIB_LKUP_RET_UNREACHABLE:  /* dest is unreachable; can be dropped */
			case BPF_FIB_LKUP_RET_PROHIBIT:     /* dest not allowed; can be dropped */
				action = XDP_DROP;
				break;
			case BPF_FIB_LKUP_RET_NOT_FWDED:    /* packet is not forwarded */
			case BPF_FIB_LKUP_RET_FWD_DISABLED: /* fwding is not enabled on ingress */
			case BPF_FIB_LKUP_RET_UNSUPP_LWT:   /* fwd requires encapsulation */
			case BPF_FIB_LKUP_RET_NO_NEIGH:     /* no neighbor entry for nh */
			case BPF_FIB_LKUP_RET_FRAG_NEEDED:  /* fragmentation required to fwd */
				/* PASS */
				break;
			}
			goto out;
		}
	}
 out:
	return xdp_stats_record_action(ctx, action);
}


// OP-4: randomly drop packet at P probability 
SEC("xdp/random_drop")
int xdp_op4_random_drop(struct xdp_md *ctx) {
	u32 action = XDP_PASS;

	// 只开启一种算法
	int one_op = use_one_op();
	if (one_op) {
		xdp_stats_record_op(ctx, XDP_OP_DEFAULT);	
	}

	u32 p = get_belta_p();	
	
	if (roll(p)) {
		action = XDP_DROP;
	}

	xdp_stats_record_op(ctx, XDP_OP_4);
	return xdp_stats_record_action(ctx, action);
}

SEC("xdp/partial_upload")
int xdp_op5_partial_upload(struct xdp_md *ctx) {
	u32 action = XDP_PASS;

	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct hdr_cursor nh;
	struct ethhdr *eth;
	struct iphdr *iphdr;
	struct tcphdr *tcphdr;
	int eth_type;
	int ip_type;
	int tcp_len;

	nh.pos = data;

	// 只开启一种算法
	int one_op = use_one_op();
	if (one_op) {
		xdp_stats_record_op(ctx, XDP_OP_DEFAULT);	
	}

	u32 p = get_belta_p();
	
	eth_type = parse_ethhdr(&nh, data_end, &eth);
	if (eth_type == bpf_htons(ETH_P_IP)) {
		ip_type = parse_iphdr(&nh, data_end, &iphdr);
		if (ip_type < 0) {
			action = XDP_ABORTED;
			goto out;
		}
		u16 ip_len = bpf_ntohs(iphdr->tot_len);
		if (ip_type == IPPROTO_TCP) {
			tcp_len = parse_tcphdr(&nh, data_end, &tcphdr);
			if (tcp_len < 0) {
				action = XDP_ABORTED;
				goto out;
			}
			if (!roll(p)) {
				goto out;
			}
			u16 payload_len = ip_len - iphdr->ihl * 4 - tcp_len;
			if (payload_len < 0) {
				action = XDP_ABORTED;
				goto out;
			}
			u16 new_ip_len = ip_len - payload_len / 2;
			int len_delta = ip_len - new_ip_len;
			iphdr->check = modify_csums(iphdr->check, iphdr->tot_len, bpf_htons(new_ip_len));
			iphdr->tot_len = bpf_htons(new_ip_len);
			tcphdr->check = 0;
			tcphdr->check = udp_csum(iphdr->saddr, iphdr->daddr, new_ip_len - iphdr->ihl * 4, IPPROTO_TCP, (u16*)tcphdr, data_end);
			int ret = bpf_xdp_adjust_tail(ctx, -len_delta);
			if (ret < 0) {
				action = XDP_ABORTED;
				goto out;
			}
			xdp_stats_record_op(ctx, XDP_OP_5);
			goto out;
		}
	}
 out:
	return xdp_stats_record_action(ctx, action);
}

#endif // XDP_OP_H_

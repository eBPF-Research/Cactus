#ifndef XDP_TAIL_CALL_H_
#define XDP_TAIL_CALL_H_

#include "include/all.h"
#include "op_states.h"
#include <stdbool.h>

/*
Dispatch operations via tail call
*/

// struct {
// 	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
// 	__type(key, u32);
// 	__type(value, u32);
// 	__uint(max_entries, 4);
// } xdp_prog_array SEC(".maps");

struct bpf_map_def SEC("maps/xdp_jump_table") xdp_jump_table = {
	.type = BPF_MAP_TYPE_PROG_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u32),
	.max_entries = XDP_OP_END + 1,
};

SEC("xdp/ingress")
int ingress(struct xdp_md *ctx) {
	u32 p = get_alpha_precent();
	// LOAD_CONSTANT("opt_delta", p);
	bpf_printk("new packet captured (XDP): %u\n", p);
	// return xdp_stats_record_action(ctx, XDP_PASS);
	return XDP_PASS;
};

static __always_inline 
bool is_ack_packet(struct xdp_md *ctx) {
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

	eth_type = parse_ethhdr(&nh, data_end, &eth);
	if (eth_type == bpf_htons(ETH_P_IP)) {
		ip_type = parse_iphdr(&nh, data_end, &iphdr);
		if (ip_type < 0) {
			return false;
		}
		if (ip_type == IPPROTO_TCP) {
			tcp_len = parse_tcphdr(&nh, data_end, &tcphdr);
			if (tcp_len < 0) {
				return false;
			}
			return tcphdr->ack == 1;
		}
	}

	return false;
}


// receive packet
SEC("xdp/dispatch")
int xdp_dispatch(struct xdp_md *ctx) {
	xdp_stats_record_op(ctx, XDP_OP_DEFAULT);

	u32 alpha = get_alpha_precent();
	bool use_op_1 = roll(alpha);

	/* 实际测试发现ack包过少，所以先看op-1能不能触发，不能执行再去看op-3能不能触发
	*/
	// if (is_ack_packet(ctx)) { // OP-1 

	if (use_op_1) { // OP-1
		// bpf_printk("is ack use op-1");
		bpf_tail_call(ctx, &xdp_jump_table, XDP_OP_1);
	} else { // OP-3 partial_upload
		// bpf_printk("is not ack use op-3\n");
		bpf_tail_call(ctx, &xdp_jump_table, XDP_OP_3);
	}

	return XDP_PASS;
}

#endif // XDP_TAIL_CALL_H_

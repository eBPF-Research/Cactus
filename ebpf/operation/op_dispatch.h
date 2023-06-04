#ifndef ES_OP_DISPATCH_H_
#define ES_OP_DISPATCH_H_

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

/* tail call map里面只能放同一种类型的程序
*/
struct bpf_map_def SEC("maps/tc_jump_table") tc_jump_table = {
	.type = BPF_MAP_TYPE_PROG_ARRAY,
	.key_size = 4,
	.value_size = 4,
	.max_entries = ES_OP_POS_END + 1,
};

// SEC("xdp/ingress")
int ingress(struct xdp_md *ctx) {
	u32 p = get_alpha_precent();
	// LOAD_CONSTANT("opt_delta", p);
	bpf_printk("new packet captured (XDP): %u\n", p);
	// return xdp_stats_record_action(ctx, XDP_PASS);
	return XDP_PASS;
};

// receive packet
SEC("xdp/ingress")
int xdp_dispatch(struct xdp_md *ctx) {
	// es_stats_record_op(ES_OP_ALL_PKT);

	u32 alpha = get_alpha_precent();
	bool use_this_op = roll(alpha);

	/* 实际测试发现ack包过少，所以先看op-1能不能触发，不能执行再去看op-3能不能触发
	*/
	// if (is_ack_packet(ctx)) { // OP-1 

	if (use_this_op) { // OP-1
		bpf_printk("is ack use op-1");
		// bpf_tail_call(ctx, &tc_jump_table, ES_OP3_XDP);
	}

	return XDP_PASS;
}

// receive packet
SEC("tc/dispatch_ingress")
int tc_dispatch_ingress(struct __sk_buff *skb) {
	es_stats_record_op(ES_OP_ALL_PKT);

	u32 alpha = get_alpha_precent();
	bool use_this_op = roll(alpha);

	if (use_this_op) {
		bpf_tail_call(skb, &tc_jump_table, ES_OP1_2_TC);
	}

	return TC_ACT_OK;
}

// send packet
SEC("tc/dispatch_egress")
int tc_dispatch_egress(struct __sk_buff *skb) {
	es_stats_record_op(ES_OP_ALL_PKT);
	u32 alpha = get_alpha_precent();
	bool use_this_op = roll(alpha);

	if (use_this_op && is_ack_packet_tc(skb)) {
		bpf_tail_call(skb, &tc_jump_table, ES_OP4_TC);
	}

	// randonly choose one from op-1 or op-2
	if (use_this_op) {
		bpf_tail_call(skb, &tc_jump_table, ES_OP1_1_TC);
	}

	return TC_ACT_OK;
}

#endif // XDP_TAIL_CALL_H_

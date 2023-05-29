#ifndef XDP_TAIL_CALL_H_
#define XDP_TAIL_CALL_H_

#include "include/all.h"
#include "xdp_states.h"

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
	.max_entries = 34,
};

// use contanst to choose jump target

// SEC("xdp/op_1")
// int xdp_op1(struct xdp_md *ctx) {
// 	bpf_printk("xdp_op1\n");
// 	return XDP_PASS;
// }

// SEC("xdp/op_2")
// int xdp_op2(struct xdp_md *ctx) {
// 	bpf_printk("xdp_op2\n");
// 	return XDP_PASS;
// }

// SEC("xdp/op_3")
// int xdp_op3(struct xdp_md *ctx) {
// 	bpf_printk("xdp_op3\n");
// 	return XDP_PASS;
// }

SEC("xdp/dispatch")
int xdp_dispatch(struct xdp_md *ctx) {
	int t = bpf_get_prandom_u32() % 3;

	bpf_tail_call(ctx, &xdp_jump_table, t);
	return XDP_PASS;
}

#endif // XDP_TAIL_CALL_H_

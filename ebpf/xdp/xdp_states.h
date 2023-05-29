#ifndef OP_STATES_H_
#define OP_STATES_H_

#include "include/all.h"

/* This is the data record stored in the map */
struct datarec {
	__u64 rx_packets;
	__u64 rx_bytes;
};

#ifndef XDP_ACTION_MAX
#define XDP_ACTION_MAX (XDP_REDIRECT + 1)
#endif

enum XDPop{
	XDP_OP_1 = 1,
	XDP_OP_2,
	XDP_OP_3,
	XDP_OP_4,
	XDP_OP_5,
	XDP_OP_6,
	XDP_OP_END
};

// 根据最新libbpf来修改：
// https://github.com/libbpf/libbpf-bootstrap/blob/master/examples/c/bootstrap.bpf.c

/* Keeps stats per (enum) xdp_action */
struct bpf_map_def SEC("maps/xdp_action_stats") xdp_action_stats = {
	.type        = BPF_MAP_TYPE_ARRAY,
	.key_size    = sizeof(__u32),
	.value_size  = sizeof(struct datarec),
	.max_entries = XDP_ACTION_MAX,
};

struct bpf_map_def SEC("maps/xdp_op_stats") xdp_op_stats = {
	.type        = BPF_MAP_TYPE_ARRAY,
	.key_size    = sizeof(__u32),
	.value_size  = sizeof(__u32),
	.max_entries = XDP_OP_END,
};

// struct {
// 	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
// 	__uint(max_entries, XDP_ACTION_MAX);
// 	__type(key, u32);
// 	__type(value, struct datarec);
// } xdp_stats_map SEC("maps/xdp_stats_map");

static __always_inline
__u32 xdp_stats_record_action(struct xdp_md *ctx, __u32 action) {
	if (action >= XDP_ACTION_MAX)
		return XDP_ABORTED;

	/* Lookup in kernel BPF-side return pointer to actual data record */
	struct datarec *rec = bpf_map_lookup_elem(&xdp_action_stats, &action);
	if (!rec)
		return XDP_ABORTED;

	/* BPF_MAP_TYPE_PERCPU_ARRAY returns a data record specific to current
	 * CPU and XDP hooks runs under Softirq, which makes it safe to update
	 * without atomic operations.
	 */
	rec->rx_packets++;
	rec->rx_bytes += (ctx->data_end - ctx->data);

	return action;
}

static __always_inline
u32 get_alpha_p() {
	return 0;
}

/* Todo: 后面改成公式计算，从map中读取
*/
static __always_inline
u32 get_belta_p() {
	u64 belta_p;
	LOAD_CONSTANT("opt_belta", belta_p);
	return belta_p;
}


#endif

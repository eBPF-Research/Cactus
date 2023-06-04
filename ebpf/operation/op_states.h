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

enum EBPFOp{
	ES_OP_ALL_PKT = 0,
	ES_OP1_1_TC,
	ES_OP1_2_TC,
	ES_OP2_TC,
	ES_OP3_XDP,
	ES_OP4_TC,   // 5
	ES_OP_POS_END
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

// struct {
// 	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
// 	__uint(max_entries, XDP_ACTION_MAX);
// 	__type(key, u32);
// 	__type(value, struct datarec);
// } xdp_stats_map SEC("maps/xdp_stats_map");

struct bpf_map_def SEC("maps/es_op_stats") es_op_stats = {
	.type        = BPF_MAP_TYPE_ARRAY,
	.key_size    = sizeof(__u32),
	.value_size  = sizeof(__u32),
	.max_entries = ES_OP_POS_END + 1,
};

static __always_inline bool roll(u32 percentile) {
	u32 rand_u = bpf_get_prandom_u32() % 100 + 1;
	// u32 thresh = PERCENT(percentile);
	// return rand_u < thresh;
	return rand_u <= percentile;
}

static __always_inline u32 rand_n(u32 N) {
	return bpf_get_prandom_u32() % N;
}

// #define USE_XDP_ACTION_LOG

static __always_inline
__u32 xdp_stats_record_action(struct xdp_md *ctx, __u32 action) {
#ifndef USE_XDP_ACTION_LOG
	return action;
#endif

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
void es_stats_record_op(__u32 op) {
	if (op >= ES_OP_POS_END)
		return;

	/* Lookup in kernel BPF-side return pointer to actual data record */
	__u32 *rec = bpf_map_lookup_elem(&es_op_stats, &op);
	if (!rec)
		return;

	*rec += 1;
}

/* Todo: 后面改成公式计算，从map中读取
*/
static __always_inline
u32 get_alpha_precent() {
	u64 alpha_p = 12;
	LOAD_CONSTANT("opt_alpha", alpha_p);
	return alpha_p;
}

/* 不用tail call，只开启一种算法，用于评估单独op的效果
*/
static __always_inline
u32 use_one_op() {
	u64 one_op = 0;
	LOAD_CONSTANT("one_op", one_op);
	return one_op;
}

static __always_inline
void es_stats_one_op_mode() {
	/* if only one op is loaded, 
	 	pkt should be statisticed in individual function
	*/
	int one_op = use_one_op();
	if (one_op) {
		es_stats_record_op(ES_OP_ALL_PKT);	
	}
}

#endif

#include "include/checksum.h"


#define PERCENT(x) (__UINT32_MAX__ / 100 * (x))

static __always_inline bool roll(u32 percentile) {
	u32 rand_u = bpf_get_prandom_u32();
	u32 thresh = PERCENT(percentile);
	return rand_u < thresh;
}

SEC("xdp/ingress")
int ingress(struct __sk_buff *skb) {
	bpf_printk("new packet captured (XDP)\n");
	return XDP_PASS;
};


SEC("xdp/random_drop")
int xdp_random_drop_func(struct xdp_md *ctx) {
	u32 action = XDP_PASS;

	u32 p = 30;	
	if (roll(p)) {
		action = XDP_DROP;
	}

	// return xdp_stats_record_action(ctx, action);
	return action;
}



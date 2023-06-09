#include "include/all.h"

static __always_inline bool roll(u32 percentile) {
	u32 rand_u = bpf_get_prandom_u32() % 100 + 1;
	// u32 thresh = PERCENT(percentile);
	// return rand_u < thresh;
	return rand_u <= percentile;
}

static __always_inline u32 rand_n(u32 N) {
	return bpf_get_prandom_u32() % N;
}
#ifndef _TC_DROP_H_
#define _TC_DROP_H_

#include "include/all.h"

SEC("tc/classifier/ingress_redirect")
int ingress_redirect(struct __sk_buff *skb)
{
	bpf_printk("(classifier/ingress_redirect) new packet captured (TC)");

	// Tail call
	// int key = TAIL_CALL_KEY;
	// bpf_tail_call(skb, &tc_prog_array, key);

	// Tail call failed
	// bpf_printk("(classifier/one) couldn't tail call (TC)\n");
	return TC_ACT_OK;
};

#endif

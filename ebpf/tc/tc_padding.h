#ifndef _TC_PADDING_H_
#define _TC_PADDING_H_

#include "include/all.h"

#define ORIGINAL_PACKET 0b10

SEC("classifier/ingress_redirect")
int ingress_redirect(struct __sk_buff *skb) {

	if (skb->mark == ORIGINAL_PACKET) {
		skb->mark = 0;
		bpf_printk("send packet: %d tstamp: %ld ifindex: %u", ORIGINAL_PACKET, skb->tstamp, skb->ifindex);
		return TC_ACT_OK;
	}

	skb->mark = ORIGINAL_PACKET;
	bpf_clone_redirect(skb, skb->ifindex, BPF_F_INGRESS);
	// 

	bpf_printk("clone packet tstamp: %ld", skb->tstamp);
	return bpf_redirect(skb->ifindex, 0);
}

#endif // _TC_PADDING_H_
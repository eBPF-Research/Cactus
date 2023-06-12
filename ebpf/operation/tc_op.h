#ifndef _TC_DROP_H_
#define _TC_DROP_H_

#include "include/all.h"
#include "net/checksum.h"
#include "net/parsing_helpers.h"
#include "net/random.h"
#include "op_states.h"

#define MIN(x, y) (((x) < (y)) ? (x) : (y))

#define ORIGINAL_PACKET 2
#define EGRESS_PACKET 3
#define PROCESSED_PACKET 4
#define FRAGMENT_PACKET 1024
#define SPLIT_BUFFER_LEN 400

// SEC("tc/classifier/log")
int log_func(struct __sk_buff *skb) {
	bpf_printk("(classifier/log) new packet captured (TC)");

	// Tail call
	// int key = TAIL_CALL_KEY;
	// bpf_tail_call(skb, &tc_prog_array, key);

	// Tail call failed
	// bpf_printk("(classifier/one) couldn't tail call (TC)\n");
	return TC_ACT_OK;
};

// execute the following command first
// sysctl -w net.ipv4.ip_forward=1
// SEC("tc/classifier/dummy_tc")
int tc_op_dummy_tc(struct __sk_buff *skb) {
	if (skb->mark == ORIGINAL_PACKET) {
		skb->mark = 0;
		return TC_ACT_OK;
	}

	es_stats_one_op_mode();

	skb->mark = ORIGINAL_PACKET;
	bpf_clone_redirect(skb, skb->ifindex, BPF_F_INGRESS);
	skb->mark = 0;

	void *data = (void *)(long)skb->data;
  	void *data_end = (void *)(long)skb->data_end;
	struct hdr_cursor nh;
	struct ethhdr *eth;
	struct iphdr *iphdr;
	struct tcphdr *tcphdr;
	int eth_type;
	int ip_type;
	int tcp_len;
	int action = TC_ACT_OK;

	nh.pos = data;
	

	eth_type = parse_ethhdr(&nh, data_end, &eth);
	if (eth_type == bpf_htons(ETH_P_IP)) {
		ip_type = parse_iphdr(&nh, data_end, &iphdr);
		if (ip_type < 0) {
			action = TC_ACT_STOLEN;
			goto out;
		}
		u16 ip_len = bpf_ntohs(iphdr->tot_len);
		if (ip_type == IPPROTO_TCP) {
			tcp_len = parse_tcphdr(&nh, data_end, &tcphdr);
			if (tcp_len < 0) {
				action = TC_ACT_STOLEN;
				goto out;
			}
			
			u16 payload_len = ip_len - iphdr->ihl * 4 - tcp_len;
			if (payload_len < 0) {
				action = TC_ACT_STOLEN;
				goto out;
			}

			u32 saddr = iphdr->saddr;
			iphdr->saddr = iphdr->daddr;
			iphdr->daddr = saddr;
			u16 new_ip_len = iphdr->ihl * 4 + sizeof(struct tcphdr);
			iphdr->tot_len = bpf_htons(new_ip_len);
			iphdr->check = modify_csums(iphdr->check, bpf_htons(ip_len), iphdr->tot_len);

			u16 sport = tcphdr->source;
			tcphdr->source = tcphdr->dest;
			tcphdr->dest = sport;
			u32 seq = bpf_ntohl(tcphdr->seq);
			tcphdr->seq = tcphdr->ack_seq;
			tcphdr->ack_seq = bpf_htonl(seq + payload_len / 2);
			tcphdr->doff = 5;
			tcphdr->check = 0;
			tcphdr->check = udp_csum(iphdr->saddr, iphdr->daddr, sizeof(struct tcphdr), IPPROTO_TCP, (u16*)tcphdr, data_end);

			struct bpf_fib_lookup fib_params = {};
			fib_params.family	= AF_INET;
			fib_params.tos		= iphdr->tos;
			fib_params.l4_protocol	= iphdr->protocol;
			fib_params.sport	= 0;
			fib_params.dport	= 0;
			fib_params.tot_len	= bpf_ntohs(iphdr->tot_len);
			fib_params.ipv4_src	= iphdr->saddr;
			fib_params.ipv4_dst	= iphdr->daddr;
			fib_params.ifindex = skb->ifindex;

			int rc = bpf_fib_lookup(skb, &fib_params, sizeof(fib_params), 0);
			switch (rc) {
			case BPF_FIB_LKUP_RET_SUCCESS:         /* lookup successful */
				// COPY_MAC(eth->h_dest, fib_params.dmac);
				// COPY_MAC(eth->h_source, fib_params.smac);
				// 为了过verifier，只能加一行对h_dest的修改
				// eth->h_dest[0] = fib_params.dmac[0];
				__builtin_memcpy(eth->h_dest, fib_params.dmac, ETH_ALEN);
				__builtin_memcpy(eth->h_source, fib_params.smac, ETH_ALEN);
				break;
			case BPF_FIB_LKUP_RET_BLACKHOLE:    /* dest is blackholed; can be dropped */
			case BPF_FIB_LKUP_RET_UNREACHABLE:  /* dest is unreachable; can be dropped */
			case BPF_FIB_LKUP_RET_PROHIBIT:     /* dest not allowed; can be dropped */
				action = TC_ACT_STOLEN;
				goto out;
			case BPF_FIB_LKUP_RET_NOT_FWDED:    /* packet is not forwarded */
			case BPF_FIB_LKUP_RET_FWD_DISABLED: /* fwding is not enabled on ingress */
			case BPF_FIB_LKUP_RET_UNSUPP_LWT:   /* fwd requires encapsulation */
			case BPF_FIB_LKUP_RET_NO_NEIGH:     /* no neighbor entry for nh */
			case BPF_FIB_LKUP_RET_FRAG_NEEDED:  /* fragmentation required to fwd */
				/* PASS */
				goto out;
			}
			unsigned char modified_tcphdr[20];
			__builtin_memcpy(modified_tcphdr, tcphdr, 20);
			int ret = bpf_skb_adjust_room(skb, -payload_len - tcp_len + 20, BPF_ADJ_ROOM_NET, 0);
			if (ret < 0) {
				action = TC_ACT_STOLEN;
				goto out;
			}
			data = (void *)(long)skb->data;
  			data_end = (void *)(long)skb->data_end;
			nh.pos = data;
			eth_type = parse_ethhdr(&nh, data_end, &eth);
			if (eth_type == bpf_htons(ETH_P_IP)) {
				ip_type = parse_iphdr(&nh, data_end, &iphdr);
				if (ip_type < 0) {
					action = TC_ACT_STOLEN;
					goto out;
				}
				if (nh.pos + 20 <= data_end) {
					__builtin_memcpy(nh.pos, modified_tcphdr, 20);
				}
			}
			bpf_clone_redirect(skb, fib_params.ifindex, 0);
			bpf_clone_redirect(skb, fib_params.ifindex, 0);
			bpf_clone_redirect(skb, fib_params.ifindex, 0);
			action = bpf_redirect(fib_params.ifindex, 0);
		}
	}
 out:
	return action;
}

// SEC("tc/classifier/duplicated_egress")
int tc_op1_1_duplicated_egress(struct __sk_buff *skb) {
	if (skb->mark == ORIGINAL_PACKET) {
		skb->mark = 0;
		return TC_ACT_OK;
	}

	es_stats_one_op_mode();

	skb->mark = ORIGINAL_PACKET;
	int times = bpf_get_prandom_u32() % 3;
	if (times == 0) {
		bpf_clone_redirect(skb, skb->ifindex, 0);
	} else if (times == 1) {
		bpf_clone_redirect(skb, skb->ifindex, 0);
		bpf_clone_redirect(skb, skb->ifindex, 0);
	} else {
		bpf_clone_redirect(skb, skb->ifindex, 0);
		bpf_clone_redirect(skb, skb->ifindex, 0);
		bpf_clone_redirect(skb, skb->ifindex, 0);
	}
	skb->mark = 0;
	return TC_ACT_OK;
}


// TODO: disable when SYN exists
SEC("tc/classifier/egress_dummy")
int tc_op1_1_dummy_egress(struct __sk_buff *skb) {
	if (skb->mark == ORIGINAL_PACKET) {
		skb->mark = 0;
		return TC_ACT_OK;
	}

	es_stats_one_op_mode();

	void *data = (void *)(long)skb->data;
  	void *data_end = (void *)(long)skb->data_end;
	struct hdr_cursor nh;
	struct ethhdr *eth;
	struct iphdr *iphdr;
	struct tcphdr *tcphdr;
	int eth_type;
	int ip_type;
	int tcp_len;
	int action = TC_ACT_OK;

	nh.pos = data;

	eth_type = parse_ethhdr(&nh, data_end, &eth);
	if (eth_type == bpf_htons(ETH_P_IP)) {
		ip_type = parse_iphdr(&nh, data_end, &iphdr);
		if (ip_type < 0) {
			action = TC_ACT_STOLEN;
			goto out;
		}
		u16 ip_len = bpf_ntohs(iphdr->tot_len);
		long ret = bpf_skb_pull_data(skb, ip_len + 14);
		if (ret < 0) {
			bpf_printk("pull failed %ld", ret);
			goto out;
		}
	}
	skb->mark = ORIGINAL_PACKET;
	bpf_clone_redirect(skb, skb->ifindex, 0);
	skb->mark = 0;

	data = (void *)(long)skb->data;
  	data_end = (void *)(long)skb->data_end;
	nh.pos = data;

	eth_type = parse_ethhdr(&nh, data_end, &eth);
	if (eth_type == bpf_htons(ETH_P_IP)) {
		ip_type = parse_iphdr(&nh, data_end, &iphdr);
		if (ip_type < 0) {
			action = TC_ACT_STOLEN;
			goto out;
		}
		u16 ip_len = bpf_ntohs(iphdr->tot_len);
		if (ip_type == IPPROTO_TCP) {
			tcp_len = parse_tcphdr(&nh, data_end, &tcphdr);
			if (tcp_len < 0) {
				action = TC_ACT_STOLEN;
				goto out;
			}
			
			u16 payload_len = ip_len - iphdr->ihl * 4 - tcp_len;
			if (payload_len < 0) {
				action = TC_ACT_STOLEN;
				goto out;
			}

			u32 new_len = ip_len + 14 - rand_n(payload_len);
			iphdr->tot_len = bpf_htons(new_len - 14);
			iphdr->check = modify_csums(iphdr->check, bpf_htons(ip_len), iphdr->tot_len);
			tcphdr->check = modify_csums(tcphdr->check, iphdr->tot_len, bpf_htons(ip_len));
			long ret = bpf_skb_change_tail(skb, new_len, 0);
			if (ret < 0) {
				action = TC_ACT_STOLEN;
				goto out;
			}
			es_stats_record_op(ES_OP1_1_TC);
		}
	}
	
 out:
	return action;
}


// execute the following command first
// sysctl -w net.ipv4.ip_forward=1
SEC("tc/classifier/dummy_seq")
int tc_op1_2_dummy_seq_ingress(struct __sk_buff *skb) {
	if (skb->mark == ORIGINAL_PACKET) {
		skb->mark = 0;
		return TC_ACT_OK;
	}

	es_stats_one_op_mode();

	skb->mark = ORIGINAL_PACKET;
	bpf_clone_redirect(skb, skb->ifindex, BPF_F_INGRESS);
	skb->mark = 0;

	void *data = (void *)(long)skb->data;
  	void *data_end = (void *)(long)skb->data_end;
	struct hdr_cursor nh;
	struct ethhdr *eth;
	struct iphdr *iphdr;
	struct tcphdr *tcphdr;
	int eth_type;
	int ip_type;
	int tcp_len;
	int action = TC_ACT_OK;

	nh.pos = data;
	
	eth_type = parse_ethhdr(&nh, data_end, &eth);
	if (eth_type == bpf_htons(ETH_P_IP)) {
		ip_type = parse_iphdr(&nh, data_end, &iphdr);
		if (ip_type < 0) {
			action = TC_ACT_STOLEN;
			goto out;
		}
		u16 ip_len = bpf_ntohs(iphdr->tot_len);
		if (ip_type == IPPROTO_TCP) {
			tcp_len = parse_tcphdr(&nh, data_end, &tcphdr);
			if (tcp_len < 0) {
				action = TC_ACT_STOLEN;
				goto out;
			}

			if (!tcphdr->ack) {
				action = TC_ACT_STOLEN;
				goto out;
			}
			
			u16 payload_len = ip_len - iphdr->ihl * 4 - tcp_len;
			if (payload_len < 0) {
				action = TC_ACT_STOLEN;
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
			tcphdr->ack_seq = seq;
			tcphdr->doff = 5;
			tcphdr->check = 0;

			struct bpf_fib_lookup fib_params = {};
			fib_params.family	= AF_INET;
			fib_params.tos		= iphdr->tos;
			fib_params.l4_protocol	= iphdr->protocol;
			fib_params.sport	= 0;
			fib_params.dport	= 0;
			fib_params.tot_len	= bpf_ntohs(iphdr->tot_len);
			fib_params.ipv4_src	= iphdr->saddr;
			fib_params.ipv4_dst	= iphdr->daddr;
			fib_params.ifindex = skb->ifindex;

			int rc = bpf_fib_lookup(skb, &fib_params, sizeof(fib_params), 0);
			switch (rc) {
			case BPF_FIB_LKUP_RET_SUCCESS:         /* lookup successful */
				// COPY_MAC(eth->h_dest, fib_params.dmac);
				// COPY_MAC(eth->h_source, fib_params.smac);
				// 为了过verifier，只能加一行对h_dest的修改
				__builtin_memcpy(eth->h_dest, fib_params.dmac, ETH_ALEN);
				__builtin_memcpy(eth->h_source, fib_params.smac, ETH_ALEN);
				break;
			case BPF_FIB_LKUP_RET_BLACKHOLE:    /* dest is blackholed; can be dropped */
			case BPF_FIB_LKUP_RET_UNREACHABLE:  /* dest is unreachable; can be dropped */
			case BPF_FIB_LKUP_RET_PROHIBIT:     /* dest not allowed; can be dropped */
				action = TC_ACT_STOLEN;
				goto out;
			case BPF_FIB_LKUP_RET_NOT_FWDED:    /* packet is not forwarded */
			case BPF_FIB_LKUP_RET_FWD_DISABLED: /* fwding is not enabled on ingress */
			case BPF_FIB_LKUP_RET_UNSUPP_LWT:   /* fwd requires encapsulation */
			case BPF_FIB_LKUP_RET_NO_NEIGH:     /* no neighbor entry for nh */
			case BPF_FIB_LKUP_RET_FRAG_NEEDED:  /* fragmentation required to fwd */
				/* PASS */
				goto out;
			}

			if (payload_len > 100) {
				// math between pkt pointer and register with unbounded min value is not allowed
				// https://lists.iovisor.org/g/iovisor-dev/topic/30285987
				int pkt_len = (payload_len + tcp_len); // & 0xf; 这里只有pkt_len < f才能过20.04的verifier
				tcphdr->check = udp_csum(iphdr->saddr, iphdr->daddr, pkt_len, IPPROTO_TCP, (u16*)tcphdr, data_end);
			} else {
				payload_len += tcp_len;
				u16 new_ip_len = payload_len + 20 + iphdr->ihl * 4;
				iphdr->tot_len = bpf_htons(new_ip_len);
				iphdr->check = modify_csums(iphdr->check, bpf_htons(ip_len), iphdr->tot_len);

				unsigned char modified_tcphdr[20];
				__builtin_memcpy(modified_tcphdr, tcphdr, 20);
				int ret = bpf_skb_adjust_room(skb, 20, BPF_ADJ_ROOM_NET, 0);
				if (ret < 0) {
					action = TC_ACT_STOLEN;
					goto out;
				}
				data = (void *)(long)skb->data;
				data_end = (void *)(long)skb->data_end;
				nh.pos = data;
				eth_type = parse_ethhdr(&nh, data_end, &eth);
				if (eth_type == bpf_htons(ETH_P_IP)) {
					ip_type = parse_iphdr(&nh, data_end, &iphdr);
					if (ip_type < 0) {
						action = TC_ACT_STOLEN;
						goto out;
					}
					if (nh.pos + 20 <= data_end) {
						__builtin_memcpy(nh.pos, modified_tcphdr, 20);
					}
					tcp_len = parse_tcphdr(&nh, data_end, &tcphdr);
					if (tcp_len < 0) {
						action = TC_ACT_STOLEN;
						goto out;
					}
					tcphdr->doff = 5;
					tcphdr->check = udp_csum(iphdr->saddr, iphdr->daddr, payload_len + 20, IPPROTO_TCP, (u16*)tcphdr, data_end);
				}
			}

			es_stats_record_op(ES_OP1_2_TC);
			action = bpf_redirect(fib_params.ifindex, 0);
		}
	}
 out:
	return action;
}

// TODO: disable when SYN exists
SEC("tc/classifier/egress_split")
int tc_op2_split_egress(struct __sk_buff *skb) {
	void *data = (void *)(long)skb->data;
  	void *data_end = (void *)(long)skb->data_end;
	struct hdr_cursor nh;
	struct ethhdr *eth;
	struct iphdr *iphdr;
	struct tcphdr *tcphdr;
	int eth_type;
	int ip_type;
	int tcp_len;
	int action = TC_ACT_OK;
	u16 new_payload_len;

	es_stats_one_op_mode();

	nh.pos = data;

	if (skb->mark > FRAGMENT_PACKET && skb->mark < FRAGMENT_PACKET + 1500) {
		unsigned payload_start = skb->mark - FRAGMENT_PACKET;
		skb->mark = 0;
		eth_type = parse_ethhdr(&nh, data_end, &eth);
		if (eth_type == bpf_htons(ETH_P_IP)) {
			ip_type = parse_iphdr(&nh, data_end, &iphdr);
			if (ip_type < 0) {
				action = TC_ACT_STOLEN;
				goto out;
			}
			u16 ip_len = bpf_ntohs(iphdr->tot_len);
			if (ip_type == IPPROTO_TCP) {
				tcp_len = parse_tcphdr(&nh, data_end, &tcphdr);
				if (tcp_len < 0) {
					action = TC_ACT_STOLEN;
					goto out;
				}
				
				u16 payload_len = ip_len - iphdr->ihl * 4 - tcp_len;
				if (payload_len < 0) {
					action = TC_ACT_STOLEN;
					goto out;
				}

				new_payload_len = payload_len - payload_start;
				u32 new_len = 14 + iphdr->ihl * 4 + tcp_len + new_payload_len;
				iphdr->tot_len = bpf_htons(new_len - 14);
				iphdr->check = modify_csums(iphdr->check, bpf_htons(ip_len), iphdr->tot_len);
				tcphdr->seq = bpf_htonl(bpf_ntohl(tcphdr->seq) + payload_start);
				tcphdr->check = modify_csums(tcphdr->check, iphdr->tot_len, bpf_htons(ip_len));

				char tmp[SPLIT_BUFFER_LEN] = {0};
				int src = 14 + iphdr->ihl * 4 + tcp_len + payload_start;
				int dst = 14 + iphdr->ihl * 4 + tcp_len;
				if (new_payload_len > SPLIT_BUFFER_LEN || new_payload_len <= 0) return TC_ACT_STOLEN;
				new_payload_len &= 511;
				new_payload_len |= 1;
				if (new_payload_len > SPLIT_BUFFER_LEN || new_payload_len <= 0) return TC_ACT_STOLEN;
				long ret = bpf_skb_load_bytes(skb, src, &tmp, (unsigned)new_payload_len);
				if (ret < 0) return TC_ACT_STOLEN;
				ret = bpf_skb_store_bytes(skb, dst, &tmp, (unsigned)new_payload_len, 0);
				if (ret < 0) return TC_ACT_STOLEN;
				ret = bpf_skb_change_tail(skb, new_len, 0);
				if (ret < 0) return TC_ACT_STOLEN;
			}
		}
		goto out;
	}

	eth_type = parse_ethhdr(&nh, data_end, &eth);
	if (eth_type == bpf_htons(ETH_P_IP)) {
		ip_type = parse_iphdr(&nh, data_end, &iphdr);
		if (ip_type < 0) {
			action = TC_ACT_STOLEN;
			goto out;
		}
		u16 ip_len = bpf_ntohs(iphdr->tot_len);
		long ret = bpf_skb_pull_data(skb, ip_len + 14);
		if (ret < 0) {
			bpf_printk("pull failed %ld", ret);
			goto out;
		}
		goto check;
	}
	goto out;

 check:
	data = (void *)(long)skb->data;
  	data_end = (void *)(long)skb->data_end;
	nh.pos = data;

	eth_type = parse_ethhdr(&nh, data_end, &eth);
	if (eth_type == bpf_htons(ETH_P_IP)) {
		ip_type = parse_iphdr(&nh, data_end, &iphdr);
		if (ip_type < 0) {
			action = TC_ACT_STOLEN;
			goto out;
		}
		u16 ip_len = bpf_ntohs(iphdr->tot_len);
		if (ip_type == IPPROTO_TCP) {
			tcp_len = parse_tcphdr(&nh, data_end, &tcphdr);
			if (tcp_len < 0) {
				action = TC_ACT_STOLEN;
				goto out;
			}
			
			u16 payload_len = ip_len - iphdr->ihl * 4 - tcp_len;
			if (payload_len < 10) {
				action = TC_ACT_STOLEN;
				goto out;
			}

			int delta_max = payload_len - 1;
			if (delta_max > SPLIT_BUFFER_LEN) {
				delta_max = SPLIT_BUFFER_LEN;
			}
			int payload_delta = rand_n(delta_max - 1) + 1;
			payload_delta |= 1;
			if (payload_len - payload_delta < 5) {
				payload_delta -= 2;
			}
			new_payload_len = payload_len - payload_delta;
			skb->mark = FRAGMENT_PACKET + new_payload_len;
			bpf_clone_redirect(skb, skb->ifindex, 0);
			skb->mark = 0;
			goto split;
		}
	}
	goto out;
	
 split:
	data = (void *)(long)skb->data;
  	data_end = (void *)(long)skb->data_end;
	nh.pos = data;

	eth_type = parse_ethhdr(&nh, data_end, &eth);
	if (eth_type == bpf_htons(ETH_P_IP)) {
		ip_type = parse_iphdr(&nh, data_end, &iphdr);
		if (ip_type < 0) {
			action = TC_ACT_STOLEN;
			goto out;
		}
		u16 ip_len = bpf_ntohs(iphdr->tot_len);
		if (ip_type == IPPROTO_TCP) {
			tcp_len = parse_tcphdr(&nh, data_end, &tcphdr);
			if (tcp_len < 0) {
				action = TC_ACT_STOLEN;
				goto out;
			}
			
			u16 payload_len = ip_len - iphdr->ihl * 4 - tcp_len;
			if (payload_len < 0) {
				action = TC_ACT_STOLEN;
				goto out;
			}

			u32 new_len = 14 + iphdr->ihl * 4 + tcphdr->doff * 4 + new_payload_len;
			iphdr->tot_len = bpf_htons(new_len - 14);
			iphdr->check = modify_csums(iphdr->check, bpf_htons(ip_len), iphdr->tot_len);
			tcphdr->check = modify_csums(tcphdr->check, iphdr->tot_len, bpf_htons(ip_len));
			long ret = bpf_skb_change_tail(skb, new_len, 0);
			if (ret < 0) {
				action = TC_ACT_STOLEN;
				goto out;
			}
		}
	}
	
 out:
	if (action != TC_ACT_STOLEN) {
		es_stats_record_op(ES_OP2_TC);
	}
	return action;
}


SEC("tc/classifier/wnd_size")
int tc_op4_wnd_size_egress(struct __sk_buff *skb) {
	void *data = (void *)(long)skb->data;
  	void *data_end = (void *)(long)skb->data_end;
	struct hdr_cursor nh;
	struct ethhdr *eth;
	struct iphdr *iphdr;
	struct tcphdr *tcphdr;
	int eth_type;
	int ip_type;
	int tcp_len;
	int action = TC_ACT_OK;

	nh.pos = data;
	
	es_stats_one_op_mode();

	eth_type = parse_ethhdr(&nh, data_end, &eth);
	if (eth_type == bpf_htons(ETH_P_IP)) {
		ip_type = parse_iphdr(&nh, data_end, &iphdr);
		if (ip_type < 0) {
			action = TC_ACT_STOLEN;
			goto out;
		}
		if (ip_type == IPPROTO_TCP) {
			tcp_len = parse_tcphdr(&nh, data_end, &tcphdr);
			if (tcp_len < 0) {
				action = TC_ACT_STOLEN;
				goto out;
			}

			es_stats_record_op(ES_OP4_TC);

			// u16 wnd = tcphdr->window;
			tcphdr->window = bpf_htons(bpf_get_prandom_u32() % 1460 + 1);
			// tcphdr->check = modify_csums(tcphdr->check, wnd, tcphdr->window);
		}
	}
 out:
	return action;
}



#endif

#ifndef _TC_DROP_H_
#define _TC_DROP_H_

#include "include/all.h"
#include "net/checksum.h"
#include "net/parsing_helpers.h"
#include "net/random.h"

#define ORIGINAL_PACKET 2
#define EGRESS_PACKET 3
#define PROCESSED_PACKET 4
#define FRAGMENT_PACKET 1024

SEC("tc/classifier/log")
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
SEC("tc/classifier/dummy_tc")
int dummy_tc(struct __sk_buff *skb) {
	if (skb->mark == ORIGINAL_PACKET) {
		skb->mark = 0;
		return TC_ACT_OK;
	}

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

// execute the following command first
// sysctl -w net.ipv4.ip_forward=1
SEC("tc/classifier/dummy_seq")
int dummy_seq(struct __sk_buff *skb) {
	if (skb->mark == ORIGINAL_PACKET) {
		skb->mark = 0;
		return TC_ACT_OK;
	}

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

			if (payload_len > 100) {
				tcphdr->check = udp_csum(iphdr->saddr, iphdr->daddr, payload_len + tcp_len, IPPROTO_TCP, (u16*)tcphdr, data_end);
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
			
			action = bpf_redirect(fib_params.ifindex, 0);
		}
	}
 out:
	return action;
}

SEC("tc/classifier/duplicated_egress")
int duplicated_egress(struct __sk_buff *skb) {
	if (skb->mark == ORIGINAL_PACKET) {
		skb->mark = 0;
		return TC_ACT_OK;
	}

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


SEC("tc/classifier/wnd_size")
int wnd_size(struct __sk_buff *skb) {
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
		if (ip_type == IPPROTO_TCP) {
			tcp_len = parse_tcphdr(&nh, data_end, &tcphdr);
			if (tcp_len < 0) {
				action = TC_ACT_STOLEN;
				goto out;
			}

			// u16 wnd = tcphdr->window;
			tcphdr->window = bpf_htons(bpf_get_prandom_u32() % 1460 + 1);
			// tcphdr->check = modify_csums(tcphdr->check, wnd, tcphdr->window);
		}
	}
 out:
	return action;
}

// TODO: disable when SYN exists
SEC("tc/classifier/egress_dummy")
int egress_dummy(struct __sk_buff *skb) {
	if (skb->mark == ORIGINAL_PACKET) {
		skb->mark = 0;
		return TC_ACT_OK;
	}

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
		}
	}
	
 out:
	return action;
}

// TODO: disable when SYN exists
SEC("tc/classifier/egress_split")
int egress_split(struct __sk_buff *skb) {
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
	int new_payload_len;
	unsigned char modified_hdr[40];

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
				bpf_printk("new_payload_len: %d", new_payload_len);
				u32 new_len = 14 + iphdr->ihl * 4 + 20 + new_payload_len;
				iphdr->tot_len = bpf_htons(new_len - 14);
				iphdr->check = modify_csums(iphdr->check, bpf_htons(ip_len), iphdr->tot_len);
				tcphdr->seq = bpf_htonl(bpf_ntohl(tcphdr->seq) + payload_start);
				// tcphdr->check = modify_csums(tcphdr->check, iphdr->tot_len, bpf_htons(ip_len));
				tcphdr->doff = 5;

				// __builtin_memcpy(modified_tcphdr, tcphdr, 20);
				bpf_skb_load_bytes(skb, 14, modified_hdr, 40);
				bpf_printk("================");
				for (int i = 0; i < 40; i++) {
					bpf_printk("%x", modified_hdr[i]);
				}
				bpf_printk("++++++++++++++++");
				int ret = bpf_skb_adjust_room(skb, new_payload_len + 20 - tcp_len - payload_len, BPF_ADJ_ROOM_MAC, 0);
				if (ret < 0) {
					action = TC_ACT_STOLEN;
					goto out;
				}

				data = (void *)(long)skb->data;
				data_end = (void *)(long)skb->data_end;
				nh.pos = data;
				eth_type = parse_ethhdr(&nh, data_end, &eth);
				if (eth_type < 0) {
					action = TC_ACT_STOLEN;
					goto out;
				}
				bpf_printk("================");
				for (int i = 0; i < 40; i++) {
					bpf_printk("%x", modified_hdr[i]);
				}
				bpf_printk("++++++++++++++++");
				if (nh.pos + 40 < data_end) {
					__builtin_memcpy(nh.pos, modified_hdr, 40);
					// bpf_skb_store_bytes(skb, 14 + iphdr->ihl * 4, modified_tcphdr, 20, BPF_F_RECOMPUTE_CSUM);
				}
				bpf_printk("nh.pos: %x, modified_hdr: %x", nh.pos, modified_hdr);
				bpf_printk("================");
				for (int i = 0; i < 40; i++) {
					if (nh.pos + i < data_end) {
						bpf_printk("%x", *(unsigned char*)(nh.pos + i));
					}
				}
				bpf_printk("++++++++++++++++");
				return TC_ACT_OK;
				// if (eth_type == bpf_htons(ETH_P_IP)) {
				// 	ip_type = parse_iphdr(&nh, data_end, &iphdr);
				// 	if (ip_type < 0) {
				// 		action = TC_ACT_STOLEN;
				// 		goto out;
				// 	}
					
				// 	tcp_len = parse_tcphdr(&nh, data_end, &tcphdr);
				// 	if (tcp_len < 0) {
				// 		action = TC_ACT_STOLEN;
				// 		goto out;
				// 	}
				// 	tcphdr->check = 0;
				// 	tcphdr->check = udp_csum(iphdr->saddr, iphdr->daddr, new_payload_len + 20, IPPROTO_TCP, (u16*)tcphdr, data_end);
				// 	bpf_printk("%x", tcphdr->check);
				// }
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
			if (payload_len < 0) {
				action = TC_ACT_STOLEN;
				goto out;
			}

			new_payload_len = rand_n(payload_len - 1) + 1;
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
	return action;
}


#endif

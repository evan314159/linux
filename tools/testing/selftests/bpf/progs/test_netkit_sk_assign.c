// SPDX-License-Identifier: GPL-2.0
#include <stdbool.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define CONNECT_PORT	4321

struct {
	__uint(type, BPF_MAP_TYPE_SOCKMAP);
	__type(key, int);
	__type(value, __u64);
	__uint(max_entries, 1);
} server_map SEC(".maps");

int assign_ret = 1;
int nr_assigned;

int primary_assign_ret = 1;
__u32 primary_ifindex;
__u32 redirect_ifindex;
int nr_redirected;

char _license[] SEC("license") = "GPL";

static struct bpf_sock_tuple *
get_tuple(struct __sk_buff *skb, bool *ipv4, __u8 *proto)
{
	void *data_end = (void *)(long)skb->data_end;
	void *data = (void *)(long)skb->data;
	struct ethhdr *eth = data;

	if (eth + 1 > data_end)
		return NULL;

	if (eth->h_proto == bpf_htons(ETH_P_IP)) {
		struct iphdr *iph = (void *)(eth + 1);

		if (iph + 1 > data_end || iph->ihl != 5)
			return NULL;
		*ipv4 = true;
		*proto = iph->protocol;
		return (struct bpf_sock_tuple *)&iph->saddr;
	} else if (eth->h_proto == bpf_htons(ETH_P_IPV6)) {
		struct ipv6hdr *ip6h = (void *)(eth + 1);

		if (ip6h + 1 > data_end)
			return NULL;
		*ipv4 = false;
		*proto = ip6h->nexthdr;
		return (struct bpf_sock_tuple *)&ip6h->saddr;
	}
	return NULL;
}

static int assign(struct __sk_buff *skb, struct bpf_sock_tuple *tuple,
		  bool ipv4, __u8 proto)
{
	__u32 len = ipv4 ? sizeof(tuple->ipv4) : sizeof(tuple->ipv6);
	struct bpf_sock *sk;
	const int zero = 0;
	__be16 dport;

	if (proto != IPPROTO_TCP && proto != IPPROTO_UDP)
		return TC_ACT_OK;
	if ((void *)tuple + len > (void *)(long)skb->data_end)
		return TC_ACT_SHOT;
	dport = ipv4 ? tuple->ipv4.dport : tuple->ipv6.dport;
	if (dport != bpf_htons(CONNECT_PORT))
		return TC_ACT_OK;

	if (proto == IPPROTO_TCP) {
		/* Request and established sockets are refcounted. */
		sk = bpf_skc_lookup_tcp(skb, tuple, len, BPF_F_CURRENT_NETNS, 0);
		if (sk) {
			if (sk->state != BPF_TCP_LISTEN)
				goto assign;
			bpf_sk_release(sk);
		}
	}

	/* Listeners and UDP sockets are not refcounted. */
	sk = bpf_map_lookup_elem(&server_map, &zero);
	if (!sk)
		return TC_ACT_SHOT;
assign:
	assign_ret = bpf_sk_assign(skb, sk, 0);
	bpf_sk_release(sk);
	if (assign_ret)
		return TC_ACT_SHOT;
	__sync_fetch_and_add(&nr_assigned, 1);
	return TC_ACT_OK;
}

SEC("netkit/peer")
int peer_assign(struct __sk_buff *skb)
{
	struct bpf_sock_tuple *tuple;
	bool ipv4 = false;
	__u8 proto = 0;

	tuple = get_tuple(skb, &ipv4, &proto);
	if (!tuple)
		return TC_ACT_OK;
	return assign(skb, tuple, ipv4, proto);
}

/* Only the test's datagram, not e.g. IPv6 MLD or RS from the devices. */
static bool is_test_udp4(struct __sk_buff *skb)
{
	struct bpf_sock_tuple *tuple;
	bool ipv4 = false;
	__u8 proto = 0;

	tuple = get_tuple(skb, &ipv4, &proto);
	if (!tuple || !ipv4 || proto != IPPROTO_UDP)
		return false;
	if ((void *)tuple + sizeof(tuple->ipv4) > (void *)(long)skb->data_end)
		return false;
	return tuple->ipv4.dport == bpf_htons(CONNECT_PORT);
}

SEC("netkit/primary")
int primary_ctx(struct __sk_buff *skb)
{
	struct bpf_sock *sk;
	const int zero = 0;

	if (!is_test_udp4(skb))
		return TC_ACT_OK;

	primary_ifindex = skb->ifindex;

	sk = bpf_map_lookup_elem(&server_map, &zero);
	if (sk) {
		primary_assign_ret = bpf_sk_assign(skb, sk, 0);
		bpf_sk_release(sk);
	}

	if (redirect_ifindex)
		return bpf_redirect(redirect_ifindex, 0);
	return TC_ACT_OK;
}

SEC("tcx/ingress")
int redirect_target(struct __sk_buff *skb)
{
	if (!is_test_udp4(skb))
		return TC_ACT_OK;
	__sync_fetch_and_add(&nr_redirected, 1);
	return TC_ACT_SHOT;
}

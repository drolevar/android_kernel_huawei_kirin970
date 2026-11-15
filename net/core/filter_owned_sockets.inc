/* SPDX-License-Identifier: GPL-2.0 */
/* Socket lookup/release adapted from the consolidated Pixel 4.14 donor.
 * See Documentation/bpf/owned-sockets.md for source provenance and limits.
 * Included only with CONFIG_INET; exposed only to CGROUP_SKB.
 */
static struct sock *sk_lookup(struct net *net, struct bpf_sock_tuple *tuple,
			      int dif, int sdif, u8 family, u8 proto)
{
	bool refcounted = false;
	struct sock *sk = NULL;

	if (family == AF_INET) {
		__be32 src4 = tuple->ipv4.saddr;
		__be32 dst4 = tuple->ipv4.daddr;

		if (proto == IPPROTO_TCP)
			sk = __inet_lookup(net, &tcp_hashinfo, NULL, 0,
					   src4, tuple->ipv4.sport,
					   dst4, tuple->ipv4.dport,
					   dif, sdif, &refcounted);
		else
			sk = __udp4_lib_lookup(net, src4, tuple->ipv4.sport,
					       dst4, tuple->ipv4.dport,
					       dif, sdif, &udp_table, NULL);
#if IS_ENABLED(CONFIG_IPV6)
	} else {
		struct in6_addr *src6 = (struct in6_addr *)&tuple->ipv6.saddr;
		struct in6_addr *dst6 = (struct in6_addr *)&tuple->ipv6.daddr;

		if (!ipv6_bpf_stub)
			return NULL;
		if (proto == IPPROTO_TCP)
			sk = ipv6_bpf_stub->tcp6_lookup(net, &tcp_hashinfo, NULL, 0,
					    src6, tuple->ipv6.sport,
					    dst6, ntohs(tuple->ipv6.dport),
					    dif, sdif, &refcounted);
		else if (likely(ipv6_bpf_stub))
			sk = ipv6_bpf_stub->udp6_lib_lookup(net,
							    src6, tuple->ipv6.sport,
							    dst6, tuple->ipv6.dport,
							    dif, sdif,
							    &udp_table, NULL);
#endif
	}

	if (unlikely(sk && !refcounted && !sock_flag(sk, SOCK_RCU_FREE))) {
		WARN_ONCE(1, "Found non-RCU, unreferenced socket!");
		sk = NULL;
	}
	return sk;
}

/* bpf_skc_lookup performs the core lookup for different types of sockets,
 * taking a reference on the socket if it doesn't have the flag SOCK_RCU_FREE.
 * Returns the socket as an 'unsigned long' to simplify the casting in the
 * callers to satisfy BPF_CALL declarations.
 */
static struct sock *
__bpf_skc_lookup(struct sk_buff *skb, struct bpf_sock_tuple *tuple, u32 len,
		 struct net *caller_net, u32 ifindex, u8 proto, u64 netns_id,
		 u64 flags)
{
	struct sock *sk = NULL;
	u8 family = AF_UNSPEC;
	struct net *net;
	int sdif;

	if (len == sizeof(tuple->ipv4))
		family = AF_INET;
	else if (len == sizeof(tuple->ipv6))
		family = AF_INET6;
	else
		return NULL;

	if (unlikely(family == AF_UNSPEC || flags ||
		     !((s32)netns_id < 0 || netns_id <= S32_MAX)))
		goto out;

	if (family == AF_INET)
		sdif = inet_sdif(skb);
	else
		sdif = inet6_sdif(skb);

	if ((s32)netns_id < 0) {
		net = caller_net;
		sk = sk_lookup(net, tuple, ifindex, sdif, family, proto);
	} else {
		net = get_net_ns_by_id(caller_net, netns_id);
		if (unlikely(!net))
			goto out;
		sk = sk_lookup(net, tuple, ifindex, sdif, family, proto);
		put_net(net);
	}

out:
	return sk;
}

static struct sock *
bpf_skc_lookup(struct sk_buff *skb, struct bpf_sock_tuple *tuple, u32 len,
	       u8 proto, u64 netns_id, u64 flags)
{
	struct net *caller_net;
	int ifindex;

	if (skb->dev) {
		caller_net = dev_net(skb->dev);
		ifindex = skb->dev->ifindex;
	} else {
		if (!skb->sk)
			return NULL;
		caller_net = sock_net(skb->sk);
		ifindex = 0;
	}

	return __bpf_skc_lookup(skb, tuple, len, caller_net, ifindex, proto,
				netns_id, flags);
}

static struct sock *
bpf_sk_lookup(struct sk_buff *skb, struct bpf_sock_tuple *tuple, u32 len,
	      u8 proto, u64 netns_id, u64 flags)
{
	struct sock *sk = bpf_skc_lookup(skb, tuple, len, proto, netns_id,
					 flags);

	if (sk) {
		struct sock *sk2 = sk_to_full_sk(sk);

		/* sk_to_full_sk() may return (sk)->rsk_listener, so make sure the original sk
		 * sock refcnt is decremented to prevent a request_sock leak.
		 */
		if (!sk_fullsock(sk2))
			sk2 = NULL;
		if (sk2 != sk) {
			sock_gen_put(sk);
			/* Ensure there is no need to bump sk2 refcnt */
			if (unlikely(sk2 && !sock_flag(sk2, SOCK_RCU_FREE))) {
				WARN_ONCE(1, "Found non-RCU, unreferenced socket!");
				return NULL;
			}
			sk = sk2;
		}
	}

	return sk;
}

BPF_CALL_5(bpf_sk_lookup_tcp, struct sk_buff *, skb,
	   struct bpf_sock_tuple *, tuple, u32, len, u64, netns_id, u64, flags)
{
	return (unsigned long)bpf_sk_lookup(skb, tuple, len, IPPROTO_TCP,
					    netns_id, flags);
}

static const struct bpf_func_proto bpf_sk_lookup_tcp_proto = {
	.func		= bpf_sk_lookup_tcp,
	.gpl_only	= false,
	.pkt_access	= true,
	.ret_type	= RET_PTR_TO_SOCKET_OR_NULL,
	.acquires_reference = true,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_PTR_TO_MEM,
	.arg3_type	= ARG_CONST_SIZE,
	.arg4_type	= ARG_ANYTHING,
	.arg5_type	= ARG_ANYTHING,
};

BPF_CALL_5(bpf_sk_lookup_udp, struct sk_buff *, skb,
	   struct bpf_sock_tuple *, tuple, u32, len, u64, netns_id, u64, flags)
{
	return (unsigned long)bpf_sk_lookup(skb, tuple, len, IPPROTO_UDP,
					    netns_id, flags);
}

static const struct bpf_func_proto bpf_sk_lookup_udp_proto = {
	.func		= bpf_sk_lookup_udp,
	.gpl_only	= false,
	.pkt_access	= true,
	.ret_type	= RET_PTR_TO_SOCKET_OR_NULL,
	.acquires_reference = true,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_PTR_TO_MEM,
	.arg3_type	= ARG_CONST_SIZE,
	.arg4_type	= ARG_ANYTHING,
	.arg5_type	= ARG_ANYTHING,
};

BPF_CALL_1(bpf_sk_release, struct sock *, sk)
{
	if (sk && (!sk_fullsock(sk) || !sock_flag(sk, SOCK_RCU_FREE)))
		sock_gen_put(sk);
	return 0;
}

static const struct bpf_func_proto bpf_sk_release_proto = {
	.func		= bpf_sk_release,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_SOCK_COMMON,
	.releases_reference = true,
};


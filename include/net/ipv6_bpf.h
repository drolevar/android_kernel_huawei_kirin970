/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _NET_IPV6_BPF_H
#define _NET_IPV6_BPF_H
#include <linux/types.h>
struct net;
struct sock;
struct sk_buff;
struct in6_addr;
struct inet_hashinfo;
struct udp_table;
/* Indirection keeps built-in BPF free of IPv6 module symbol dependencies. */
struct ipv6_bpf_stub {
	struct sock *(*tcp6_lookup)(struct net *, struct inet_hashinfo *,
				  struct sk_buff *, int, const struct in6_addr *, __be16,
				  const struct in6_addr *, u16, int, int, bool *);
	struct sock *(*udp6_lib_lookup)(struct net *, const struct in6_addr *, __be16,
				  const struct in6_addr *, __be16, int, int, struct udp_table *, struct sk_buff *);
};
extern const struct ipv6_bpf_stub *ipv6_bpf_stub;
#endif

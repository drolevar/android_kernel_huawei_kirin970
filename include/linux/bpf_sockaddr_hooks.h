/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_BPF_SOCKADDR_HOOKS_H
#define _LINUX_BPF_SOCKADDR_HOOKS_H
struct sockaddr;
#ifdef CONFIG_CGROUP_BPF
int __cgroup_bpf_run_filter_sock_addr(struct sock *sk, struct sockaddr *uaddr,
				      enum bpf_attach_type type, void *t_ctx);
#define BPF_CGROUP_RUN_SA_PROG(sk, uaddr, type)				       \
({									       \
	int __ret = 0;							       \
	if (cgroup_bpf_enabled)						       \
		__ret = __cgroup_bpf_run_filter_sock_addr(sk, uaddr, type,     \
							  NULL);	       \
	__ret;								       \
})

#define BPF_CGROUP_RUN_SA_PROG_LOCK(sk, uaddr, type, t_ctx)		       \
({									       \
	int __ret = 0;							       \
	if (cgroup_bpf_enabled)	{					       \
		lock_sock(sk);						       \
		__ret = __cgroup_bpf_run_filter_sock_addr(sk, uaddr, type,     \
							  t_ctx);	       \
		release_sock(sk);					       \
	}								       \
	__ret;								       \
})

#define BPF_CGROUP_RUN_PROG_INET4_BIND(sk, uaddr)			       \
	BPF_CGROUP_RUN_SA_PROG(sk, uaddr, BPF_CGROUP_INET4_BIND)

#define BPF_CGROUP_RUN_PROG_INET6_BIND(sk, uaddr)			       \
	BPF_CGROUP_RUN_SA_PROG(sk, uaddr, BPF_CGROUP_INET6_BIND)

#define BPF_CGROUP_PRE_CONNECT_ENABLED(sk) (cgroup_bpf_enabled && \
					    sk->sk_prot->pre_connect)

#define BPF_CGROUP_RUN_PROG_INET4_CONNECT(sk, uaddr)			       \
	BPF_CGROUP_RUN_SA_PROG(sk, uaddr, BPF_CGROUP_INET4_CONNECT)

#define BPF_CGROUP_RUN_PROG_INET6_CONNECT(sk, uaddr)			       \
	BPF_CGROUP_RUN_SA_PROG(sk, uaddr, BPF_CGROUP_INET6_CONNECT)

#define BPF_CGROUP_RUN_PROG_INET4_CONNECT_LOCK(sk, uaddr)		       \
	BPF_CGROUP_RUN_SA_PROG_LOCK(sk, uaddr, BPF_CGROUP_INET4_CONNECT, NULL)

#define BPF_CGROUP_RUN_PROG_INET6_CONNECT_LOCK(sk, uaddr)		       \
	BPF_CGROUP_RUN_SA_PROG_LOCK(sk, uaddr, BPF_CGROUP_INET6_CONNECT, NULL)

#define BPF_CGROUP_RUN_PROG_UDP4_SENDMSG_LOCK(sk, uaddr, t_ctx)		       \
	BPF_CGROUP_RUN_SA_PROG_LOCK(sk, uaddr, BPF_CGROUP_UDP4_SENDMSG, t_ctx)

#define BPF_CGROUP_RUN_PROG_UDP6_SENDMSG_LOCK(sk, uaddr, t_ctx)		       \
	BPF_CGROUP_RUN_SA_PROG_LOCK(sk, uaddr, BPF_CGROUP_UDP6_SENDMSG, t_ctx)

#define BPF_CGROUP_RUN_PROG_UDP4_RECVMSG_LOCK(sk, uaddr)			\
	BPF_CGROUP_RUN_SA_PROG_LOCK(sk, uaddr, BPF_CGROUP_UDP4_RECVMSG, NULL)

#define BPF_CGROUP_RUN_PROG_UDP6_RECVMSG_LOCK(sk, uaddr)			\
	BPF_CGROUP_RUN_SA_PROG_LOCK(sk, uaddr, BPF_CGROUP_UDP6_RECVMSG, NULL)


#else
#define BPF_CGROUP_RUN_PROG_INET4_BIND(sk, uaddr) (0)
#define BPF_CGROUP_RUN_PROG_INET4_CONNECT(sk, uaddr) (0)
#define BPF_CGROUP_RUN_PROG_INET4_CONNECT_LOCK(sk, uaddr) (0)
#define BPF_CGROUP_RUN_PROG_UDP4_SENDMSG_LOCK(sk, uaddr, t_ctx) (0)
#define BPF_CGROUP_RUN_PROG_UDP4_RECVMSG_LOCK(sk, uaddr) (0)
#define BPF_CGROUP_RUN_PROG_INET6_BIND(sk, uaddr) (0)
#define BPF_CGROUP_RUN_PROG_INET6_CONNECT(sk, uaddr) (0)
#define BPF_CGROUP_RUN_PROG_INET6_CONNECT_LOCK(sk, uaddr) (0)
#define BPF_CGROUP_RUN_PROG_UDP6_SENDMSG_LOCK(sk, uaddr, t_ctx) (0)
#define BPF_CGROUP_RUN_PROG_UDP6_RECVMSG_LOCK(sk, uaddr) (0)
#define BPF_CGROUP_PRE_CONNECT_ENABLED(sk) (false)
#endif
#endif

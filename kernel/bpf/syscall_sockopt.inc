/* SPDX-License-Identifier: GPL-2.0 */
/* Bounded expected-attach admission; unsupported hooks remain unsupported. */
static void bpf_prog_load_fixup_attach_type(union bpf_attr *attr)
{
	if (attr->prog_type == BPF_PROG_TYPE_CGROUP_SOCK &&
	    !attr->expected_attach_type)
		attr->expected_attach_type = BPF_CGROUP_INET_SOCK_CREATE;
}

static int bpf_prog_load_check_attach(enum bpf_prog_type type,
				     enum bpf_attach_type expected, u32 ifindex)
{
	if (ifindex)
		return -EOPNOTSUPP;
	switch (type) {
	case BPF_PROG_TYPE_CGROUP_SOCK_ADDR:
		switch (expected) {
		case BPF_CGROUP_INET4_BIND:
		case BPF_CGROUP_INET6_BIND:
		case BPF_CGROUP_INET4_CONNECT:
		case BPF_CGROUP_INET6_CONNECT:
		case BPF_CGROUP_UDP4_SENDMSG:
		case BPF_CGROUP_UDP6_SENDMSG:
		case BPF_CGROUP_UDP4_RECVMSG:
		case BPF_CGROUP_UDP6_RECVMSG:
			return 0;
		default:
			return -EINVAL;
		}
	case BPF_PROG_TYPE_CGROUP_SOCKOPT:
		return expected == BPF_CGROUP_GETSOCKOPT ||
		       expected == BPF_CGROUP_SETSOCKOPT ? 0 : -EINVAL;
	case BPF_PROG_TYPE_CGROUP_SOCK:
		return expected == BPF_CGROUP_INET_SOCK_CREATE ? 0 : -EINVAL;
	case BPF_PROG_TYPE_CGROUP_SKB:
		return expected == BPF_CGROUP_INET_INGRESS ||
		       expected == BPF_CGROUP_INET_EGRESS ? 0 : -EINVAL;
	case BPF_PROG_TYPE_SOCK_OPS:
		return !expected || expected == BPF_CGROUP_SOCK_OPS ? 0 : -EINVAL;
	case BPF_PROG_TYPE_SK_SKB:
		return !expected || expected == BPF_SK_SKB_STREAM_PARSER ||
		       expected == BPF_SK_SKB_STREAM_VERDICT ? 0 : -EINVAL;
	default:
		return expected ? -EINVAL : 0;
	}
}

static int bpf_prog_check_attach(const struct bpf_prog *prog,
				enum bpf_attach_type attach_type)
{
	/* Zero remains the legacy unspecified mode except for SOCKOPT, where
	 * load admission requires an explicit GET/SET contract.
	 */
	if (prog->expected_attach_type && prog->expected_attach_type != attach_type)
		return -EINVAL;
	if (prog->type == BPF_PROG_TYPE_CGROUP_SOCKOPT &&
	    prog->expected_attach_type != attach_type)
		return -EINVAL;
	return 0;
}

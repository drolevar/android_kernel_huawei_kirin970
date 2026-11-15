/* SPDX-License-Identifier: GPL-2.0 */
/* Bounded measured GET/SET context. No generic skb or owned-socket helpers. */
static const struct bpf_func_proto *
cg_sockopt_func_proto(enum bpf_func_id func_id)
{
	if (func_id == BPF_FUNC_sk_storage_get)
		return &bpf_sk_storage_get_borrowed_proto;
	return NULL;
}

static bool cg_sockopt_is_valid_access(int off, int size,
				       enum bpf_access_type type,
				       struct bpf_insn_access_aux *info)
{
	const int size_default = sizeof(__u32);

	if (size <= 0 || off < 0 || off >= sizeof(struct bpf_sockopt) ||
	    (info->expected_attach_type != BPF_CGROUP_GETSOCKOPT &&
	     info->expected_attach_type != BPF_CGROUP_SETSOCKOPT))
		return false;

	if (off % size != 0)
		return false;

	if (type == BPF_WRITE) {
		switch (off) {
		case offsetof(struct bpf_sockopt, retval):
			if (size != size_default)
				return false;
			return info->expected_attach_type ==
				BPF_CGROUP_GETSOCKOPT;
		case offsetof(struct bpf_sockopt, optname):
			/* fallthrough */
		case offsetof(struct bpf_sockopt, level):
			if (size != size_default)
				return false;
			return info->expected_attach_type ==
				BPF_CGROUP_SETSOCKOPT;
		case offsetof(struct bpf_sockopt, optlen):
			return size == size_default;
		default:
			return false;
		}
	}

	switch (off) {
	case offsetof(struct bpf_sockopt, sk):
		if (size != sizeof(__u64))
			return false;
		info->reg_type = PTR_TO_SOCKET;
		break;
	case offsetof(struct bpf_sockopt, optval):
		if (size != sizeof(__u64))
			return false;
		info->reg_type = PTR_TO_PACKET;
		break;
	case offsetof(struct bpf_sockopt, optval_end):
		if (size != sizeof(__u64))
			return false;
		info->reg_type = PTR_TO_PACKET_END;
		break;
	case offsetof(struct bpf_sockopt, retval):
		if (size != size_default)
			return false;
		return info->expected_attach_type == BPF_CGROUP_GETSOCKOPT;
	case offsetof(struct bpf_sockopt, level):
	case offsetof(struct bpf_sockopt, optname):
	case offsetof(struct bpf_sockopt, optlen):
		return size == size_default;
	default:
		return false;
	}
	return true;
}

#define CG_SOCKOPT_ACCESS_FIELD(T, F)					\
	T(BPF_FIELD_SIZEOF(struct bpf_sockopt_kern, F),			\
	  si->dst_reg, si->src_reg,					\
	  offsetof(struct bpf_sockopt_kern, F))

static u32 cg_sockopt_convert_ctx_access(enum bpf_access_type type,
					 const struct bpf_insn *si,
					 struct bpf_insn *insn_buf,
					 struct bpf_prog *prog,
					 u32 *target_size)
{
	struct bpf_insn *insn = insn_buf;

	switch (si->off) {
	case offsetof(struct bpf_sockopt, sk):
		*insn++ = CG_SOCKOPT_ACCESS_FIELD(BPF_LDX_MEM, sk);
		break;
	case offsetof(struct bpf_sockopt, level):
		if (type == BPF_WRITE)
			*insn++ = CG_SOCKOPT_ACCESS_FIELD(BPF_STX_MEM, level);
		else
			*insn++ = CG_SOCKOPT_ACCESS_FIELD(BPF_LDX_MEM, level);
		break;
	case offsetof(struct bpf_sockopt, optname):
		if (type == BPF_WRITE)
			*insn++ = CG_SOCKOPT_ACCESS_FIELD(BPF_STX_MEM, optname);
		else
			*insn++ = CG_SOCKOPT_ACCESS_FIELD(BPF_LDX_MEM, optname);
		break;
	case offsetof(struct bpf_sockopt, optlen):
		if (type == BPF_WRITE)
			*insn++ = CG_SOCKOPT_ACCESS_FIELD(BPF_STX_MEM, optlen);
		else
			*insn++ = CG_SOCKOPT_ACCESS_FIELD(BPF_LDX_MEM, optlen);
		break;
	case offsetof(struct bpf_sockopt, retval):
		if (type == BPF_WRITE)
			*insn++ = CG_SOCKOPT_ACCESS_FIELD(BPF_STX_MEM, retval);
		else
			*insn++ = CG_SOCKOPT_ACCESS_FIELD(BPF_LDX_MEM, retval);
		break;
	case offsetof(struct bpf_sockopt, optval):
		*insn++ = CG_SOCKOPT_ACCESS_FIELD(BPF_LDX_MEM, optval);
		break;
	case offsetof(struct bpf_sockopt, optval_end):
		*insn++ = CG_SOCKOPT_ACCESS_FIELD(BPF_LDX_MEM, optval_end);
		break;
	}

	return insn - insn_buf;
}

static int cg_sockopt_get_prologue(struct bpf_insn *insn_buf,
				   bool direct_write,
				   const struct bpf_prog *prog)
{
	/* Nothing to do for sockopt argument. The data is kzalloc'ated.
	 */
	return 0;
}

const struct bpf_verifier_ops cg_sockopt_prog_ops = {
	.get_func_proto = cg_sockopt_func_proto,
	.is_valid_access = cg_sockopt_is_valid_access,
	.convert_ctx_access = cg_sockopt_convert_ctx_access,
	.gen_prologue = cg_sockopt_get_prologue,
};

/* SPDX-License-Identifier: GPL-2.0 */
/* Measured API37/5.10 sockaddr route: only map lookup is emitted. */
static const struct bpf_func_proto *sock_addr_func_proto(enum bpf_func_id id)
{
	return id == BPF_FUNC_map_lookup_elem ? &bpf_map_lookup_elem_proto : NULL;
}

static bool sock_addr_is_valid_access(int off, int size,
				     enum bpf_access_type type,
				     struct bpf_insn_access_aux *info)
{
	bool ipv6, array = false;
	int base, width;

	if (size <= 0 || off < 0 || off >= sizeof(struct bpf_sock_addr) ||
	    off % size)
		return false;

	switch (info->expected_attach_type) {
	case BPF_CGROUP_INET4_BIND:
	case BPF_CGROUP_INET4_CONNECT:
	case BPF_CGROUP_UDP4_SENDMSG:
	case BPF_CGROUP_UDP4_RECVMSG:
		ipv6 = false;
		break;
	case BPF_CGROUP_INET6_BIND:
	case BPF_CGROUP_INET6_CONNECT:
	case BPF_CGROUP_UDP6_SENDMSG:
	case BPF_CGROUP_UDP6_RECVMSG:
		ipv6 = true;
		break;
	default:
		return false;
	}

	switch (off) {
	case offsetof(struct bpf_sock_addr, sk):
		if (type != BPF_READ || size != sizeof(__u64))
			return false;
		info->reg_type = PTR_TO_SOCKET;
		return true;
	case offsetof(struct bpf_sock_addr, user_family):
	case offsetof(struct bpf_sock_addr, family):
	case offsetof(struct bpf_sock_addr, type):
	case offsetof(struct bpf_sock_addr, protocol):
		return type == BPF_READ && size == sizeof(__u32);
	case bpf_ctx_range(struct bpf_sock_addr, user_ip4):
		if (ipv6)
			return false;
		base = offsetof(struct bpf_sock_addr, user_ip4);
		width = sizeof(__u32);
		break;
	case bpf_ctx_range_till(struct bpf_sock_addr, user_ip6[0], user_ip6[3]):
		if (!ipv6)
			return false;
		base = offsetof(struct bpf_sock_addr, user_ip6);
		width = FIELD_SIZEOF(struct bpf_sock_addr, user_ip6);
		array = true;
		break;
	case bpf_ctx_range(struct bpf_sock_addr, msg_src_ip4):
		if (info->expected_attach_type != BPF_CGROUP_UDP4_SENDMSG)
			return false;
		base = offsetof(struct bpf_sock_addr, msg_src_ip4);
		width = sizeof(__u32);
		break;
	case bpf_ctx_range_till(struct bpf_sock_addr, msg_src_ip6[0], msg_src_ip6[3]):
		if (info->expected_attach_type != BPF_CGROUP_UDP6_SENDMSG)
			return false;
		base = offsetof(struct bpf_sock_addr, msg_src_ip6);
		width = FIELD_SIZEOF(struct bpf_sock_addr, msg_src_ip6);
		array = true;
		break;
	case bpf_ctx_range(struct bpf_sock_addr, user_port):
		base = offsetof(struct bpf_sock_addr, user_port);
		width = sizeof(__u32);
		break;
	default:
		return false;
	}

	if (size > width || off - base > width - size)
		return false;
	if (type == BPF_WRITE)
		return size == sizeof(__u32) || (array && size == sizeof(__u64));
	bpf_ctx_record_field_size(info, sizeof(__u32));
	return (array && size == sizeof(__u64)) ||
		bpf_ctx_narrow_access_ok(off, size, sizeof(__u32));
}

/* SOCK_ADDR_LOAD_NESTED_FIELD() loads Nested Field S.F.NF where S is type of
 * context Structure, F is Field in context structure that contains a pointer
 * to Nested Structure of type NS that has the field NF.
 *
 * SIZE encodes the load size (BPF_B, BPF_H, etc). It's up to caller to make
 * sure that SIZE is not greater than actual size of S.F.NF.
 *
 * If offset OFF is provided, the load happens from that offset relative to
 * offset of NF.
 */
#define SOCK_ADDR_LOAD_NESTED_FIELD_SIZE_OFF(S, NS, F, NF, SIZE, OFF)	       \
	do {								       \
		*insn++ = BPF_LDX_MEM(BPF_FIELD_SIZEOF(S, F), si->dst_reg,     \
				      si->src_reg, offsetof(S, F));	       \
		*insn++ = BPF_LDX_MEM(					       \
			SIZE, si->dst_reg, si->dst_reg,			       \
			bpf_target_off(NS, NF, FIELD_SIZEOF(NS, NF),	       \
				       target_size)			       \
				+ OFF);					       \
	} while (0)

#define SOCK_ADDR_LOAD_NESTED_FIELD(S, NS, F, NF)			       \
	SOCK_ADDR_LOAD_NESTED_FIELD_SIZE_OFF(S, NS, F, NF,		       \
					     BPF_FIELD_SIZEOF(NS, NF), 0)

/* SOCK_ADDR_STORE_NESTED_FIELD_OFF() has semantic similar to
 * SOCK_ADDR_LOAD_NESTED_FIELD_SIZE_OFF() but for store operation.
 *
 * In addition it uses Temporary Field TF (member of struct S) as the 3rd
 * "register" since two registers available in convert_ctx_access are not
 * enough: we can't override neither SRC, since it contains value to store, nor
 * DST since it contains pointer to context that may be used by later
 * instructions. But we need a temporary place to save pointer to nested
 * structure whose field we want to store to.
 */
#define SOCK_ADDR_STORE_NESTED_FIELD_OFF(S, NS, F, NF, SIZE, OFF, TF)	       \
	do {								       \
		int tmp_reg = BPF_REG_9;				       \
		if (si->src_reg == tmp_reg || si->dst_reg == tmp_reg)	       \
			--tmp_reg;					       \
		if (si->src_reg == tmp_reg || si->dst_reg == tmp_reg)	       \
			--tmp_reg;					       \
		*insn++ = BPF_STX_MEM(BPF_DW, si->dst_reg, tmp_reg,	       \
				      offsetof(S, TF));			       \
		*insn++ = BPF_LDX_MEM(BPF_FIELD_SIZEOF(S, F), tmp_reg,	       \
				      si->dst_reg, offsetof(S, F));	       \
		*insn++ = BPF_STX_MEM(SIZE, tmp_reg, si->src_reg,	       \
			bpf_target_off(NS, NF, FIELD_SIZEOF(NS, NF),	       \
				       target_size)			       \
				+ OFF);					       \
		*insn++ = BPF_LDX_MEM(BPF_DW, tmp_reg, si->dst_reg,	       \
				      offsetof(S, TF));			       \
	} while (0)

#define SOCK_ADDR_LOAD_OR_STORE_NESTED_FIELD_SIZE_OFF(S, NS, F, NF, SIZE, OFF, \
						      TF)		       \
	do {								       \
		if (type == BPF_WRITE) {				       \
			SOCK_ADDR_STORE_NESTED_FIELD_OFF(S, NS, F, NF, SIZE,   \
							 OFF, TF);	       \
		} else {						       \
			SOCK_ADDR_LOAD_NESTED_FIELD_SIZE_OFF(		       \
				S, NS, F, NF, SIZE, OFF);  \
		}							       \
	} while (0)

#define SOCK_ADDR_LOAD_OR_STORE_NESTED_FIELD(S, NS, F, NF, TF)		       \
	SOCK_ADDR_LOAD_OR_STORE_NESTED_FIELD_SIZE_OFF(			       \
		S, NS, F, NF, BPF_FIELD_SIZEOF(NS, NF), 0, TF)

static u32 sock_addr_convert_ctx_access(enum bpf_access_type type,
					const struct bpf_insn *si,
					struct bpf_insn *insn_buf,
					struct bpf_prog *prog, u32 *target_size)
{
	int off, port_size = FIELD_SIZEOF(struct sockaddr_in6, sin6_port);
	struct bpf_insn *insn = insn_buf;

	switch (si->off) {
	case offsetof(struct bpf_sock_addr, user_family):
		SOCK_ADDR_LOAD_NESTED_FIELD(struct bpf_sock_addr_kern,
					    struct sockaddr, uaddr, sa_family);
		break;

	case offsetof(struct bpf_sock_addr, user_ip4):
		SOCK_ADDR_LOAD_OR_STORE_NESTED_FIELD_SIZE_OFF(
			struct bpf_sock_addr_kern, struct sockaddr_in, uaddr,
			sin_addr, BPF_SIZE(si->code), 0, tmp_reg);
		break;

	case bpf_ctx_range_till(struct bpf_sock_addr, user_ip6[0], user_ip6[3]):
		off = si->off;
		off -= offsetof(struct bpf_sock_addr, user_ip6[0]);
		SOCK_ADDR_LOAD_OR_STORE_NESTED_FIELD_SIZE_OFF(
			struct bpf_sock_addr_kern, struct sockaddr_in6, uaddr,
			sin6_addr.s6_addr32[0], BPF_SIZE(si->code), off,
			tmp_reg);
		break;

	case offsetof(struct bpf_sock_addr, user_port):
		/* To get port we need to know sa_family first and then treat
		 * sockaddr as either sockaddr_in or sockaddr_in6.
		 * Though we can simplify since port field has same offset and
		 * size in both structures.
		 * Here we check this invariant and use just one of the
		 * structures if it's true.
		 */
		BUILD_BUG_ON(offsetof(struct sockaddr_in, sin_port) !=
			     offsetof(struct sockaddr_in6, sin6_port));
		BUILD_BUG_ON(FIELD_SIZEOF(struct sockaddr_in, sin_port) !=
			     FIELD_SIZEOF(struct sockaddr_in6, sin6_port));
		/* Account for sin6_port being smaller than user_port. */
		port_size = min(port_size, BPF_LDST_BYTES(si));
		SOCK_ADDR_LOAD_OR_STORE_NESTED_FIELD_SIZE_OFF(
			struct bpf_sock_addr_kern, struct sockaddr_in6, uaddr,
			sin6_port, bytes_to_bpf_size(port_size), 0, tmp_reg);
		break;

	case offsetof(struct bpf_sock_addr, family):
		SOCK_ADDR_LOAD_NESTED_FIELD(struct bpf_sock_addr_kern,
					    struct sock, sk, sk_family);
		break;

	case offsetof(struct bpf_sock_addr, type):
	case offsetof(struct bpf_sock_addr, protocol): {
		struct bpf_insn nested = *si;

		/* Huawei stores these fields in a packed flag word. Reuse the
		 * existing mask/shift conversion rather than taking a bitfield
		 * address or changing the JIT.
		 */
		*insn++ = BPF_LDX_MEM(BPF_FIELD_SIZEOF(struct bpf_sock_addr_kern, sk),
				      si->dst_reg, si->src_reg,
				      offsetof(struct bpf_sock_addr_kern, sk));
		nested.src_reg = si->dst_reg;
		nested.off = si->off == offsetof(struct bpf_sock_addr, type) ?
			offsetof(struct bpf_sock, type) : offsetof(struct bpf_sock, protocol);
		insn += bpf_sock_convert_ctx_access(type, &nested, insn, prog, target_size);
		break;
	}

	case offsetof(struct bpf_sock_addr, msg_src_ip4):
		/* Treat t_ctx as struct in_addr for msg_src_ip4. */
		SOCK_ADDR_LOAD_OR_STORE_NESTED_FIELD_SIZE_OFF(
			struct bpf_sock_addr_kern, struct in_addr, t_ctx,
			s_addr, BPF_SIZE(si->code), 0, tmp_reg);
		break;

	case bpf_ctx_range_till(struct bpf_sock_addr, msg_src_ip6[0],
				msg_src_ip6[3]):
		off = si->off;
		off -= offsetof(struct bpf_sock_addr, msg_src_ip6[0]);
		/* Treat t_ctx as struct in6_addr for msg_src_ip6. */
		SOCK_ADDR_LOAD_OR_STORE_NESTED_FIELD_SIZE_OFF(
			struct bpf_sock_addr_kern, struct in6_addr, t_ctx,
			s6_addr32[0], BPF_SIZE(si->code), off, tmp_reg);
		break;
	case offsetof(struct bpf_sock_addr, sk):
		*insn++ = BPF_LDX_MEM(BPF_FIELD_SIZEOF(struct bpf_sock_addr_kern, sk),
				      si->dst_reg, si->src_reg,
				      offsetof(struct bpf_sock_addr_kern, sk));
		break;
	}

	return insn - insn_buf;
}

const struct bpf_verifier_ops cg_sock_addr_prog_ops = {
	.get_func_proto = sock_addr_func_proto,
	.is_valid_access = sock_addr_is_valid_access,
	.convert_ctx_access = sock_addr_convert_ctx_access,
};

/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2018 Covalent IO, Inc.
 * Copyright (c) 2020 Facebook
 */
/* Single-frame Huawei adaptation of upstream reference tracking and bounded
 * allocation verification. See Documentation/bpf/verifier-ownership.md.
 * No helper provider is enabled by these interfaces.
 */
static bool reference_is_live(const struct bpf_verifier_state *state, u32 id)
{
	int i;
	if (!id)
		return false;
	for (i = 0; i < state->acquired_refs; i++)
		if (state->refs[i].id == id)
			return true;
	return false;
}

static int copy_reference_state(struct bpf_verifier_state *dst,
				const struct bpf_verifier_state *src)
{
	struct bpf_reference_state *refs = NULL;
	if (src->acquired_refs) {
		refs = kmalloc_array(src->acquired_refs, sizeof(*refs), GFP_KERNEL);
		if (!refs)
			return -ENOMEM;
		memcpy(refs, src->refs, src->acquired_refs * sizeof(*refs));
	}
	kfree(dst->refs);
	dst->refs = refs;
	dst->acquired_refs = src->acquired_refs;
	return 0;
}

static int acquire_reference_state(struct bpf_verifier_env *env, int insn_idx)
{
	struct bpf_verifier_state *state = env->cur_state;
	struct bpf_reference_state *refs;
	int count = state->acquired_refs;
	u32 id;

	/* No loops or BPF-to-BPF calls: bounded by the instruction limit.
	 * A positive int return cannot encode larger ids.
	 */
	if (count >= BPF_MAXINSNS || env->id_gen >= INT_MAX)
		return -E2BIG;
	refs = kmalloc_array(count + 1, sizeof(*refs), GFP_KERNEL);
	if (!refs)
		return -ENOMEM;
	if (count)
		memcpy(refs, state->refs, count * sizeof(*refs));
	id = ++env->id_gen;
	refs[count].id = id;
	refs[count].insn_idx = insn_idx;
	kfree(state->refs);
	state->refs = refs;
	state->acquired_refs = count + 1;
	return id;
}

static int release_reference_state(struct bpf_verifier_state *state, u32 id)
{
	int i;
	if (!id)
		return -EINVAL;
	for (i = 0; i < state->acquired_refs; i++) {
		if (state->refs[i].id != id)
			continue;
		state->acquired_refs--;
		memmove(state->refs + i, state->refs + i + 1,
			(state->acquired_refs - i) * sizeof(*state->refs));
		return 0;
	}
	return -EINVAL;
}

static int release_reference(struct bpf_verifier_env *env, u32 id)
{
	struct bpf_verifier_state *state = env->cur_state;
	int i, err = release_reference_state(state, id);
	if (err)
		return err;
	/* Never turn stale kernel addresses into readable scalars, even for
	 * privileged programs. Nullable cast aliases share ownership, not id.
	 */
	for (i = 0; i < MAX_BPF_REG; i++)
		if (state->regs[i].ref_obj_id == id)
			__mark_reg_not_init(&state->regs[i]);
	for (i = 0; i < state->allocated_stack / BPF_REG_SIZE; i++)
		if (state->stack[i].slot_type[0] == STACK_SPILL &&
		    state->stack[i].spilled_ptr.ref_obj_id == id)
			__mark_reg_not_init(&state->stack[i].spilled_ptr);
	return 0;
}

static int check_reference_release_arg(struct bpf_verifier_env *env,
				       const struct bpf_reg_state *reg)
{
	if (reg->type != PTR_TO_MEM || reg->off ||
	    !tnum_equals_const(reg->var_off, 0) ||
	    !reference_is_live(env->cur_state, reg->ref_obj_id))
		return -EINVAL;
	return 0;
}

static __maybe_unused int release_reference_reg(struct bpf_verifier_env *env,
					const struct bpf_reg_state *reg)
{
	int err = check_reference_release_arg(env, reg);
	return err ? err : release_reference(env, reg->ref_obj_id);
}

static int check_reference_leak(struct bpf_verifier_env *env)
{
	struct bpf_verifier_state *state = env->cur_state;
	int i;
	for (i = 0; i < state->acquired_refs; i++)
		verbose("Unreleased reference id=%u alloc_insn=%d\n",
			state->refs[i].id, state->refs[i].insn_idx);
	return state->acquired_refs ? -EINVAL : 0;
}

static bool refsafe(const struct bpf_verifier_state *old,
		   const struct bpf_verifier_state *cur)
{
	int i;
	/* Conservative exact identity; never use register liveness to erase
	 * obligations. Alpha-renaming can improve pruning in a later patch.
	 */
	if (old->acquired_refs != cur->acquired_refs)
		return false;
	for (i = 0; i < old->acquired_refs; i++)
		if (old->refs[i].id != cur->refs[i].id)
			return false;
	return true;
}

static int check_alloc_mem_size(const struct bpf_reg_state *reg,
			       struct bpf_call_arg_meta *meta)
{
	if (meta->alloc_size_set || reg->type != SCALAR_VALUE ||
	    !tnum_is_const(reg->var_off) || reg->var_off.value > BPF_MAX_VAR_SIZ)
		return -EINVAL;
	meta->mem_size = reg->var_off.value;
	meta->alloc_size_set = true;
	return 0;
}

static int set_alloc_mem_return(struct bpf_verifier_env *env,
			       struct bpf_reg_state *reg, u32 size, int insn_idx)
{
	int id;
	if (size > BPF_MAX_VAR_SIZ)
		return -EINVAL;
	id = acquire_reference_state(env, insn_idx);
	if (id < 0)
		return id;
	__mark_reg_known_zero(reg);
	reg->type = PTR_TO_MEM_OR_NULL;
	reg->off = 0;
	reg->mem_size = size;
	reg->id = id;
	reg->ref_obj_id = id;
	return 0;
}

static int check_reference_mem_access(struct bpf_verifier_env *env,
				      const struct bpf_reg_state *reg,
				      s64 off, int size, bool zero_allowed)
{
	/* Wide signed arithmetic here: instruction offset plus fixed offset
	 * must not overflow before the bounds check.
	 */
	if (reg->type != PTR_TO_MEM ||
	    !reference_is_live(env->cur_state, reg->ref_obj_id) ||
	    size < 0 || (!size && !zero_allowed) ||
	    reg->smin_value < 0 || reg->umax_value >= BPF_MAX_VAR_OFF ||
	    off < -BPF_MAX_VAR_OFF || off > BPF_MAX_VAR_OFF ||
	    reg->smin_value + off < 0 ||
	    (s64)reg->umax_value + off + size > reg->mem_size)
		return -EACCES;
	return 0;
}

static int check_reference_proto(const struct bpf_func_proto *fn)
{
	const enum bpf_arg_type args[] = { fn->arg1_type, fn->arg2_type,
		fn->arg3_type, fn->arg4_type, fn->arg5_type };
	int i, sizes = 0, pointers = 0;
	for (i = 0; i < 5; i++) {
		sizes += args[i] == ARG_CONST_ALLOC_SIZE_OR_ZERO;
		pointers += args[i] == ARG_PTR_TO_ALLOC_MEM;
	}
	if (fn->ret_type == RET_PTR_TO_ALLOC_MEM_OR_NULL)
		return sizes == 1 && !pointers && !fn->releases_reference ? 0 : -EINVAL;
	if (sizes)
		return -EINVAL;
	if (fn->releases_reference)
		return pointers == 1 && fn->ret_type == RET_VOID ? 0 : -EINVAL;
	return 0;
}

static int adjust_reference_min_max_vals(struct bpf_verifier_env *env,
					struct bpf_insn *insn,
					const struct bpf_reg_state *ptr,
					const struct bpf_reg_state *offset)
{
	struct bpf_reg_state value = *ptr;
	s64 delta, fixed;
	if (!tnum_is_const(offset->var_off) ||
	    !reference_is_live(env->cur_state, ptr->ref_obj_id))
		return -EACCES;
	/* Restrict arithmetic to constant ADD/SUB, without 32-bit truncation.
	 * This also avoids inheriting the legacy variable-ALU masking path.
	 */
	delta = (s64)offset->var_off.value;
	if (delta < -BPF_MAX_VAR_OFF || delta > BPF_MAX_VAR_OFF)
		return -EACCES;
	if (BPF_OP(insn->code) == BPF_SUB) {
		if (ptr != &env->cur_state->regs[insn->dst_reg])
			return -EACCES;
		delta = -delta;
	} else if (BPF_OP(insn->code) != BPF_ADD) {
		return -EACCES;
	}
	fixed = (s64)ptr->off + delta;
	if (fixed < -BPF_MAX_VAR_OFF || fixed > BPF_MAX_VAR_OFF)
		return -EACCES;
	value.off = fixed;
	env->cur_state->regs[insn->dst_reg] = value;
	return 0;
}

/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2018 Facebook. See program-btf-upstream.txt.
 * Huawei adaptation: a single entry point, no subprogram table.
 */
#define MIN_BPF_LINEINFO_SIZE 16
#define MAX_LINEINFO_REC_SIZE MAX_FUNCINFO_REC_SIZE

static int check_btf_line(struct bpf_verifier_env *env,
			  const union bpf_attr *attr,
			  union bpf_attr __user *uattr)
{
	struct bpf_prog *prog = env->prog;
	struct bpf_line_info *linfo;
	void __user *ulinfo = u64_to_user_ptr(attr->line_info);
	u32 count = attr->line_info_cnt, size = attr->line_info_rec_size;
	u32 i, prev_offset = 0;
	int err;

	if (!count)
		return 0;
	if (count > INT_MAX / sizeof(*linfo) || count > prog->len ||
	    size < MIN_BPF_LINEINFO_SIZE || size > MAX_LINEINFO_REC_SIZE ||
	    size % sizeof(u32))
		return -EINVAL;

	linfo = kvmalloc_array(count, sizeof(*linfo),
			      GFP_KERNEL | __GFP_ZERO | __GFP_NOWARN);
	if (!linfo)
		return -ENOMEM;

	for (i = 0; i < count; i++, ulinfo += size) {
		err = bpf_check_uarg_tail_zero(ulinfo, sizeof(*linfo), size);
		if (err) {
			if (err == -E2BIG &&
			    put_user(sizeof(*linfo), &uattr->line_info_rec_size))
				err = -EFAULT;
			goto err_free;
		}
		if (copy_from_user(&linfo[i], ulinfo, sizeof(*linfo))) {
			err = -EFAULT;
			goto err_free;
		}

		err = -EINVAL;
		if ((!i && linfo[i].insn_off) ||
		    (i && linfo[i].insn_off <= prev_offset) ||
		    linfo[i].insn_off >= prog->len ||
		    !prog->insnsi[linfo[i].insn_off].code)
			goto err_free;
		/* These are raw BTF string offsets, not C identifiers. */
		if (!btf_name_by_offset(prog->aux->btf, linfo[i].line_off) ||
		    !btf_name_by_offset(prog->aux->btf, linfo[i].file_name_off))
			goto err_free;
		prev_offset = linfo[i].insn_off;
	}

	prog->aux->linfo = linfo;
	prog->aux->nr_linfo = count;
	return 0;
err_free:
	kvfree(linfo);
	return err;
}

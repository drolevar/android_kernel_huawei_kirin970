/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2018 Facebook. See program-btf-upstream.txt.
 * Huawei adaptation: this verifier has one frame and rejects pseudo-calls.
 * Metadata describes only that frame; it never changes argument admission.
 */
#define MIN_BPF_FUNCINFO_SIZE 8
#define MAX_FUNCINFO_REC_SIZE 252

static int check_btf_func(struct bpf_verifier_env *env,
			  const union bpf_attr *attr,
			  union bpf_attr __user *uattr)
{
	struct bpf_prog_aux *aux = env->prog->aux;
	const struct btf_type *type, *proto;
	struct bpf_func_info *record;
	void __user *urecord = u64_to_user_ptr(attr->func_info);
	u32 size = attr->func_info_rec_size;
	int err;

	if (!attr->func_info_cnt)
		return 0;
	if (attr->func_info_cnt != 1 || size < MIN_BPF_FUNCINFO_SIZE ||
	    size > MAX_FUNCINFO_REC_SIZE || size % sizeof(u32))
		return -EINVAL;

	record = kzalloc(sizeof(*record), GFP_KERNEL | __GFP_NOWARN);
	if (!record)
		return -ENOMEM;

	err = bpf_check_uarg_tail_zero(urecord, sizeof(*record), size);
	if (err) {
		if (err == -E2BIG &&
		    put_user(sizeof(*record), &uattr->func_info_rec_size))
			err = -EFAULT;
		goto err_free;
	}
	if (copy_from_user(record, urecord, sizeof(*record))) {
		err = -EFAULT;
		goto err_free;
	}

	err = -EINVAL;
	if (record->insn_off)
		goto err_free;
	type = btf_type_by_id(aux->btf, record->type_id);
	if (!type || BTF_INFO_KIND(type->info) != BTF_KIND_FUNC)
		goto err_free;
	proto = btf_type_by_id(aux->btf, type->type);
	if (!proto || BTF_INFO_KIND(proto->info) != BTF_KIND_FUNC_PROTO)
		goto err_free;

	aux->func_info = record;
	aux->func_info_cnt = 1;
	return 0;
err_free:
	kfree(record);
	return err;
}

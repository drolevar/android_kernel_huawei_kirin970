/* SPDX-License-Identifier: GPL-2.0 */
/* Huawei single-frame integration of the Facebook program BTF metadata
 * contract. See Documentation/bpf/program-btf-upstream.txt for provenance.
 */
static int check_btf_info(struct bpf_verifier_env *env,
			  const union bpf_attr *attr,
			  union bpf_attr __user *uattr)
{
	struct bpf_prog_aux *aux = env->prog->aux;
	struct btf *btf;
	int err;

	if (!attr->func_info_cnt && !attr->line_info_cnt)
		return 0;
	btf = btf_get_by_fd(attr->prog_btf_fd);
	if (IS_ERR(btf))
		return PTR_ERR(btf);
	aux->btf = btf;

	err = check_btf_func(env, attr, uattr);
	if (!err)
		err = check_btf_line(env, attr, uattr);
	if (err) {
		kfree(aux->func_info);
		aux->func_info = NULL;
		aux->func_info_cnt = 0;
		/* check_btf_line frees its unpublished allocation on error. */
		aux->btf = NULL;
		btf_put(btf);
		verbose("invalid program BTF metadata: %d\n", err);
	}
	return err;
}

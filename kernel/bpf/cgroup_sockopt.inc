/* SPDX-License-Identifier: GPL-2.0 */
/* Consolidated donor sockopt runners; Huawei array adapter below. */
static bool sockopt_array_empty(struct cgroup *cgrp, enum bpf_attach_type type)
{
 bool empty;
 rcu_read_lock();
 empty = !bpf_prog_array_length(rcu_dereference(cgrp->bpf.effective[type]));
 rcu_read_unlock();
 return empty;
}

static int sockopt_alloc_buf(struct bpf_sockopt_kern *ctx, int max_optlen)
{
	if (unlikely(max_optlen < 0))
		return -EINVAL;

	if (unlikely(max_optlen > PAGE_SIZE)) {
		/* We don't expose optvals that are greater than PAGE_SIZE
		 * to the BPF program.
		 */
		max_optlen = PAGE_SIZE;
	}

	ctx->optval = kzalloc(max_optlen, GFP_USER);
	if (!ctx->optval)
		return -ENOMEM;

	ctx->optval_end = ctx->optval + max_optlen;

	return max_optlen;
}

static void sockopt_free_buf(struct bpf_sockopt_kern *ctx)
{
	kfree(ctx->optval);
}

int __cgroup_bpf_run_filter_setsockopt(struct sock *sk, int *level,
				       int *optname, char __user *optval,
				       int *optlen, char **kernel_optval)
{
	struct cgroup *cgrp = sock_cgroup_ptr(&sk->sk_cgrp_data);
	struct bpf_sockopt_kern ctx = {
		.sk = sk,
		.level = *level,
		.optname = *optname,
	};
	int ret, max_optlen;

	/* Opportunistic check to see whether we have any BPF program
	 * attached to the hook so we don't waste time allocating
	 * memory and locking the socket.
	 */
	if (!cgroup_bpf_enabled ||
	    sockopt_array_empty(cgrp, BPF_CGROUP_SETSOCKOPT))
		return 0;

	/* Allocate a bit more than the initial user buffer for
	 * BPF program. The canonical use case is overriding
	 * TCP_CONGESTION(nv) to TCP_CONGESTION(cubic).
	 */
	max_optlen = max_t(int, 16, *optlen);

	max_optlen = sockopt_alloc_buf(&ctx, max_optlen);
	if (max_optlen < 0)
		return max_optlen;

	ctx.optlen = *optlen;

	if (copy_from_user(ctx.optval, optval, min(*optlen, max_optlen)) != 0) {
		ret = -EFAULT;
		goto out;
	}

	lock_sock(sk);
	ret = BPF_PROG_RUN_ARRAY(cgrp->bpf.effective[BPF_CGROUP_SETSOCKOPT],
				 &ctx, BPF_PROG_RUN);
	release_sock(sk);

	if (!ret) {
		ret = -EPERM;
		goto out;
	}

	if (ctx.optlen == -1) {
		/* optlen set to -1, bypass kernel */
		ret = 1;
	} else if (ctx.optlen > max_optlen || ctx.optlen < -1) {
		/* optlen is out of bounds */
		ret = -EFAULT;
	} else {
		/* optlen within bounds, run kernel handler */
		ret = 0;

		/* export any potential modifications */
		*level = ctx.level;
		*optname = ctx.optname;

		/* optlen == 0 from BPF indicates that we should
		 * use original userspace data.
		 */
		if (ctx.optlen != 0) {
			*optlen = ctx.optlen;
			*kernel_optval = ctx.optval;
			/* export and don't free sockopt buf */
			return 0;
		}
	}

out:
	sockopt_free_buf(&ctx);
	return ret;
}

int __cgroup_bpf_run_filter_getsockopt(struct sock *sk, int level,
				       int optname, char __user *optval,
				       int __user *optlen, int max_optlen,
				       int retval)
{
	struct cgroup *cgrp = sock_cgroup_ptr(&sk->sk_cgrp_data);
	struct bpf_sockopt_kern ctx = {
		.sk = sk,
		.level = level,
		.optname = optname,
		.retval = retval,
	};
	int ret;

	/* Opportunistic check to see whether we have any BPF program
	 * attached to the hook so we don't waste time allocating
	 * memory and locking the socket.
	 */
	if (!cgroup_bpf_enabled ||
	    sockopt_array_empty(cgrp, BPF_CGROUP_GETSOCKOPT))
		return retval;

	ctx.optlen = max_optlen;

	max_optlen = sockopt_alloc_buf(&ctx, max_optlen);
	if (max_optlen < 0)
		return max_optlen;

	if (!retval) {
		/* If kernel getsockopt finished successfully,
		 * copy whatever was returned to the user back
		 * into our temporary buffer. Set optlen to the
		 * one that kernel returned as well to let
		 * BPF programs inspect the value.
		 */

		if (get_user(ctx.optlen, optlen)) {
			ret = -EFAULT;
			goto out;
		}

		if (ctx.optlen < 0) {
			ret = -EFAULT;
			goto out;
		}

		if (copy_from_user(ctx.optval, optval,
				   min(ctx.optlen, max_optlen)) != 0) {
			ret = -EFAULT;
			goto out;
		}
	}

	lock_sock(sk);
	ret = BPF_PROG_RUN_ARRAY(cgrp->bpf.effective[BPF_CGROUP_GETSOCKOPT],
				 &ctx, BPF_PROG_RUN);
	release_sock(sk);

	if (!ret) {
		ret = -EPERM;
		goto out;
	}

	if (optval && (ctx.optlen > max_optlen || ctx.optlen < 0)) {
		ret = -EFAULT;
		goto out;
	}

	/* BPF programs only allowed to set retval to 0, not some
	 * arbitrary value.
	 */
	if (ctx.retval != 0 && ctx.retval != retval) {
		ret = -EFAULT;
		goto out;
	}

	if (ctx.optlen != 0) {
		if (optval && copy_to_user(optval, ctx.optval, ctx.optlen)) {
			ret = -EFAULT;
			goto out;
		}
		if (put_user(ctx.optlen, optlen)) {
			ret = -EFAULT;
			goto out;
		}
	}

	ret = ctx.retval;

out:
	sockopt_free_buf(&ctx);
	return ret;
}

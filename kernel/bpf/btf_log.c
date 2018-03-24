// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2018 Facebook
 * Object-BTF portion of the shared verifier diagnostic writer.
 */
#include <linux/kernel.h>
#include <linux/bpf_verifier.h>
#include <linux/uaccess.h>

void bpf_verifier_vlog(struct bpf_verifier_log *log, const char *fmt,
		       va_list args)
{
	unsigned int n;

	/* A multipart diagnostic may have filled or faulted the log already. */
	if (!bpf_verifier_log_needed(log))
		return;

	n = vscnprintf(log->kbuf, BPF_VERIFIER_TMP_LOG_SIZE, fmt, args);

	WARN_ONCE(n >= BPF_VERIFIER_TMP_LOG_SIZE - 1,
		  "verifier log line truncated - local buffer too short\n");

	n = min(log->len_total - log->len_used - 1, n);
	log->kbuf[n] = '\0';

	if (!copy_to_user(log->ubuf + log->len_used, log->kbuf, n + 1))
		log->len_used += n;
	else
		log->ubuf = NULL;
}

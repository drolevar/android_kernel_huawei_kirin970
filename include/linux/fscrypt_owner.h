/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_FSCRYPT_OWNER_H
#define _LINUX_FSCRYPT_OWNER_H

#include <linux/types.h>
#include <linux/stddef.h>

struct fscrypt_master_key;
struct fscrypt_mk_lease;

/* A non-copyable owner of a core reference, not a master-secret capability.
 * The key representation and admission lease remain private to fscrypt.
 * Initialize once on fresh private storage; never reinitialize a live owner.
 * Enroll while holding admission, before publishing ci.  A failed/losing
 * private candidate must drop its owner just like the final inode release.
 * The caller provides inode/ci lifetime and excludes live conversion.
 */
struct fscrypt_mk_owner {
	struct fscrypt_master_key *key;
	u64 generation;
};

static inline void fscrypt_mk_init_owner(struct fscrypt_mk_owner *owner)
{
	owner->key = NULL;
	owner->generation = 0;
}

/* Attach takes an independent reference; it never consumes the lease.
 * Drop does not take the secret guard or perform filesystem operations.
 * Both require exclusive access to this token; drop accepts an empty token.
 */
int fscrypt_mk_enroll(const struct fscrypt_mk_lease *lease,
		      struct fscrypt_mk_owner *owner);
void fscrypt_mk_drop_owner(struct fscrypt_mk_owner *owner);

#endif

/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _FSCRYPT_MASTER_KEY_H
#define _FSCRYPT_MASTER_KEY_H

#include <linux/atomic.h>
#include <linux/refcount.h>
#include <linux/rwsem.h>
#include <linux/types.h>
#include <linux/fscrypt_owner.h>

/* Internal Huawei raw-key lifetime primitive, not an ioctl or keyring ABI.
 * The registry (not yet implemented) must retain one reference, including for
 * absent tombstones.  Every caller must hold a reference while using a key.
 */
#define FSCRYPT_MK_RAW_SIZE 64
#define FSCRYPT_MK_FINGERPRINT_SIZE 32
struct fscrypt_master_key {
	refcount_t refs;
	struct rw_semaphore secret_sem;
	atomic_t owners;
	u64 generation;
	bool present;
	u8 raw[FSCRYPT_MK_RAW_SIZE];
	u8 fingerprint[FSCRYPT_MK_FINGERPRINT_SIZE];
};

/* Zero initialize tokens; never copy or share a live token between threads.
 * A lease holds secret_sem for read and one key reference.  Enrolling an owner
 * takes a separate reference; it does not release or consume the lease.
 * Callers enroll before publishing ci, and drop the owner on a losing publish.
 */
struct fscrypt_mk_lease {
	struct fscrypt_master_key *key;
	u64 generation;
};
enum fscrypt_mk_state {
	FSCRYPT_MK_ABSENT,
	FSCRYPT_MK_PRESENT,
	FSCRYPT_MK_BUSY,
};

struct fscrypt_master_key *fscrypt_mk_alloc(const u8 *raw, size_t size);
void fscrypt_mk_get(struct fscrypt_master_key *key);
void fscrypt_mk_put(struct fscrypt_master_key *key);
int fscrypt_mk_add(struct fscrypt_master_key *key, const u8 *raw, size_t size);
/* generation == 0 admits the current generation; nonzero requires exact match.
 * Cached child wrapping must use its owner's generation, never zero.
 */
int fscrypt_mk_acquire(struct fscrypt_master_key *key, u64 generation,
		       struct fscrypt_mk_lease *lease);
/* Borrowed immutable bytes, valid only until lease release.  No vendor slot
 * metadata is inferred from these raw key bytes.
 */
const u8 *fscrypt_mk_secret(const struct fscrypt_mk_lease *lease);
void fscrypt_mk_release(struct fscrypt_mk_lease *lease);
/* Remove serializes with admitted operations, wipes the secret, and reports
 * whether owners remain.  It never evicts an inode or calls a filesystem.
 */
bool fscrypt_mk_remove(struct fscrypt_master_key *key);
enum fscrypt_mk_state fscrypt_mk_status(struct fscrypt_master_key *key);

#endif

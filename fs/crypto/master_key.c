// SPDX-License-Identifier: GPL-2.0
/*
 * Huawei fscrypt managed master-secret admission and owner lifetime.
 *
 * This is an internal dependency for the filesystem-keyring adapter.  It does
 * not expose modern ioctls, enroll existing inodes, or change legacy key lookup.
 * The separate secret guard and retained-owner design follows upstream fscrypt
 * (Google LLC, fs/crypto/keyring.c and keysetup.c); Huawei context handling and
 * registry/inode integration remain separate from this primitive.
 */
#include <crypto/algapi.h>
#include <crypto/hash.h>
#include <linux/err.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/string.h>
#include "master_key.h"

static int fingerprint_secret(const u8 *raw, u8 *fingerprint)
{
	struct crypto_shash *tfm;
	int err;

	tfm = crypto_alloc_shash("sha256", 0, 0);
	if (IS_ERR(tfm))
		return PTR_ERR(tfm);
	{
		SHASH_DESC_ON_STACK(desc, tfm);

		desc->tfm = tfm;
		desc->flags = 0;
		err = crypto_shash_digest(desc, raw, FSCRYPT_MK_RAW_SIZE,
					  fingerprint);
		shash_desc_zero(desc);
	}
	crypto_free_shash(tfm);
	return err;
}

struct fscrypt_master_key *fscrypt_mk_alloc(const u8 *raw, size_t size)
{
	struct fscrypt_master_key *key;
	int err;

	if (!raw || size != FSCRYPT_MK_RAW_SIZE)
		return ERR_PTR(-EINVAL);
	key = kzalloc(sizeof(*key), GFP_KERNEL);
	if (!key)
		return ERR_PTR(-ENOMEM);
	refcount_set(&key->refs, 1);
	init_rwsem(&key->secret_sem);
	atomic_set(&key->owners, 0);
	err = fingerprint_secret(raw, key->fingerprint);
	if (err) {
		fscrypt_mk_put(key);
		return ERR_PTR(err);
	}
	memcpy(key->raw, raw, FSCRYPT_MK_RAW_SIZE);
	key->generation = 1;
	key->present = true;
	return key;
}

void fscrypt_mk_get(struct fscrypt_master_key *key)
{
	refcount_inc(&key->refs);
}

void fscrypt_mk_put(struct fscrypt_master_key *key)
{
	if (!key || !refcount_dec_and_test(&key->refs))
		return;
	WARN_ON_ONCE(atomic_read(&key->owners));
	memzero_explicit(key->raw, sizeof(key->raw));
	memzero_explicit(key->fingerprint, sizeof(key->fingerprint));
	kfree(key);
}

int fscrypt_mk_add(struct fscrypt_master_key *key, const u8 *raw, size_t size)
{
	u8 fingerprint[FSCRYPT_MK_FINGERPRINT_SIZE] = { 0 };
	int err;

	if (!raw || size != FSCRYPT_MK_RAW_SIZE)
		return -EINVAL;
	err = fingerprint_secret(raw, fingerprint);
	if (err)
		goto out;
	down_write(&key->secret_sem);
	/* A descriptor is not a key identity.  Never replace the material behind
	 * an admitted old-generation owner, including after secret withdrawal.
	 */
	if ((key->present || atomic_read(&key->owners)) &&
	    crypto_memneq(key->fingerprint, fingerprint, sizeof(fingerprint))) {
		err = -EKEYREJECTED;
		goto unlock;
	}
	if (key->present)
		goto unlock;
	if (key->generation == U64_MAX) {
		err = -EOVERFLOW;
		goto unlock;
	}
	memcpy(key->raw, raw, FSCRYPT_MK_RAW_SIZE);
	memcpy(key->fingerprint, fingerprint, sizeof(fingerprint));
	key->generation++;
	key->present = true;
unlock:
	up_write(&key->secret_sem);
out:
	memzero_explicit(fingerprint, sizeof(fingerprint));
	return err;
}

int fscrypt_mk_acquire(struct fscrypt_master_key *key, u64 generation,
		       struct fscrypt_mk_lease *lease)
{
	if (lease->key)
		return -EBUSY;
	fscrypt_mk_get(key);
	down_read(&key->secret_sem);
	if (!key->present || (generation && generation != key->generation)) {
		up_read(&key->secret_sem);
		fscrypt_mk_put(key);
		return -ENOKEY;
	}
	lease->key = key;
	lease->generation = key->generation;
	return 0;
}

const u8 *fscrypt_mk_secret(const struct fscrypt_mk_lease *lease)
{
	return lease->key ? lease->key->raw : NULL;
}

void fscrypt_mk_release(struct fscrypt_mk_lease *lease)
{
	struct fscrypt_master_key *key = lease->key;

	memzero_explicit(lease, sizeof(*lease));
	if (!key)
		return;
	up_read(&key->secret_sem);
	fscrypt_mk_put(key);
}

int fscrypt_mk_enroll(const struct fscrypt_mk_lease *lease,
		      struct fscrypt_mk_owner *owner)
{
	struct fscrypt_master_key *key = lease->key;

	if (!key)
		return -EINVAL;
	if (owner->key)
		return -EBUSY;
	if (!atomic_add_unless(&key->owners, 1, INT_MAX))
		return -EOVERFLOW;
	fscrypt_mk_get(key);
	owner->key = key;
	owner->generation = lease->generation;
	return 0;
}

void fscrypt_mk_drop_owner(struct fscrypt_mk_owner *owner)
{
	struct fscrypt_master_key *key = owner->key;

	memzero_explicit(owner, sizeof(*owner));
	if (!key)
		return;
	atomic_dec(&key->owners);
	fscrypt_mk_put(key);
}

bool fscrypt_mk_remove(struct fscrypt_master_key *key)
{
	bool busy;

	down_write(&key->secret_sem);
	memzero_explicit(key->raw, sizeof(key->raw));
	key->present = false;
	busy = atomic_read(&key->owners) != 0;
	up_write(&key->secret_sem);
	return busy;
}

enum fscrypt_mk_state fscrypt_mk_status(struct fscrypt_master_key *key)
{
	enum fscrypt_mk_state state;

	down_read(&key->secret_sem);
	state = key->present ? FSCRYPT_MK_PRESENT :
		(atomic_read(&key->owners) ? FSCRYPT_MK_BUSY : FSCRYPT_MK_ABSENT);
	up_read(&key->secret_sem);
	return state;
}

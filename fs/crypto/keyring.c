// SPDX-License-Identifier: GPL-2.0
/*
 * Filesystem-level keyring for fscrypt
 *
 * Copyright 2019 Google LLC
 *
 * Huawei adaptation: internal raw64/descriptor registry over master_key.c.
 * Donor: pixel-msm-4.14 bb17b7de4b570f2c0c32ddba0543cac03c58dd84,
 * originating in 3a7ee916f32bcb0d204b3d1abc87751e974acbfb (Eric Biggers).
 * No public ioctls, v2 user claims, or legacy lookup changes here.
 */
#include <linux/capability.h>
#include <linux/cred.h>
#include <linux/key-type.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/seq_file.h>
#include <linux/string.h>
#include "registry.h"

/* Serializes first keyring creation and find + link, not read-side lookups.
 * Like the donor ADD mutex, this may sleep; it is never an inode/crypto reader
 * lock. Callers must not enter ADD while holding a master-secret lease.
 */
static DEFINE_MUTEX(fscrypt_registry_add_mutex);

static int fscrypt_key_instantiate(struct key *key,
				   struct key_preparsed_payload *prep)
{
	struct fscrypt_master_key *mk = (void *)prep->data;

	/* Own a reference independent of ADD's temporary allocation reference.
	 * key_instantiate_and_link prepares the fallible link before this call.
	 */
	fscrypt_mk_get(mk);
	key->payload.data[0] = mk;
	return 0;
}

static void fscrypt_key_destroy(struct key *key)
{
	struct fscrypt_master_key *mk = key->payload.data[0];

	/* Teardown withdraws the secret even if a core reference still exists.
	 * Normal REMOVE never invalidates the key: its tombstone stays linked.
	 */
	fscrypt_mk_remove(mk);
	fscrypt_mk_put(mk);
}

static void fscrypt_key_describe(const struct key *key, struct seq_file *m)
{
	/* Description only: no secret-sem acquisition under proc/key locks. */
	seq_puts(m, key->description);
}

/* The leading dot prohibits userspace add_key(). No update, read or revoke
 * callback, and no SEARCH/WRITE/LINK/SETATTR permissions are granted to userspace.
 */
static struct key_type key_type_fscrypt = {
	.name			= "._fscrypt",
	.instantiate		= fscrypt_key_instantiate,
	.destroy		= fscrypt_key_destroy,
	.describe		= fscrypt_key_describe,
};

static struct key *search_fscrypt_keyring(struct key *keyring,
					const char *description)
{
	key_ref_t keyref = make_key_ref(keyring, true /* possessed */);

	keyref = keyring_search(keyref, &key_type_fscrypt, description);
	if (IS_ERR(keyref)) {
		/* Unlike the donor, do not turn revoked/negative/etc into absence.
		 * This private type cannot create negative keys or expire entries.
		 */
		if (PTR_ERR(keyref) == -EAGAIN)
			return ERR_PTR(-ENOENT);
		return ERR_CAST(keyref);
	}
	return key_ref_to_ptr(keyref);
}

struct fscrypt_master_key *fscrypt_registry_lookup(struct super_block *sb,
						 const u8 *descriptor)
{
	char description[2 * FS_KEY_DESCRIPTOR_SIZE + 1];
	struct fscrypt_master_key *mk;
	struct key *keyring, *key;
	int err;

	if (!descriptor)
		return ERR_PTR(-EINVAL);
	/* Caller owns a live sb; teardown cannot race this pointer borrow. */
	keyring = smp_load_acquire(&sb->s_fscrypt_keys);
	if (!keyring)
		return ERR_PTR(-ENOENT);
	*bin2hex(description, descriptor, FS_KEY_DESCRIPTOR_SIZE) = '\0';
	key = search_fscrypt_keyring(keyring, description);
	if (IS_ERR(key))
		return ERR_CAST(key);

	down_read(&key->sem);
	err = key_validate(key);
	if (err) {
		mk = ERR_PTR(err);
	} else if (!key_is_positive(key) || !key->payload.data[0]) {
		mk = ERR_PTR(-EBADMSG);
	} else {
		mk = key->payload.data[0];
		fscrypt_mk_get(mk);
	}
	up_read(&key->sem);
	key_put(key);
	return mk;
}

/* Caller holds ADD mutex; published ring persists even after failed ADD. */
static int allocate_filesystem_keyring(struct super_block *sb)
{
	char description[sizeof("fscrypt-") + sizeof(sb->s_id)];
	struct key *keyring;

	if (sb->s_fscrypt_keys)
		return 0;
	/* Huawei fscrypt is tristate. Keep the type registered for the entire
	 * live registry, including ownerless tombstones and empty rings.
	 */
	if (!try_module_get(THIS_MODULE))
		return -ENODEV;
	snprintf(description, sizeof(description), "fscrypt-%s", sb->s_id);
	/* Allocation publishes the serial/name before we can set KEEP. Grant
	 * SEARCH only to possessed kernel lookups from the outset; userspace
	 * must not invalidate this ring during that publication window.
	 */
	keyring = keyring_alloc(description, GLOBAL_ROOT_UID, GLOBAL_ROOT_GID,
				current_cred(), KEY_POS_SEARCH |
				KEY_USR_READ | KEY_USR_VIEW,
				KEY_ALLOC_NOT_IN_QUOTA, NULL, NULL);
	if (IS_ERR(keyring)) {
		module_put(THIS_MODULE);
		return PTR_ERR(keyring);
	}
	/* Defense in depth once published; allocation-time permissions protect
	 * the earlier window. KEEP propagates to entries during instantiation.
	 */
	set_bit(KEY_FLAG_KEEP, &keyring->flags);
	sb->s_fscrypt_keys_owner = THIS_MODULE;
	smp_store_release(&sb->s_fscrypt_keys, keyring);
	return 0;
}

static int add_new_master_key(struct key *keyring, const u8 *descriptor,
			      const u8 *raw, size_t size)
{
	char description[2 * FS_KEY_DESCRIPTOR_SIZE + 1];
	struct fscrypt_master_key *mk;
	struct key *key;
	int err;

	mk = fscrypt_mk_alloc(raw, size);
	if (IS_ERR(mk))
		return PTR_ERR(mk);
	*bin2hex(description, descriptor, FS_KEY_DESCRIPTOR_SIZE) = '\0';
	/* Donor v1 policy: only initial-namespace CAP_SYS_ADMIN can add these
	 * keys. No per-user claims or custom quota is introduced. As for the
	 * ring, withhold user SEARCH at allocation: positive state is published
	 * before key_instantiate_and_link() copies KEEP from the ring.
	 */
	key = key_alloc(&key_type_fscrypt, description,
			GLOBAL_ROOT_UID, GLOBAL_ROOT_GID, current_cred(),
			KEY_POS_SEARCH | KEY_USR_VIEW,
			KEY_ALLOC_NOT_IN_QUOTA, NULL);
	if (IS_ERR(key)) {
		err = PTR_ERR(key);
		goto out;
	}
	err = key_instantiate_and_link(key, mk, sizeof(*mk), keyring, NULL);
	key_put(key);
out:
	fscrypt_mk_put(mk);
	return err;
}

int fscrypt_registry_add(struct super_block *sb, const u8 *descriptor,
			 const u8 *raw, size_t size)
{
	struct fscrypt_master_key *mk;
	int err;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;
	if (!descriptor || !raw || size != FSCRYPT_MK_RAW_SIZE)
		return -EINVAL;
	mutex_lock(&fscrypt_registry_add_mutex);
	mk = fscrypt_registry_lookup(sb, descriptor);
	if (!IS_ERR(mk)) {
		err = fscrypt_mk_add(mk, raw, size);
		fscrypt_mk_put(mk);
	} else {
		err = PTR_ERR(mk);
		if (err != -ENOENT)
			goto out;
		err = allocate_filesystem_keyring(sb);
		if (!err)
			err = add_new_master_key(sb->s_fscrypt_keys, descriptor,
						 raw, size);
	}
out:
	mutex_unlock(&fscrypt_registry_add_mutex);
	return err;
}

int __init fscrypt_registry_init(void)
{
	return register_key_type(&key_type_fscrypt);
}

void fscrypt_registry_exit(void)
{
	/* Synchronously reaps custom payloads before module text can disappear.
	 * Live filesystem registries hold a module reference and prevent exit.
	 */
	unregister_key_type(&key_type_fscrypt);
}

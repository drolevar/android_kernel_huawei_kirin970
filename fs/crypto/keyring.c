// SPDX-License-Identifier: GPL-2.0
/*
 * Filesystem-level keyring for fscrypt
 *
 * Copyright 2019 Google LLC
 *
 * Selected donor primitives; Huawei wiring is a separate adaptation commit.
 */
#include <linux/key-type.h>
#include <linux/seq_file.h>
#include "fscrypt_private.h"

static int fscrypt_key_instantiate(struct key *key,
				   struct key_preparsed_payload *prep)
{
	key->payload.data[0] = (struct fscrypt_master_key *)prep->data;
	return 0;
}

static void fscrypt_key_destroy(struct key *key)
{
	free_master_key(key->payload.data[0]);
}

static void fscrypt_key_describe(const struct key *key, struct seq_file *m)
{
	seq_puts(m, key->description);

	if (key_is_positive(key)) {
		const struct fscrypt_master_key *mk = key->payload.data[0];

		if (!is_master_key_secret_present(&mk->mk_secret))
			seq_puts(m, ": secret removed");
	}
}

/*
 * Type of key in ->s_master_keys.  Each key of this type represents a master
 * key which has been added to the filesystem.  Its payload is a
 * 'struct fscrypt_master_key'.  The "." prefix in the key type name prevents
 * users from adding keys of this type via the keyrings syscalls rather than via
 * the intended method of FS_IOC_ADD_ENCRYPTION_KEY.
 */
static struct key_type key_type_fscrypt = {
	.name			= "._fscrypt",
	.instantiate		= fscrypt_key_instantiate,
	.destroy		= fscrypt_key_destroy,
	.describe		= fscrypt_key_describe,
};

/* Search ->s_master_keys or ->mk_users */
static struct key *search_fscrypt_keyring(struct key *keyring,
					  struct key_type *type,
					  const char *description)
{
	/*
	 * We need to mark the keyring reference as "possessed" so that we
	 * acquire permission to search it, via the KEY_POS_SEARCH permission.
	 */
	key_ref_t keyref = make_key_ref(keyring, true /* possessed */);

	keyref = keyring_search(keyref, type, description);
	if (IS_ERR(keyref)) {
		if (PTR_ERR(keyref) == -EAGAIN || /* not found */
		    PTR_ERR(keyref) == -EKEYREVOKED) /* recently invalidated */
			keyref = ERR_PTR(-ENOKEY);
		return ERR_CAST(keyref);
	}
	return key_ref_to_ptr(keyref);
}


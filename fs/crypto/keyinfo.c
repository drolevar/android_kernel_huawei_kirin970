// SPDX-License-Identifier: GPL-2.0
/*
 * key management facility for FS encryption support.
 *
 * Copyright (C) 2015, Google, Inc.
 *
 * This contains encryption key functions.
 *
 * Written by Michael Halcrow, Ildar Muslukhov, and Uday Savagaonkar, 2015.
 */

#include <keys/user-type.h>
#include <linux/scatterlist.h>
#include <linux/ratelimit.h>
#include <linux/refcount.h>
#include <crypto/aes.h>
#include <crypto/sha.h>
#include <crypto/skcipher.h>
#include "fscrypt_private.h"
#ifdef CONFIG_HWDPS
#include <linux/security.h>
#include <securec.h>
#include <huawei_platform/hwdps/hwdps_limits.h>
#include <huawei_platform/hwdps/hwdps_fs_hooks.h>
#define HWDPS_KEY_DESC_STANDARD_FLAG 0x42
#endif

static struct crypto_shash *essiv_hash_tfm;

static void derive_crypt_complete(struct crypto_async_request *req, int rc)
{
        struct fscrypt_completion_result *ecr = req->data;

        if (rc == -EINPROGRESS)
                return;

        ecr->res = rc;
        complete(&ecr->completion);
}

int fscrypt_set_gcm_key(struct crypto_aead *tfm,
                       const u8 deriving_key[FS_AES_256_GCM_KEY_SIZE])
{
	int res = 0;
	unsigned int iv_len;

	crypto_aead_set_flags(tfm, CRYPTO_TFM_REQ_WEAK_KEY);

	iv_len = crypto_aead_ivsize(tfm);
	if (iv_len > FS_KEY_DERIVATION_IV_SIZE) {
		res = -EINVAL;
		pr_err("fscrypt %s : IV length is incompatible\n", __func__);
		goto out;
	}

	res = crypto_aead_setauthsize(tfm, FS_KEY_DERIVATION_TAG_SIZE);
	if (res < 0) {
		pr_err("fscrypt %s : Failed to set authsize\n", __func__);
		goto out;
	}

	res = crypto_aead_setkey(tfm, deriving_key,
					FS_AES_256_GCM_KEY_SIZE);
	if (res < 0)
	        pr_err("fscrypt %s : Failed to set deriving key\n", __func__);
	out:
      return res;
}

int fscrypt_derive_gcm_key(struct crypto_aead *tfm,
			 const u8 source_key[FS_KEY_DERIVATION_CIPHER_SIZE],
			       u8 derived_key[FS_KEY_DERIVATION_CIPHER_SIZE],
			       u8 iv[FS_KEY_DERIVATION_IV_SIZE],
			       int enc)
{
	int res = 0;
	struct aead_request *req = NULL;
	DECLARE_FS_COMPLETION_RESULT(ecr);
	struct scatterlist src_sg, dst_sg;
	unsigned int ilen;
#ifdef CONFIG_VMAP_STACK
	u8 *src = NULL;
	u8 *dst = NULL;

	src = kmalloc(FS_KEY_DERIVATION_CIPHER_SIZE, GFP_NOFS);
	if (!src) {
		res = -ENOMEM;
		goto out;
	}
	dst = kmalloc(FS_KEY_DERIVATION_CIPHER_SIZE, GFP_NOFS);
	if (!dst) {
		res = -ENOMEM;
		goto out;
	}
#endif

	if (!tfm) {
		res = -EINVAL;
		goto out;
	}

	if (IS_ERR(tfm)) {
		res = PTR_ERR(tfm);
		goto out;
	}

	req = aead_request_alloc(tfm, GFP_NOFS);
	if (!req) {
		res = -ENOMEM;
		goto out;
	}

	aead_request_set_callback(req,
			CRYPTO_TFM_REQ_MAY_BACKLOG | CRYPTO_TFM_REQ_MAY_SLEEP,
			derive_crypt_complete, &ecr);


	ilen = enc ? FS_KEY_DERIVATION_NONCE_SIZE :
			FS_KEY_DERIVATION_CIPHER_SIZE;

#ifdef CONFIG_VMAP_STACK
	memcpy(src, source_key, FS_KEY_DERIVATION_CIPHER_SIZE);
	memcpy(dst, derived_key, FS_KEY_DERIVATION_CIPHER_SIZE);
	sg_init_one(&src_sg, src, FS_KEY_DERIVATION_CIPHER_SIZE);
	sg_init_one(&dst_sg, dst, FS_KEY_DERIVATION_CIPHER_SIZE);
#else
	sg_init_one(&src_sg, source_key, FS_KEY_DERIVATION_CIPHER_SIZE);
	sg_init_one(&dst_sg, derived_key, FS_KEY_DERIVATION_CIPHER_SIZE);
#endif

	aead_request_set_ad(req, 0);

	aead_request_set_crypt(req, &src_sg, &dst_sg, ilen, iv);
	res = enc ? crypto_aead_encrypt(req) : crypto_aead_decrypt(req);
	if (res == -EINPROGRESS || res == -EBUSY) {
		wait_for_completion(&ecr.completion);
		res = ecr.res;
	}
#ifdef CONFIG_VMAP_STACK
	memcpy(derived_key, dst, FS_KEY_DERIVATION_CIPHER_SIZE);
out:
	kfree(src);
	kfree(dst);
#else
out:
#endif

	if (req)
		aead_request_free(req);
	return res;
}

struct key *fscrypt_request_key(const u8 *descriptor, const u8 *prefix,
			       int prefix_size)
{
	u8 *full_key_descriptor = NULL;
	struct key *keyring_key = NULL;
	int full_key_len = prefix_size + (FS_KEY_DESCRIPTOR_SIZE * 2) + 1;

	full_key_descriptor = kmalloc(full_key_len, GFP_NOFS);
	if (!full_key_descriptor)
		return (struct key *)ERR_PTR(-ENOMEM);

	memcpy(full_key_descriptor, prefix, prefix_size);
	sprintf(full_key_descriptor + prefix_size,
			"%*phN", FS_KEY_DESCRIPTOR_SIZE,
			descriptor);
	full_key_descriptor[full_key_len - 1] = '\0';
	keyring_key = request_key(&key_type_logon, full_key_descriptor, NULL);
	kfree(full_key_descriptor);

	return keyring_key;
}

/*
 * Explicit legacy-prefix policy: only request_key's -ENOKEY permits trying
 * the alternate filesystem prefix.  This result is ambiguous (e.g. negative
 * or expired keys), NOT evidence of absence.  Once a key is returned, failed
 * validation never falls back.  No modern filesystem-keyring state is used.
 */
int fscrypt_acquire_ce_key(const u8 *descriptor, const char *alternate,
			   struct fscrypt_ce_key *lease)
{
	const struct user_key_payload *ukp;
	const struct fscrypt_key *payload;
	struct key *key;
	int err;

	memset(lease, 0, sizeof(*lease));
	key = fscrypt_request_key(descriptor, FS_KEY_DESC_PREFIX,
				  FS_KEY_DESC_PREFIX_SIZE);
	if (key == ERR_PTR(-ENOKEY) && alternate) {
		key = fscrypt_request_key(descriptor, alternate, strlen(alternate));
		lease->alternate_prefix = true;
	}
	if (IS_ERR(key)) {
		err = PTR_ERR(key);
		goto wipe;
	}

	down_read(&key->sem);
	err = key_validate(key);
	if (err)
		goto unlock;
	if (key->type != &key_type_logon) {
		err = -EKEYREJECTED;
		goto unlock;
	}
	ukp = user_key_payload_locked(key);
	if (!ukp) {
		err = -EKEYREVOKED;
		goto unlock;
	}
	if (ukp->datalen != sizeof(*payload)) {
		err = -EINVAL;
		goto unlock;
	}
	payload = (const struct fscrypt_key *)ukp->data;
	/* Both existing userspace representations carry a 32-byte GCM key.
	 * Never normalize the shared payload, nor discard raw[32..63].
	 */
	if (payload->size != FS_AES_256_GCM_KEY_SIZE &&
	    payload->size != FS_MAX_KEY_SIZE) {
		err = -EINVAL;
		goto unlock;
	}
	memcpy(&lease->material, payload, sizeof(*payload));
	lease->key = key;
	return 0;

unlock:
	up_read(&key->sem);
	key_put(key);
wipe:
	memzero_explicit(lease, sizeof(*lease));
	return err;
}
EXPORT_SYMBOL(fscrypt_acquire_ce_key);

void fscrypt_release_ce_key(struct fscrypt_ce_key *lease)
{
	if (lease->key) {
		up_read(&lease->key->sem);
		key_put(lease->key);
	}
	memzero_explicit(lease, sizeof(*lease));
}
EXPORT_SYMBOL(fscrypt_release_ce_key);

struct fscrypt_ce_tfm {
	refcount_t refs;
	struct crypto_aead *tfm;
	u8 descriptor[FS_KEY_DESCRIPTOR_SIZE];
	u8 legacy_slot;
};

struct fscrypt_ce_scope {
	struct super_block *sb;
	u8 descriptor[FS_KEY_DESCRIPTOR_SIZE];
	enum fscrypt_ce_purpose purpose;
	struct fscrypt_ce_tfm *owner;
};

static void fscrypt_ce_tfm_get(struct fscrypt_ce_tfm *owner)
{
	refcount_inc(&owner->refs);
}

void fscrypt_ce_tfm_put(struct fscrypt_ce_tfm *owner)
{
	if (!owner || !refcount_dec_and_test(&owner->refs))
		return;
	crypto_free_aead(owner->tfm);
	memzero_explicit(owner, sizeof(*owner));
	kfree(owner);
}
EXPORT_SYMBOL_GPL(fscrypt_ce_tfm_put);

int fscrypt_ce_scope_open(struct inode *inode,
		const u8 descriptor[FS_KEY_DESCRIPTOR_SIZE],
		enum fscrypt_ce_purpose purpose, struct fscrypt_ce_scope **out)
{
	struct fscrypt_ce_scope *scope = NULL;
	struct fscrypt_ce_tfm *owner = NULL;
	struct fscrypt_ce_key lease = { };
	struct fscrypt_key material = { };
	const char *alternate;
	int err;

	if (!out) {
		err = -EINVAL;
		goto out;
	}
	*out = NULL;
	if (!inode || !inode->i_sb || !inode->i_sb->s_cop || !descriptor) {
		err = -EINVAL;
		goto out;
	}
	if (purpose != POLICY_WRAP && purpose != FILE_UNWRAP &&
	    purpose != SDP_CE_SOURCE) {
		err = -EINVAL;
		goto out;
	}

	scope = kzalloc(sizeof(*scope), GFP_NOFS);
	if (!scope) {
		err = -ENOMEM;
		goto out;
	}
	owner = kzalloc(sizeof(*owner), GFP_NOFS);
	if (!owner) {
		err = -ENOMEM;
		goto out;
	}

	alternate = purpose == SDP_CE_SOURCE ? NULL :
		inode->i_sb->s_cop->key_prefix;
	err = fscrypt_acquire_ce_key(descriptor, alternate, &lease);
	if (err)
		goto out;
	memcpy(&material, &lease.material, sizeof(material));
	fscrypt_release_ce_key(&lease);

	owner->tfm = crypto_alloc_aead("gcm(aes)", 0, 0);
	if (IS_ERR(owner->tfm)) {
		err = PTR_ERR(owner->tfm);
		owner->tfm = NULL;
		goto out;
	}
	err = fscrypt_set_gcm_key(owner->tfm, material.raw);
	if (err)
		goto out;
	refcount_set(&owner->refs, 1);
	owner->legacy_slot = material.raw[63];
	memcpy(owner->descriptor, descriptor, sizeof(owner->descriptor));
	scope->sb = inode->i_sb;
	memcpy(scope->descriptor, descriptor, sizeof(scope->descriptor));
	scope->purpose = purpose;
	scope->owner = owner;
	*out = scope;
	scope = NULL;
	owner = NULL;
	err = 0;

out:
	fscrypt_release_ce_key(&lease);
	if (owner) {
		crypto_free_aead(owner->tfm);
		memzero_explicit(owner, sizeof(*owner));
		kfree(owner);
	}
	if (scope) {
		memzero_explicit(scope, sizeof(*scope));
		kfree(scope);
	}
	memzero_explicit(&material, sizeof(material));
	return err;
}
EXPORT_SYMBOL_GPL(fscrypt_ce_scope_open);

int fscrypt_ce_scope_open_cached(struct inode *inode,
		enum fscrypt_ce_purpose purpose, struct fscrypt_ce_scope **out)
{
	struct fscrypt_ce_scope *scope;
	struct fscrypt_info *ci;

	if (!out)
		return -EINVAL;
	*out = NULL;
	if (!inode || purpose != CHILD_WRAP)
		return -EINVAL;
	ci = READ_ONCE(inode->i_crypt_info);
	if (!ci || ci->ci_hw_enc_flag || !ci->ci_gtfm_owner ||
	    ci->ci_gtfm != ci->ci_gtfm_owner->tfm ||
	    memcmp(ci->ci_master_key, ci->ci_gtfm_owner->descriptor,
		   FS_KEY_DESCRIPTOR_SIZE))
		return -ENOKEY;
	scope = kzalloc(sizeof(*scope), GFP_NOFS);
	if (!scope)
		return -ENOMEM;
	fscrypt_ce_tfm_get(ci->ci_gtfm_owner);
	scope->sb = inode->i_sb;
	memcpy(scope->descriptor, ci->ci_gtfm_owner->descriptor,
	       sizeof(scope->descriptor));
	scope->purpose = purpose;
	scope->owner = ci->ci_gtfm_owner;
	*out = scope;
	return 0;
}

bool fscrypt_ce_scope_matches(const struct fscrypt_ce_scope *scope,
		const struct inode *inode,
		const u8 descriptor[FS_KEY_DESCRIPTOR_SIZE],
		enum fscrypt_ce_purpose purpose)
{
	return scope && inode && descriptor && scope->owner &&
		scope->sb == inode->i_sb && scope->purpose == purpose &&
		!memcmp(scope->descriptor, descriptor,
			FS_KEY_DESCRIPTOR_SIZE);
}

int fscrypt_ce_scope_crypt(struct fscrypt_ce_scope *scope, const u8 *src,
		u8 *dst, const u8 iv[FS_KEY_DERIVATION_IV_SIZE], bool encrypt)
{
	if (!scope || !scope->owner || !scope->owner->tfm ||
	    !src || !dst || !iv)
		return -EINVAL;
	return fscrypt_derive_gcm_key(scope->owner->tfm, src, dst, (u8 *)iv,
			encrypt ? 1 : 0);
}
EXPORT_SYMBOL_GPL(fscrypt_ce_scope_crypt);

int fscrypt_ce_scope_legacy_slot(const struct fscrypt_ce_scope *scope,
		u8 *slot)
{
	if (!scope || !scope->owner || !slot)
		return -EINVAL;
	*slot = scope->owner->legacy_slot;
	return 0;
}
EXPORT_SYMBOL_GPL(fscrypt_ce_scope_legacy_slot);

static int fscrypt_ce_scope_attach_legacy_tfm(struct fscrypt_ce_scope *scope,
		struct fscrypt_info *ci)
{
	if (!scope || !scope->owner || !ci || ci->ci_gtfm_owner || ci->ci_gtfm)
		return -EINVAL;
	if (scope->purpose != FILE_UNWRAP && scope->purpose != CHILD_WRAP)
		return -EINVAL;
	fscrypt_ce_tfm_get(scope->owner);
	ci->ci_gtfm_owner = scope->owner;
	ci->ci_gtfm = scope->owner->tfm;
	return 0;
}

void fscrypt_ce_scope_put(struct fscrypt_ce_scope *scope)
{
	if (!scope)
		return;
	fscrypt_ce_tfm_put(scope->owner);
	memzero_explicit(scope, sizeof(*scope));
	kfree(scope);
}
EXPORT_SYMBOL_GPL(fscrypt_ce_scope_put);

/* Find the master key, then derive the inode's actual encryption key */
static int find_and_derive_key_with_scope(const struct inode *inode,
			       struct fscrypt_info *crypt_info,
			       const struct fscrypt_context *ctx,
			       u8 *derived_key, unsigned int derived_keysize,
			       struct fscrypt_ce_scope *borrowed)
{
	struct fscrypt_ce_scope *scope = borrowed;
	u8 plain_text[FS_KEY_DERIVATION_CIPHER_SIZE] = {0};
	u8 slot;
	int err;

	if (derived_keysize > FS_KEY_DERIVATION_NONCE_SIZE)
		return -EINVAL;
	if (scope) {
		if (!fscrypt_ce_scope_matches(scope, inode,
				ctx->master_key_descriptor, CHILD_WRAP))
			return -EINVAL;
	} else {
		err = fscrypt_ce_scope_open((struct inode *)inode,
				ctx->master_key_descriptor, FILE_UNWRAP,
				&scope);
		if (err)
			return err;
	}

	err = fscrypt_ce_scope_legacy_slot(scope, &slot);
	if (err)
		goto out;
	crypt_info->ci_key_index = slot;
	err = fscrypt_ce_scope_crypt(scope, ctx->nonce, plain_text, ctx->iv,
			false);
	if (err)
		goto out;
	memcpy(derived_key, plain_text, derived_keysize);
	err = fscrypt_ce_scope_attach_legacy_tfm(scope, crypt_info);

out:
	if (!borrowed)
		fscrypt_ce_scope_put(scope);
	memzero_explicit(plain_text, sizeof(plain_text));
	return err;
}

static int find_and_derive_key(const struct inode *inode,
			       struct fscrypt_info *crypt_info,
			       const struct fscrypt_context *ctx,
			       u8 *derived_key, unsigned int derived_keysize)
{
	return find_and_derive_key_with_scope(inode, crypt_info, ctx,
			derived_key, derived_keysize, NULL);
}

static struct fscrypt_mode {
	const char *friendly_name;
	const char *cipher_str;
	int keysize;
	bool logged_impl_name;
} available_modes[] = {
	[FS_ENCRYPTION_MODE_AES_256_XTS] = {
		.friendly_name = "AES-256-XTS",
		.cipher_str = "xts(aes)",
		.keysize = 64,
	},
	[FS_ENCRYPTION_MODE_AES_256_CTS] = {
		.friendly_name = "AES-256-CTS-CBC",
		.cipher_str = "cts(cbc(aes))",
		.keysize = 32,
	},
	[FS_ENCRYPTION_MODE_AES_128_CBC] = {
		.friendly_name = "AES-128-CBC",
		.cipher_str = "cbc(aes)",
		.keysize = 16,
	},
	[FS_ENCRYPTION_MODE_AES_128_CTS] = {
		.friendly_name = "AES-128-CTS-CBC",
		.cipher_str = "cts(cbc(aes))",
		.keysize = 16,
	},
};

static struct fscrypt_mode *
select_encryption_mode(const struct fscrypt_info *ci, const struct inode *inode)
{
	if (!fscrypt_valid_enc_modes(ci->ci_data_mode, ci->ci_filename_mode)) {
		fscrypt_warn(inode->i_sb,
			     "inode %lu uses unsupported encryption modes(contents mode %d, filenames mode %d)",
			     inode->i_ino, ci->ci_data_mode,
			     ci->ci_filename_mode);
		return ERR_PTR(-EINVAL);
	}

	if (S_ISREG(inode->i_mode))
		return &available_modes[ci->ci_data_mode];

	if (S_ISDIR(inode->i_mode) || S_ISLNK(inode->i_mode))
		return &available_modes[ci->ci_filename_mode];

	WARN_ONCE(1, "fscrypt: filesystem tried to load encryption info for inode %lu, which is not encryptable (file type %d)\n",
		  inode->i_ino, (inode->i_mode & S_IFMT));
	return ERR_PTR(-EINVAL);
}

static int determine_cipher_type(struct fscrypt_info *ci, struct inode *inode,
				 const char **cipher_str_ret, int *keysize_ret)
{
	u32 mode;
	if (!fscrypt_valid_enc_modes(ci->ci_data_mode, ci->ci_filename_mode)) {
		pr_warn_ratelimited("inode %lu err enc mode (contents %d,%d)\n",
				    inode->i_ino,
				    ci->ci_data_mode, ci->ci_filename_mode);
		return -EINVAL;
	}

	if (S_ISREG(inode->i_mode)) {
		mode = ci->ci_data_mode;
	} else if (S_ISDIR(inode->i_mode) || S_ISLNK(inode->i_mode)) {
		mode = ci->ci_filename_mode;
	} else {
		WARN_ONCE(1, "inode %lu not encryptable, file type %d\n",
			  inode->i_ino, (inode->i_mode & S_IFMT));
		return -EINVAL;
	}

	*cipher_str_ret = available_modes[mode].cipher_str;
	*keysize_ret = available_modes[mode].keysize;
	return 0;
}

static void put_crypt_info(struct fscrypt_info *ci)
{
	void *prev = NULL;
	void *key = NULL;
	if (!ci)
		return;

	/*lint -save -e529 -e438*/
	key = ACCESS_ONCE(ci->ci_key);
	/*lint -restore*/
	/*lint -save -e1072 -e747 -e50*/
	prev = cmpxchg(&ci->ci_key, key, NULL);
	/*lint -restore*/
	if (prev == key && key) {
		memzero_explicit(key, (size_t)FS_MAX_KEY_SIZE);
		kfree(key);
		ci->ci_key_len = 0;
		ci->ci_key_index = -1;
	}
	if (ci->ci_gtfm_owner)
		fscrypt_ce_tfm_put(ci->ci_gtfm_owner);
	else if (ci->ci_gtfm)
		crypto_free_aead(ci->ci_gtfm);
	crypto_free_skcipher(ci->ci_ctfm);
	crypto_free_cipher(ci->ci_essiv_tfm);
	fscrypt_mk_drop_owner(&ci->ci_owner);
	kmem_cache_free(fscrypt_info_cachep, ci);
}

static int derive_essiv_salt(const u8 *key, int keysize, u8 *salt)
{
	struct crypto_shash *tfm = READ_ONCE(essiv_hash_tfm);

	/* init hash transform on demand */
	if (unlikely(!tfm)) {
		struct crypto_shash *prev_tfm;

		tfm = crypto_alloc_shash("sha256", 0, 0);
		if (IS_ERR(tfm)) {
			fscrypt_warn(NULL,
				     "error allocating SHA-256 transform: %ld",
				     PTR_ERR(tfm));
			return PTR_ERR(tfm);
		}
		prev_tfm = cmpxchg(&essiv_hash_tfm, NULL, tfm);
		if (prev_tfm) {
			crypto_free_shash(tfm);
			tfm = prev_tfm;
		}
	}

	{
		SHASH_DESC_ON_STACK(desc, tfm);
		desc->tfm = tfm;
		desc->flags = 0;

		return crypto_shash_digest(desc, key, keysize, salt);
	}
}

static int init_essiv_generator(struct fscrypt_info *ci, const u8 *raw_key,
				int keysize)
{
	int err;
	struct crypto_cipher *essiv_tfm;
	u8 salt[SHA256_DIGEST_SIZE];

	essiv_tfm = crypto_alloc_cipher("aes", 0, 0);
	if (IS_ERR(essiv_tfm))
		return PTR_ERR(essiv_tfm);

	ci->ci_essiv_tfm = essiv_tfm;

	err = derive_essiv_salt(raw_key, keysize, salt);
	if (err)
		goto out;

	/*
	 * Using SHA256 to derive the salt/key will result in AES-256 being
	 * used for IV generation. File contents encryption will still use the
	 * configured keysize (AES-128) nevertheless.
	 */
	err = crypto_cipher_setkey(essiv_tfm, salt, sizeof(salt));
	if (err)
		goto out;

out:
	memzero_explicit(salt, sizeof(salt));
	return err;
}

void __exit fscrypt_essiv_cleanup(void)
{
	crypto_free_shash(essiv_hash_tfm);
}

static int fscrypt_get_encryption_info_internal(struct inode *inode,
		const struct fscrypt_context *supplied_ctx,
		struct fscrypt_ce_scope *scope)
{
	struct fscrypt_info *crypt_info;
	struct fscrypt_context ctx;
	struct crypto_skcipher *ctfm;
	struct fscrypt_mode *mode;
	u8 *raw_key = NULL;
	int res;
	int flag = 0;

	/* TicketNo:AR000B5MB3 -- HWDPS file needs to check access control */
	/* TicketNo:AR0009DF3P -- SDP file needs to check master key */
	if (inode->i_crypt_info && !inode->i_crypt_info->ci_hw_enc_flag)
		return 0;
	/* TicketNo:AR0009DF3P END */
	/* TicketNo:AR000B5MB3 END */

	res = fscrypt_initialize(inode->i_sb->s_cop->flags);
	if (res)
		return res;

	/* TicketNo:AR000B5MB3 -- For HWDPS protection */
	/* TicketNo:AR0009DF3P -- For SDP protection */
	if (!supplied_ctx && inode->i_sb->s_cop &&
	    inode->i_sb->s_cop->get_keyinfo) {
		res = inode->i_sb->s_cop->get_keyinfo(inode, NULL, &flag);
		if (res) { /* err case */
			pr_err("f2fs_sdp: get_keyinfo failed res:%d", res);
			return res;
		}
		if (flag) /* get sdp crypt info success */
			return 0;
	}
	/* TicketNo:AR0009DF3P END */
	/* TicketNo:AR000B5MB3 END */

	if (supplied_ctx) {
		ctx = *supplied_ctx;
	} else {
		res = inode->i_sb->s_cop->get_context(inode, &ctx, sizeof(ctx));
		if (res < 0) {
			if (!fscrypt_dummy_context_enabled(inode) ||
			    IS_ENCRYPTED(inode))
				return res;
			/* Fake up a context for an unencrypted directory */
			memset(&ctx, 0, sizeof(ctx));
			ctx.format = FS_ENCRYPTION_CONTEXT_FORMAT_V2;
			ctx.contents_encryption_mode =
				FS_ENCRYPTION_MODE_AES_256_XTS;
			ctx.filenames_encryption_mode =
				FS_ENCRYPTION_MODE_AES_256_CTS;
			memset(ctx.master_key_descriptor, 0x42,
			       FS_KEY_DESCRIPTOR_SIZE);
		} else if (res != sizeof(ctx)) {
			pr_err("%s: inode %lu incorrect ctx size [%u : %lu]\n",
				inode->i_sb->s_type->name, inode->i_ino, res,
				sizeof(ctx));
			return -EINVAL;
		}
	}

	if (ctx.format != FS_ENCRYPTION_CONTEXT_FORMAT_V2)
		return -EINVAL;

	if (ctx.flags & ~FS_POLICY_FLAGS_VALID)
		return -EINVAL;

	crypt_info = kmem_cache_alloc(fscrypt_info_cachep, GFP_NOFS);
	if (!crypt_info)
		return -ENOMEM;
	fscrypt_mk_init_owner(&crypt_info->ci_owner);

	crypt_info->ci_flags = ctx.flags;
	crypt_info->ci_data_mode = ctx.contents_encryption_mode;
	crypt_info->ci_filename_mode = ctx.filenames_encryption_mode;
	crypt_info->ci_ctfm = NULL;
	crypt_info->ci_gtfm = NULL;
	crypt_info->ci_gtfm_owner = NULL;
	crypt_info->ci_essiv_tfm = NULL;
	crypt_info->ci_key = NULL;
	crypt_info->ci_key_len = 0;
	crypt_info->ci_key_index = -1;
	crypt_info->ci_hw_enc_flag = 0;
	memcpy(crypt_info->ci_master_key, ctx.master_key_descriptor,
				sizeof(crypt_info->ci_master_key));

	mode = select_encryption_mode(crypt_info, inode);
	if (IS_ERR(mode)) {
		res = PTR_ERR(mode);
		goto out;
	}

	/*
	 * This cannot be a stack buffer because it is passed to the scatterlist
	 * crypto API as part of key derivation.
	 */
	res = -ENOMEM;
	raw_key = kmalloc(mode->keysize, GFP_NOFS);
	if (!raw_key)
		goto out;

	res = find_and_derive_key_with_scope(inode, crypt_info, &ctx, raw_key,
			mode->keysize, scope);
	if (res)
		goto out;

	ctfm = crypto_alloc_skcipher(mode->cipher_str, 0, 0);
	if (IS_ERR(ctfm)) {
		res = PTR_ERR(ctfm);
		fscrypt_warn(inode->i_sb,
			     "error allocating '%s' transform for inode %lu: %d",
			     mode->cipher_str, inode->i_ino, res);
		goto out;
	}
	if (unlikely(!mode->logged_impl_name)) {
		/*
		 * fscrypt performance can vary greatly depending on which
		 * crypto algorithm implementation is used.  Help people debug
		 * performance problems by logging the ->cra_driver_name the
		 * first time a mode is used.  Note that multiple threads can
		 * race here, but it doesn't really matter.
		 */
		mode->logged_impl_name = true;
		pr_info("fscrypt: %s using implementation \"%s\"\n",
			mode->friendly_name,
			crypto_skcipher_alg(ctfm)->base.cra_driver_name);
	}
	crypt_info->ci_ctfm = ctfm;
	crypto_skcipher_set_flags(ctfm, CRYPTO_TFM_REQ_WEAK_KEY);
	res = crypto_skcipher_setkey(ctfm, raw_key, mode->keysize);
	if (res)
		goto out;

	if (S_ISREG(inode->i_mode) &&
			inode->i_sb->s_cop->is_inline_encrypted &&
			inode->i_sb->s_cop->is_inline_encrypted(inode)) {
		crypt_info->ci_key = kzalloc((size_t)FS_MAX_KEY_SIZE, GFP_NOFS);
		if (!crypt_info->ci_key) {
			res = -ENOMEM;
			goto out;
		}
		crypt_info->ci_key_len = mode->keysize;
		/*lint -save -e732 -e747*/
		memcpy(crypt_info->ci_key, raw_key, crypt_info->ci_key_len);
		/*lint -restore*/
		res = fscrypt_get_metadata(inode, crypt_info);
		if (res && res != -EOPNOTSUPP)
			goto out;
		else
			res = 0;
	}

	if (S_ISREG(inode->i_mode) &&
	    crypt_info->ci_data_mode == FS_ENCRYPTION_MODE_AES_128_CBC) {
		res = init_essiv_generator(crypt_info, raw_key, mode->keysize);
		if (res) {
			fscrypt_warn(inode->i_sb,
				     "error initializing ESSIV generator for inode %lu: %d",
				     inode->i_ino, res);
			goto out;
		}
	}
	if (cmpxchg(&inode->i_crypt_info, NULL, crypt_info) == NULL)
		crypt_info = NULL;
out:
	if (res == -ENOKEY)
		res = 0;
	put_crypt_info(crypt_info);
	kzfree(raw_key);
	return res;
}

int fscrypt_get_encryption_info_with_scope(struct inode *inode,
		const struct fscrypt_context *ctx,
		struct fscrypt_ce_scope *scope)
{
	if (!ctx || !fscrypt_ce_scope_matches(scope, inode,
			ctx->master_key_descriptor, CHILD_WRAP))
		return -EINVAL;
	return fscrypt_get_encryption_info_internal(inode, ctx, scope);
}

int fscrypt_get_encryption_info(struct inode *inode)
{
	return fscrypt_get_encryption_info_internal(inode, NULL, NULL);
}
EXPORT_SYMBOL(fscrypt_get_encryption_info);

void fscrypt_put_encryption_info(struct inode *inode)
{
	put_crypt_info(inode->i_crypt_info);
	inode->i_crypt_info = NULL;
}
EXPORT_SYMBOL(fscrypt_put_encryption_info);

#ifdef CONFIG_HWDPS
#ifdef CONFIG_SCSI_UFS_ENHANCED_INLINE_CRYPTO_V2
#define MAX_HISI_KEY_INDEX 31
#define FS_KEY_INDEX_OFFSET 63
static int hwdps_get_key_index(u8 *descriptor)
{
	struct key *keyring_key;
	const struct user_key_payload *ukp;
	struct fscrypt_key *primary_key;
	int res;

	keyring_key = fscrypt_request_key(descriptor, FS_KEY_DESC_PREFIX,
		FS_KEY_DESC_PREFIX_SIZE);
	if (IS_ERR(keyring_key)) {
		pr_err("hwdps request_key failed!\n");
		return PTR_ERR(keyring_key);
	}

	down_read(&keyring_key->sem);
	if (keyring_key->type != &key_type_logon) {
		pr_err("hwdps key type must be logon\n");
		res = -ENOKEY;
		goto out;
	}
	ukp = user_key_payload_locked(keyring_key);
	if (!ukp) {
		/* key was revoked before we acquired its semaphore */
		pr_warn_once("hwdps key was revoked\n");
		res = -EKEYREVOKED;
		goto out;
	}
	if (ukp->datalen != sizeof(struct fscrypt_key)) {
		pr_warn_once("hwdps fscrypt key size err %d", ukp->datalen);
		res = -EINVAL;
		goto out;
	}
	primary_key = (struct fscrypt_key *)ukp->data;
	if (primary_key->size != FS_AES_256_GCM_KEY_SIZE) {
		pr_warn_once("hwdps key size err %d", primary_key->size);
		res = -ENOKEY;
		goto out;
	}
	res = (int) (*(primary_key->raw + FS_KEY_INDEX_OFFSET) & 0xff);

out:
	up_read(&keyring_key->sem);
	key_put(keyring_key);
	return res;
}
#endif

/*
 * Description: Get the context of a file inode whether support the hwdps.
 * Input: inode: the inode requesting fek struct
 * Input: ctx: the fscrypt_context of the inode
 * Return: 0: successfully get the context
 *         -EOPNOTSUPP: not support
 */
static int hwdps_do_get_context(struct inode *inode,
	struct fscrypt_context *ctx)
{
	int err;

	pr_info_once("%s enter\n", __func__);
	if (!inode || !inode->i_sb || !inode->i_sb->s_cop ||
		!inode->i_sb->s_cop->get_context || !ctx)
		return -EOPNOTSUPP;

	err = fscrypt_initialize(inode->i_sb->s_cop->flags);
	if (err != 0) {
		pr_err("hwdps ino %lu init fscrypt fail\n", inode->i_ino);
		return err;
	}
	err = inode->i_sb->s_cop->get_context(inode, ctx, sizeof(*ctx));
	if (err < 0) {
		if (!fscrypt_dummy_context_enabled(inode) ||
			inode->i_sb->s_cop->is_encrypted(inode))
			return err;
		/* Fake up a context for an unencrypted directory */
		if (memset_s(ctx, sizeof(*ctx), 0, sizeof(*ctx)) != EOK)
			return err;
		ctx->format = FS_ENCRYPTION_CONTEXT_FORMAT_V2;
		ctx->contents_encryption_mode = FS_ENCRYPTION_MODE_AES_256_XTS;
		ctx->filenames_encryption_mode = FS_ENCRYPTION_MODE_AES_256_CTS;
		if (memset_s(ctx->master_key_descriptor, FS_KEY_DESCRIPTOR_SIZE,
			HWDPS_KEY_DESC_STANDARD_FLAG,
			FS_KEY_DESCRIPTOR_SIZE) != EOK)
			return err;
	} else if (err != sizeof(*ctx)) {
		pr_err("hwdps ino %lu ctx size [%u : %lu]\n",
			inode->i_ino, err, sizeof(*ctx));
		return -EINVAL;
	}
	if (ctx->format != FS_ENCRYPTION_CONTEXT_FORMAT_V2) {
		pr_err("hwdps format error, format %x", ctx->format);
		return -EINVAL;
	}
	if (ctx->flags & ~FS_POLICY_FLAGS_VALID)
		return -EINVAL;

	return 0;
}

int hwdps_update_context(struct inode *inode, uid_t new_uid)
{
	int err;
	uint32_t fek_len;
	struct fscrypt_context ctx;
	encrypt_id id;
	uint8_t *encoded_wfek = NULL;
	uint8_t *fek = NULL;
	secondary_buffer_t fek_buffer = { &fek, &fek_len };
	buffer_t encoded_wfek_buffer = { NULL, 0 };
	uint32_t flags = 0;

	if (hwdps_check_support(inode, &flags) != 0)
		return 0;
	encoded_wfek = hwdps_do_get_attr(inode, HWDPS_ENCODED_WFEK_SIZE, flags);
	if (!encoded_wfek) {
		pr_err("hwdps_do_get_attr failed\n");
		return -ENOMEM;
	}
	encoded_wfek_buffer.data = encoded_wfek;
	encoded_wfek_buffer.len = HWDPS_ENCODED_WFEK_SIZE;
	err = hwdps_has_access(inode, &encoded_wfek_buffer, flags);
	if (err != 0) {
		pr_err("hwdps_has_access %d\n", err);
		goto free_encoded_wfek;
	}
	err = hwdps_do_get_context(inode, &ctx);
	if (err != 0) {
		pr_err("hwdps_do_get_context failed %d\n", err);
		goto free_encoded_wfek;
	}
	id.uid = new_uid;
	id.task_uid = inode->i_uid.val;
	err = hwdps_update_fek(ctx.master_key_descriptor, &encoded_wfek_buffer,
		&fek_buffer, new_uid, inode->i_uid.val);
	if (err != 0) {
		pr_err("hwdps ino %lu update_fek err %d\n", inode->i_ino, err);
		goto free_fek;
	}
	if (inode->i_sb->s_cop->update_hwdps_attr)
		err = inode->i_sb->s_cop->update_hwdps_attr(inode, encoded_wfek,
			HWDPS_ENCODED_WFEK_SIZE, NULL);
	else
		err = -EINVAL;
	if (err != 0)
		pr_err("hwdps ino %lu update xattr err %d\n", inode->i_ino, err);

free_fek:
	kzfree(fek);
	if (err == -ENOKEY)
		err = 0;
free_encoded_wfek:
	kzfree(encoded_wfek);
	return err;
}
EXPORT_SYMBOL(hwdps_update_context); //lint !e580

static struct fscrypt_info *hwdps_get_fscrypt_info(struct fscrypt_context *ctx,
	struct inode *inode, const char **cipher_str, int *keysize)
{
	struct fscrypt_info *ci;
	int err;

	ci = kmem_cache_alloc(fscrypt_info_cachep, GFP_NOFS);
	if (!ci)
		return ERR_PTR(-ENOMEM);
	fscrypt_mk_init_owner(&ci->ci_owner);
	ci->ci_flags = ctx->flags;
	ci->ci_data_mode = ctx->contents_encryption_mode;
	ci->ci_filename_mode = ctx->filenames_encryption_mode;
	ci->ci_ctfm = NULL;
	ci->ci_gtfm = NULL;
	ci->ci_gtfm_owner = NULL;
	ci->ci_essiv_tfm = NULL;
	ci->ci_key = NULL;
	ci->ci_key_len = 0;
	ci->ci_key_index = -1; // inited as invalid
	if (memcpy_s(ci->ci_master_key, sizeof(ci->ci_master_key),
		ctx->master_key_descriptor,
		sizeof(ctx->master_key_descriptor)) != EOK) {
		put_crypt_info(ci);
		return ERR_PTR(-EINVAL);
	}
	err = determine_cipher_type(ci, inode, cipher_str, keysize);
	if (err != 0) {
		pr_err("hwdps ino %lu cipher type fail\n", inode->i_ino);
		put_crypt_info(ci);
		return ERR_PTR(err);
	}
	return ci;
}

static int hwdps_do_set_cipher(struct inode *inode, const char *cipher_str,
	secondary_buffer_t fek_buffer, int keysize, struct fscrypt_info *ci)
{
	int err;
	struct crypto_skcipher *ctfm = NULL;

	ctfm = crypto_alloc_skcipher(cipher_str, 0, 0); // 0 as default value
	if (!ctfm || IS_ERR(ctfm)) {
		err = ctfm ? PTR_ERR(ctfm) : -ENOMEM;
		pr_err("hwdps ino %lu alloc ctfm err %d\n", inode->i_ino, err);
		return err;
	}
	ci->ci_ctfm = ctfm;
	crypto_skcipher_clear_flags(ctfm, ~0);
	crypto_skcipher_set_flags(ctfm, CRYPTO_TFM_REQ_WEAK_KEY);
	err = crypto_skcipher_setkey(ctfm, *fek_buffer.data, keysize);
	if (err != 0) {
		pr_err("hwdps ino %lu setkey fail\n", inode->i_ino);
		return err;
	}
	if (S_ISREG(inode->i_mode) && inode->i_sb->s_cop->is_inline_encrypted &&
		inode->i_sb->s_cop->is_inline_encrypted(inode)) {
		ci->ci_key = kzalloc(FS_MAX_KEY_SIZE, GFP_NOFS);
		if (!ci->ci_key)
			return -ENOMEM;
		ci->ci_key_len = *fek_buffer.len;
		if (memcpy_s(ci->ci_key, FS_MAX_KEY_SIZE,
			*fek_buffer.data, *fek_buffer.len) != EOK)
			return -EINVAL;
	}
	if (S_ISREG(inode->i_mode) &&
		(ci->ci_data_mode == FS_ENCRYPTION_MODE_AES_128_CBC)) {
		err = init_essiv_generator(ci, *fek_buffer.data, keysize);
		if (err != 0) {
			pr_err("hwdps ino %lu alloc essiv err %d\n",
				inode->i_ino, err);
			return err;
		}
	}
	/* cached kmem may have dirty data */
	ci->ci_hw_enc_flag = (u8)(HWDPS_XATTR_ENABLE_FLAG_NEW);
#ifdef CONFIG_SCSI_UFS_ENHANCED_INLINE_CRYPTO_V2
	if (inode->i_crypt_info && (inode->i_crypt_info->ci_key_index >= 0) &&
	    	(inode->i_crypt_info->ci_key_index <= MAX_HISI_KEY_INDEX))
		ci->ci_key_index = inode->i_crypt_info->ci_key_index;
	else
		ci->ci_key_index = hwdps_get_key_index(ci->ci_master_key);
	if ((ci->ci_key_index < 0) || (ci->ci_key_index > MAX_HISI_KEY_INDEX)) {
		pr_err("ci_key_index: %d\n", ci->ci_key_index);
		return -EINVAL;
	}
#endif
	return 0;
}

static int hwdps_check_support_and_get_attr(struct inode *inode, u32 *flags,
	buffer_t *encoded_wfek)
{
	int err;

	err = hwdps_check_support(inode, flags);
	if (err != 0)
		return err;

	if (*flags == HWDPS_XATTR_ENABLE_FLAG) {
		encoded_wfek->data = hwdps_do_get_attr(inode,
			HWDPS_ENCODE_WFEK_SIZE_OLD, *flags);
		encoded_wfek->len = HWDPS_ENCODE_WFEK_SIZE_OLD;
	} else {
		encoded_wfek->data = hwdps_do_get_attr(inode,
			HWDPS_ENCODED_WFEK_SIZE, *flags);
		encoded_wfek->len = HWDPS_ENCODED_WFEK_SIZE;
	}
	if (!encoded_wfek->data)
		return -ENOMEM;
	return 0;
}

/*
 * mainly copied from fscrypt_get_encryption_info
 *
 * Return:
 *  o -EAGAIN: file is not protected by HWDPS
 *  o -EPERM: no permission to open the file
 *  o 0: SUCC
 *  o other errno: other errors
 */
int hwdps_get_context(struct inode *inode)
{
	int err;
	int keysize;
	struct fscrypt_context ctx;
	struct fscrypt_info *ci = NULL;
	const char *cipher_str = NULL;
	buffer_t encoded_wfek = { NULL, 0 };
	uint8_t *fek = NULL;
	uint32_t fek_len = 0;
	uint32_t flags = 0;
	secondary_buffer_t fek_buffer = { &fek, &fek_len };

	err = hwdps_check_support_and_get_attr(inode, &flags, &encoded_wfek);
	if (err != 0)
		return err;
	if (inode->i_crypt_info) {
		err = hwdps_has_access(inode, &encoded_wfek, flags);
		goto free_encoded_wfek; // return anyway
	}
	err = hwdps_do_get_context(inode, &ctx);
	if (err != 0)
		goto free_encoded_wfek;
	ci = hwdps_get_fscrypt_info(&ctx, inode, &cipher_str, &keysize);
	if (IS_ERR(ci)) {
		err = PTR_ERR(ci);
		goto free_encoded_wfek;
	}
	err = hwdps_get_fek(ctx.master_key_descriptor, inode, &encoded_wfek,
		&fek_buffer, flags);
	if (err != 0)
		goto free_fek;
	err = hwdps_do_set_cipher(inode, cipher_str, fek_buffer, keysize, ci);
	if (err != 0)
		goto free_fek;
	err = fscrypt_get_metadata(inode, ci);
	if (err && err != -EOPNOTSUPP)
		goto free_fek;
	else
		err = 0;
	if (cmpxchg(&inode->i_crypt_info, NULL, ci) == NULL)
		ci = NULL;
free_fek:
	kzfree(fek);
	if (err == -ENOKEY)
		err = 0;
	put_crypt_info(ci);
free_encoded_wfek:
	kfree(encoded_wfek.data);
	return err;
}
EXPORT_SYMBOL(hwdps_get_context); //lint !e580
#endif

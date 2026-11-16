/* SPDX-License-Identifier: GPL-2.0 */
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef uint8_t u8;
#define __packed __attribute__((packed))
#define FS_KEY_DESCRIPTOR_SIZE 8
#define FS_KEY_DERIVATION_NONCE_SIZE 64
#define FS_KEY_DERIVATION_IV_SIZE 16
#define FS_KEY_DERIVATION_CIPHER_SIZE 80
#define FSCRYPT_SET_CONTEXT_MAX_SIZE 108
#define FS_ENCRYPTION_CONTEXT_FORMAT_V2 2
#define FS_POLICY_FLAGS_VALID 0xff
#define BUILD_BUG_ON(condition) _Static_assert(!(condition), "BUILD_BUG_ON")
#define READ_ONCE(value) (value)
#define WARN_ON_ONCE(condition) (!!(condition))

enum fscrypt_ce_purpose { POLICY_WRAP, FILE_UNWRAP, SDP_CE_SOURCE, CHILD_WRAP };
enum fscrypt_context_origin {
	FSCRYPT_CTX_OWNED_POLICY = 0,
	FSCRYPT_CTX_BORROWED_INHERIT = 1,
};
enum fscrypt_context_phase {
	FSCRYPT_CTX_PREPARED = 0,
	FSCRYPT_CTX_INSTALLED = 1,
};

struct inode;
struct fscrypt_context_op;
struct fscrypt_operations {
	int (*set_context)(struct inode *, const void *, size_t, void *);
	int (*prepare_context)(struct inode *, enum fscrypt_context_origin,
			       void *, struct fscrypt_context_op **);
	int (*set_context_prepared)(struct inode *, const void *, size_t,
				    struct fscrypt_context_op *);
	int (*finish_context)(struct inode *, struct fscrypt_context_op *, int,
			      bool *);
};
struct super_block { const struct fscrypt_operations *s_cop; };
struct fscrypt_context_op {
	const struct fscrypt_operations *cop;
	struct inode *inode;
	enum fscrypt_context_origin origin;
	enum fscrypt_context_phase phase;
	void *fs_data;
	bool owns_fs_data;
	int *retry_count;
};
struct fscrypt_info {
	u8 ci_data_mode;
	u8 ci_filename_mode;
	u8 ci_flags;
	u8 ci_master_key[FS_KEY_DESCRIPTOR_SIZE];
};
struct inode {
	struct super_block *i_sb;
	struct fscrypt_info *i_crypt_info;
};
struct fscrypt_policy {
	u8 version;
	u8 contents_encryption_mode;
	u8 filenames_encryption_mode;
	u8 flags;
	u8 master_key_descriptor[FS_KEY_DESCRIPTOR_SIZE];
};
struct fscrypt_context {
	u8 format;
	u8 contents_encryption_mode;
	u8 filenames_encryption_mode;
	u8 flags;
	u8 master_key_descriptor[FS_KEY_DESCRIPTOR_SIZE];
	u8 nonce[FS_KEY_DERIVATION_CIPHER_SIZE];
	u8 iv[FS_KEY_DERIVATION_IV_SIZE];
} __packed;
struct fscrypt_ce_scope {
	struct super_block *sb;
	u8 descriptor[FS_KEY_DESCRIPTOR_SIZE];
	enum fscrypt_ce_purpose purpose;
};

static int opens, scope_puts, crypts, wipes, get_infos, cached_opens, preloads;
static int prepares, installs, finishes, legacy_sets, event_id;
static int install_answers[2], finish_answers[2];
static bool finish_retries[2];
static enum fscrypt_context_origin seen_origin;
static void *seen_fs_data;
static struct fscrypt_context seen_ctx;
static struct fscrypt_context_op fixture_op;
static struct fscrypt_ce_scope fixture_scope;
static struct fscrypt_info parent_ci;

static bool fscrypt_valid_enc_modes(u8 contents, u8 filenames)
{
	return contents != 0 && filenames != 0;
}

static int fscrypt_generate_metadata_nonce(u8 *nonce, struct inode *inode,
					   size_t len)
{
	(void)inode;
	memset(nonce, 0x11, len);
	return 0;
}

static void get_random_bytes(void *buffer, size_t len)
{
	memset(buffer, 0x22, len);
}

static void memzero_explicit(void *buffer, size_t len)
{
	memset(buffer, 0, len);
	wipes++;
}

static int fscrypt_ce_scope_open(struct inode *inode, const u8 *descriptor,
				enum fscrypt_ce_purpose purpose,
				struct fscrypt_ce_scope **out)
{
	opens++;
	fixture_scope.sb = inode->i_sb;
	memcpy(fixture_scope.descriptor, descriptor, FS_KEY_DESCRIPTOR_SIZE);
	fixture_scope.purpose = purpose;
	*out = &fixture_scope;
	event_id = 1;
	return 0;
}

static int fscrypt_ce_scope_open_cached(struct inode *inode,
				       enum fscrypt_ce_purpose purpose,
				       struct fscrypt_ce_scope **out)
{
	cached_opens++;
	return fscrypt_ce_scope_open(inode, parent_ci.ci_master_key, purpose, out);
}

static bool fscrypt_ce_scope_matches(const struct fscrypt_ce_scope *scope,
				    const struct inode *inode,
				    const u8 *descriptor,
				    enum fscrypt_ce_purpose purpose)
{
	return scope && scope->sb == inode->i_sb && scope->purpose == purpose &&
	       !memcmp(scope->descriptor, descriptor, FS_KEY_DESCRIPTOR_SIZE);
}

static int fscrypt_ce_scope_crypt(struct fscrypt_ce_scope *scope,
				 const u8 *src, u8 *dst, const u8 *iv,
				 bool encrypt)
{
	(void)scope;
	(void)iv;
	(void)encrypt;
	assert(event_id == 1 || seen_origin == FSCRYPT_CTX_BORROWED_INHERIT);
	memcpy(dst, src, FS_KEY_DERIVATION_NONCE_SIZE);
	memset(dst + FS_KEY_DERIVATION_NONCE_SIZE, 0x33,
	       FS_KEY_DERIVATION_CIPHER_SIZE - FS_KEY_DERIVATION_NONCE_SIZE);
	crypts++;
	event_id = 2;
	return 0;
}

static void fscrypt_ce_scope_put(struct fscrypt_ce_scope *scope)
{
	if (scope) {
		scope_puts++;
		event_id = 3;
	}
}

static int fscrypt_get_encryption_info(struct inode *inode)
{
	get_infos++;
	return inode->i_crypt_info ? 0 : -ENOKEY;
}

static int fscrypt_get_encryption_info_with_scope(
		struct inode *inode, const struct fscrypt_context *ctx,
		struct fscrypt_ce_scope *scope)
{
	assert(inode != NULL);
	assert(fscrypt_ce_scope_matches(scope, inode,
			ctx->master_key_descriptor, CHILD_WRAP));
	seen_ctx = *ctx;
	preloads++;
	event_id = 7;
	return 0;
}

static int fixture_prepare(struct inode *inode,
			   enum fscrypt_context_origin origin, void *fs_data,
			   struct fscrypt_context_op **out)
{
	if (origin == FSCRYPT_CTX_OWNED_POLICY) {
		assert(event_id == 3 || event_id == 6);
		assert(wipes >= 2);
	}
	memset(&fixture_op, 0, sizeof(fixture_op));
	fixture_op.cop = inode->i_sb->s_cop;
	fixture_op.inode = inode;
	fixture_op.origin = origin;
	fixture_op.phase = FSCRYPT_CTX_PREPARED;
	fixture_op.fs_data = fs_data;
	fixture_op.owns_fs_data = origin == FSCRYPT_CTX_OWNED_POLICY;
	seen_origin = origin;
	seen_fs_data = fs_data;
	prepares++;
	event_id = 4;
	*out = &fixture_op;
	return 0;
}

static int fixture_install(struct inode *inode, const void *ctx, size_t len,
			   struct fscrypt_context_op *op)
{
	assert(op == &fixture_op && op->inode == inode);
	assert(len == sizeof(struct fscrypt_context));
	assert(event_id == 4);
	seen_ctx = *(const struct fscrypt_context *)ctx;
	op->phase = FSCRYPT_CTX_INSTALLED;
	event_id = 5;
	return install_answers[installs++];
}

static int fixture_finish(struct inode *inode, struct fscrypt_context_op *op,
			  int install_error, bool *retry)
{
	int index = finishes++;

	assert(op == &fixture_op && op->inode == inode);
	assert(event_id == 5 || event_id == 7);
	assert(install_error == install_answers[index] || event_id == 7);
	*retry = finish_retries[index];
	event_id = 6;
	return finish_answers[index];
}

static int fixture_legacy_set(struct inode *inode, const void *ctx, size_t len,
			      void *fs_data)
{
	(void)inode;
	(void)fs_data;
	assert(len == sizeof(struct fscrypt_context));
	seen_ctx = *(const struct fscrypt_context *)ctx;
	legacy_sets++;
	return 0;
}

#include "subject_policy.h"

static void reset_fixture(void)
{
	opens = scope_puts = crypts = wipes = get_infos = cached_opens = 0;
	preloads = 0;
	prepares = installs = finishes = legacy_sets = event_id = 0;
	memset(install_answers, 0, sizeof(install_answers));
	memset(finish_answers, 0, sizeof(finish_answers));
	memset(finish_retries, 0, sizeof(finish_retries));
	memset(&seen_ctx, 0, sizeof(seen_ctx));
	seen_fs_data = NULL;
}

int main(int argc, char **argv)
{
	struct fscrypt_operations ops = {
		.set_context = fixture_legacy_set,
		.prepare_context = fixture_prepare,
		.set_context_prepared = fixture_install,
		.finish_context = fixture_finish,
	};
	struct super_block sb = { .s_cop = &ops };
	struct inode parent = { .i_sb = &sb, .i_crypt_info = &parent_ci };
	struct inode child = { .i_sb = &sb };
	struct fscrypt_policy policy = {
		.contents_encryption_mode = 1,
		.filenames_encryption_mode = 2,
		.flags = 0,
		.master_key_descriptor = { 1, 2, 3, 4, 5, 6, 7, 8 },
	};
	int fs_cookie;

	assert(argc == 2);
	reset_fixture();
	memset(&parent_ci, 0, sizeof(parent_ci));
	parent_ci.ci_data_mode = 1;
	parent_ci.ci_filename_mode = 2;
	memcpy(parent_ci.ci_master_key, policy.master_key_descriptor,
	       FS_KEY_DESCRIPTOR_SIZE);

	if (!strcmp(argv[1], "policy-owned-order")) {
		install_answers[0] = -ENOSPC;
		finish_retries[0] = true;
		finish_answers[0] = -ENOSPC;
		assert(create_encryption_context_from_policy(&child, &policy) == 0);
		assert(opens == 1 && scope_puts == 1 && crypts == 1 && wipes == 2);
		assert(prepares == 2 && installs == 2 && finishes == 2);
		assert(legacy_sets == 0);
	} else if (!strcmp(argv[1], "legacy-set-context-fallback")) {
		ops.finish_context = NULL;
		assert(create_encryption_context_from_policy(&child, &policy) == 0);
		assert(legacy_sets == 1 && prepares == 0 && installs == 0 &&
		       finishes == 0);
	} else if (!strcmp(argv[1], "inherit-borrowed-private-preload")) {
		fixture_scope.sb = &sb;
		fixture_scope.purpose = CHILD_WRAP;
		memcpy(fixture_scope.descriptor, parent_ci.ci_master_key,
		       FS_KEY_DESCRIPTOR_SIZE);
		seen_origin = FSCRYPT_CTX_BORROWED_INHERIT;
		assert(fscrypt_inherit_context_prepared(&parent, &child, &fs_cookie,
						  &fixture_scope, true) == 0);
		assert(get_infos == 0 && cached_opens == 0 && opens == 0 &&
		       scope_puts == 0);
		assert(prepares == 1 && installs == 1 && finishes == 1 && preloads == 1);
		assert(seen_origin == FSCRYPT_CTX_BORROWED_INHERIT);
		assert(seen_fs_data == &fs_cookie);
		assert(!memcmp(seen_ctx.master_key_descriptor,
			       parent_ci.ci_master_key, FS_KEY_DESCRIPTOR_SIZE));
	} else {
		return 2;
	}
	printf("PASS %s\n", argv[1]);
	return 0;
}

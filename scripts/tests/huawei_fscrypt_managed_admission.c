// SPDX-License-Identifier: GPL-2.0
#include "huawei_fscrypt_ce_scope_host.h"
#include "crypto-subject.h"
#include <pthread.h>

static int set_sdp_calls;
static int get_sdp_calls;
static int set_context_calls;
static int f2fs_sdp_keyring_checks;
static int hmfs_sdp_keyring_checks;
static int hwdps_attr_get_calls;
static int hwdps_attr_set_calls;
static int hwdps_flag_set_calls;
static int hwdps_create_fek_calls;
static int hwdps_get_fek_calls;
static int hwdps_origin_fek_calls;
static int hwdps_access_calls;
static bool host_hwdps_attr_present;
static u32 host_sdp_flags;
static struct f2fs_sdp_fscrypt_context host_sdp_context;

static int host_get_sdp_context(struct inode *inode, void *data, size_t size,
		void *fs_data)
{
	CHECK(size == sizeof(host_sdp_context));
	memcpy(data, &host_sdp_context, size);
	get_sdp_calls++;
	return sizeof(host_sdp_context);
}

static int host_set_sdp_context(struct inode *inode, const void *data,
		size_t size, void *fs_data)
{
	CHECK(size == sizeof(host_sdp_context));
	set_sdp_calls++;
	return 0;
}

static int host_get_sdp_flags(struct inode *inode, void *fs_data, u32 *flags)
{
	*flags = host_sdp_flags;
	return 0;
}

static int host_set_sdp_flags(struct inode *inode, void *fs_data, u32 *flags)
{
	host_sdp_flags = *flags;
	return 0;
}

static int f2fs_inode_set_sdp_encryption_flags(struct inode *inode,
		void *fs_data, u32 flags)
{
	host_sdp_flags |= flags;
	return 0;
}

static int hmfs_inode_set_sdp_encryption_flags(struct inode *inode,
		void *fs_data, u32 flags)
{
	return f2fs_inode_set_sdp_encryption_flags(inode, fs_data, flags);
}

static int f2fs_inode_get_sdp_encrypt_flags(struct inode *inode,
		void *fs_data, u32 *flags)
{
	return host_get_sdp_flags(inode, fs_data, flags);
}

static int hmfs_inode_get_sdp_encrypt_flags(struct inode *inode,
		void *fs_data, u32 *flags)
{
	return host_get_sdp_flags(inode, fs_data, flags);
}

static bool f2fs_inode_is_config_encryption(struct inode *inode)
{
	return inode->i_sb->s_cop->get_context &&
		inode->i_sb->s_cop->get_context(inode, NULL, 0) > 0;
}

static int f2fs_get_ece_crypt_info_from_context(struct inode *inode,
		struct fscrypt_context *ctx,
		struct f2fs_sdp_fscrypt_context *sdp,
		struct fscrypt_info *ci, int inherit, void *fs_data)
{
	return 0;
}

static int f2fs_get_sece_crypt_info_from_context(struct inode *inode,
		struct fscrypt_context *ctx,
		struct f2fs_sdp_fscrypt_context *sdp,
		struct fscrypt_info *ci, int inherit, void *fs_data)
{
	return 0;
}

static int fscrypt_new_ece_metadata(struct inode *inode,
		struct fscrypt_info *ci, void *fs_data)
{
	return 0;
}

static int fscrypt_new_sece_metadata(struct inode *inode,
		struct fscrypt_info *ci, void *fs_data)
{
	return 0;
}

s32 hwdps_check_support(struct inode *inode, uint32_t *flags);

static uint8_t *hwdps_do_get_attr(struct inode *inode, size_t size, u32 flags)
{
	hwdps_attr_get_calls++;
	return kzalloc(size, GFP_NOFS);
}

static hwdps_result_t hwdps_has_access(struct inode *inode,
		const buffer_t *encoded_wfek, s32 flags)
{
	hwdps_access_calls++;
	return 0;
}

static struct fscrypt_info *hwdps_get_fscrypt_info(struct fscrypt_context *ctx,
		struct inode *inode, const char **cipher_str, int *keysize)
{
	struct fscrypt_info *ci;

	ci = kmem_cache_alloc(fscrypt_info_cachep, GFP_NOFS);
	if (!ci)
		return ERR_PTR(-ENOMEM);
	memset(ci, 0, sizeof(*ci));
	fscrypt_mk_init_owner(&ci->ci_owner);
	memcpy(ci->ci_master_key, ctx->master_key_descriptor,
	       FS_KEY_DESCRIPTOR_SIZE);
	ci->ci_data_mode = ctx->contents_encryption_mode;
	ci->ci_filename_mode = ctx->filenames_encryption_mode;
	*cipher_str = "xts(aes)";
	*keysize = 64;
	return ci;
}

static hwdps_result_t hwdps_get_fek(const u8 *desc, struct inode *inode,
		const buffer_t *encoded_wfek, secondary_buffer_t *fek, u32 flags)
{
	hwdps_get_fek_calls++;
	return -ENOKEY;
}

static int hwdps_do_set_cipher(struct inode *inode, const char *cipher_str,
		secondary_buffer_t fek_buffer, int keysize,
		struct fscrypt_info *ci)
{
	return 0;
}

static hwdps_result_t hwdps_update_fek(const u8 *desc,
		const buffer_t *encoded_wfek, secondary_buffer_t *fek,
		uid_t new_uid, uid_t old_uid)
{
	return 0;
}

static hwdps_result_t hwdps_get_fek_from_origin(const u8 *desc,
		struct inode *inode, secondary_buffer_t *encoded_wfek)
{
	hwdps_origin_fek_calls++;
	*encoded_wfek->data = kzalloc(HWDPS_ENCODED_WFEK_SIZE, GFP_NOFS);
	*encoded_wfek->len = HWDPS_ENCODED_WFEK_SIZE;
	return 0;
}

static int f2fs_set_hwdps_enable_flags(struct inode *inode, void *fs_data)
{
	hwdps_flag_set_calls++;
	return 0;
}

static hwdps_result_t hwdps_create_fek(const u8 *desc, struct inode *inode,
		const struct dentry *dentry, fek_efek_t *fek_efek,
		u32 parent_flags)
{
	hwdps_create_fek_calls++;
	return 0;
}

static void get_create_task_uid(encrypt_id *id)
{
	memset(id, 0, sizeof(*id));
}

static void hiview_for_hwdps(int type, hwdps_result_t result,
		const encrypt_id *id)
{
}

static int hash_generate_mac(const buffer_t *tag, const buffer_t *message,
		buffer_t *output)
{
	memset(output->data, 0xa7, output->len);
	return 0;
}

static int hwdps_check_support_and_get_attr(struct inode *inode, u32 *flags,
		buffer_t *encoded_wfek)
{
	int err = hwdps_check_support(inode, flags);

	if (err)
		return err;
	encoded_wfek->len = HWDPS_ENCODED_WFEK_SIZE;
	encoded_wfek->data = hwdps_do_get_attr(inode, encoded_wfek->len,
						     *flags);
	return encoded_wfek->data ? 0 : -ENOMEM;
}

int f2fs_change_to_sdp_crypto(struct inode *inode, void *fs_data);
int hmfs_change_to_sdp_crypto(struct inode *inode, void *fs_data);

#include "subject.h"

static struct fscrypt_context managed_context;
static bool inline_encrypted = true;

static int load_managed_context(struct inode *inode, void *data, size_t size)
{
	if (!data && !size)
		return sizeof(managed_context);
	CHECK(size == sizeof(managed_context));
	memcpy(data, &managed_context, size);
	return sizeof(managed_context);
}

static int save_managed_context(struct inode *inode, const void *data,
		size_t size, void *fs_data)
{
	CHECK(size == sizeof(managed_context));
	set_context_calls++;
	return 0;
}

static bool managed_is_inline(struct inode *inode)
{
	return inline_encrypted;
}

static int host_get_hwdps_flags(struct inode *inode, void *fs_data, u32 *flags)
{
	*flags = host_sdp_flags;
	return 0;
}

static int host_set_hwdps_flags(struct inode *inode, void *fs_data, u32 *flags)
{
	host_sdp_flags = *flags;
	hwdps_flag_set_calls++;
	return 0;
}

static int host_get_hwdps_attr(struct inode *inode, void *data, size_t size,
		u32 flags, void *fs_data)
{
	hwdps_attr_get_calls++;
	if (!host_hwdps_attr_present)
		return -ENODATA;
	memset(data, 0x4d, size);
	return size;
}

static int host_set_hwdps_attr(struct inode *inode, const void *data,
		size_t size, void *fs_data)
{
	hwdps_attr_set_calls++;
	return 0;
}

static struct operations managed_ops = {
	.key_prefix = "f2fs:",
	.set_context = save_managed_context,
	.get_context = load_managed_context,
	.is_inline_encrypted = managed_is_inline,
	.is_encrypted = managed_is_inline,
	.get_hwdps_flags = host_get_hwdps_flags,
	.set_hwdps_flags = host_set_hwdps_flags,
	.get_hwdps_attr = host_get_hwdps_attr,
	.set_hwdps_attr = host_set_hwdps_attr,
	.update_hwdps_attr = host_set_hwdps_attr,
};
static const struct f2fs_sdp_fscrypt_operations managed_sdp_ops = {
	.get_sdp_context = host_get_sdp_context,
	.set_sdp_context = host_set_sdp_context,
	.update_sdp_context = host_set_sdp_context,
	.update_context = save_managed_context,
	.get_sdp_encrypt_flags = host_get_sdp_flags,
	.set_sdp_encrypt_flags = host_set_sdp_flags,
};
static struct f2fs_sb_info managed_sbi = {
	.s_sdp_cop = &managed_sdp_ops,
	.encryption_ver = INLINE_CRYPTO_V2,
	.sdp_enabled = true,
};
static struct f2fs_inode_info managed_fi;
static struct f2fs_inode_info child_fi;
static struct f2fs_inode_info second_child_fi;
static struct file_system_type managed_type = { .name = "managed-host" };
static struct super_block managed_sb = {
	.s_cop = &managed_ops,
	.s_type = &managed_type,
	.s_fs_info = &managed_sbi,
};
static struct inode managed_inode = {
	.i_sb = &managed_sb,
	.i_ino = 101,
	.i_mode = S_IFREG,
	.private = &managed_fi,
	.i_uid = { .val = 1000 },
};
static struct inode sdp_child = {
	.i_sb = &managed_sb,
	.i_ino = 102,
	.i_mode = S_IFREG,
	.private = &child_fi,
	.i_uid = { .val = 1000 },
};
static struct inode second_child = {
	.i_sb = &managed_sb,
	.i_ino = 103,
	.i_mode = S_IFREG,
	.private = &second_child_fi,
	.i_uid = { .val = 1000 },
};
static struct file managed_file = { .inode = &managed_inode };
static struct dentry managed_dentry;
static struct user_key_payload managed_payload;
static struct key managed_legacy_key;
static struct fscrypt_master_key managed_mk;
static const u8 managed_desc[FS_KEY_DESCRIPTOR_SIZE] = {
	0x10, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87,
};
static const u8 legacy_desc[FS_KEY_DESCRIPTOR_SIZE] = {
	0x91, 0x82, 0x73, 0x64, 0x55, 0x46, 0x37, 0x28,
};

static void reset_case(unsigned int legacy_size, int reg_error, bool present)
{
	struct fscrypt_key *legacy = (void *)managed_payload.data;
	unsigned int i;

	memset(&managed_payload, 0, sizeof(managed_payload));
	memset(&managed_legacy_key, 0, sizeof(managed_legacy_key));
	managed_payload.datalen = sizeof(*legacy);
	legacy->size = legacy_size;
	for (i = 0; i < sizeof(legacy->raw); i++)
		legacy->raw[i] = (u8)(0x80 + i);
	legacy->raw[63] = 29;
	managed_legacy_key.type = &key_type_logon;
	managed_legacy_key.payload = &managed_payload;
	lookup_key = &managed_legacy_key;
	alternate_key = NULL;
	primary_error = 0;
	alternate_error = -ENOKEY;
	lookups = 0;
	registry_sb = &managed_sb;
	registry_mk = &managed_mk;
	memcpy(registry_descriptor, managed_desc, sizeof(registry_descriptor));
	registry_error = reg_error;
	registry_lookups = 0;
	registry_allow_tombstone_lookup = false;
	memset(&managed_mk, 0, sizeof(managed_mk));
	managed_mk.refs = 1;
	managed_mk.generation = 1;
	managed_mk.present = present;
	for (i = 0; i < sizeof(managed_mk.raw); i++)
		managed_mk.raw[i] = (u8)(i + 1);
	managed_mk.raw[63] = 31;
	managed_inode.i_crypt_info = NULL;
	fail_kmalloc = 0;
	fail_tfm = 0;
	fail_setkey = 0;
	fail_request = 0;
	allocations = 0;
	frees = 0;
	wipes = 0;
	material_wipes = 0;
	scope_wipes = 0;
	secret_wipes = 0;
	key_readers = 0;
	tfm_live = 0;
	skcipher_live = 0;
	requests = 0;
	metadata_calls = 0;
	metadata_result = 0;
	inline_encrypted = true;
	set_sdp_calls = 0;
	get_sdp_calls = 0;
	set_context_calls = 0;
	f2fs_sdp_keyring_checks = 0;
	hmfs_sdp_keyring_checks = 0;
	hwdps_attr_get_calls = 0;
	hwdps_attr_set_calls = 0;
	hwdps_flag_set_calls = 0;
	hwdps_create_fek_calls = 0;
	hwdps_get_fek_calls = 0;
	hwdps_origin_fek_calls = 0;
	hwdps_access_calls = 0;
	host_hwdps_attr_present = false;
	inode_lock_depth = 0;
	mount_write_depth = 0;
	host_sdp_flags = 0;
	memset(&host_sdp_context, 0, sizeof(host_sdp_context));
	host_sdp_context.format = FS_ENCRYPTION_CONTEXT_FORMAT_V2;
	host_sdp_context.sdpclass = FSCRYPT_SDP_ECE_CLASS;
	host_sdp_context.contents_encryption_mode =
		FS_ENCRYPTION_MODE_AES_256_XTS;
	host_sdp_context.filenames_encryption_mode =
		FS_ENCRYPTION_MODE_AES_256_CTS;
	memcpy(host_sdp_context.master_key_descriptor, managed_desc,
	       sizeof(host_sdp_context.master_key_descriptor));
	memset(&managed_context, 0, sizeof(managed_context));
	managed_context.format = FS_ENCRYPTION_CONTEXT_FORMAT_V2;
	managed_context.contents_encryption_mode =
		FS_ENCRYPTION_MODE_AES_256_XTS;
	managed_context.filenames_encryption_mode =
		FS_ENCRYPTION_MODE_AES_256_CTS;
	memcpy(managed_context.master_key_descriptor, managed_desc,
	       sizeof(managed_context.master_key_descriptor));
	memset(&managed_fi, 0, sizeof(managed_fi));
	memset(&child_fi, 0, sizeof(child_fi));
	memset(&second_child_fi, 0, sizeof(second_child_fi));
	sdp_child.i_crypt_info = NULL;
	second_child.i_crypt_info = NULL;
	cp_rwsem_held = false;
	monitored_sdp_sem = &managed_fi.i_sdp_sem;
	sdp_under_cp_calls = 0;
}

static void assert_balanced(void)
{
	CHECK(managed_legacy_key.refs == 0);
	CHECK(managed_legacy_key.sem.readers == 0);
	CHECK(managed_legacy_key.sem.down == managed_legacy_key.sem.up);
	CHECK(managed_mk.refs == 1);
	CHECK(managed_mk.owners == 0);
	CHECK(managed_mk.secret_sem.readers == 0);
	CHECK(managed_mk.secret_sem.down == managed_mk.secret_sem.up);
	CHECK(key_readers == 0);
	CHECK(tfm_live == 0);
	CHECK(requests == 0);
	CHECK(allocations == frees);
}

static void prepare_sdp_payload(u32 sdpclass)
{
	struct fscrypt_sdp_key *key = (void *)managed_payload.data;

	memset(&managed_payload, 0, sizeof(managed_payload));
	managed_payload.datalen = sizeof(*key);
	key->sdpclass = sdpclass;
	key->size = FS_AES_256_GCM_KEY_SIZE;
	memset(key->raw, 0x6b, key->size);
}

static struct fscrypt_info *new_ci(void)
{
	struct fscrypt_info *ci;

	ci = kmem_cache_alloc(fscrypt_info_cachep, GFP_NOFS);
	CHECK(ci);
	memset(ci, 0, sizeof(*ci));
	fscrypt_mk_init_owner(&ci->ci_owner);
	ci->ci_key_index = -1;
	memcpy(ci->ci_master_key, managed_desc, sizeof(ci->ci_master_key));
	return ci;
}

static void prepare_context(const u8 key[FS_AES_256_GCM_KEY_SIZE])
{
	struct crypto_aead *tfm;
	u8 plain[FS_KEY_DERIVATION_CIPHER_SIZE] = { 0x37 };

	memset(&managed_context, 0, sizeof(managed_context));
	managed_context.format = FS_ENCRYPTION_CONTEXT_FORMAT_V2;
	managed_context.contents_encryption_mode = FS_ENCRYPTION_MODE_AES_256_XTS;
	managed_context.filenames_encryption_mode = FS_ENCRYPTION_MODE_AES_256_CTS;
	memcpy(managed_context.master_key_descriptor, managed_desc,
	       sizeof(managed_context.master_key_descriptor));
	memset(managed_context.iv, 0x42, sizeof(managed_context.iv));
	tfm = crypto_alloc_aead("gcm(aes)", 0, 0);
	CHECK(!IS_ERR(tfm));
	CHECK(!fscrypt_set_gcm_key(tfm, key));
	CHECK(!fscrypt_derive_gcm_key(tfm, plain, managed_context.nonce,
				      managed_context.iv, 1));
	crypto_free_aead(tfm);
}

static void test_descriptor_admission(void)
{
	int refs;

	reset_case(32, 0, true);
	refs = managed_mk.refs;
	CHECK(fscrypt_check_unmanaged_descriptor(NULL, managed_desc) == -EINVAL);
	CHECK(fscrypt_check_unmanaged_descriptor(&managed_sb, NULL) == -EINVAL);
	CHECK(fscrypt_check_unmanaged_descriptor(&managed_sb, managed_desc) ==
	      -EOPNOTSUPP);
	CHECK(managed_mk.refs == refs);
	registry_error = -ENOENT;
	CHECK(fscrypt_check_unmanaged_descriptor(&managed_sb, managed_desc) == 0);
	registry_error = -EBADMSG;
	CHECK(fscrypt_check_unmanaged_descriptor(&managed_sb, managed_desc) ==
	      -EBADMSG);
	assert_balanced();
}

static void test_managed_policy(void)
{
	struct fscrypt_ce_scope *scope = NULL;
	u8 slot = 0;

	reset_case(32, 0, true);
	CHECK(!fscrypt_ce_scope_open(&managed_inode, managed_desc, POLICY_WRAP,
				    &scope));
	CHECK(scope && scope->owner->managed);
	CHECK(!scope->owner->has_legacy_slot);
	CHECK(!scope->mk_owner.key && !scope->mk_owner.generation);
	CHECK(fscrypt_ce_scope_legacy_slot(scope, &slot) == -EOPNOTSUPP);
	CHECK(registry_lookups == 1 && lookups == 0);
	CHECK(managed_mk.secret_sem.readers == 0);
	CHECK(secret_wipes >= 1);
	fscrypt_ce_scope_put(scope);
	scope = (void *)1;
	CHECK(fscrypt_ce_scope_open(&managed_inode, managed_desc, SDP_CE_SOURCE,
				   &scope) == -EOPNOTSUPP);
	CHECK(!scope);
	assert_balanced();
}

static void test_managed_file_owner(void)
{
	struct fscrypt_ce_scope *scope = NULL;
	struct fscrypt_info *ci;

	reset_case(64, 0, true);
	CHECK(!fscrypt_ce_scope_open(&managed_inode, managed_desc, FILE_UNWRAP,
				    &scope));
	CHECK(scope->mk_owner.key == &managed_mk);
	CHECK(scope->mk_owner.generation == 1);
	CHECK(managed_mk.owners == 1);
	ci = new_ci();
	CHECK(!fscrypt_ce_scope_attach_legacy_tfm(scope, ci));
	CHECK(ci->ci_owner.key == &managed_mk);
	CHECK(!scope->mk_owner.key && !scope->mk_owner.generation);
	CHECK(ci->ci_key_index == -1);
	CHECK(fscrypt_mk_remove(&managed_mk));
	put_crypt_info(ci);
	CHECK(managed_mk.owners == 0);
	fscrypt_ce_scope_put(scope);
	assert_balanced();
}

struct publication_arg {
	struct fscrypt_info *ci;
	pthread_barrier_t *barrier;
	bool won;
};

static void wait_for_publication(pthread_barrier_t *barrier)
{
	int res = pthread_barrier_wait(barrier);

	CHECK(!res || res == PTHREAD_BARRIER_SERIAL_THREAD);
}

static void *publish_candidate(void *data)
{
	struct publication_arg *arg = data;
	struct fscrypt_info *old;

	wait_for_publication(arg->barrier);
	old = cmpxchg(&managed_inode.i_crypt_info, NULL, arg->ci);
	arg->won = !old;
	if (old) {
		put_crypt_info(arg->ci);
		arg->ci = NULL;
	}
	return NULL;
}

static void test_publication_loser(void)
{
	struct fscrypt_ce_scope *first_scope = NULL;
	struct fscrypt_ce_scope *second_scope = NULL;
	struct publication_arg args[2] = { 0 };
	pthread_barrier_t barrier;
	pthread_t threads[2];
	struct fscrypt_info *winner;
	int i;

	reset_case(64, 0, true);
	CHECK(!fscrypt_ce_scope_open(&managed_inode, managed_desc, FILE_UNWRAP,
				    &first_scope));
	CHECK(!fscrypt_ce_scope_open(&managed_inode, managed_desc, FILE_UNWRAP,
				    &second_scope));
	args[0].ci = new_ci();
	args[1].ci = new_ci();
	CHECK(!fscrypt_ce_scope_attach_legacy_tfm(first_scope, args[0].ci));
	CHECK(!fscrypt_ce_scope_attach_legacy_tfm(second_scope, args[1].ci));
	CHECK(managed_mk.owners == 2);
	CHECK(!pthread_barrier_init(&barrier, NULL, 3));
	for (i = 0; i < 2; i++) {
		args[i].barrier = &barrier;
		CHECK(!pthread_create(&threads[i], NULL, publish_candidate,
				      &args[i]));
	}
	wait_for_publication(&barrier);
	for (i = 0; i < 2; i++)
		CHECK(!pthread_join(threads[i], NULL));
	CHECK(!pthread_barrier_destroy(&barrier));
	CHECK(args[0].won != args[1].won);
	winner = args[0].won ? args[0].ci : args[1].ci;
	CHECK(managed_inode.i_crypt_info == winner);
	CHECK(managed_mk.owners == 1);
	CHECK(fscrypt_mk_remove(&managed_mk));
	managed_inode.i_crypt_info = NULL;
	put_crypt_info(winner);
	CHECK(managed_mk.owners == 0);
	fscrypt_ce_scope_put(first_scope);
	fscrypt_ce_scope_put(second_scope);
	assert_balanced();
}

static struct fscrypt_info *install_managed_parent(void)
{
	struct fscrypt_ce_scope *scope = NULL;
	struct fscrypt_info *ci;

	CHECK(!fscrypt_ce_scope_open(&managed_inode, managed_desc, FILE_UNWRAP,
				    &scope));
	ci = new_ci();
	ci->ci_data_mode = FS_ENCRYPTION_MODE_AES_256_XTS;
	ci->ci_filename_mode = FS_ENCRYPTION_MODE_AES_256_CTS;
	CHECK(!fscrypt_ce_scope_attach_legacy_tfm(scope, ci));
	managed_inode.i_crypt_info = ci;
	fscrypt_ce_scope_put(scope);
	return ci;
}

static void test_managed_inheritance(void)
{
	struct fscrypt_ce_scope *scope = NULL;
	struct fscrypt_info *parent_ci;

	reset_case(64, 0, true);
	inline_encrypted = false;
	parent_ci = install_managed_parent();
	CHECK(managed_mk.owners == 1);
	CHECK(!fscrypt_ce_scope_open_cached(&managed_inode, CHILD_WRAP, &scope));
	CHECK(managed_mk.owners == 2);
	CHECK(!fscrypt_inherit_context_prepared(&managed_inode, &sdp_child, NULL,
						 scope, true));
	CHECK(sdp_child.i_crypt_info);
	CHECK(sdp_child.i_crypt_info->ci_owner.key == &managed_mk);
	CHECK(sdp_child.i_crypt_info->ci_owner.generation == 1);
	CHECK(!scope->mk_owner.key);
	CHECK(managed_mk.owners == 2);
	CHECK(fscrypt_inherit_context_prepared(&managed_inode, &second_child,
					       NULL, scope, true) == -EINVAL);
	CHECK(!second_child.i_crypt_info);
	CHECK(managed_mk.owners == 2);
	CHECK(set_context_calls == 2);
	fscrypt_ce_scope_put(scope);
	fscrypt_put_encryption_info(&sdp_child);
	managed_inode.i_crypt_info = NULL;
	put_crypt_info(parent_ci);
	assert_balanced();

	reset_case(64, 0, true);
	inline_encrypted = false;
	parent_ci = install_managed_parent();
	CHECK(!fscrypt_ce_scope_open_cached(&managed_inode, CHILD_WRAP, &scope));
	CHECK(managed_mk.owners == 2);
	CHECK(!fscrypt_inherit_context_prepared(&managed_inode, &sdp_child, NULL,
						 scope, false));
	CHECK(!sdp_child.i_crypt_info);
	CHECK(managed_mk.owners == 2);
	fscrypt_ce_scope_put(scope);
	CHECK(managed_mk.owners == 1);
	managed_inode.i_crypt_info = NULL;
	put_crypt_info(parent_ci);
	assert_balanced();
}

static void test_tombstone_and_legacy_slots(void)
{
	struct fscrypt_ce_scope *scope = (void *)1;
	u8 slot = 0;

	reset_case(32, 0, false);
	registry_allow_tombstone_lookup = true;
	CHECK(fscrypt_ce_scope_open(&managed_inode, managed_desc, POLICY_WRAP,
				   &scope) == -ENOKEY);
	CHECK(!scope && lookups == 0);
	CHECK(fscrypt_ce_scope_open(&managed_inode, managed_desc, FILE_UNWRAP,
				   &scope) == -ENOKEY);
	CHECK(!scope && lookups == 0);
	CHECK(fscrypt_ce_scope_open(&managed_inode, managed_desc, SDP_CE_SOURCE,
				   &scope) == -EOPNOTSUPP);
	CHECK(!scope && lookups == 0);
	assert_balanced();

	reset_case(32, -ENOENT, false);
	CHECK(!fscrypt_ce_scope_open(&managed_inode, managed_desc, FILE_UNWRAP,
				    &scope));
	CHECK(!scope->owner->managed && scope->owner->has_legacy_slot);
	CHECK(!fscrypt_ce_scope_legacy_slot(scope, &slot) && slot == 29);
	fscrypt_ce_scope_put(scope);
	assert_balanced();

	reset_case(64, -ENOENT, false);
	CHECK(!fscrypt_ce_scope_open(&managed_inode, managed_desc, FILE_UNWRAP,
				    &scope));
	CHECK(!scope->owner->managed && !scope->owner->has_legacy_slot);
	CHECK(fscrypt_ce_scope_legacy_slot(scope, &slot) == -EOPNOTSUPP);
	fscrypt_ce_scope_put(scope);
	assert_balanced();
}

static void test_cached_retirement(void)
{
	struct fscrypt_ce_scope *scope = NULL;
	struct fscrypt_info *old_ci;
	struct fscrypt_info *new_info;
	u8 raw[64];

	reset_case(64, 0, true);
	memcpy(raw, managed_mk.raw, sizeof(raw));
	CHECK(!fscrypt_ce_scope_open(&managed_inode, managed_desc, FILE_UNWRAP,
				    &scope));
	old_ci = new_ci();
	CHECK(!fscrypt_ce_scope_attach_legacy_tfm(scope, old_ci));
	managed_inode.i_crypt_info = old_ci;
	fscrypt_ce_scope_put(scope);
	scope = NULL;
	CHECK(!fscrypt_ce_scope_open_cached(&managed_inode, CHILD_WRAP, &scope));
	CHECK(scope->mk_owner.generation == 1);
	fscrypt_ce_scope_put(scope);
	scope = NULL;
	CHECK(fscrypt_mk_remove(&managed_mk));
	CHECK(fscrypt_ce_scope_open_cached(&managed_inode, CHILD_WRAP, &scope) ==
	      -ENOKEY);
	CHECK(!scope);
	CHECK(!fscrypt_mk_add(&managed_mk, raw, sizeof(raw)));
	CHECK(managed_mk.generation == 2);
	CHECK(fscrypt_ce_scope_open_cached(&managed_inode, CHILD_WRAP, &scope) ==
	      -ENOKEY);
	CHECK(!scope);
	managed_inode.i_crypt_info = NULL;
	put_crypt_info(old_ci);
	CHECK(!fscrypt_ce_scope_open(&managed_inode, managed_desc, FILE_UNWRAP,
				    &scope));
	new_info = new_ci();
	CHECK(!fscrypt_ce_scope_attach_legacy_tfm(scope, new_info));
	CHECK(new_info->ci_owner.generation == 2);
	managed_inode.i_crypt_info = new_info;
	fscrypt_ce_scope_put(scope);
	scope = NULL;
	CHECK(!fscrypt_ce_scope_open_cached(&managed_inode, CHILD_WRAP, &scope));
	CHECK(scope->mk_owner.generation == 2);
	fscrypt_ce_scope_put(scope);
	managed_inode.i_crypt_info = NULL;
	put_crypt_info(new_info);
	assert_balanced();
}

static void test_inline_keyindex(void)
{
#ifdef CONFIG_SCSI_UFS_ENHANCED_INLINE_CRYPTO_V2
	struct fscrypt_key *legacy;

	reset_case(64, 0, true);
	prepare_context(managed_mk.raw);
	CHECK(fscrypt_get_encryption_info(&managed_inode) == -EOPNOTSUPP);
	CHECK(!managed_inode.i_crypt_info && metadata_calls == 0);
	assert_balanced();

	reset_case(32, -ENOENT, false);
	legacy = (void *)managed_payload.data;
	legacy->raw[63] = 32;
	prepare_context(legacy->raw);
	CHECK(fscrypt_get_encryption_info(&managed_inode) == -EINVAL);
	CHECK(!managed_inode.i_crypt_info && metadata_calls == 0);
	assert_balanced();
#else
	reset_case(64, 0, true);
	prepare_context(managed_mk.raw);
	CHECK(!fscrypt_get_encryption_info(&managed_inode));
	CHECK(managed_inode.i_crypt_info);
	CHECK(managed_inode.i_crypt_info->ci_key_index == -1);
	CHECK(metadata_calls == 1);
	fscrypt_put_encryption_info(&managed_inode);
	assert_balanced();
#endif
}

static void test_hwdps_keyindex(void)
{
#ifdef CONFIG_SCSI_UFS_ENHANCED_INLINE_CRYPTO_V2
	reset_case(32, 0, true);
	CHECK(hwdps_get_key_index(&managed_sb, (u8 *)managed_desc) ==
	      -EOPNOTSUPP);
	CHECK(lookups == 0);
	assert_balanced();

	reset_case(32, 0, false);
	CHECK(hwdps_get_key_index(&managed_sb, (u8 *)managed_desc) ==
	      -ENOKEY);
	CHECK(lookups == 0);
	assert_balanced();

	reset_case(32, -ENOENT, false);
	CHECK(hwdps_get_key_index(&managed_sb, (u8 *)managed_desc) == 29);
	CHECK(lookups == 1);
	assert_balanced();

	reset_case(32, -ENOENT, false);
	managed_legacy_key.validation_error = -EKEYREVOKED;
	CHECK(hwdps_get_key_index(&managed_sb, (u8 *)managed_desc) ==
	      -EKEYREVOKED);
	assert_balanced();
#endif
}

static void test_sdp_keyindex(void)
{
#ifdef CONFIG_SCSI_UFS_ENHANCED_INLINE_CRYPTO_V2
	int slot = -1;

	reset_case(32, 0, true);
	CHECK(f2fs_do_get_keyindex(&managed_sb, (u8 *)managed_desc, &slot) ==
	      -EOPNOTSUPP);
	CHECK(hmfs_do_get_keyindex(&managed_sb, (u8 *)managed_desc, &slot,
				   INLINE_CRYPTO_V2) == -EOPNOTSUPP);
	CHECK(lookups == 0);
	assert_balanced();

	reset_case(32, 0, false);
	CHECK(f2fs_do_get_keyindex(&managed_sb, (u8 *)managed_desc, &slot) ==
	      -ENOKEY);
	CHECK(hmfs_do_get_keyindex(&managed_sb, (u8 *)managed_desc, &slot,
				   INLINE_CRYPTO_V2) == -ENOKEY);
	CHECK(lookups == 0);
	assert_balanced();

	reset_case(32, -ENOENT, false);
	CHECK(!f2fs_do_get_keyindex(&managed_sb, (u8 *)managed_desc, &slot));
	CHECK(slot == 29);
	CHECK(!hmfs_do_get_keyindex(&managed_sb, (u8 *)managed_desc, &slot,
				    INLINE_CRYPTO_V2));
	CHECK(slot == 29);
	assert_balanced();

	reset_case(32, -ENOENT, false);
	managed_legacy_key.validation_error = -EKEYREVOKED;
	CHECK(f2fs_do_get_keyindex(&managed_sb, (u8 *)managed_desc, &slot) ==
	      -EKEYREVOKED);
	CHECK(hmfs_do_get_keyindex(&managed_sb, (u8 *)managed_desc, &slot,
				   INLINE_CRYPTO_V2) == -EKEYREVOKED);
	assert_balanced();
#endif
}

static void test_sdp_guards_and_publication(void)
{
	struct fscrypt_sdp_policy policy = {
		.sdpclass = FSCRYPT_SDP_ECE_CLASS,
		.contents_encryption_mode = FS_ENCRYPTION_MODE_AES_256_XTS,
		.filenames_encryption_mode = FS_ENCRYPTION_MODE_AES_256_CTS,
	};
	struct fscrypt_info managed_ci = { 0 };
	struct fscrypt_info second_ci = { 0 };

	memcpy(policy.master_key_descriptor, managed_desc,
	       sizeof(policy.master_key_descriptor));
	reset_case(32, -ENOENT, true);
	memcpy(managed_context.master_key_descriptor, managed_desc,
	       sizeof(managed_context.master_key_descriptor));
	managed_ci.ci_owner.key = &managed_mk;
	managed_ci.ci_owner.generation = 1;
	managed_inode.i_crypt_info = &managed_ci;
	CHECK(f2fs_create_sdp_encryption_context_from_policy(&managed_inode,
							      &policy) ==
	      -EOPNOTSUPP);
	CHECK(hmfs_create_sdp_encryption_context_from_policy(&managed_inode,
							      &policy) ==
	      -EOPNOTSUPP);
	CHECK(set_sdp_calls == 0);
	CHECK(f2fs_change_to_sdp_crypto(&managed_inode, NULL) == -EOPNOTSUPP);
	CHECK(hmfs_change_to_sdp_crypto(&managed_inode, NULL) == -EOPNOTSUPP);
	CHECK(get_sdp_calls == 0);
	CHECK(f2fs_sdp_crypt_inherit(&managed_inode, &sdp_child, NULL, NULL) ==
	      -EOPNOTSUPP);
	CHECK(hmfs_sdp_crypt_inherit(&managed_inode, &sdp_child, NULL, NULL) ==
	      -EOPNOTSUPP);
	CHECK(set_sdp_calls == 0);

	host_sdp_flags = F2FS_XATTR_SDP_ECE_CONFIG_FLAG;
	managed_inode.i_crypt_info = NULL;
	CHECK(f2fs_publish_crypt_info(&managed_inode, &managed_ci) ==
	      -EOPNOTSUPP);
	CHECK(hmfs_publish_crypt_info(&managed_inode, &managed_ci) ==
	      -EOPNOTSUPP);
	CHECK(!managed_inode.i_crypt_info);

	host_sdp_flags = 0;
	CHECK(!f2fs_publish_crypt_info(&managed_inode, &managed_ci));
	CHECK(managed_inode.i_crypt_info == &managed_ci);
	managed_inode.i_crypt_info = NULL;
	second_ci.ci_owner.key = &managed_mk;
	second_ci.ci_owner.generation = 1;
	CHECK(!hmfs_publish_crypt_info(&managed_inode, &second_ci));
	CHECK(managed_inode.i_crypt_info == &second_ci);
	managed_inode.i_crypt_info = NULL;
	managed_ci.ci_owner.key = NULL;
	second_ci.ci_owner.key = NULL;
	assert_balanced();

	reset_case(32, 0, true);
	memcpy(managed_context.master_key_descriptor, managed_desc,
	       sizeof(managed_context.master_key_descriptor));
	CHECK(f2fs_create_sdp_encryption_context_from_policy(&managed_inode,
							      &policy) ==
	      -EOPNOTSUPP);
	CHECK(hmfs_create_sdp_encryption_context_from_policy(&managed_inode,
							      &policy) ==
	      -EOPNOTSUPP);
	CHECK(set_sdp_calls == 0);
	assert_balanced();

	reset_case(32, 0, true);
	memset(host_sdp_context.master_key_descriptor, 0x5c,
	       sizeof(host_sdp_context.master_key_descriptor));
	memcpy(managed_context.master_key_descriptor, managed_desc,
	       sizeof(managed_context.master_key_descriptor));
	CHECK(f2fs_sdp_crypt_inherit(&managed_inode, &sdp_child, NULL, NULL) ==
	      -EOPNOTSUPP);
	CHECK(hmfs_sdp_crypt_inherit(&managed_inode, &sdp_child, NULL, NULL) ==
	      -EOPNOTSUPP);
	CHECK(set_sdp_calls == 0);
	assert_balanced();
}

static void test_publish_dir_lock_order(void)
{
	struct fscrypt_info managed_ci = { 0 };
	struct fscrypt_info unmanaged_ci = { 0 };
	int down_before;

	reset_case(32, -ENOENT, true);
	managed_ci.ci_owner.key = &managed_mk;
	managed_ci.ci_owner.generation = 1;
	managed_inode.i_mode = S_IFDIR;
	cp_rwsem_held = true;
	CHECK(!f2fs_publish_crypt_info(&managed_inode, &managed_ci));
	CHECK(managed_inode.i_crypt_info == &managed_ci);
	managed_inode.i_crypt_info = NULL;
	CHECK(!hmfs_publish_crypt_info(&managed_inode, &managed_ci));
	cp_rwsem_held = false;
	CHECK(managed_inode.i_crypt_info == &managed_ci);
	CHECK(sdp_under_cp_calls == 0);
	managed_inode.i_crypt_info = NULL;

	managed_inode.i_mode = S_IFREG;
	down_before = managed_fi.i_sdp_sem.down;
	CHECK(!f2fs_publish_crypt_info(&managed_inode, &unmanaged_ci));
	CHECK(managed_fi.i_sdp_sem.down == down_before);
	managed_inode.i_crypt_info = NULL;
	CHECK(!hmfs_publish_crypt_info(&managed_inode, &unmanaged_ci));
	CHECK(managed_fi.i_sdp_sem.down == down_before);
	managed_inode.i_crypt_info = NULL;

	host_sdp_flags = F2FS_XATTR_SDP_ECE_CONFIG_FLAG;
	CHECK(f2fs_publish_crypt_info(&managed_inode, &managed_ci) ==
	      -EOPNOTSUPP);
	CHECK(hmfs_publish_crypt_info(&managed_inode, &managed_ci) ==
	      -EOPNOTSUPP);
	CHECK(!managed_inode.i_crypt_info);

	host_sdp_flags = HWDPS_XATTR_ENABLE_FLAG_NEW;
	CHECK(f2fs_publish_crypt_info(&managed_inode, &managed_ci) ==
	      -EOPNOTSUPP);
	CHECK(hmfs_publish_crypt_info(&managed_inode, &managed_ci) ==
	      -EOPNOTSUPP);
	CHECK(!managed_inode.i_crypt_info);
	managed_ci.ci_owner.key = NULL;
	managed_inode.i_mode = S_IFREG;
	assert_balanced();
}

typedef int (*cold_sdp_fn)(struct inode *, void *);

static void check_cold_guard(cold_sdp_fn fn, bool ce_guard,
		bool present, int expected)
{
	int result;

	reset_case(32, 0, present);
	managed_inode.size = 0;
	if (ce_guard) {
		memcpy(managed_context.master_key_descriptor, managed_desc,
		       FS_KEY_DESCRIPTOR_SIZE);
		memcpy(host_sdp_context.master_key_descriptor, legacy_desc,
		       FS_KEY_DESCRIPTOR_SIZE);
	} else {
		memcpy(managed_context.master_key_descriptor, legacy_desc,
		       FS_KEY_DESCRIPTOR_SIZE);
		memcpy(host_sdp_context.master_key_descriptor, managed_desc,
		       FS_KEY_DESCRIPTOR_SIZE);
	}
	result = fn(&managed_inode, NULL);
	if (result != expected)
		fprintf(stderr, "cold guard ce=%d present=%d got=%d expected=%d\n",
			ce_guard, present, result, expected);
	CHECK(result == expected);
	CHECK(!managed_inode.i_crypt_info);
	CHECK(lookups == 0);
	CHECK(set_sdp_calls == 0);
	CHECK(set_context_calls == 0);
	assert_balanced();
}

static void test_sdp_cold_and_warm_guards(void)
{
	cold_sdp_fn cold[] = {
		f2fs_get_sdp_ece_crypt_info,
		f2fs_get_sdp_sece_crypt_info,
		hmfs_get_sdp_ece_crypt_info,
		hmfs_get_sdp_sece_crypt_info,
	};
	struct fscrypt_sdp_policy policy = {
		.sdpclass = FSCRYPT_SDP_ECE_CLASS,
		.contents_encryption_mode = FS_ENCRYPTION_MODE_AES_256_XTS,
		.filenames_encryption_mode = FS_ENCRYPTION_MODE_AES_256_CTS,
	};
	u8 raw[FS_MAX_KEY_SIZE];
	int size;
	unsigned int i;
	struct fscrypt_info managed_ci = { 0 };

	for (i = 0; i < sizeof(cold) / sizeof(cold[0]); i++) {
		check_cold_guard(cold[i], true, true, -EOPNOTSUPP);
		check_cold_guard(cold[i], false, true, -EOPNOTSUPP);
		check_cold_guard(cold[i], true, false, -ENOKEY);
		check_cold_guard(cold[i], false, false, -ENOKEY);
	}

	reset_case(32, 0, true);
	prepare_sdp_payload(FSCRYPT_SDP_ECE_CLASS);
	CHECK(f2fs_inode_check_sdp_keyring(&managed_sb, (u8 *)managed_desc, 1) ==
	      -EOPNOTSUPP);
	CHECK(hmfs_inode_check_sdp_keyring(&managed_sb, (u8 *)managed_desc, 1,
					   INLINE_CRYPTO_V2) == -EOPNOTSUPP);
	CHECK(lookups == 0);
	assert_balanced();

	reset_case(32, 0, true);
	prepare_sdp_payload(FSCRYPT_SDP_ECE_CLASS);
	CHECK(f2fs_do_get_keyring_payload(&managed_sb, (u8 *)managed_desc, raw,
					  sizeof(raw), &size, false,
					  FSCRYPT_SDP_ECE_CLASS) ==
	      -EOPNOTSUPP);
	CHECK(hmfs_do_get_keyring_payload(&managed_sb, (u8 *)managed_desc, raw,
					  &size, false, INLINE_CRYPTO_V2) ==
	      -EOPNOTSUPP);
	CHECK(lookups == 0);
	assert_balanced();

	reset_case(32, 0, false);
	prepare_sdp_payload(FSCRYPT_SDP_ECE_CLASS);
	CHECK(f2fs_do_get_keyring_payload(&managed_sb, (u8 *)managed_desc, raw,
					  sizeof(raw), &size, false,
					  FSCRYPT_SDP_ECE_CLASS) == -ENOKEY);
	CHECK(hmfs_do_get_keyring_payload(&managed_sb, (u8 *)managed_desc, raw,
					  &size, false, INLINE_CRYPTO_V2) == -ENOKEY);
	CHECK(lookups == 0);
	assert_balanced();

	reset_case(32, -ENOENT, false);
	prepare_sdp_payload(FSCRYPT_SDP_ECE_CLASS);
	managed_ci.ci_owner.key = &managed_mk;
	managed_ci.ci_owner.generation = 1;
	memcpy(managed_ci.ci_master_key, legacy_desc, FS_KEY_DESCRIPTOR_SIZE);
	managed_inode.i_crypt_info = &managed_ci;
	host_sdp_flags = F2FS_XATTR_SDP_ECE_ENABLE_FLAG;
	CHECK(f2fs_get_sdp_crypt_info(&managed_inode, NULL) == -EOPNOTSUPP);
	CHECK(hmfs_get_sdp_crypt_info(&managed_inode, NULL) == -EOPNOTSUPP);
	CHECK(lookups == 0);
	managed_inode.i_crypt_info = NULL;
	managed_ci.ci_owner.key = NULL;
	assert_balanced();

	reset_case(32, 0, false);
	prepare_sdp_payload(FSCRYPT_SDP_ECE_CLASS);
	CHECK(f2fs_inode_check_sdp_keyring(&managed_sb, (u8 *)managed_desc, 1) ==
	      -ENOKEY);
	CHECK(hmfs_inode_check_sdp_keyring(&managed_sb, (u8 *)managed_desc, 1,
					   INLINE_CRYPTO_V2) == -ENOKEY);
	CHECK(lookups == 0);
	assert_balanced();

	reset_case(32, -ENOENT, false);
	prepare_sdp_payload(FSCRYPT_SDP_ECE_CLASS);
	managed_legacy_key.validation_error = -EKEYREVOKED;
	CHECK(f2fs_inode_check_sdp_keyring(&managed_sb, (u8 *)legacy_desc, 1) ==
	      -EKEYREVOKED);
	CHECK(hmfs_inode_check_sdp_keyring(&managed_sb, (u8 *)legacy_desc, 1,
					   INLINE_CRYPTO_V2) == -EKEYREVOKED);
	assert_balanced();

	reset_case(32, -ENOENT, false);
	prepare_sdp_payload(FSCRYPT_SDP_ECE_CLASS);
	managed_legacy_key.validation_error = -EKEYREVOKED;
	CHECK(hmfs_do_get_keyring_payload(&managed_sb, (u8 *)legacy_desc, raw,
					  &size, false, INLINE_CRYPTO_V2) ==
	      -EKEYREVOKED);
	assert_balanced();

	memcpy(policy.master_key_descriptor, legacy_desc,
	       FS_KEY_DESCRIPTOR_SIZE);
	reset_case(32, 0, true);
	prepare_sdp_payload(FSCRYPT_SDP_ECE_CLASS);
	memcpy(managed_context.master_key_descriptor, managed_desc,
	       FS_KEY_DESCRIPTOR_SIZE);
	CHECK(f2fs_create_sdp_encryption_context_from_policy(&managed_inode,
							      &policy) ==
	      -EOPNOTSUPP);
	CHECK(lookups == 0 && set_sdp_calls == 0);
	CHECK(f2fs_sdp_keyring_checks == 0);
	assert_balanced();

	reset_case(32, 0, true);
	prepare_sdp_payload(FSCRYPT_SDP_ECE_CLASS);
	memcpy(managed_context.master_key_descriptor, managed_desc,
	       FS_KEY_DESCRIPTOR_SIZE);
	CHECK(hmfs_create_sdp_encryption_context_from_policy(&managed_inode,
							      &policy) ==
	      -EOPNOTSUPP);
	CHECK(lookups == 0 && set_sdp_calls == 0);
	CHECK(hmfs_sdp_keyring_checks == 0);
	assert_balanced();

	memcpy(policy.master_key_descriptor, managed_desc,
	       FS_KEY_DESCRIPTOR_SIZE);
	reset_case(32, 0, true);
	prepare_sdp_payload(FSCRYPT_SDP_ECE_CLASS);
	memcpy(managed_context.master_key_descriptor, legacy_desc,
	       FS_KEY_DESCRIPTOR_SIZE);
	CHECK(f2fs_create_sdp_encryption_context_from_policy(&managed_inode,
							      &policy) ==
	      -EOPNOTSUPP);
	CHECK(lookups == 0 && set_sdp_calls == 0);
	CHECK(f2fs_sdp_keyring_checks == 0);
	assert_balanced();

	reset_case(32, 0, true);
	prepare_sdp_payload(FSCRYPT_SDP_ECE_CLASS);
	memcpy(managed_context.master_key_descriptor, legacy_desc,
	       FS_KEY_DESCRIPTOR_SIZE);
	CHECK(hmfs_create_sdp_encryption_context_from_policy(&managed_inode,
							      &policy) ==
	      -EOPNOTSUPP);
	CHECK(lookups == 0 && set_sdp_calls == 0);
	CHECK(hmfs_sdp_keyring_checks == 0);
	assert_balanced();
}

typedef int (*set_dps_policy_fn)(struct file *, struct inode *);

static void check_set_dps_policy(set_dps_policy_fn fn, unsigned int mode,
		bool warm_managed, bool present, int expected)
{
	struct fscrypt_info managed_ci = { 0 };

	reset_case(32, 0, present);
	managed_inode.i_mode = mode;
	memcpy(managed_context.master_key_descriptor,
	       warm_managed ? legacy_desc : managed_desc,
	       FS_KEY_DESCRIPTOR_SIZE);
	if (warm_managed) {
		managed_ci.ci_owner.key = &managed_mk;
		managed_ci.ci_owner.generation = 1;
		memcpy(managed_ci.ci_master_key, managed_desc,
		       FS_KEY_DESCRIPTOR_SIZE);
		managed_inode.i_crypt_info = &managed_ci;
	}
	CHECK(fn(&managed_file, &managed_inode) == expected);
	CHECK(hwdps_attr_set_calls == 0);
	CHECK(hwdps_flag_set_calls == 0);
	CHECK(hwdps_origin_fek_calls == 0);
	CHECK(inode_lock_depth == 0 && mount_write_depth == 0);
	managed_inode.i_crypt_info = NULL;
	managed_ci.ci_owner.key = NULL;
	managed_inode.i_mode = S_IFREG;
	assert_balanced();
}

static void check_cold_hwdps_open(bool hmfs, bool present)
{
	int flag = 0;
	int result;

	reset_case(32, 0, present);
	managed_inode.i_mode = S_IFREG;
	host_sdp_flags = HWDPS_XATTR_ENABLE_FLAG_NEW;
	host_hwdps_attr_present = true;
	memcpy(managed_context.master_key_descriptor, managed_desc,
	       FS_KEY_DESCRIPTOR_SIZE);
	result = hmfs ? hmfs_get_crypt_keyinfo(&managed_inode, NULL, &flag) :
		f2fs_get_crypt_keyinfo(&managed_inode, NULL, &flag);
	CHECK(result == -EACCES);
	CHECK(flag == 1);
	CHECK(!managed_inode.i_crypt_info);
	CHECK(lookups == 0);
	CHECK(hwdps_get_fek_calls == 0);
	assert_balanced();
}

static void check_unmanaged_cold_regular_policy(set_dps_policy_fn fn)
{
	reset_case(32, -ENOENT, false);
	managed_inode.i_mode = S_IFREG;
	memcpy(managed_context.master_key_descriptor, legacy_desc,
	       FS_KEY_DESCRIPTOR_SIZE);
	CHECK(fn(&managed_file, &managed_inode) == -ENOKEY);
	CHECK(hwdps_attr_set_calls == 0 && hwdps_flag_set_calls == 0);
	CHECK(hwdps_origin_fek_calls == 0);
	CHECK(inode_lock_depth == 0 && mount_write_depth == 0);
	managed_inode.i_mode = S_IFREG;
	assert_balanced();
}

static void test_hwdps_admission_guards(void)
{
	set_dps_policy_fn setters[] = {
		set_dps_policy_inner,
		hmfs_set_dps_policy_inner,
	};
	struct fscrypt_info parent_ci = { 0 };
	struct fscrypt_info warm_ci = { 0 };
	buffer_t aes_key;
	u8 aes[AES256_KEY_LEN];
	u32 flags;
	int flag;
	unsigned int i;

	for (i = 0; i < sizeof(setters) / sizeof(setters[0]); i++) {
		check_set_dps_policy(setters[i], S_IFDIR, true, true,
				     -EOPNOTSUPP);
		check_set_dps_policy(setters[i], S_IFREG, true, true,
				     -EOPNOTSUPP);
		check_set_dps_policy(setters[i], S_IFDIR, false, true,
				     -EOPNOTSUPP);
		check_set_dps_policy(setters[i], S_IFREG, false, true,
				     -EOPNOTSUPP);
		check_set_dps_policy(setters[i], S_IFDIR, false, false, -ENOKEY);
		check_set_dps_policy(setters[i], S_IFREG, false, false, -ENOKEY);
		check_unmanaged_cold_regular_policy(setters[i]);
	}

	reset_case(32, 0, true);
	managed_inode.i_mode = S_IFDIR;
	parent_ci.ci_owner.key = &managed_mk;
	parent_ci.ci_owner.generation = 1;
	memcpy(parent_ci.ci_master_key, managed_desc, FS_KEY_DESCRIPTOR_SIZE);
	managed_inode.i_crypt_info = &parent_ci;
	sdp_child.i_mode = S_IFDIR;
	CHECK(!hwdps_inherit_context(&managed_inode, &sdp_child,
				     &managed_dentry, (void *)1, NULL));
	sdp_child.i_mode = S_IFREG;
	CHECK(!hwdps_inherit_context(&managed_inode, &sdp_child,
				     &managed_dentry, (void *)1, NULL));
	CHECK(hwdps_create_fek_calls == 0);
	CHECK(hwdps_attr_set_calls == 0 && hwdps_flag_set_calls == 0);
	CHECK(registry_lookups == 0);
	managed_inode.i_crypt_info = NULL;
	parent_ci.ci_owner.key = NULL;
	assert_balanced();

	reset_case(32, 0, true);
	managed_inode.i_mode = S_IFDIR;
	parent_ci.ci_owner.key = &managed_mk;
	parent_ci.ci_owner.generation = 1;
	memcpy(parent_ci.ci_master_key, managed_desc, FS_KEY_DESCRIPTOR_SIZE);
	managed_inode.i_crypt_info = &parent_ci;
	host_hwdps_attr_present = true;
	sdp_child.i_mode = S_IFDIR;
	CHECK(hwdps_inherit_context(&managed_inode, &sdp_child,
				    &managed_dentry, (void *)1, NULL) ==
	      -EOPNOTSUPP);
	sdp_child.i_mode = S_IFREG;
	CHECK(hwdps_inherit_context(&managed_inode, &sdp_child,
				    &managed_dentry, (void *)1, NULL) ==
	      -EOPNOTSUPP);
	CHECK(hwdps_create_fek_calls == 0);
	CHECK(hwdps_attr_set_calls == 0 && hwdps_flag_set_calls == 0);
	managed_inode.i_crypt_info = NULL;
	parent_ci.ci_owner.key = NULL;
	assert_balanced();

	reset_case(32, 0, false);
	managed_inode.i_mode = S_IFDIR;
	memset(&parent_ci, 0, sizeof(parent_ci));
	memcpy(parent_ci.ci_master_key, managed_desc, FS_KEY_DESCRIPTOR_SIZE);
	managed_inode.i_crypt_info = &parent_ci;
	host_hwdps_attr_present = true;
	sdp_child.i_mode = S_IFDIR;
	CHECK(hwdps_inherit_context(&managed_inode, &sdp_child,
				    &managed_dentry, (void *)1, NULL) == -ENOKEY);
	sdp_child.i_mode = S_IFREG;
	CHECK(hwdps_inherit_context(&managed_inode, &sdp_child,
				    &managed_dentry, (void *)1, NULL) == -ENOKEY);
	CHECK(hwdps_create_fek_calls == 0);
	CHECK(hwdps_attr_set_calls == 0 && hwdps_flag_set_calls == 0);
	managed_inode.i_crypt_info = NULL;
	assert_balanced();

	check_cold_hwdps_open(false, true);
	check_cold_hwdps_open(true, true);
	check_cold_hwdps_open(false, false);
	check_cold_hwdps_open(true, false);

	reset_case(32, 0, true);
	warm_ci.ci_owner.key = &managed_mk;
	warm_ci.ci_owner.generation = 1;
	warm_ci.ci_hw_enc_flag = 0;
	host_sdp_flags = 0;
	managed_inode.i_crypt_info = &warm_ci;
	CHECK(hwdps_check_support(&managed_inode, &flags) == -EOPNOTSUPP);
	CHECK(hwdps_get_context(&managed_inode) == -EOPNOTSUPP);
	flag = -1;
	CHECK(!f2fs_get_crypt_keyinfo(&managed_inode, NULL, &flag) && flag == 0);
	flag = -1;
	CHECK(!hmfs_get_crypt_keyinfo(&managed_inode, NULL, &flag) && flag == 0);
	hwdps_attr_get_calls = 0;
	CHECK(hwdps_update_context(&managed_inode, 2000) == 0);
	CHECK(hwdps_attr_get_calls == 0);

	warm_ci.ci_hw_enc_flag = HWDPS_XATTR_ENABLE_FLAG_NEW;
	CHECK(hwdps_check_support(&managed_inode, &flags) == 0);
	CHECK(hwdps_get_context(&managed_inode) == -EKEYREJECTED);
	CHECK(hwdps_access_calls == 0);
	flag = -1;
	CHECK(f2fs_get_crypt_keyinfo(&managed_inode, NULL, &flag) == -EACCES &&
	      flag == 1);
	flag = -1;
	CHECK(hmfs_get_crypt_keyinfo(&managed_inode, NULL, &flag) == -EACCES &&
	      flag == 1);
	hwdps_attr_get_calls = 0;
	CHECK(hwdps_update_context(&managed_inode, 2000) == -EOPNOTSUPP);
	CHECK(hwdps_attr_get_calls == 0);
	managed_inode.i_crypt_info = NULL;
	warm_ci.ci_owner.key = NULL;
	assert_balanced();

	reset_case(32, -ENOENT, false);
	managed_legacy_key.validation_error = -EKEYREVOKED;
	aes_key.data = aes;
	aes_key.len = sizeof(aes);
	CHECK(hwdps_get_key(legacy_desc, &aes_key, 1000) == -EKEYREVOKED);
	assert_balanced();
	managed_inode.i_mode = S_IFREG;
	sdp_child.i_mode = S_IFREG;
}

int main(int argc, char **argv)
{
	CHECK(argc == 2);
	if (!strcmp(argv[1], "descriptor-admission"))
		test_descriptor_admission();
	else if (!strcmp(argv[1], "managed-policy"))
		test_managed_policy();
	else if (!strcmp(argv[1], "managed-file-owner"))
		test_managed_file_owner();
	else if (!strcmp(argv[1], "publication-loser"))
		test_publication_loser();
	else if (!strcmp(argv[1], "tombstone-legacy"))
		test_tombstone_and_legacy_slots();
	else if (!strcmp(argv[1], "cached-retirement"))
		test_cached_retirement();
	else if (!strcmp(argv[1], "managed-inheritance"))
		test_managed_inheritance();
	else if (!strcmp(argv[1], "inline-keyindex"))
		test_inline_keyindex();
	else if (!strcmp(argv[1], "hwdps-keyindex"))
		test_hwdps_keyindex();
	else if (!strcmp(argv[1], "sdp-keyindex"))
		test_sdp_keyindex();
	else if (!strcmp(argv[1], "sdp-guards-publication"))
		test_sdp_guards_and_publication();
	else if (!strcmp(argv[1], "publish-dir-lock-order"))
		test_publish_dir_lock_order();
	else if (!strcmp(argv[1], "sdp-cold-and-warm-guards"))
		test_sdp_cold_and_warm_guards();
	else if (!strcmp(argv[1], "hwdps-admission-guards"))
		test_hwdps_admission_guards();
	else
		CHECK(false);
	return 0;
}

/* SPDX-License-Identifier: GPL-2.0 */
#include "huawei_fscrypt_ce_scope_host.h"
#include "crypto-subject.h"
#include "subject.h"

static struct fscrypt_context saved;
static int set_error;
static int set_calls;
static int get_context_calls;

static int save_context(struct inode *inode, const void *data, size_t size,
			void *fs_data)
{
	CHECK(size == sizeof(saved));
	CHECK(!lookup_key || lookup_key->sem.readers == 0);
	memcpy(&saved, data, size);
	set_calls++;
	return set_error;
}

static int load_context(struct inode *inode, void *data, size_t size)
{
	CHECK(size == sizeof(saved));
	memcpy(data, &saved, size);
	get_context_calls++;
	return sizeof(saved);
}

static struct operations ops = {
	.key_prefix = "f2fs:",
	.set_context = save_context,
	.get_context = load_context,
};
static struct file_system_type fs_type = { .name = "hostfs" };
static struct super_block sb = { .s_cop = &ops, .s_type = &fs_type };
static struct super_block other_sb = { .s_cop = &ops, .s_type = &fs_type };
static struct inode ino = { .i_sb = &sb, .i_ino = 1, .i_mode = S_IFREG };
static struct inode child = { .i_sb = &sb, .i_ino = 2, .i_mode = S_IFREG };
static struct inode grandchild = {
	.i_sb = &sb,
	.i_ino = 3,
	.i_mode = S_IFREG,
};
static struct user_key_payload ukp;
static struct user_key_payload alt_ukp;
static struct key key;
static struct key alt;
static const u8 desc[FS_KEY_DESCRIPTOR_SIZE] = { 0, 1, 2, 3, 4, 5, 6, 7 };

static void setup(unsigned int size)
{
	struct fscrypt_key *payload;
	unsigned int i;

	memset(&ukp, 0, sizeof(ukp));
	memset(&key, 0, sizeof(key));
	ukp.datalen = sizeof(struct fscrypt_key);
	payload = (void *)ukp.data;
	payload->size = size;
	for (i = 0; i < sizeof(payload->raw); i++)
		payload->raw[i] = (u8)(i + 1);
	payload->raw[63] = 29;
	key.type = &key_type_logon;
	key.payload = &ukp;
	alt_ukp = ukp;
	alt = key;
	alt.payload = &alt_ukp;
	lookup_key = &key;
	alternate_key = &alt;
	primary_error = 0;
	alternate_error = 0;
	lookups = 0;
	revoke_on_lock = false;
	fail_kmalloc = 0;
	fail_tfm = 0;
	fail_setkey = 0;
	fail_request = 0;
	set_error = 0;
	set_calls = 0;
	get_context_calls = 0;
	allocations = 0;
	frees = 0;
	wipes = 0;
	material_wipes = 0;
	scope_wipes = 0;
	key_readers = 0;
	tracked_scope = NULL;
	tracked_scope_size = 0;
	tfm_live = 0;
	skcipher_live = 0;
	requests = 0;
	memset(&saved, 0, sizeof(saved));
	ino.i_crypt_info = NULL;
	child.i_crypt_info = NULL;
	grandchild.i_crypt_info = NULL;
}

static void balanced(void)
{
	CHECK(key.refs == 0 && key.sem.readers == 0 &&
	      key.sem.down == key.sem.up);
	CHECK(alt.refs == 0 && alt.sem.readers == 0 &&
	      alt.sem.down == alt.sem.up);
	CHECK(!requests);
	CHECK(!key_readers);
	CHECK(!tfm_live);
	CHECK(!skcipher_live);
	CHECK(allocations == frees);
}

static void prepare_parent_context(void)
{
	struct fscrypt_key *payload = (void *)ukp.data;
	struct crypto_aead *tfm;
	u8 plain[FS_KEY_DERIVATION_CIPHER_SIZE] = { 0x31 };

	saved.format = FS_ENCRYPTION_CONTEXT_FORMAT_V2;
	saved.contents_encryption_mode = FS_ENCRYPTION_MODE_AES_256_XTS;
	saved.filenames_encryption_mode = FS_ENCRYPTION_MODE_AES_256_CTS;
	memcpy(saved.master_key_descriptor, desc, sizeof(desc));
	memset(saved.iv, 0x42, sizeof(saved.iv));
	tfm = crypto_alloc_aead("gcm(aes)", 0, 0);
	CHECK(!IS_ERR(tfm));
	CHECK(!fscrypt_set_gcm_key(tfm, payload->raw));
	CHECK(!fscrypt_derive_gcm_key(tfm, plain, saved.nonce, saved.iv, 1));
	crypto_free_aead(tfm);
}

static void revoke_keyring(void)
{
	primary_error = -EKEYREVOKED;
	alternate_error = -EKEYREVOKED;
}

static void put_tracked_scope(struct fscrypt_ce_scope *scope)
{
	int before = scope_wipes;

	tracked_scope = scope;
	tracked_scope_size = sizeof(*scope);
	fscrypt_ce_scope_put(scope);
	CHECK(scope_wipes == before + 1);
	tracked_scope = NULL;
	tracked_scope_size = 0;
}

static void roundtrip(struct inode *inode,
		int (*fn)(struct inode *, u8 *, u8 *, u8 *, u8 *, int))
{
	u8 plain[80] = { 1 };
	u8 cipher[80] = { 0 };
	u8 output[80] = { 0 };
	u8 iv[16] = { 0 };

	CHECK(!fn(inode, (u8 *)desc, cipher, plain, iv, 1));
	CHECK(!fn(inode, (u8 *)desc, cipher, output, iv, 0));
	CHECK(!memcmp(plain, output, 64));
}

static void primary_only(struct inode *inode,
		int (*fn)(struct inode *, u8 *, u8 *, u8 *, u8 *, int))
{
	u8 plain[80] = { 1 };
	u8 cipher[80] = { 0 };
	u8 iv[16] = { 0 };

	setup(32);
	primary_error = -ENOKEY;
	CHECK(fn(inode, (u8 *)desc, cipher, plain, iv, 1) == -ENOKEY);
	CHECK(lookups == 1);
	balanced();
}

static void preload_child(void)
{
	prepare_parent_context();
	CHECK(!fscrypt_get_encryption_info(&ino));
	CHECK(ino.i_crypt_info != NULL);
	CHECK(lookups == 1);
	CHECK(get_context_calls == 1);
	revoke_keyring();
	CHECK(!fscrypt_inherit_context(&ino, &child, NULL, true));
	CHECK(child.i_crypt_info != NULL);
	CHECK(child.i_crypt_info->ci_gtfm_owner ==
	      ino.i_crypt_info->ci_gtfm_owner);
	CHECK(child.i_crypt_info->ci_key_index == 29);
	CHECK(lookups == 1);
	CHECK(get_context_calls == 1);
}

static void test_scope(void)
{
	struct fscrypt_ce_scope *scope = NULL;
	u8 slot = 0;
	u8 plain[80] = { 3 };
	u8 cipher[80] = { 0 };
	u8 output[80] = { 0 };
	u8 iv[16] = { 0 };

	CHECK(!fscrypt_ce_scope_open(&ino, desc, FILE_UNWRAP, &scope));
	CHECK(scope);
	CHECK(material_wipes == 1);
	CHECK(key.sem.readers == 0 && key.refs == 0);
	CHECK(!fscrypt_ce_scope_legacy_slot(scope, &slot) && slot == 29);
	CHECK(!fscrypt_ce_scope_crypt(scope, plain, cipher, iv, true));
	CHECK(!fscrypt_ce_scope_crypt(scope, cipher, output, iv, false));
	CHECK(!memcmp(plain, output, 64));
	put_tracked_scope(scope);
}

static void test_purpose(void)
{
	struct fscrypt_ce_scope *scope = NULL;
	struct inode other = { .i_sb = &other_sb };
	u8 bad[FS_KEY_DESCRIPTOR_SIZE] = { 9 };
	u8 iv[16] = { 0 };
	u8 plain[80] = { 0 };
	u8 cipher[80] = { 0 };

	CHECK(fscrypt_ce_scope_open(&ino, desc, CHILD_WRAP, &scope) == -EINVAL);
	CHECK(!scope);
	CHECK(!fscrypt_ce_scope_open(&ino, desc, POLICY_WRAP, &scope));
	CHECK(fscrypt_ce_scope_matches(scope, &ino, desc, POLICY_WRAP));
	CHECK(!fscrypt_ce_scope_matches(scope, &ino, desc, FILE_UNWRAP));
	CHECK(!fscrypt_ce_scope_matches(scope, &ino, bad, POLICY_WRAP));
	CHECK(!fscrypt_ce_scope_matches(scope, &other, desc, POLICY_WRAP));
	CHECK(!fscrypt_ce_scope_crypt(scope, plain, cipher, iv, true));
	fscrypt_ce_scope_put(scope);
}

static void test_failures(void)
{
	int failure;

	for (failure = 0; failure < 3; failure++) {
		struct fscrypt_ce_scope *scope = (void *)1;

		setup(32);
		if (failure == 0)
			fail_kmalloc = 1;
		if (failure == 1)
			fail_tfm = 1;
		if (failure == 2)
			fail_setkey = 1;
		CHECK(fscrypt_ce_scope_open(&ino, desc, FILE_UNWRAP, &scope) < 0);
		CHECK(!scope);
		CHECK(material_wipes == 1);
		balanced();
	}
}

static void test_policy_boundary(void)
{
	struct fscrypt_policy policy = {
		.contents_encryption_mode = FS_ENCRYPTION_MODE_AES_256_XTS,
		.filenames_encryption_mode = FS_ENCRYPTION_MODE_AES_256_CTS,
	};

	memcpy(policy.master_key_descriptor, desc, sizeof(desc));
	CHECK(!create_encryption_context_from_policy(&ino, &policy));
	CHECK(set_calls == 1);
}

static void test_cached(void)
{
	struct fscrypt_ce_scope *scope = NULL;
	struct fscrypt_info ci = { 0 };
	int res;

	CHECK(!fscrypt_ce_scope_open(&ino, desc, FILE_UNWRAP, &scope));
	memcpy(ci.ci_master_key, desc, sizeof(desc));
	CHECK(!fscrypt_ce_scope_attach_legacy_tfm(scope, &ci));
	ino.i_crypt_info = &ci;
	fscrypt_ce_scope_put(scope);
	revoke_keyring();
	CHECK(!fscrypt_ce_scope_open_cached(&ino, CHILD_WRAP, &scope));
	CHECK(lookups == 1);
	fscrypt_ce_scope_put(scope);

	ci.ci_hw_enc_flag = 1;
	res = fscrypt_ce_scope_open_cached(&ino, CHILD_WRAP, &scope);
	if (!res)
		fscrypt_ce_scope_put(scope);
	CHECK(res == -ENOKEY);
	CHECK(!scope);
	ci.ci_hw_enc_flag = 0;
	ci.ci_master_key[0] ^= 0xff;
	res = fscrypt_ce_scope_open_cached(&ino, CHILD_WRAP, &scope);
	if (!res)
		fscrypt_ce_scope_put(scope);
	CHECK(res == -ENOKEY);
	CHECK(!scope);
	fscrypt_ce_tfm_put(ci.ci_gtfm_owner);
	ino.i_crypt_info = NULL;
}

static void test_preload(void)
{
	preload_child();
	fscrypt_put_encryption_info(&child);
	fscrypt_put_encryption_info(&ino);
}

static void test_child_lifetime(void)
{
	preload_child();
	fscrypt_put_encryption_info(&ino);
	CHECK(ino.i_crypt_info == NULL);
	CHECK(!fscrypt_inherit_context(&child, &grandchild, NULL, true));
	CHECK(grandchild.i_crypt_info != NULL);
	CHECK(lookups == 1);
	CHECK(get_context_calls == 1);
	fscrypt_put_encryption_info(&grandchild);
	fscrypt_put_encryption_info(&child);
	CHECK(tfm_live == 0);
	CHECK(allocations == frees);
}

int main(int argc, char **argv)
{
	const char *test;

	CHECK(argc == 2);
	test = argv[1];
	setup(64);
	if (!strcmp(test, "scope"))
		test_scope();
	else if (!strcmp(test, "purpose"))
		test_purpose();
	else if (!strcmp(test, "failures"))
		test_failures();
	else if (!strcmp(test, "policy-boundary"))
		test_policy_boundary();
	else if (!strcmp(test, "cached"))
		test_cached();
	else if (!strcmp(test, "preload"))
		test_preload();
	else if (!strcmp(test, "child-lifetime"))
		test_child_lifetime();
	else if (!strcmp(test, "f2fs-ce")) {
		roundtrip(&ino, f2fs_do_get_ce_fek);
		CHECK(lookups == 2);
		balanced();
		primary_only(&ino, f2fs_do_get_ce_fek);
	} else if (!strcmp(test, "hmfs-ce")) {
		roundtrip(&ino, hmfs_do_get_ce_fek);
		CHECK(lookups == 2);
		balanced();
		primary_only(&ino, hmfs_do_get_ce_fek);
	} else {
		CHECK(false);
	}
	balanced();
	return 0;
}

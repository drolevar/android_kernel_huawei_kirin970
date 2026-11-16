/* SPDX-License-Identifier: GPL-2.0 */
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>

typedef uint8_t u8;
typedef uint32_t u32;
typedef uint64_t u64;
typedef int32_t s32;
typedef uint8_t __u8;
typedef uint32_t __u32;
typedef unsigned int gfp_t;
typedef struct { unsigned int refs; } refcount_t;

#define __packed __attribute__((packed))
#include "declarations.h"

#define INLINE_CRYPTO_V2 2
#define FS_SDP_ECC_PRIV_KEY_SIZE 32
#define FS_SDP_ECC_PUB_KEY_SIZE 64
struct fscrypt_sdp_key {
	u32 version;
	u32 sdpclass;
	u32 mode;
	u8 raw[FS_MAX_KEY_SIZE];
	u32 size;
	u8 pubkey[FS_MAX_KEY_SIZE];
	u32 pubkeysize;
} __packed;

#define CHECK(x) do { \
	if (!(x)) { \
		fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #x); \
		exit(1); \
	} \
} while (0)
#define ERR_PTR(e) ((void *)(intptr_t)(e))
#define PTR_ERR(p) ((long)(intptr_t)(p))
#define IS_ERR(p) ((uintptr_t)(p) >= (uintptr_t)-4095)
#define GFP_NOFS 0
#define CRYPTO_TFM_REQ_WEAK_KEY 1
#define CRYPTO_TFM_REQ_MAY_BACKLOG 2
#define CRYPTO_TFM_REQ_MAY_SLEEP 4
#define EXPORT_SYMBOL(x)
#define EXPORT_SYMBOL_GPL(x)
#define BUILD_BUG_ON(x) _Static_assert(!(x), #x)
#define ACCESS_ONCE(x) (x)
#define READ_ONCE(x) (x)
#define unlikely(x) (x)
#define pr_err(...) ((void)0)
#define pr_info(...) ((void)0)
#define pr_info_once(...) ((void)0)
#define pr_warn_once(...) ((void)0)
#define fscrypt_warn(...) ((void)0)
#define WARN_ONCE(c, ...) ((void)(c))
#define EOK 0
#define memcpy_s(dst, dst_size, src, count) \
	(((count) > (dst_size)) ? -EINVAL : \
	 (memcpy((dst), (src), (count)), EOK))
#define memset_s(dst, dst_size, value, count) \
	(((count) > (dst_size)) ? -EINVAL : \
	 (memset((dst), (value), (count)), EOK))
#define IS_ENCRYPTED(inode) true
#define cmpxchg(p, old, new) ({ \
	__typeof__(*(p)) expected = (old); \
	__atomic_compare_exchange_n((p), &expected, (new), false, \
				    __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST); \
	expected; \
})

static int fail_kmalloc;
static int allocations;
static int frees;
static int wipes;
static int material_wipes;
static int scope_wipes;
static int secret_wipes;
static int key_readers;
static void *tracked_scope;
static size_t tracked_scope_size;

static void *host_alloc(size_t n)
{
	void *p;

	if (fail_kmalloc) {
		fail_kmalloc--;
		return NULL;
	}
	p = malloc(n);
	CHECK(p);
	allocations++;
	return p;
}

static void *host_zalloc(size_t n)
{
	void *p = host_alloc(n);

	if (p)
		memset(p, 0, n);
	return p;
}

static void host_free(void *p)
{
	if (p) {
		frees++;
		free(p);
	}
}

#define kmalloc(n, f) host_alloc(n)
#define kzalloc(n, f) host_zalloc(n)
#define kfree(p) host_free(p)

static void memzero_explicit(void *p, size_t n)
{
	if (!p || !n)
		return;
	if (n == sizeof(struct fscrypt_key))
		material_wipes++;
	if (n == FS_AES_256_GCM_KEY_SIZE)
		secret_wipes++;
	if (p == tracked_scope && n == tracked_scope_size)
		scope_wipes++;
	OPENSSL_cleanse(p, n);
	wipes++;
}

static void refcount_set(refcount_t *r, unsigned int n)
{
	r->refs = n;
}

static void refcount_inc(refcount_t *r)
{
	CHECK(r->refs);
	r->refs++;
}

static bool refcount_dec_and_test(refcount_t *r)
{
	CHECK(r->refs);
	return --r->refs == 0;
}

struct crypto_aead {
	u8 key[32];
	int authsize;
};
struct crypto_async_request { void *data; };
struct fscrypt_completion_result { int completion; int res; };
#define DECLARE_FS_COMPLETION_RESULT(x) \
	struct fscrypt_completion_result x = { 0 }

static void complete(int *completion)
{
	*completion = 1;
}

static void wait_for_completion(int *completion)
{
	CHECK(*completion);
}

struct scatterlist { void *p; size_t n; };
struct aead_request {
	struct crypto_aead *tfm;
	struct scatterlist *src;
	struct scatterlist *dst;
	unsigned int n;
	unsigned int ad;
	u8 *iv;
};

static int fail_tfm;
static int fail_setkey;
static int fail_request;
static int tfm_live;
static int requests;

static struct crypto_aead *crypto_alloc_aead(const char *name, int type,
					      int mask)
{
	struct crypto_aead *tfm;

	CHECK(!strcmp(name, "gcm(aes)"));
	if (fail_tfm)
		return ERR_PTR(-ENOMEM);
	tfm = host_zalloc(sizeof(*tfm));
	tfm_live++;
	return tfm;
}

static void crypto_free_aead(struct crypto_aead *tfm)
{
	if (tfm) {
		CHECK(!IS_ERR(tfm));
		memzero_explicit(tfm, sizeof(*tfm));
		tfm_live--;
		host_free(tfm);
	}
}

static void crypto_aead_set_flags(struct crypto_aead *tfm, int flags) { }
static unsigned int crypto_aead_ivsize(struct crypto_aead *tfm) { return 12; }

static int crypto_aead_setauthsize(struct crypto_aead *tfm, int size)
{
	tfm->authsize = size;
	return 0;
}

static int crypto_aead_setkey(struct crypto_aead *tfm, const u8 *key,
			      size_t size)
{
	CHECK(key_readers == 0);
	if (fail_setkey)
		return -EINVAL;
	CHECK(size == sizeof(tfm->key));
	memcpy(tfm->key, key, size);
	return 0;
}

static struct aead_request *aead_request_alloc(struct crypto_aead *tfm,
					       int flags)
{
	struct aead_request *request;

	if (fail_request)
		return NULL;
	request = host_zalloc(sizeof(*request));
	request->tfm = tfm;
	requests++;
	return request;
}

static void aead_request_free(struct aead_request *request)
{
	requests--;
	host_free(request);
}

static void aead_request_set_callback(struct aead_request *request, int flags,
		void (*callback)(struct crypto_async_request *, int), void *data)
{
}

static void sg_init_one(struct scatterlist *sg, const void *p, size_t n)
{
	sg->p = (void *)p;
	sg->n = n;
}

static void aead_request_set_ad(struct aead_request *request, unsigned int n)
{
	request->ad = n;
}

static void aead_request_set_crypt(struct aead_request *request,
		struct scatterlist *src, struct scatterlist *dst,
		unsigned int n, u8 *iv)
{
	request->src = src;
	request->dst = dst;
	request->n = n;
	request->iv = iv;
}

static int host_crypt(struct aead_request *request, bool encrypt)
{
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	int n = 0;
	int final = 0;
	int ok;
	u8 tag[16];

	CHECK(ctx);
	if (encrypt) {
		ok = EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) &&
		     EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) &&
		     EVP_EncryptInit_ex(ctx, NULL, NULL, request->tfm->key,
				request->iv) &&
		     EVP_EncryptUpdate(ctx, request->dst->p, &n,
			       request->src->p, 64) &&
		     EVP_EncryptFinal_ex(ctx, (u8 *)request->dst->p + n,
					 &final) &&
		     EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag);
		if (ok)
			memcpy((u8 *)request->dst->p + 64, tag, sizeof(tag));
	} else {
		memcpy(tag, (u8 *)request->src->p + 64, sizeof(tag));
		ok = EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) &&
		     EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) &&
		     EVP_DecryptInit_ex(ctx, NULL, NULL, request->tfm->key,
				request->iv) &&
		     EVP_DecryptUpdate(ctx, request->dst->p, &n,
			       request->src->p, 64) &&
		     EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag) &&
		     EVP_DecryptFinal_ex(ctx, (u8 *)request->dst->p + n,
					 &final);
	}
	EVP_CIPHER_CTX_free(ctx);
	return ok ? 0 : -EBADMSG;
}

static int crypto_aead_encrypt(struct aead_request *request)
{
	return host_crypt(request, true);
}

static int crypto_aead_decrypt(struct aead_request *request)
{
	return host_crypt(request, false);
}

struct semaphore { int readers; int down; int up; };
struct user_key_payload { size_t datalen; u8 data[256]; };
struct key {
	void *type;
	struct user_key_payload *payload;
	struct semaphore sem;
	int refs;
	int validation_error;
};
static int logon;
#define key_type_logon logon
static struct key *lookup_key;
static struct key *alternate_key;
static int primary_error;
static int alternate_error;
static int lookups;
static bool revoke_on_lock;
static bool cp_rwsem_held;
static struct semaphore *monitored_sdp_sem;
static int sdp_under_cp_calls;

static int key_validate(struct key *key)
{
	CHECK(key->sem.readers == 1);
	return key->validation_error;
}

static void down_read(struct semaphore *sem)
{
	if (cp_rwsem_held && sem == monitored_sdp_sem)
		sdp_under_cp_calls++;
	sem->readers++;
	sem->down++;
	key_readers++;
	if (revoke_on_lock) {
		lookup_key->payload = NULL;
		revoke_on_lock = false;
	}
}

static void up_read(struct semaphore *sem)
{
	CHECK(sem->readers);
	sem->readers--;
	sem->up++;
	key_readers--;
}

static void down_write(struct semaphore *sem)
{
	CHECK(!sem->readers);
	sem->readers = -1;
	sem->down++;
}

static void up_write(struct semaphore *sem)
{
	CHECK(sem->readers == -1);
	sem->readers = 0;
	sem->up++;
}

static void key_put(struct key *key)
{
	CHECK(key->refs);
	key->refs--;
}

static struct key *fscrypt_request_key(const u8 *descriptor, const u8 *prefix,
				       int prefix_size)
{
	bool alternate = strcmp((const char *)prefix, FS_KEY_DESC_PREFIX);
	int error = alternate ? alternate_error : primary_error;
	struct key *key = alternate ? alternate_key : lookup_key;

	lookups++;
	if (error)
		return ERR_PTR(error);
	if (!key)
		return ERR_PTR(-ENOKEY);
	key->refs++;
	return key;
}

static const struct user_key_payload *user_key_payload_locked(struct key *key)
{
	CHECK(key->sem.readers == 1);
	return key->payload;
}

struct fscrypt_ce_tfm;
struct crypto_skcipher;
struct crypto_cipher;
struct fscrypt_master_key;
struct fscrypt_mk_owner {
	struct fscrypt_master_key *key;
	u64 generation;
};
struct fscrypt_info {
	int ci_key_index;
	struct crypto_skcipher *ci_ctfm;
	struct crypto_aead *ci_gtfm;
	struct fscrypt_ce_tfm *ci_gtfm_owner;
	struct crypto_cipher *ci_essiv_tfm;
	void *ci_key;
	int ci_key_len;
	int ci_hw_enc_flag;
	struct fscrypt_mk_owner ci_owner;
	u8 ci_data_mode;
	u8 ci_filename_mode;
	u8 ci_flags;
	u8 ci_master_key[FS_KEY_DESCRIPTOR_SIZE];
};

struct inode;
struct dentry { int unused; };
struct page { int unused; };
struct file { struct inode *inode; };
enum fscrypt_context_origin {
	FSCRYPT_CTX_OWNED_POLICY = 0,
	FSCRYPT_CTX_BORROWED_INHERIT = 1,
};
struct fscrypt_context_op;
struct operations {
	const char *key_prefix;
	unsigned int flags;
	int (*set_context)(struct inode *, const void *, size_t, void *);
	int (*publish_crypt_info)(struct inode *, struct fscrypt_info *);
	int (*prepare_context)(struct inode *, enum fscrypt_context_origin,
			       void *, struct fscrypt_context_op **);
	int (*set_context_prepared)(struct inode *, const void *, size_t,
				    struct fscrypt_context_op *);
	int (*finish_context)(struct inode *, struct fscrypt_context_op *, int,
			      bool *);
	int (*get_context)(struct inode *, void *, size_t);
	int (*get_keyinfo)(struct inode *, void *, int *);
	bool (*is_inline_encrypted)(struct inode *);
	bool (*is_encrypted)(struct inode *);
	int (*get_hwdps_flags)(struct inode *, void *, u32 *);
	int (*set_hwdps_flags)(struct inode *, void *, u32 *);
	int (*get_hwdps_attr)(struct inode *, void *, size_t, u32, void *);
	int (*set_hwdps_attr)(struct inode *, const void *, size_t, void *);
	int (*update_hwdps_attr)(struct inode *, const void *, size_t, void *);
};
#define fscrypt_operations operations
struct file_system_type { const char *name; };
struct super_block {
	struct operations *s_cop;
	struct file_system_type *s_type;
	void *s_fs_info;
};
struct inode {
	struct super_block *i_sb;
	struct fscrypt_info *i_crypt_info;
	unsigned long i_ino;
	unsigned int i_mode;
	void *private;
	long size;
	struct { uid_t val; } i_uid;
};

static int inode_lock_depth;
static int mount_write_depth;
static int mnt_want_write_file(struct file *file)
{
	mount_write_depth++;
	return 0;
}
static void mnt_drop_write_file(struct file *file)
{
	CHECK(mount_write_depth > 0);
	mount_write_depth--;
}
static void inode_lock(struct inode *inode) { inode_lock_depth++; }
static void inode_unlock(struct inode *inode)
{
	CHECK(inode_lock_depth > 0);
	inode_lock_depth--;
}

struct f2fs_sdp_fscrypt_operations {
	int (*get_sdp_context)(struct inode *, void *, size_t, void *);
	int (*set_sdp_context)(struct inode *, const void *, size_t, void *);
	int (*update_sdp_context)(struct inode *, const void *, size_t, void *);
	int (*update_context)(struct inode *, const void *, size_t, void *);
	int (*get_sdp_encrypt_flags)(struct inode *, void *, u32 *);
	int (*set_sdp_encrypt_flags)(struct inode *, void *, u32 *);
};

struct f2fs_inode_info {
	struct semaphore i_sdp_sem;
};

struct f2fs_sb_info {
	const struct f2fs_sdp_fscrypt_operations *s_sdp_cop;
	unsigned char encryption_ver;
	bool sdp_enabled;
};

#define F2FS_I(inode) ((struct f2fs_inode_info *)(inode)->private)
#define F2FS_I_SB(inode) ((struct f2fs_sb_info *)(inode)->i_sb->s_fs_info)
#define SDP_ENCRYPT 1
#define test_hw_opt(sbi, opt) ((sbi)->sdp_enabled)
#define i_size_read(inode) ((inode)->size)

#define FSCRYPT_SDP_ECE_CLASS 2
#define FSCRYPT_SDP_SECE_CLASS 3
#define F2FS_XATTR_SDP_ECE_ENABLE_FLAG 0x01
#define F2FS_XATTR_SDP_ECE_CONFIG_FLAG 0x02
#define F2FS_XATTR_SDP_SECE_ENABLE_FLAG 0x04
#define F2FS_XATTR_SDP_SECE_CONFIG_FLAG 0x08
#define HMFS_XATTR_SDP_ECE_CONFIG_FLAG F2FS_XATTR_SDP_ECE_CONFIG_FLAG
#define HMFS_XATTR_SDP_SECE_CONFIG_FLAG F2FS_XATTR_SDP_SECE_CONFIG_FLAG
#define HWDPS_ENABLE_FLAG 0x00f0
#define HWDPS_XATTR_ENABLE_FLAG_NEW 0x20
#define HWDPS_XATTR_ENABLE_FLAG 0x10
#define HWDPS_ENCODED_WFEK_SIZE 97
#define HWDPS_ENCODE_WFEK_SIZE_OLD 251
#define HWDPS_KEY_DESC_STANDARD_FLAG 0x42
#define HWDPS_SUCCESS 0
#define HWDPS_ERR_NOT_SUPPORTED 100
#define HWDPS_ERR_INVALID_ARGS -EINVAL
#define HWDPS_ERR_INTERNAL -EIO
#define HWDPS_HIVIEW_CREATE 1000
#define AES256_KEY_LEN 32
#define hwdps_pr_err(...) ((void)0)

#define hwdps_result_t s32
#define F2FS_INODE_IS_SDP_ENCRYPTED(flag) ((flag) & 0x0f)
#define F2FS_INODE_IS_ENABLED_SDP_ECE_ENCRYPTION(flag) \
	((flag) & F2FS_XATTR_SDP_ECE_ENABLE_FLAG)
#define F2FS_INODE_IS_ENABLED_SDP_SECE_ENCRYPTION(flag) \
	((flag) & F2FS_XATTR_SDP_SECE_ENABLE_FLAG)
#define F2FS_INODE_IS_ENABLED_SDP_ENCRYPTION(flag) \
	((flag) & (F2FS_XATTR_SDP_ECE_ENABLE_FLAG | \
		   F2FS_XATTR_SDP_SECE_ENABLE_FLAG))
#define F2FS_INODE_IS_CONFIG_SDP_ENCRYPTION(flag) \
	((flag) & (F2FS_XATTR_SDP_ECE_CONFIG_FLAG | \
		   F2FS_XATTR_SDP_SECE_CONFIG_FLAG))
#define F2FS_INODE_IS_CONFIG_SDP_ECE_ENCRYPTION(flag) \
	((flag) & F2FS_XATTR_SDP_ECE_CONFIG_FLAG)
#define HMFS_INODE_IS_CONFIG_SDP_ENCRYPTION(flag) \
	F2FS_INODE_IS_CONFIG_SDP_ENCRYPTION(flag)
#define HMFS_INODE_IS_CONFIG_SDP_ECE_ENCRYPTION(flag) \
	F2FS_INODE_IS_CONFIG_SDP_ECE_ENCRYPTION(flag)

struct fscrypt_sdp_policy {
	u8 version;
	u8 sdpclass;
	u8 contents_encryption_mode;
	u8 filenames_encryption_mode;
	u8 flags;
	u8 master_key_descriptor[FS_KEY_DESCRIPTOR_SIZE];
} __packed;

struct f2fs_sdp_fscrypt_context {
	u8 version;
	u8 sdpclass;
	u8 format;
	u8 contents_encryption_mode;
	u8 filenames_encryption_mode;
	u8 flags;
	u8 master_key_descriptor[FS_KEY_DESCRIPTOR_SIZE];
	u8 nonce[FS_KEY_DERIVATION_CIPHER_SIZE];
	u8 iv[FS_KEY_DERIVATION_IV_SIZE];
	u8 file_pub_key[64];
} __packed;

static void hmfs_sdp_rawkey_config(const struct user_key_payload *ukp,
		u8 *raw, int *size, bool filepubkey, unsigned char ver,
		int *res)
{
	const struct fscrypt_sdp_key *key = (const void *)ukp->data;

	*size = key->size;
	memcpy(raw, key->raw, key->size);
	*res = 0;
}

#define fscrypt_get_ece_metadata(...) 0
#define fscrypt_get_sece_metadata(...) 0
#define fscrypt_check_sece_metadata(...) 0

struct fscrypt_master_key {
	int refs;
	struct semaphore secret_sem;
	int owners;
	u64 generation;
	bool present;
	u8 raw[64];
};

struct fscrypt_mk_lease {
	struct fscrypt_master_key *key;
	u64 generation;
};

static struct super_block *registry_sb;
static struct fscrypt_master_key *registry_mk;
static u8 registry_descriptor[FS_KEY_DESCRIPTOR_SIZE];
static int registry_error = -ENOENT;
static int registry_lookups;
static bool registry_allow_tombstone_lookup;

static void fscrypt_mk_get(struct fscrypt_master_key *mk)
{
	CHECK(mk && mk->refs > 0);
	mk->refs++;
}

static void fscrypt_mk_put(struct fscrypt_master_key *mk)
{
	CHECK(mk && mk->refs > 0);
	mk->refs--;
}

static struct fscrypt_master_key *fscrypt_registry_lookup(
		struct super_block *candidate_sb, const u8 *descriptor)
{
	registry_lookups++;
	if (registry_error)
		return ERR_PTR(registry_error);
	if (!registry_mk || candidate_sb != registry_sb ||
	    memcmp(descriptor, registry_descriptor, FS_KEY_DESCRIPTOR_SIZE))
		return ERR_PTR(-ENOENT);
	if (!registry_mk->present && !registry_allow_tombstone_lookup)
		return ERR_PTR(-ENOKEY);
	fscrypt_mk_get(registry_mk);
	return registry_mk;
}

static int fscrypt_mk_acquire(struct fscrypt_master_key *mk, u64 generation,
		struct fscrypt_mk_lease *lease)
{
	if (lease->key)
		return -EBUSY;
	fscrypt_mk_get(mk);
	down_read(&mk->secret_sem);
	if (!mk->present || (generation && generation != mk->generation)) {
		up_read(&mk->secret_sem);
		fscrypt_mk_put(mk);
		return -ENOKEY;
	}
	lease->key = mk;
	lease->generation = mk->generation;
	return 0;
}

static const u8 *fscrypt_mk_secret(const struct fscrypt_mk_lease *lease)
{
	return lease->key ? lease->key->raw : NULL;
}

static void fscrypt_mk_release(struct fscrypt_mk_lease *lease)
{
	struct fscrypt_master_key *mk = lease->key;

	memzero_explicit(lease, sizeof(*lease));
	if (!mk)
		return;
	up_read(&mk->secret_sem);
	fscrypt_mk_put(mk);
}

static int fscrypt_mk_enroll(const struct fscrypt_mk_lease *lease,
		struct fscrypt_mk_owner *owner)
{
	struct fscrypt_master_key *mk = lease->key;

	if (!mk)
		return -EINVAL;
	if (owner->key)
		return -EBUSY;
	mk->owners++;
	fscrypt_mk_get(mk);
	owner->key = mk;
	owner->generation = lease->generation;
	return 0;
}

static void fscrypt_mk_drop_owner(struct fscrypt_mk_owner *owner)
{
	struct fscrypt_master_key *mk = owner->key;

	memzero_explicit(owner, sizeof(*owner));
	if (!mk)
		return;
	CHECK(mk->owners > 0);
	mk->owners--;
	fscrypt_mk_put(mk);
}

static bool fscrypt_mk_remove(struct fscrypt_master_key *mk)
{
	memzero_explicit(mk->raw, sizeof(mk->raw));
	mk->present = false;
	return mk->owners != 0;
}

static int fscrypt_mk_add(struct fscrypt_master_key *mk, const u8 *raw,
		size_t size)
{
	CHECK(size == sizeof(mk->raw));
	if (mk->present)
		return 0;
	memcpy(mk->raw, raw, size);
	mk->generation++;
	mk->present = true;
	return 0;
}
struct fscrypt_context_op {
	const struct operations *cop;
	struct inode *inode;
	enum fscrypt_context_origin origin;
	int phase;
	void *fs_data;
	bool owns_fs_data;
	int *retry_count;
};
#define WARN_ON_ONCE(condition) (!!(condition))

struct crypto_alg { const char *cra_driver_name; };
struct skcipher_alg { struct crypto_alg base; };
struct crypto_skcipher {
	u8 key[64];
	struct skcipher_alg alg;
};
struct crypto_cipher { int unused; };
struct fscrypt_mode {
	const char *friendly_name;
	const char *cipher_str;
	int keysize;
	bool logged_impl_name;
};

static void *fscrypt_info_cachep = (void *)1;
static int skcipher_live;

static void *kmem_cache_alloc(void *cache, gfp_t flags)
{
	void *p;

	CHECK(cache == fscrypt_info_cachep);
	p = host_alloc(sizeof(struct fscrypt_info));
	if (p)
		memset(p, 0xa5, sizeof(struct fscrypt_info));
	return p;
}

static void kmem_cache_free(void *cache, void *p)
{
	CHECK(cache == fscrypt_info_cachep);
	host_free(p);
}

static void fscrypt_mk_init_owner(struct fscrypt_mk_owner *owner)
{
	owner->key = NULL;
	owner->generation = 0;
}

static void fscrypt_mk_drop_owner(struct fscrypt_mk_owner *owner);

static int fscrypt_initialize(unsigned int flags) { return 0; }

static bool fscrypt_valid_enc_modes(u32 contents, u32 filenames)
{
	return contents == FS_ENCRYPTION_MODE_AES_256_XTS &&
	       filenames == FS_ENCRYPTION_MODE_AES_256_CTS;
}

static struct fscrypt_mode *select_encryption_mode(
		const struct fscrypt_info *ci, const struct inode *inode)
{
	static struct fscrypt_mode mode = {
		.friendly_name = "AES-256-XTS",
		.cipher_str = "xts(aes)",
		.keysize = 64,
	};

	if (!S_ISREG(inode->i_mode) ||
	    !fscrypt_valid_enc_modes(ci->ci_data_mode, ci->ci_filename_mode))
		return ERR_PTR(-EINVAL);
	return &mode;
}

static struct crypto_skcipher *crypto_alloc_skcipher(const char *name,
						     int type, int mask)
{
	struct crypto_skcipher *tfm;

	CHECK(!strcmp(name, "xts(aes)"));
	tfm = host_zalloc(sizeof(*tfm));
	if (!tfm)
		return ERR_PTR(-ENOMEM);
	tfm->alg.base.cra_driver_name = "host-xts";
	skcipher_live++;
	return tfm;
}

static void crypto_free_skcipher(struct crypto_skcipher *tfm)
{
	if (tfm) {
		memzero_explicit(tfm, sizeof(*tfm));
		skcipher_live--;
		host_free(tfm);
	}
}

static struct skcipher_alg *crypto_skcipher_alg(struct crypto_skcipher *tfm)
{
	return &tfm->alg;
}

static void crypto_skcipher_set_flags(struct crypto_skcipher *tfm, int flags)
{
}

static int crypto_skcipher_setkey(struct crypto_skcipher *tfm, const u8 *key,
				  size_t size)
{
	CHECK(size == sizeof(tfm->key));
	memcpy(tfm->key, key, size);
	return 0;
}

static void crypto_free_cipher(struct crypto_cipher *tfm)
{
	host_free(tfm);
}

static void kzfree(void *p)
{
	if (p) {
		memzero_explicit(p, 64);
		host_free(p);
	}
}

static bool fscrypt_dummy_context_enabled(struct inode *inode) { return false; }
static int metadata_calls;
static int metadata_result = -EOPNOTSUPP;
static int fscrypt_get_metadata(struct inode *inode, struct fscrypt_info *ci)
{
	metadata_calls++;
	return metadata_result;
}
static int init_essiv_generator(struct fscrypt_info *ci, const u8 *raw_key,
				int keysize)
{
	return -EOPNOTSUPP;
}

static void get_random_bytes(void *p, size_t n) { memset(p, 0x5a, n); }
static int fscrypt_generate_metadata_nonce(u8 *nonce, struct inode *inode,
					   size_t size)
{
	return -EOPNOTSUPP;
}

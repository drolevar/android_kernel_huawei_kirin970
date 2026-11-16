/* SPDX-License-Identifier: GPL-2.0 */
/* Host boundaries only. Not kernel locking, keyrings or a production adapter. */
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>

typedef uint8_t u8;
typedef uint32_t u32;
typedef u8 __u8;
typedef u32 __u32;
#define __packed __attribute__((packed))
#include "declarations.h"

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #x); exit(1); } } while (0)
#define ERR_PTR(e) ((void *)(intptr_t)(e))
#define PTR_ERR(p) ((long)(intptr_t)(p))
#define IS_ERR(p) ((uintptr_t)(p) >= (uintptr_t)-4095)
#define GFP_NOFS 0
#define CRYPTO_TFM_REQ_WEAK_KEY 1
#define CRYPTO_TFM_REQ_MAY_BACKLOG 2
#define CRYPTO_TFM_REQ_MAY_SLEEP 4
#define pr_err(...) ((void)0)
#define fscrypt_warn(...) ((void)0)
#define printk_once(...) ((void)0)
#define KERN_WARNING ""
#define BUILD_BUG_ON(x) _Static_assert(!(x), #x)
static void memzero_explicit(void *p, size_t n) { OPENSSL_cleanse(p, n); }

/* Failure injection is at allocation/setkey/AEAD boundaries, never an echo crypto mock. */
static int fail_alloc, fail_setkey, fail_unwrap, fail_request;
static int tfm_live, request_live;
struct crypto_aead { u8 key[32]; int authsize; };
struct crypto_async_request { void *data; };
struct fscrypt_completion_result { int completion; int res; };
#define DECLARE_FS_COMPLETION_RESULT(x) struct fscrypt_completion_result x = {0}
static void complete(int *c) { *c = 1; }
static void wait_for_completion(int *c) { CHECK(*c); }
struct scatterlist { void *p; size_t n; };
struct aead_request {
    struct crypto_aead *tfm;
    struct scatterlist *src, *dst;
    unsigned int n, ad;
    u8 *iv;
};
static struct crypto_aead *crypto_alloc_aead(const char *name, int a, int b)
{
    CHECK(!strcmp(name, "gcm(aes)"));
    if (fail_alloc) return ERR_PTR(-ENOMEM);
    struct crypto_aead *tfm = calloc(1, sizeof(*tfm));
    CHECK(tfm); tfm_live++; return tfm;
}
static void crypto_free_aead(struct crypto_aead *tfm)
{
    if (!tfm) return;
    CHECK(!IS_ERR(tfm)); memzero_explicit(tfm, sizeof(*tfm)); free(tfm); tfm_live--;
}
static void crypto_aead_set_flags(struct crypto_aead *t, int flags) { (void)t; }
static unsigned int crypto_aead_ivsize(struct crypto_aead *t) { return 12; }
static int crypto_aead_setauthsize(struct crypto_aead *t, int n)
{
    CHECK(n == 16); t->authsize = n; return 0;
}
static int crypto_aead_setkey(struct crypto_aead *t, const u8 *k, size_t n)
{
    if (fail_setkey) return -EINVAL;
    CHECK(n == 32); memcpy(t->key, k, n); return 0;
}
static struct aead_request *aead_request_alloc(struct crypto_aead *t, int flags)
{
    if (fail_request) return NULL;
    struct aead_request *r = calloc(1, sizeof(*r));
    CHECK(r); r->tfm = t; request_live++; return r;
}
static void aead_request_free(struct aead_request *r) { free(r); request_live--; }
static void aead_request_set_callback(struct aead_request *r, int flags,
    void (*callback)(struct crypto_async_request *, int), void *data) { (void)r; }
static void sg_init_one(struct scatterlist *sg, const void *p, size_t n)
{ sg->p = (void *)p; sg->n = n; }
static void aead_request_set_ad(struct aead_request *r, unsigned int n) { r->ad = n; }
static void aead_request_set_crypt(struct aead_request *r, struct scatterlist *s,
                                  struct scatterlist *d, unsigned int n, u8 *iv)
{ r->src = s; r->dst = d; r->n = n; r->iv = iv; }

static int host_gcm(struct aead_request *r, bool enc)
{
    int n = 0, tail = 0, ok;
    u8 temporary[80] = {0};
    u8 *input = r->src->p;
    CHECK(r->ad == 0 && r->tfm->authsize == 16);
    CHECK(r->n == (enc ? 64U : 80U));
    CHECK(r->src->n >= 80 && r->dst->n >= 80);
    if (!enc && fail_unwrap) return -EBADMSG;
    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
    CHECK(c);
    CHECK(EVP_CipherInit_ex(c, EVP_aes_256_gcm(), NULL, NULL, NULL, enc) == 1);
    CHECK(EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) == 1);
    CHECK(EVP_CipherInit_ex(c, NULL, NULL, r->tfm->key, r->iv, enc) == 1);
    CHECK(EVP_CipherUpdate(c, temporary, &n, input, 64) == 1);
    if (!enc) CHECK(EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_TAG, 16, input + 64) == 1);
    ok = EVP_CipherFinal_ex(c, temporary + n, &tail);
    if (enc) CHECK(EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_GET_TAG, 16, temporary + 64) == 1);
    EVP_CIPHER_CTX_free(c);
    if (ok == 1) memcpy(r->dst->p, temporary, enc ? 80 : 64);
    memzero_explicit(temporary, sizeof(temporary));
    return ok == 1 ? 0 : -EBADMSG;
}
static int crypto_aead_encrypt(struct aead_request *r) { return host_gcm(r, true); }
static int crypto_aead_decrypt(struct aead_request *r) { return host_gcm(r, false); }

/* Instrumented read-semaphore/key boundary for unchanged original functions. */
struct semaphore { int readers, down, up, underflow; };
struct user_key_payload { unsigned int datalen; u8 data[sizeof(struct fscrypt_sdp_key)]; };
struct key { int *type; struct semaphore sem; struct user_key_payload *payload; int refs; char *description; };
static int key_type_logon;
static struct key *lookup_key;
static bool revoke_on_lock;
static void down_read(struct semaphore *s)
{
    s->readers++; s->down++;
    if (revoke_on_lock) { lookup_key->payload = NULL; revoke_on_lock = false; }
}
static void up_read(struct semaphore *s)
{ if (s->readers == 0) s->underflow++; else s->readers--; s->up++; }
static void key_put(struct key *key) { CHECK(key && !IS_ERR(key)); CHECK(key->refs > 0); key->refs--; }
static struct key *fscrypt_request_key(const u8 *descriptor, const u8 *prefix, int size)
{
    if (!lookup_key) return ERR_PTR(-ENOKEY);
    lookup_key->refs++; return lookup_key;
}
static const struct user_key_payload *user_key_payload_locked(struct key *key)
{ CHECK(key->sem.readers == 1); return key->payload; }
static const struct user_key_payload *user_key_payload_rcu(struct key *key)
{ return user_key_payload_locked(key); }
struct fscrypt_info { int ci_key_index; struct crypto_aead *ci_gtfm; };
struct inode;
struct operations { const char *key_prefix; int (*set_context)(struct inode *, const void *, size_t, void *); };
struct super_block { struct operations *s_cop; };
struct inode { struct super_block *i_sb; };
static bool fscrypt_valid_enc_modes(u32 data, u32 names)
{ return data == FS_ENCRYPTION_MODE_AES_256_XTS && names == FS_ENCRYPTION_MODE_AES_256_CTS; }
/* Deterministic synthetic bytes, not a random generator for production. */
static void get_random_bytes(void *p, size_t n) { memset(p, 0x5a, n); }
static int fscrypt_generate_metadata_nonce(u8 *n, struct inode *i, size_t size) { return -EOPNOTSUPP; }

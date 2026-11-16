/* SPDX-License-Identifier: GPL-2.0 */
#define EXPORT_SYMBOL_GPL(name)
#include "core-shim.h"
#include "core.h"
#define FS_KEY_DESCRIPTOR_SIZE 8
#define METADATA_BYTE_IN_KDF 16
#define FS_MAX_KEY_SIZE 64
#define GFP_NOFS 0
#define EOK 0
#define ACCESS_ONCE(x) (x)
/* Sequential publication schedule, not a replacement for kernel cmpxchg. */
#define cmpxchg(p, old, new) ({ __typeof__(*(p)) was = *(p); if (was == (old)) *(p) = (new); was; })
#define pr_err(...) ((void)0)
struct crypto_skcipher { int unused; };
struct crypto_aead { int unused; };
struct crypto_cipher { int unused; };
#include "layout.h"
struct inode { struct fscrypt_info *i_crypt_info; unsigned long i_ino; };
struct fscrypt_context {
    u8 flags, contents_encryption_mode, filenames_encryption_mode;
    u8 master_key_descriptor[8];
};
static void *fscrypt_info_cachep = (void *)1;
static int fail_slab, slab_live, transforms, fail_copy, fail_cipher;
static void *file_key;
static void check_before_free(void *p)
{
    if (p == file_key) {
        for (size_t i = 0; i < 64; i++) assert(((u8 *)p)[i] == 0);
        file_key = NULL;
        return;
    }
    struct fscrypt_master_key *k = p;
    for (size_t i = 0; i < sizeof(k->raw); i++) assert(k->raw[i] == 0);
    for (size_t i = 0; i < sizeof(k->fingerprint); i++) assert(k->fingerprint[i] == 0);
    assert(!pthread_rwlock_destroy(&k->secret_sem.lock));
}
static void *kmem_cache_alloc(void *cache, int flags)
{
    assert(cache == fscrypt_info_cachep);
    if (fail_slab) return NULL;
    struct fscrypt_info *ci = malloc(sizeof(*ci));
    assert(ci);
    memset(ci, 0xa5, sizeof(*ci)); /* slab allocation is not zeroing */
    slab_live++;
    return ci;
}
static void kmem_cache_free(void *cache, void *p)
{
    assert(cache == fscrypt_info_cachep);
    struct fscrypt_info *ci = p;
    assert(ci->ci_owner.key == NULL && ci->ci_owner.generation == 0);
    assert(slab_live > 0);
    slab_live--;
    free(p);
}
static void free_transform(void *p) { if (p) { assert(transforms > 0); transforms--; free(p); } }
#define crypto_free_skcipher(p) free_transform(p)
#define crypto_free_aead(p) free_transform(p)
#define crypto_free_cipher(p) free_transform(p)
static void kzfree(void *p) { assert(!p); }
static int memcpy_s(void *dst, size_t cap, const void *src, size_t len)
{
    if (fail_copy) return EINVAL;
    assert(len <= cap); memcpy(dst, src, len); return EOK;
}
static int determine_cipher_type(struct fscrypt_info *ci, struct inode *inode,
                                 const char **cipher, int *size)
{
    return fail_cipher ? -EOPNOTSUPP : 0;
}
#include "release.h"
#include "construct.h"

static int construct(int n, struct fscrypt_info **ci)
{
    switch (n) {
    case 0: return ctor_0(ci);
    case 1: {
        struct inode inode = {0}; struct fscrypt_context ctx = {0};
        const char *cipher; int size;
        struct fscrypt_info *result = hwdps_get_fscrypt_info(&ctx, &inode, &cipher, &size);
        if (IS_ERR(result)) return PTR_ERR(result);
        *ci = result; return 0;
    }
    case 2: return ctor_2(ci);
    case 3: return ctor_3(ci);
    case 4: return ctor_4(ci);
    case 5: return ctor_5(ci);
    default: abort();
    }
}
static struct fscrypt_info *make_ci(int n)
{
    struct fscrypt_info *ci = NULL;
    assert(!construct(n, &ci)); assert(ci);
    assert(ci->ci_owner.key == NULL && ci->ci_owner.generation == 0);
    return ci;
}
static struct fscrypt_master_key *make_key(void)
{
    u8 raw[64] = {3};
    struct fscrypt_master_key *k = fscrypt_mk_alloc(raw, sizeof(raw));
    assert(!IS_ERR(k)); return k;
}
static void attach(struct fscrypt_master_key *k, struct fscrypt_info *ci)
{
    struct fscrypt_mk_lease lease = {0};
    assert(!fscrypt_mk_acquire(k, 0, &lease));
    assert(!fscrypt_mk_enroll(&lease, &ci->ci_owner));
    assert(ci->ci_owner.key == k && ci->ci_owner.generation == 1);
    fscrypt_mk_release(&lease);
}
static int publish(struct inode *inode, struct fscrypt_info *crypt_info, int res)
{
    void *raw_key = NULL;
    if (res) goto out; /* fixture-selected failure after attachment */
#include "publish.h"
}
static void (*const destroy[])(struct fscrypt_info *) = {
    put_crypt_info, f2fs_put_crypt_info, hmfs_put_crypt_info
};
static void drop_case(int n)
{
    struct fscrypt_master_key *k = make_key();
    struct fscrypt_info *ci = make_ci(n == 0 ? 0 : n * 2);
    attach(k, ci);
    ci->ci_ctfm = malloc(sizeof(*ci->ci_ctfm));
    ci->ci_gtfm = malloc(sizeof(*ci->ci_gtfm));
    ci->ci_essiv_tfm = malloc(sizeof(*ci->ci_essiv_tfm));
    assert(ci->ci_ctfm && ci->ci_gtfm && ci->ci_essiv_tfm); transforms = 3;
    file_key = ci->ci_key = malloc(64); assert(file_key); memset(file_key, 0x93, 64);
    allocations++; /* kfree accounts for this separate synthetic file buffer */
    assert(fscrypt_mk_remove(k));
    assert(fscrypt_mk_status(k) == FSCRYPT_MK_BUSY);
    destroy[n](ci);
    assert(!transforms && !file_key && !slab_live);
    assert(atomic_read(&k->owners) == 0 && refcount_read(&k->refs) == 1);
    assert(fscrypt_mk_status(k) == FSCRYPT_MK_ABSENT);
    fscrypt_mk_put(k);
}
int main(int argc, char **argv)
{
    assert(argc == 2);
    const char *s = argv[1];
    if (!strncmp(s, "ctor-", 5)) {
        int n = atoi(s + 5); struct fscrypt_info *ci = make_ci(n);
        destroy[n < 2 ? 0 : n / 2](ci);
    } else if (!strncmp(s, "alloc-failure-", 14)) {
        fail_slab = 1; struct fscrypt_info *ci = NULL;
        assert(construct(atoi(s + 14), &ci) == -ENOMEM); assert(!ci);
    } else if (!strcmp(s, "hwdps-copy-failure") || !strcmp(s, "hwdps-cipher-failure")) {
        fail_copy = !strcmp(s, "hwdps-copy-failure"); fail_cipher = !fail_copy;
        struct fscrypt_info *ci = NULL;
        assert(construct(1, &ci) == (fail_copy ? -EINVAL : -EOPNOTSUPP)); assert(!ci);
    } else if (!strcmp(s, "empty-drop")) {
        for (int n = 0; n < 3; n++) { destroy[n](NULL); destroy[n](make_ci(n * 2)); }
    } else if (!strncmp(s, "drop-", 5)) {
        drop_case(atoi(s + 5));
    } else if (!strcmp(s, "attach-errors")) {
        struct fscrypt_master_key *k = make_key(); struct fscrypt_info *ci = make_ci(0);
        struct fscrypt_mk_lease lease = {0};
        assert(fscrypt_mk_enroll(&lease, &ci->ci_owner) == -EINVAL);
        assert(!ci->ci_owner.key && !ci->ci_owner.generation);
        assert(!fscrypt_mk_acquire(k, 0, &lease));
        atomic_set(&k->owners, INT_MAX);
        assert(fscrypt_mk_enroll(&lease, &ci->ci_owner) == -EOVERFLOW);
        assert(!ci->ci_owner.key && refcount_read(&k->refs) == 2);
        atomic_set(&k->owners, 0);
        assert(!fscrypt_mk_enroll(&lease, &ci->ci_owner));
        assert(fscrypt_mk_enroll(&lease, &ci->ci_owner) == -EBUSY);
        assert(atomic_read(&k->owners) == 1 && refcount_read(&k->refs) == 3);
        fscrypt_mk_release(&lease); put_crypt_info(ci); fscrypt_mk_put(k);
    } else if (!strcmp(s, "private-failure")) {
        struct inode inode = {0}; struct fscrypt_master_key *k = make_key();
        struct fscrypt_info *ci = make_ci(0); attach(k, ci);
        assert(publish(&inode, ci, -EIO) == -EIO); assert(!inode.i_crypt_info);
        assert(!atomic_read(&k->owners) && refcount_read(&k->refs) == 1); fscrypt_mk_put(k);
    } else if (!strcmp(s, "publication-loser")) {
        struct inode inode = {0}; struct fscrypt_master_key *k = make_key();
        struct fscrypt_info *first = make_ci(0), *second = make_ci(0);
        attach(k, first); attach(k, second); assert(atomic_read(&k->owners) == 2);
        assert(!publish(&inode, first, 0)); assert(!publish(&inode, second, 0));
        assert(inode.i_crypt_info == first && slab_live == 1);
        assert(atomic_read(&k->owners) == 1 && refcount_read(&k->refs) == 2);
        assert(fscrypt_mk_remove(k));
        fscrypt_put_encryption_info(&inode); assert(!inode.i_crypt_info);
        fscrypt_put_encryption_info(&inode);
        assert(fscrypt_mk_status(k) == FSCRYPT_MK_ABSENT); fscrypt_mk_put(k);
    } else if (!strcmp(s, "final-eviction")) {
        struct inode inode = {0}; struct fscrypt_master_key *k = make_key();
        struct fscrypt_info *ci = make_ci(0); attach(k, ci); assert(!publish(&inode, ci, 0));
        assert(fscrypt_mk_remove(k)); assert(fscrypt_mk_status(k) == FSCRYPT_MK_BUSY);
        fscrypt_put_encryption_info(&inode); assert(!inode.i_crypt_info);
        assert(fscrypt_mk_status(k) == FSCRYPT_MK_ABSENT);
        assert(refcount_read(&k->refs) == 1); fscrypt_mk_put(k);
    } else if (!strcmp(s, "last-reference")) {
        struct inode inode = {0}; struct fscrypt_master_key *k = make_key();
        struct fscrypt_info *ci = make_ci(0); attach(k, ci); assert(!publish(&inode, ci, 0));
        fscrypt_mk_put(k); assert(frees == 0); fscrypt_put_encryption_info(&inode); assert(frees == 1);
    } else if (!strcmp(s, "parent-child")) {
        struct inode parent = {0}, child = {0}; struct fscrypt_master_key *k = make_key();
        struct fscrypt_info *p = make_ci(0), *c = make_ci(0);
        attach(k, p); attach(k, c); assert(!publish(&parent, p, 0)); assert(!publish(&child, c, 0));
        fscrypt_put_encryption_info(&child);
        assert(parent.i_crypt_info == p && p->ci_owner.generation == 1 && atomic_read(&k->owners) == 1);
        assert(fscrypt_mk_remove(k)); fscrypt_put_encryption_info(&parent); fscrypt_mk_put(k);
    } else abort();
    assert(!slab_live && !transforms && !file_key && allocations == frees && !hashes);
    printf("PASS %s\n", s); return 0;
}

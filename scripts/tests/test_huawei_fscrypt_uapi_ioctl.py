#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Host Clang ASan/UBSan test and mutation suite for Stage 1B fscrypt UAPI ioctls."""
import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path

CASES = (
    "uapi-abi-parity",
    "add-status-remove-clean",
    "idempotent-and-conflicting-readd",
    "busy-inode-retry-lifecycle",
    "dirty-inode-retained-until-sync",
    "readd-advances-gen-retires-old",
    "concurrent-readd-during-remove-owner-check",
    "tombstone-blocks-legacy-fallback",
    "cap-sys-admin-gating",
    "unsupported-v2-and-wrapped-flags",
    "reserved-and-size-validation",
    "efault-copy-and-secret-wipe",
    "remove-all-users-parity",
    "fs-feature-gate",
    "nested-dir-shrink-order",
    "test-dummy-encryption-gcm",
)

MUTATIONS = {
    "add-cap": (
        "if (!capable(CAP_SYS_ADMIN))\n\t\treturn -EACCES;\n\n\tif (copy_from_user(raw",
        "if (false)\n\t\treturn -EACCES;\n\n\tif (copy_from_user(raw",
    ),
    "remove-cap": (
        "if (!capable(CAP_SYS_ADMIN))\n\t\treturn -EACCES;\n\n\tmk = fscrypt_registry_lookup",
        "if (false)\n\t\treturn -EACCES;\n\n\tmk = fscrypt_registry_lookup",
    ),
    "raw-size": (
        "if (arg.raw_size != FSCRYPT_MK_RAW_SIZE)",
        "if (arg.raw_size > FSCRYPT_MK_RAW_SIZE)",
    ),
    "identifier-op": (
        "return -EOPNOTSUPP;\n\tdefault:",
        "return 0;\n\tdefault:",
    ),
    "wrapped-flag": (
        "if (spec_err == -EOPNOTSUPP || arg.flags || arg.__flags || arg.key_id)",
        "if (spec_err == -EOPNOTSUPP || arg.__flags || arg.key_id)",
    ),
    "legacy-wrapped-flag": (
        "if (spec_err == -EOPNOTSUPP || arg.flags || arg.__flags || arg.key_id)",
        "if (spec_err == -EOPNOTSUPP || arg.flags || arg.key_id)",
    ),
    "key-id": (
        "if (arg.key_id && arg.raw_size)",
        "if (false)",
    ),
    "reserved-add": (
        "if (memchr_inv(arg.__reserved, 0, sizeof(arg.__reserved)))\n\t\treturn -EINVAL;\n\n\tif (arg.key_id",
        "if (false)\n\t\treturn -EINVAL;\n\n\tif (arg.key_id",
    ),
    "spec-tail": (
        "if (memchr_inv(spec->u.__reserved + FS_KEY_DESCRIPTOR_SIZE,",
        "if (false && memchr_inv(spec->u.__reserved + FS_KEY_DESCRIPTOR_SIZE,",
    ),
    "enoent-enokey": (
        "return err == -ENOENT ? -ENOKEY : err;",
        "return err;",
    ),
    "busy-flag": (
        "status_flags |=\n\t\t\t\tFSCRYPT_KEY_REMOVAL_STATUS_FLAG_FILES_BUSY;",
        "status_flags |= 0;",
    ),
    "sync-fs": (
        "err1 = sync_filesystem(sb);",
        "err1 = 0;",
    ),
    "dir-shrink": (
        "if (S_ISDIR(inode->i_mode))",
        "if (false)",
    ),
    "drop-dirty": (
        "if (inode->i_state & I_DIRTY_ALL)",
        "if (false)",
    ),
    "drop-gen": (
        "READ_ONCE(mk->generation) != ci->ci_owner.generation;",
        "false;",
    ),
    "retired-gen-filter": (
        "ci->ci_owner.generation <= retired_gen)",
        "ci->ci_owner.generation == 0)",
    ),
    "status-flags-reset": (
        "arg.status_flags = 0;",
        "arg.status_flags = 99;",
    ),
    "dummy-ctx": (
        "if (dummy_ctx) {",
        "if (false && dummy_ctx) {",
    ),
    "ext4-feature-gate": (
        "case FS_IOC_ADD_ENCRYPTION_KEY:\n\t\tif (!ext4_has_feature_encrypt(sb))",
        "case FS_IOC_ADD_ENCRYPTION_KEY:\n\t\tif (false)",
    ),
    "f2fs-feature-gate": (
        "static int f2fs_ioc_add_encryption_key(struct file *filp, unsigned long arg)\n{\n\tif (!f2fs_sb_has_encrypt(file_inode(filp)->i_sb))",
        "static int f2fs_ioc_add_encryption_key(struct file *filp, unsigned long arg)\n{\n\tif (false)",
    ),
    "ext4-drop-hook": (
        "if (!drop)\n\t\tdrop = fscrypt_drop_inode(inode);\n\n\ttrace_ext4_drop_inode",
        "if (false)\n\t\tdrop = fscrypt_drop_inode(inode);\n\n\ttrace_ext4_drop_inode",
    ),
    "f2fs-drop-hook": (
        "if (!ret)\n\t\tret = fscrypt_drop_inode(inode);\n\ttrace_f2fs_drop_inode",
        "if (false)\n\t\tret = fscrypt_drop_inode(inode);\n\ttrace_f2fs_drop_inode",
    ),
}


HOST_SHIM = '#include <assert.h>\n#include <errno.h>\n#include <limits.h>\n#include <linux/ioctl.h>\n#include <openssl/evp.h>\n#include <openssl/sha.h>\n#include <pthread.h>\n#include <sched.h>\n#include <stdatomic.h>\n#include <stdbool.h>\n#include <stddef.h>\n#include <stdint.h>\n#include <stdio.h>\n#include <stdlib.h>\n#include <string.h>\n#include <sys/stat.h>\n\ntypedef uint8_t u8;\ntypedef uint16_t u16;\ntypedef uint32_t u32;\ntypedef uint64_t u64;\ntypedef uint8_t __u8;\ntypedef uint16_t __u16;\ntypedef uint32_t __u32;\ntypedef uint64_t __u64;\ntypedef int16_t __le16;\ntypedef uint32_t __le32;\ntypedef unsigned short umode_t;\ntypedef int key_serial_t;\ntypedef unsigned int key_perm_t;\ntypedef unsigned int gfp_t;\n\ntypedef atomic_int atomic_t;\ntypedef atomic_uint refcount_t;\n\n#define U64_MAX UINT64_MAX\n#define __init\n#define __exit\n#define __user\n#define __packed __attribute__((packed))\n#define EXPORT_SYMBOL(name)\n#define EXPORT_SYMBOL_GPL(name)\n#define GFP_KERNEL 0\n#define GFP_NOFS 0\n#define SHA256_DIGEST_SIZE 32\n#define FS_KEY_DERIVATION_CIPHER_OVERHEAD 16\n#define HWDPS_XATTR_ENABLE_FLAG_NEW 0x0020\n#define HWDPS_XATTR_ENABLE_FLAG 0x0010\n\n#define CAP_SYS_ADMIN 21\n#define GLOBAL_ROOT_UID 0\n#define GLOBAL_ROOT_GID 0\n#define KEY_POS_SEARCH 0x08000000\n#define KEY_USR_SEARCH 0x00080000\n#define KEY_USR_READ 0x00020000\n#define KEY_USR_VIEW 0x00010000\n#define KEY_ALLOC_NOT_IN_QUOTA 2\n#define KEY_FLAG_KEEP 8\n#define KEY_FLAG_INVALIDATED 5\n#define KEY_FLAG_REVOKED 1\n\n#define I_DIRTY_SYNC (1UL << 0)\n#define I_DIRTY_DATASYNC (1UL << 1)\n#define I_DIRTY_PAGES (1UL << 2)\n#define I_DIRTY_ALL (I_DIRTY_SYNC | I_DIRTY_DATASYNC | I_DIRTY_PAGES)\n#define I_NEW (1UL << 3)\n#define I_SYNC (1UL << 4)\n#define I_FREEING (1UL << 5)\n#define I_WILL_FREE (1UL << 6)\n#define FI_DIRTY_INODE 1\n#define FI_INLINE_DATA 2\n#define FI_INLINE_DENTRY 3\n\n#define ERR_PTR(e) ((void *)(intptr_t)(e))\n#define PTR_ERR(p) ((intptr_t)(p))\n#define IS_ERR(p) ((uintptr_t)(p) >= (uintptr_t)-4095)\n#define ERR_CAST(p) ((void *)(p))\n#define BUILD_BUG_ON(e) _Static_assert(!(e), #e)\n#define WARN_ON_ONCE(x) ({ bool _bad = !!(x); if (_bad) abort(); _bad; })\n#define cond_resched() sched_yield()\n#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))\n\n#define CHECK(cond) do {\t\t\t\t\t\t\\\n\tif (!(cond)) {\t\t\t\t\t\t\t\\\n\t\tfprintf(stderr, "CHECK FAILED %s:%d: %s\\n",\t\t\\\n\t\t\t__FILE__, __LINE__, #cond);\t\t\t\\\n\t\texit(1);\t\t\t\t\t\t\\\n\t}\t\t\t\t\t\t\t\t\\\n} while (0)\n\n#ifndef container_of\n#define container_of(ptr, type, member) ({\t\t\t\t\\\n\tconst typeof(((type *)0)->member) *__mptr = (ptr);\t\t\\\n\t(type *)((char *)__mptr - offsetof(type, member));\t\t\\\n})\n#endif\n\nstruct list_head {\n\tstruct list_head *next;\n\tstruct list_head *prev;\n};\n\nstatic inline void INIT_LIST_HEAD(struct list_head *list)\n{\n\tlist->next = list;\n\tlist->prev = list;\n}\n\nstatic inline void list_add_tail(struct list_head *new_n, struct list_head *h)\n{\n\tstruct list_head *prev = h->prev;\n\n\th->prev = new_n;\n\tnew_n->next = h;\n\tnew_n->prev = prev;\n\tprev->next = new_n;\n}\n\nstatic inline void list_del_init(struct list_head *entry)\n{\n\tentry->next->prev = entry->prev;\n\tentry->prev->next = entry->next;\n\tINIT_LIST_HEAD(entry);\n}\n\nstatic inline int list_empty(const struct list_head *head)\n{\n\treturn head->next == head;\n}\n\n#define list_entry(ptr, type, member) container_of(ptr, type, member)\n#define list_first_entry(ptr, type, member)\t\t\t\t\\\n\tlist_entry((ptr)->next, type, member)\n#define list_for_each_entry(pos, head, member)\t\t\t\t\\\n\tfor (pos = list_first_entry(head, typeof(*pos), member);\t\\\n\t     &pos->member != (head);\t\t\t\t\t\\\n\t     pos = list_first_entry(&pos->member, typeof(*pos), member))\n#define list_for_each_entry_safe(pos, n, head, member)\t\t\t\\\n\tfor (pos = list_first_entry(head, typeof(*pos), member),\t\\\n\t     n = list_first_entry(&pos->member, typeof(*pos), member);\t\\\n\t     &pos->member != (head);\t\t\t\t\t\\\n\t     pos = n,\t\t\t\t\t\t\t\\\n\t     n = list_first_entry(&n->member, typeof(*n), member))\n\n#define atomic_read(p) atomic_load(p)\n#define atomic_set(p, n) atomic_store(p, n)\n#define atomic_inc(p) ((void)atomic_fetch_add(p, 1))\n#define atomic_dec(p) ((void)atomic_fetch_sub(p, 1))\n#define atomic_dec_and_test(p) (atomic_fetch_sub(p, 1) == 1)\nstatic bool atomic_add_unless(atomic_t *p, int n, int unless)\n{\n\tint v = atomic_load(p);\n\n\tdo {\n\t\tif (v == unless)\n\t\t\treturn false;\n\t} while (!atomic_compare_exchange_weak(p, &v, v + n));\n\treturn true;\n}\n\n#define refcount_set(p, n) atomic_store(p, n)\n#define refcount_read(p) atomic_load(p)\nstatic void refcount_inc(refcount_t *p)\n{\n\tCHECK(atomic_fetch_add(p, 1) > 0);\n}\nstatic bool refcount_dec_and_test(refcount_t *p)\n{\n\tunsigned int n = atomic_fetch_sub(p, 1);\n\n\tCHECK(n > 0);\n\treturn n == 1;\n}\n\n#define READ_ONCE(x) __atomic_load_n(&(x), __ATOMIC_RELAXED)\n#define WRITE_ONCE(x, v) __atomic_store_n(&(x), v, __ATOMIC_RELAXED)\n#define smp_load_acquire(p) __atomic_load_n(p, __ATOMIC_ACQUIRE)\n#define smp_store_release(p, v) __atomic_store_n(p, v, __ATOMIC_RELEASE)\n\nstruct rw_semaphore {\n\tpthread_rwlock_t lock;\n};\nstatic void init_rwsem(struct rw_semaphore *s)\n{\n\tCHECK(!pthread_rwlock_init(&s->lock, NULL));\n}\nstatic void destroy_rwsem(struct rw_semaphore *s)\n{\n\tCHECK(!pthread_rwlock_destroy(&s->lock));\n}\nstatic void down_read(struct rw_semaphore *s)\n{\n\tCHECK(!pthread_rwlock_rdlock(&s->lock));\n}\nstatic void up_read(struct rw_semaphore *s)\n{\n\tCHECK(!pthread_rwlock_unlock(&s->lock));\n}\nstatic void down_write(struct rw_semaphore *s)\n{\n\tCHECK(!pthread_rwlock_wrlock(&s->lock));\n}\nstatic void up_write(struct rw_semaphore *s)\n{\n\tCHECK(!pthread_rwlock_unlock(&s->lock));\n}\n\ntypedef struct {\n\tpthread_mutex_t m;\n} spinlock_t;\nstatic void spin_lock_init(spinlock_t *l)\n{\n\tCHECK(!pthread_mutex_init(&l->m, NULL));\n}\nstatic void spin_lock(spinlock_t *l)\n{\n\tCHECK(!pthread_mutex_lock(&l->m));\n}\nstatic void spin_unlock(spinlock_t *l)\n{\n\tCHECK(!pthread_mutex_unlock(&l->m));\n}\n\n#define DEFINE_MUTEX(n) pthread_mutex_t n = PTHREAD_MUTEX_INITIALIZER\n#define mutex_lock(p) CHECK(!pthread_mutex_lock(p))\n#define mutex_unlock(p) CHECK(!pthread_mutex_unlock(p))\n\nstatic void memzero_explicit(void *p, size_t n)\n{\n\tvolatile u8 *v = p;\n\n\twhile (n--)\n\t\t*v++ = 0;\n}\n\nstatic void *memchr_inv(const void *start, int c, size_t bytes)\n{\n\tconst u8 *p = start;\n\n\tfor (size_t i = 0; i < bytes; i++) {\n\t\tif (p[i] != (u8)c)\n\t\t\treturn (void *)(p + i);\n\t}\n\treturn NULL;\n}\n\nstatic int crypto_memneq(const void *a, const void *b, size_t n)\n{\n\treturn memcmp(a, b, n) != 0;\n}\n\nstatic int live_kmallocs;\nstatic int fail_alloc;\nstatic void *kzalloc(size_t n, int flags)\n{\n\tvoid *p;\n\n\tif (fail_alloc)\n\t\treturn NULL;\n\tp = calloc(1, n);\n\tCHECK(p);\n\tlive_kmallocs++;\n\treturn p;\n}\nstatic void *kmalloc(size_t n, int flags)\n{\n\treturn kzalloc(n, flags);\n}\nstatic void kfree(void *p)\n{\n\tif (p) {\n\t\tCHECK(live_kmallocs > 0);\n\t\tlive_kmallocs--;\n\t\tfree(p);\n\t}\n}\nstatic void kzfree(void *p)\n{\n\tkfree(p);\n}\n\nstatic const void *fault_user_addr;\nstatic unsigned long copy_from_user(void *to, const void __user *from,\n\t\t\t\t    unsigned long n)\n{\n\tif (!from || from == fault_user_addr)\n\t\treturn n;\n\tmemcpy(to, from, n);\n\treturn 0;\n}\nstatic unsigned long copy_to_user(void __user *to, const void *from,\n\t\t\t\t  unsigned long n)\n{\n\tif (!to || to == fault_user_addr)\n\t\treturn n;\n\tmemcpy(to, from, n);\n\treturn 0;\n}\n#define put_user(val, ptr) ({\t\t\t\t\t\t\\\n\tint _err = 0;\t\t\t\t\t\t\t\\\n\ttypeof(*(ptr)) _v = (val);\t\t\t\t\t\\\n\tif (!(ptr) || (const void *)(ptr) == fault_user_addr)\t\t\\\n\t\t_err = -EFAULT;\t\t\t\t\t\t\\\n\telse\t\t\t\t\t\t\t\t\\\n\t\t*(ptr) = _v;\t\t\t\t\t\t\\\n\t_err;\t\t\t\t\t\t\t\t\\\n})\n\nstruct crypto_shash {\n\tint dummy;\n};\nstruct shash_desc {\n\tstruct crypto_shash *tfm;\n\tint flags;\n};\n#define SHASH_DESC_ON_STACK(n, t) struct shash_desc s_##n = {0}, *n = &s_##n\nstatic struct crypto_shash *crypto_alloc_shash(const char *name, int t, int m)\n{\n\tCHECK(!strcmp(name, "sha256"));\n\treturn calloc(1, sizeof(struct crypto_shash));\n}\nstatic void crypto_free_shash(struct crypto_shash *p)\n{\n\tfree(p);\n}\nstatic int crypto_shash_digest(struct shash_desc *d, const u8 *data, size_t n,\n\t\t\t       u8 *out)\n{\n\tCHECK(SHA256(data, n, out));\n\treturn 0;\n}\nstatic void shash_desc_zero(struct shash_desc *d)\n{\n\tmemzero_explicit(d, sizeof(*d));\n}\n\nstruct module {\n\tint refs;\n};\nstatic struct module test_module;\n#define THIS_MODULE (&test_module)\nstatic bool try_module_get(struct module *m)\n{\n\tm->refs++;\n\treturn true;\n}\nstatic void module_put(struct module *m)\n{\n\tif (m) {\n\t\tCHECK(m->refs > 0);\n\t\tm->refs--;\n\t}\n}\n\nstatic bool test_admin = true;\nstatic bool capable(int cap)\n{\n\tCHECK(cap == CAP_SYS_ADMIN);\n\treturn test_admin;\n}\n\nstruct cred {\n\tint uid;\n};\nstatic struct cred test_cred;\nstatic const struct cred *current_cred(void)\n{\n\treturn &test_cred;\n}\n\nstruct seq_file {\n\tchar data[128];\n};\nstatic void seq_puts(struct seq_file *m, const char *s)\n{\n\tstrcat(m->data, s);\n}\n\nstatic char *bin2hex(char *out, const void *in, size_t n)\n{\n\tstatic const char hex[] = "0123456789abcdef";\n\tconst u8 *p = in;\n\n\twhile (n--) {\n\t\t*out++ = hex[*p >> 4];\n\t\t*out++ = hex[*p++ & 15];\n\t}\n\treturn out;\n}\n\nstatic bool test_bit(int bit, const unsigned long *p)\n{\n\treturn (*p & (1UL << bit)) != 0;\n}\nstatic void set_bit(int bit, unsigned long *p)\n{\n\t*p |= 1UL << bit;\n}\n\n/* AEAD gcm(aes) backed by OpenSSL for real dummy_ctx wrap-then-unwrap. */\n#define CRYPTO_TFM_REQ_WEAK_KEY 0x00000100\n#define CRYPTO_TFM_REQ_MAY_BACKLOG 0x00000400\n#define CRYPTO_TFM_REQ_MAY_SLEEP 0x00000200\nstruct crypto_async_request {\n\tvoid *data;\n};\nstruct completion {\n\tint done;\n};\nstruct fscrypt_completion_result {\n\tstruct completion completion;\n\tint res;\n};\n#define DECLARE_FS_COMPLETION_RESULT(n) struct fscrypt_completion_result n = {}\nstatic void complete(struct completion *c)\n{\n\tc->done = 1;\n}\nstatic void wait_for_completion(struct completion *c)\n{\n}\nstruct scatterlist {\n\tvoid *buf;\n\tunsigned int len;\n};\nstatic void sg_init_one(struct scatterlist *sg, const void *buf,\n\t\t\tunsigned int buflen)\n{\n\tsg->buf = (void *)buf;\n\tsg->len = buflen;\n}\nstruct crypto_aead {\n\tu8 key[32];\n\tunsigned int authsize;\n\tunsigned int ivsize;\n\tbool has_key;\n};\nstruct aead_request {\n\tstruct crypto_aead *tfm;\n\tstruct scatterlist *src;\n\tstruct scatterlist *dst;\n\tunsigned int cryptlen;\n\tu8 *iv;\n};\nstatic int aead_allocs;\nstatic struct crypto_aead *crypto_alloc_aead(const char *alg, u32 t, u32 m)\n{\n\tstruct crypto_aead *tfm;\n\n\tCHECK(!strcmp(alg, "gcm(aes)"));\n\ttfm = calloc(1, sizeof(*tfm));\n\tCHECK(tfm);\n\ttfm->ivsize = 12;\n\taead_allocs++;\n\treturn tfm;\n}\nstatic void crypto_free_aead(struct crypto_aead *tfm)\n{\n\tif (tfm) {\n\t\taead_allocs--;\n\t\tmemzero_explicit(tfm, sizeof(*tfm));\n\t\tfree(tfm);\n\t}\n}\nstatic void crypto_aead_set_flags(struct crypto_aead *tfm, u32 f)\n{\n}\nstatic unsigned int crypto_aead_ivsize(struct crypto_aead *tfm)\n{\n\treturn tfm->ivsize;\n}\nstatic int crypto_aead_setauthsize(struct crypto_aead *tfm,\n\t\t\t\t   unsigned int authsize)\n{\n\ttfm->authsize = authsize;\n\treturn 0;\n}\nstatic int crypto_aead_setkey(struct crypto_aead *tfm, const u8 *key,\n\t\t\t      unsigned int keylen)\n{\n\tCHECK(keylen == 32);\n\tmemcpy(tfm->key, key, 32);\n\ttfm->has_key = true;\n\treturn 0;\n}\nstatic struct aead_request *aead_request_alloc(struct crypto_aead *tfm,\n\t\t\t\t\t       gfp_t gfp)\n{\n\tstruct aead_request *req = calloc(1, sizeof(*req));\n\n\tCHECK(req);\n\treq->tfm = tfm;\n\treturn req;\n}\nstatic void aead_request_free(struct aead_request *req)\n{\n\tfree(req);\n}\nstatic void aead_request_set_callback(struct aead_request *req, u32 flags,\n\t\t\t\t      void (*cb)(struct crypto_async_request *,\n\t\t\t\t\t\t int),\n\t\t\t\t      void *data)\n{\n}\nstatic void aead_request_set_ad(struct aead_request *req,\n\t\t\t\tunsigned int assoclen)\n{\n\tCHECK(assoclen == 0);\n}\nstatic void aead_request_set_crypt(struct aead_request *req,\n\t\t\t\t   struct scatterlist *src,\n\t\t\t\t   struct scatterlist *dst,\n\t\t\t\t   unsigned int cryptlen, u8 *iv)\n{\n\treq->src = src;\n\treq->dst = dst;\n\treq->cryptlen = cryptlen;\n\treq->iv = iv;\n}\nstatic int crypto_aead_encrypt(struct aead_request *req)\n{\n\tEVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();\n\tconst u8 *src = req->src->buf;\n\tu8 *dst = req->dst->buf;\n\tint outlen = 0, finlen = 0;\n\n\tCHECK(ctx && req->tfm->has_key && req->tfm->authsize == 16);\n\tCHECK(req->cryptlen == 64);\n\tCHECK(EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) == 1);\n\tCHECK(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,\n\t\t\t\t  (int)req->tfm->ivsize, NULL) == 1);\n\tCHECK(EVP_EncryptInit_ex(ctx, NULL, NULL, req->tfm->key, req->iv) == 1);\n\tCHECK(EVP_EncryptUpdate(ctx, dst, &outlen, src, (int)req->cryptlen) == 1);\n\tCHECK(EVP_EncryptFinal_ex(ctx, dst + outlen, &finlen) == 1);\n\tCHECK(outlen + finlen == 64);\n\tCHECK(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, dst + 64) == 1);\n\tEVP_CIPHER_CTX_free(ctx);\n\treturn 0;\n}\nstatic int crypto_aead_decrypt(struct aead_request *req)\n{\n\tEVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();\n\tconst u8 *src = req->src->buf;\n\tu8 *dst = req->dst->buf;\n\tint outlen = 0, finlen = 0, ok;\n\n\tCHECK(ctx && req->tfm->has_key && req->tfm->authsize == 16);\n\tCHECK(req->cryptlen == 80);\n\tCHECK(EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) == 1);\n\tCHECK(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,\n\t\t\t\t  (int)req->tfm->ivsize, NULL) == 1);\n\tCHECK(EVP_DecryptInit_ex(ctx, NULL, NULL, req->tfm->key, req->iv) == 1);\n\tCHECK(EVP_DecryptUpdate(ctx, dst, &outlen, src, 64) == 1);\n\tCHECK(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16,\n\t\t\t\t  (void *)(src + 64)) == 1);\n\tok = EVP_DecryptFinal_ex(ctx, dst + outlen, &finlen);\n\tEVP_CIPHER_CTX_free(ctx);\n\treturn ok == 1 ? 0 : -EBADMSG;\n}\n\n#define pr_err(...) ((void)0)\n#define pr_warn_ratelimited(...) ((void)0)\n#define fscrypt_warn(...) ((void)0)\n#define trace_ext4_drop_inode(inode, drop) ((void)0)\n#define trace_f2fs_drop_inode(inode, drop) ((void)0)\n#define trace_hmfs_drop_inode(inode, drop) ((void)0)\n\n#include "uapi_subject.h"\n#ifdef HAS_BIONIC_UAPI\n#include "bionic_uapi.h"\n#endif\n\n#define MAX_HISI_KEY_INDEX 31\n#define SDP_MAX_KEY_SIZE 32\nstruct key;\nstruct key_preparsed_payload;\nenum fscrypt_context_origin { FSCRYPT_CTX_OWNED_POLICY = 0 };\nstruct fscrypt_context_op;\nstruct key_type {\n\tconst char *name;\n\tint (*instantiate)(struct key *key, struct key_preparsed_payload *prep);\n\tvoid (*destroy)(struct key *key);\n\tvoid (*describe)(const struct key *key, struct seq_file *m);\n};\nstruct key_preparsed_payload {\n\tconst void *data;\n\tsize_t datalen;\n};\nstruct user_key_payload {\n\tunsigned short datalen;\n\tchar data[128] __attribute__((aligned(8)));\n};\nstruct key {\n\tkey_perm_t perm;\n\tunsigned long flags;\n\tatomic_t refs;\n\tstruct key_type *type;\n\tchar *description;\n\tstruct {\n\t\tvoid *data[1];\n\t} payload;\n\tstruct user_key_payload *rcu_payload;\n\tstruct rw_semaphore sem;\n\tbool positive;\n\tbool ring;\n\tint state_error;\n\tpthread_mutex_t links_lock;\n\tstruct key *links[32];\n\tsize_t count;\n};\ntypedef struct key *key_ref_t;\n\nstruct fscrypt_info;\nstruct super_block;\nstruct inode;\nstruct dentry;\nstruct file;\n\n#include "common_subject.h"\n\nstruct super_operations {\n\tint (*drop_inode)(struct inode *inode);\n};\n\nstruct super_block {\n\tchar s_id[32];\n\tunsigned long s_flags;\n\tstruct key *s_fscrypt_keys;\n\tstruct module *s_fscrypt_keys_owner;\n\tspinlock_t s_inode_list_lock;\n\tstruct list_head s_inodes;\n\tstruct rw_semaphore s_umount;\n\tconst struct super_operations *s_op;\n\tconst struct fscrypt_operations *s_cop;\n\tbool has_encrypt;\n};\n\nstruct inode {\n\tunsigned long i_ino;\n\tumode_t i_mode;\n\tunsigned int i_nlink;\n\tstruct super_block *i_sb;\n\tatomic_t i_count;\n\tunsigned long i_state;\n\tspinlock_t i_lock;\n\tstruct list_head i_sb_list;\n\tstruct fscrypt_info *i_crypt_info;\n\tstruct list_head dentries;\n\tint open_refs;\n\tbool evicted;\n\tbool dummy_unencrypted;\n\tbool has_ctx;\n\tstruct fscrypt_context ctx;\n\tbool is_sdp_file;\n\tunsigned int f2fs_flags;\n\tint dirty_inode_calls;\n};\n\nstruct dentry {\n\tstruct dentry *d_parent;\n\tstruct inode *d_inode;\n\tstruct list_head d_children;\n\tstruct list_head d_child;\n\tstruct list_head d_alias;\n\tint pin_count;\n};\n\nstruct file {\n\tstruct inode *f_inode;\n};\n\nstatic inline struct inode *file_inode(const struct file *f)\n{\n\treturn f->f_inode;\n}\n\nstatic struct key_type key_type_logon = { .name = "logon" };\nstatic struct key_type *registered_key_type;\nstatic struct key *legacy_logon_key;\n\nstatic int register_key_type(struct key_type *t)\n{\n\tregistered_key_type = t;\n\treturn 0;\n}\n\nstatic void key_put(struct key *k)\n{\n\tif (!k || IS_ERR(k))\n\t\treturn;\n\tif (atomic_dec_and_test(&k->refs)) {\n\t\tif (k->ring) {\n\t\t\tfor (size_t i = 0; i < k->count; i++)\n\t\t\t\tkey_put(k->links[i]);\n\t\t} else if (k->positive && k->type && k->type->destroy) {\n\t\t\tk->type->destroy(k);\n\t\t}\n\t\tdestroy_rwsem(&k->sem);\n\t\tpthread_mutex_destroy(&k->links_lock);\n\t\tfree(k->description);\n\t\tfree(k->rcu_payload);\n\t\tfree(k);\n\t}\n}\n\nstatic void unregister_key_type(struct key_type *t)\n{\n\tCHECK(registered_key_type == t);\n\tregistered_key_type = NULL;\n}\n\nstatic struct key *new_test_key(struct key_type *t, const char *d, bool ring,\n\t\t\t\tkey_perm_t perm)\n{\n\tstruct key *k = calloc(1, sizeof(*k));\n\n\tCHECK(k);\n\tatomic_set(&k->refs, 1);\n\tk->type = t;\n\tk->description = strdup(d);\n\tCHECK(k->description);\n\tk->ring = ring;\n\tk->perm = perm;\n\tinit_rwsem(&k->sem);\n\tCHECK(!pthread_mutex_init(&k->links_lock, NULL));\n\treturn k;\n}\n\nstatic struct key *keyring_alloc(const char *d, int uid, int gid,\n\t\t\t\t const struct cred *cred, int perm, int flags,\n\t\t\t\t void *restr, void *dest)\n{\n\tstruct key *k = new_test_key(NULL, d, true, perm);\n\n\tk->positive = true;\n\treturn k;\n}\n\nstatic struct key *key_alloc(struct key_type *t, const char *d, int uid,\n\t\t\t     int gid, const struct cred *cred, int perm,\n\t\t\t     int flags, void *restr)\n{\n\tCHECK(t == registered_key_type);\n\treturn new_test_key(t, d, false, perm);\n}\n\nstatic int key_instantiate_and_link(struct key *k, const void *data, size_t len,\n\t\t\t\t    struct key *ring, void *auth)\n{\n\tstruct key_preparsed_payload prep = { data, len };\n\tint err = k->type->instantiate(k, &prep);\n\n\tif (err)\n\t\treturn err;\n\tk->positive = true;\n\tif (test_bit(KEY_FLAG_KEEP, &ring->flags))\n\t\tset_bit(KEY_FLAG_KEEP, &k->flags);\n\tpthread_mutex_lock(&ring->links_lock);\n\tCHECK(ring->count < ARRAY_SIZE(ring->links));\n\tatomic_inc(&k->refs);\n\tring->links[ring->count++] = k;\n\tpthread_mutex_unlock(&ring->links_lock);\n\treturn 0;\n}\n\nstatic key_ref_t make_key_ref(struct key *k, bool possessed)\n{\n\treturn (key_ref_t)((uintptr_t)k | (possessed ? 1UL : 0UL));\n}\nstatic struct key *key_ref_to_ptr(key_ref_t r)\n{\n\treturn (struct key *)((uintptr_t)r & ~1UL);\n}\nstatic bool key_is_positive(const struct key *k)\n{\n\treturn k->positive;\n}\nstatic int key_validate(const struct key *k)\n{\n\treturn k->state_error;\n}\nstatic key_ref_t keyring_search(key_ref_t ring_ref, struct key_type *t,\n\t\t\t\tconst char *d)\n{\n\tstruct key *ring = key_ref_to_ptr(ring_ref);\n\tkey_ref_t res = ERR_PTR(-EAGAIN);\n\n\tpthread_mutex_lock(&ring->links_lock);\n\tfor (size_t i = 0; i < ring->count; i++) {\n\t\tstruct key *k = ring->links[i];\n\n\t\tif (k->type != t || strcmp(k->description, d))\n\t\t\tcontinue;\n\t\tif (k->flags & ((1UL << KEY_FLAG_INVALIDATED) |\n\t\t\t\t(1UL << KEY_FLAG_REVOKED))) {\n\t\t\tres = ERR_PTR(-EKEYREVOKED);\n\t\t} else if (k->state_error) {\n\t\t\tres = ERR_PTR(k->state_error);\n\t\t} else {\n\t\t\tatomic_inc(&k->refs);\n\t\t\tres = make_key_ref(k, true);\n\t\t}\n\t\tbreak;\n\t}\n\tpthread_mutex_unlock(&ring->links_lock);\n\treturn res;\n}\n\nstatic struct key *request_key(struct key_type *type, const char *desc,\n\t\t\t       const char *callout)\n{\n\tCHECK(type == &key_type_logon);\n\tif (legacy_logon_key && !strcmp(legacy_logon_key->description, desc)) {\n\t\tatomic_inc(&legacy_logon_key->refs);\n\t\treturn legacy_logon_key;\n\t}\n\treturn ERR_PTR(-ENOKEY);\n}\nstatic struct key *fscrypt_request_key(const u8 *descriptor,\n\t\t\t\t       const u8 *prefix, int prefix_size)\n{\n\tchar full[64];\n\tCHECK(prefix_size + (FS_KEY_DESCRIPTOR_SIZE * 2) + 1 <= (int)sizeof(full));\n\tmemcpy(full, prefix, prefix_size);\n\t*bin2hex(full + prefix_size, descriptor, FS_KEY_DESCRIPTOR_SIZE) = 0;\n\treturn request_key(&key_type_logon, full, NULL);\n}\nstatic struct user_key_payload *user_key_payload_rcu(const struct key *key)\n{\n\treturn key->rcu_payload;\n}\nstatic struct user_key_payload *user_key_payload_locked(const struct key *key)\n{\n\treturn key->rcu_payload;\n}\n\nstatic void __iget(struct inode *inode)\n{\n\tatomic_inc(&inode->i_count);\n}\nstatic int generic_drop_inode(struct inode *inode)\n{\n\treturn !inode->i_nlink;\n}\n\nstatic int fail_sync;\nstatic bool sync_leaves_dirty;\nstatic int sync_filesystem(struct super_block *sb)\n{\n\tstruct inode *inode;\n\n\tif (fail_sync)\n\t\treturn fail_sync;\n\tif (sync_leaves_dirty)\n\t\treturn 0;\n\tspin_lock(&sb->s_inode_list_lock);\n\tlist_for_each_entry(inode, &sb->s_inodes, i_sb_list) {\n\t\tspin_lock(&inode->i_lock);\n\t\tinode->i_state &= ~I_DIRTY_ALL;\n\t\tspin_unlock(&inode->i_lock);\n\t}\n\tspin_unlock(&sb->s_inode_list_lock);\n\treturn 0;\n}\n\nstatic void model_evict_inode(struct inode *inode);\nstatic void iput(struct inode *inode)\n{\n\tint drop;\n\n\tif (!inode)\n\t\treturn;\n\tif (!atomic_dec_and_test(&inode->i_count))\n\t\treturn;\n\tspin_lock(&inode->i_lock);\n\tdrop = inode->i_sb->s_op->drop_inode(inode);\n\tif (drop) {\n\t\tinode->i_state |= I_FREEING;\n\t\tspin_unlock(&inode->i_lock);\n\t\tmodel_evict_inode(inode);\n\t\treturn;\n\t}\n\tspin_unlock(&inode->i_lock);\n}\n\nstatic struct dentry *d_find_any_alias(struct inode *inode)\n{\n\tif (list_empty(&inode->dentries))\n\t\treturn NULL;\n\treturn list_first_entry(&inode->dentries, struct dentry, d_alias);\n}\nstatic void dput(struct dentry *dentry)\n{\n}\n\nstatic void drop_dentry(struct dentry *d)\n{\n\tstruct inode *inode = d->d_inode;\n\n\tlist_del_init(&d->d_child);\n\tlist_del_init(&d->d_alias);\n\tfree(d);\n\tiput(inode);\n}\n\nstatic bool shrink_dcache_node(struct dentry *dir)\n{\n\tstruct dentry *child, *n;\n\tbool dropped = false;\n\n\tlist_for_each_entry_safe(child, n, &dir->d_children, d_child) {\n\t\tif (!list_empty(&child->d_children))\n\t\t\tdropped |= shrink_dcache_node(child);\n\t\tif (list_empty(&child->d_children) && child->pin_count == 0) {\n\t\t\tdrop_dentry(child);\n\t\t\tdropped = true;\n\t\t}\n\t}\n\treturn dropped;\n}\n\nstatic void shrink_dcache_parent(struct dentry *parent)\n{\n\twhile (shrink_dcache_node(parent))\n\t\t;\n}\n\nstatic void d_prune_aliases(struct inode *inode)\n{\n\tstruct dentry *d, *n;\n\n\tlist_for_each_entry_safe(d, n, &inode->dentries, d_alias) {\n\t\tif (d->pin_count == 0 && list_empty(&d->d_children))\n\t\t\tdrop_dentry(d);\n\t}\n}\n\nstatic bool ext4_has_feature_encrypt(struct super_block *sb)\n{\n\treturn sb->has_encrypt;\n}\nstatic bool f2fs_sb_has_encrypt(struct super_block *sb)\n{\n\treturn sb->has_encrypt;\n}\n\n/* F2FS / HMFS helpers needed when extracting their production drop_inode */\nstruct f2fs_sb_info {\n\tstruct super_block *sb;\n\tspinlock_t inode_lock[2];\n};\n#define DIRTY_META 0\n#define F2FS_I_SB(inode) ((struct f2fs_sb_info *)((inode)->i_sb->s_flags ? \\\n\tNULL : NULL))\nstatic inline bool is_inode_flag_set(struct inode *inode, int flag)\n{\n\treturn (inode->f2fs_flags & (1U << flag)) != 0;\n}\nstatic inline int f2fs_is_pinned_file(struct inode *inode)\n{\n\treturn 0;\n}\nstatic inline int f2fs_is_atomic_file(struct inode *inode)\n{\n\treturn 0;\n}\nstatic inline bool inode_unhashed(struct inode *inode)\n{\n\treturn false;\n}\nstatic inline bool is_bad_inode(struct inode *inode)\n{\n\treturn false;\n}\nstatic inline void f2fs_i_size_write(struct inode *inode, u64 size)\n{\n}\nstatic inline void f2fs_submit_merged_write_cond(void *a, struct inode *b,\n\t\t\t\t\t\t void *c, int d, int e)\n{\n}\nstatic inline void hmfs_submit_merged_write_cond(void *a, struct inode *b,\n\t\t\t\t\t\t void *c, int d, int e)\n{\n}\nstatic inline void truncate_inode_pages_final(void *m)\n{\n}\nstatic inline int F2FS_HAS_BLOCKS(struct inode *i)\n{\n\treturn 0;\n}\nstatic inline void f2fs_truncate(struct inode *i)\n{\n}\nstatic inline void hmfs_truncate(struct inode *i)\n{\n}\nstatic inline void sb_start_intwrite(struct super_block *sb)\n{\n}\nstatic inline void sb_end_intwrite(struct super_block *sb)\n{\n}\nstatic inline bool f2fs_is_drop_cache(struct inode *i)\n{\n\treturn false;\n}\nstatic inline void f2fs_drop_inmem_pages(struct inode *i)\n{\n}\nstatic inline void hmfs_drop_inmem_pages(struct inode *i)\n{\n}\nstatic inline void f2fs_destroy_extent_node(struct inode *i)\n{\n}\nstatic inline void hmfs_destroy_extent_node(struct inode *i)\n{\n}\nstatic inline void stat_dec_dirty_inode(void *s, int t)\n{\n}\nstatic inline void clear_inode_flag(struct inode *i, int f)\n{\n}\n#define i_mapping i_sb\n#define DATA 0\n\n#include "subject.h"\n'


def strip_includes(text):
    return re.sub(r'^#include[^\n]*\n', '', text, flags=re.M)


def extract(pattern, text):
    m = re.search(pattern, text, re.S | re.M)
    if not m:
        raise ValueError(f"Pattern not found: {pattern}")
    return m.group(0)


def function(text, name):
    m = re.search(
        r'^(?!\s*\*)\s*(?:static\s+)?[^\n]*\b' + re.escape(name) + r'\s*\(',
        text, re.M)
    if not m:
        raise ValueError(f"Function not found: {name}")
    start = m.start()
    prev_nl = text.rfind('\n', 0, max(0, start - 1))
    prev_line = text[prev_nl + 1:start].strip()
    if prev_line in ('static int', 'int', 'static void', 'void',
                     'static bool', 'bool', 'static long', 'long',
                     'static struct fscrypt_mode *'):
        start = prev_nl + 1
    brace = text.index('{', m.start())
    depth = 0
    for pos in range(brace, len(text)):
        if text[pos] == '{':
            depth += 1
        elif text[pos] == '}':
            depth -= 1
            if depth == 0:
                return text[start:pos + 1]
    raise ValueError(f"Unterminated function: {name}")


def read_repo_file(root, relpath, source_commit=None):
    if source_commit:
        try:
            return subprocess.check_output(
                ["git", "-C", str(root), "show", f"{source_commit}:{relpath}"],
                stderr=subprocess.DEVNULL, text=True)
        except subprocess.CalledProcessError:
            return None
    p = root / relpath
    return p.read_text() if p.is_file() else None


def build_bionic_uapi(bionic_path):
    raw = bionic_path.read_text()
    raw = strip_includes(raw)
    # Prefix identifiers cleanly to avoid colliding with kernel UAPI symbols.
    for old, new in (
        ("__FSCRYPT_", "BIONIC___FSCRYPT_"),
        ("FSCRYPT_", "BIONIC_FSCRYPT_"),
        ("FS_IOC_", "BIONIC_FS_IOC_"),
        ("FS_KEY_", "BIONIC_FS_KEY_"),
        ("FS_POLICY_", "BIONIC_FS_POLICY_"),
        ("FS_ENCRYPTION_", "BIONIC_FS_ENCRYPTION_"),
        ("FS_MAX_KEY_SIZE", "BIONIC_FS_MAX_KEY_SIZE"),
        ("struct fscrypt_", "struct bionic_fscrypt_"),
        ("fscrypt_policy ", "bionic_fscrypt_policy "),
        ("fscrypt_policy_v1", "bionic_fscrypt_policy_v1"),
        ("fscrypt_policy_v2", "bionic_fscrypt_policy_v2"),
    ):
        raw = raw.replace(old, new)
    raw = raw.replace("_UAPI_LINUX_FSCRYPT_H", "_BIONIC_UAPI_LINUX_FSCRYPT_H")
    return raw


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cc", required=True)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--bionic", type=Path)
    parser.add_argument("--source-commit")
    parser.add_argument("--expect-red", action="store_true")
    parser.add_argument("--mutation", choices=tuple(MUTATIONS))
    args = parser.parse_args()

    root = Path(__file__).resolve().parents[2]
    here = root / "scripts/tests"
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)

    version = subprocess.check_output([args.cc, "--version"], text=True)
    assert "clang version 22." in version, version

    paths = (
        "include/uapi/linux/fs.h",
        "include/uapi/linux/fscrypt.h",
        "include/linux/fscrypt_owner.h",
        "include/linux/fscrypt_common.h",
        "include/linux/fscrypt_supp.h",
        "fs/crypto/fscrypt_private.h",
        "fs/crypto/master_key.h",
        "fs/crypto/master_key.c",
        "fs/crypto/registry.h",
        "fs/crypto/keyring.c",
        "fs/crypto/keymgmt_ioctl.c",
        "fs/crypto/keyinfo.c",
        "fs/ext4/super.c",
        "fs/ext4/ioctl.c",
        "fs/f2fs/super.c",
        "fs/f2fs/file.c",
        "fs/hmfs/super.c",
        "fs/hmfs/file.c",
    )
    inputs = {p: read_repo_file(root, p, args.source_commit) for p in paths}
    is_red_commit = inputs["include/uapi/linux/fscrypt.h"] is None

    uapi_fs = inputs["include/uapi/linux/fs.h"]
    uapi_defs = [
        extract(r'^#define FS_KEY_DESCRIPTOR_SIZE[^\n]*', uapi_fs),
        extract(r'^#define FS_POLICY_FLAGS_VALID[^\n]*', uapi_fs),
        extract(r'^#define FS_KEY_DESC_PREFIX\b[^\n]*', uapi_fs),
        extract(r'^#define FS_KEY_DESC_PREFIX_SIZE\b[^\n]*', uapi_fs),
        extract(r'^#define FS_MAX_KEY_SIZE\b[^\n]*', uapi_fs),
        extract(r'^struct fscrypt_key\s*\{.*?^\};', uapi_fs),
        extract(r'^struct fscrypt_policy\s*\{.*?^\};', uapi_fs),
    ]
    if is_red_commit:
        uapi_defs.append("""
#define FSCRYPT_KEY_SPEC_TYPE_DESCRIPTOR 1
#define FSCRYPT_KEY_SPEC_TYPE_IDENTIFIER 2
#define FSCRYPT_KEY_DESCRIPTOR_SIZE 8
#define FSCRYPT_KEY_IDENTIFIER_SIZE 16
#define FSCRYPT_ADD_KEY_FLAG_HW_WRAPPED 1
#define __FSCRYPT_ADD_KEY_FLAG_HW_WRAPPED 1
#define FSCRYPT_KEY_REMOVAL_STATUS_FLAG_FILES_BUSY 1
#define FSCRYPT_KEY_STATUS_ABSENT 1
#define FSCRYPT_KEY_STATUS_PRESENT 2
#define FSCRYPT_KEY_STATUS_INCOMPLETELY_REMOVED 3
struct fscrypt_key_specifier { __u32 type; __u32 __reserved; union { __u8 __reserved[32]; __u8 descriptor[8]; __u8 identifier[16]; } u; };
struct fscrypt_add_key_arg { struct fscrypt_key_specifier key_spec; __u32 raw_size; __u32 key_id; __u32 flags; __u32 __reserved[6]; __u32 __flags; __u8 raw[]; };
struct fscrypt_remove_key_arg { struct fscrypt_key_specifier key_spec; __u32 removal_status_flags; __u32 __reserved[5]; };
struct fscrypt_get_key_status_arg { struct fscrypt_key_specifier key_spec; __u32 __reserved[6]; __u32 status; __u32 status_flags; __u32 user_count; __u32 __out_reserved[13]; };
#define FS_IOC_ADD_ENCRYPTION_KEY _IOWR('f', 23, struct fscrypt_add_key_arg)
#define FS_IOC_REMOVE_ENCRYPTION_KEY _IOWR('f', 24, struct fscrypt_remove_key_arg)
#define FS_IOC_REMOVE_ENCRYPTION_KEY_ALL_USERS _IOWR('f', 25, struct fscrypt_remove_key_arg)
#define FS_IOC_GET_ENCRYPTION_KEY_STATUS _IOWR('f', 26, struct fscrypt_get_key_status_arg)
""")
    else:
        uapi_defs.append(strip_includes(inputs["include/uapi/linux/fscrypt.h"]))
    (out / "uapi_subject.h").write_text("\n".join(uapi_defs) + "\n")

    extra_cflags = []
    if args.bionic and not is_red_commit:
        (out / "bionic_uapi.h").write_text(build_bionic_uapi(args.bionic))
        extra_cflags.append("-DHAS_BIONIC_UAPI")

    common_h = inputs["include/linux/fscrypt_common.h"]
    supp_h = inputs["include/linux/fscrypt_supp.h"]
    priv_h = inputs["fs/crypto/fscrypt_private.h"]
    common_defs = [
        strip_includes(inputs["include/linux/fscrypt_owner.h"]),
        extract(r'^#define FS_KEY_DERIVATION_NONCE_SIZE[^\n]*', common_h),
        extract(r'^#define FS_KEY_DERIVATION_IV_SIZE[^\n]*', common_h),
        extract(r'^#define FS_KEY_DERIVATION_TAG_SIZE[^\n]*', common_h),
        extract(r'^#define FS_KEY_DERIVATION_CIPHER_SIZE[^\n]*', common_h),
        extract(r'^#define METADATA_BYTE_IN_KDF[^\n]*', common_h),
        extract(r'^#define FS_AES_256_GCM_KEY_SIZE[^\n]*', priv_h),
        extract(r'^#define FS_ENCRYPTION_CONTEXT_FORMAT_V2[^\n]*', priv_h),
        extract(r'^struct fscrypt_context\s*\{.*?^\}[^;]*;', common_h),
        extract(r'^struct fscrypt_info\s*\{.*?^\};', common_h),
        function(common_h, "fscrypt_ci_is_managed"),
        extract(r'^enum fscrypt_ce_purpose\s*\{.*?^\};', supp_h),
        extract(r'^struct fscrypt_ce_key\s*\{.*?^\};', supp_h),
        extract(r'^struct fscrypt_operations\s*\{.*?^\};', common_h),
        strip_includes(inputs["fs/crypto/master_key.h"]),
        strip_includes(inputs["fs/crypto/registry.h"]),
    ]
    (out / "common_subject.h").write_text("\n".join(common_defs) + "\n")

    keyinfo = inputs["fs/crypto/keyinfo.c"]
    subj_parts = [
        strip_includes(inputs["fs/crypto/master_key.c"]),
        strip_includes(inputs["fs/crypto/keyring.c"]),
    ]
    if is_red_commit:
        subj_parts.append("""
static int fscrypt_ioctl_add_key(struct file *f, void __user *u) { return -EOPNOTSUPP; }
static int fscrypt_ioctl_remove_key(struct file *f, void __user *u) { return -EOPNOTSUPP; }
static int fscrypt_ioctl_remove_key_all_users(struct file *f, void __user *u) { return -EOPNOTSUPP; }
static int fscrypt_ioctl_get_key_status(struct file *f, void __user *u) { return -EOPNOTSUPP; }
static int fscrypt_drop_inode(struct inode *i) { return 0; }
static bool has_retired_busy_owners(struct super_block *sb, struct fscrypt_master_key *mk, u64 gen) { return true; }
""")
    else:
        subj_parts.append(strip_includes(inputs["fs/crypto/keymgmt_ioctl.c"]))

    subj_parts.append(extract(r'^struct fscrypt_ce_tfm\s*\{.*?^\};', keyinfo))
    subj_parts.append(extract(r'^struct fscrypt_ce_scope\s*\{.*?^\};', keyinfo))
    for fn in (
        "derive_crypt_complete",
        "fscrypt_set_gcm_key",
        "fscrypt_derive_gcm_key",
        "fscrypt_check_unmanaged_descriptor",
        "fscrypt_acquire_ce_key",
        "fscrypt_release_ce_key",
        "fscrypt_ce_tfm_get",
        "fscrypt_ce_tfm_put",
        "fscrypt_ce_scope_open",
        "fscrypt_ce_scope_matches",
        "fscrypt_ce_scope_crypt",
        "fscrypt_ce_scope_legacy_slot",
        "fscrypt_ce_scope_attach_legacy_tfm",
        "fscrypt_ce_scope_put",
    ):
        subj_parts.append(function(keyinfo, fn))

    if is_red_commit:
        # Wrap 6-arg baseline find_and_derive_key_with_scope so test binary builds.
        fdk = function(keyinfo, "find_and_derive_key_with_scope")
        fdk = fdk.replace("find_and_derive_key_with_scope(",
                          "base_find_and_derive_key_with_scope(", 1)
        subj_parts.append(fdk)
        subj_parts.append("""
static int find_and_derive_key_with_scope(const struct inode *inode,
    struct fscrypt_info *crypt_info, const struct fscrypt_context *ctx,
    u8 *derived_key, unsigned int derived_keysize,
    struct fscrypt_ce_scope *borrowed, bool dummy_ctx)
{
    (void)dummy_ctx;
    return base_find_and_derive_key_with_scope(inode, crypt_info, ctx,
        derived_key, derived_keysize, borrowed);
}
""")
        fdk_plain = function(keyinfo, "find_and_derive_key").replace(
            "NULL);", "NULL, false);")
        subj_parts.append(fdk_plain)
    else:
        subj_parts.append(function(keyinfo, "find_and_derive_key_with_scope"))
        subj_parts.append(function(keyinfo, "find_and_derive_key"))
        subj_parts.append(function(keyinfo, "fscrypt_drop_inode"))

    subj_parts.append(function(inputs["fs/ext4/super.c"], "ext4_drop_inode"))
    subj_parts.append(function(inputs["fs/f2fs/super.c"], "f2fs_drop_inode"))
    subj_parts.append(
        function(inputs["fs/hmfs/super.c"], "f2fs_drop_inode").replace(
            "static int f2fs_drop_inode(", "static int hmfs_drop_inode(", 1))

    if is_red_commit:
        subj_parts.append("""
static long subj_ext4_fscrypt_ioctl(struct file *filp, unsigned int cmd, unsigned long arg) { return -ENOTTY; }
static long subj_f2fs_fscrypt_ioctl(struct file *filp, unsigned int cmd, unsigned long arg) { return -ENOTTY; }
static long subj_hmfs_fscrypt_ioctl(struct file *filp, unsigned int cmd, unsigned long arg) { return -ENOTTY; }
""")
    else:
        ext4_ioctl = inputs["fs/ext4/ioctl.c"]
        e_start = ext4_ioctl.index("\tcase FS_IOC_ADD_ENCRYPTION_KEY:")
        e_end = ext4_ioctl.index("\tcase EXT4_IOC_FSGETXATTR:", e_start)
        subj_parts.append(
            "static long subj_ext4_fscrypt_ioctl(struct file *filp,\n"
            "\tunsigned int cmd, unsigned long arg)\n{\n"
            "\tstruct super_block *sb = file_inode(filp)->i_sb;\n"
            "\tswitch (cmd) {\n" + ext4_ioctl[e_start:e_end] +
            "\tdefault:\n\t\treturn -ENOTTY;\n\t}\n}\n")

        f2fs_file = inputs["fs/f2fs/file.c"]
        for fn in (
            "f2fs_ioc_add_encryption_key",
            "f2fs_ioc_remove_encryption_key",
            "f2fs_ioc_remove_encryption_key_all_users",
            "f2fs_ioc_get_encryption_key_status",
        ):
            subj_parts.append(function(f2fs_file, fn))
        f_start = f2fs_file.index("\tcase FS_IOC_ADD_ENCRYPTION_KEY:")
        f_end = f2fs_file.index("\tcase F2FS_IOC_GARBAGE_COLLECT:", f_start)
        subj_parts.append(
            "static long subj_f2fs_fscrypt_ioctl(struct file *filp,\n"
            "\tunsigned int cmd, unsigned long arg)\n{\n"
            "\tswitch (cmd) {\n" + f2fs_file[f_start:f_end] +
            "\tdefault:\n\t\treturn -ENOTTY;\n\t}\n}\n")

        hmfs_file = inputs["fs/hmfs/file.c"]
        hmfs_fns = []
        for fn in (
            "f2fs_ioc_add_encryption_key",
            "f2fs_ioc_remove_encryption_key",
            "f2fs_ioc_remove_encryption_key_all_users",
            "f2fs_ioc_get_encryption_key_status",
        ):
            hmfs_fns.append(function(hmfs_file, fn).replace(
                "f2fs_ioc_", "hmfs_ioc_"))
        h_start = hmfs_file.index("\tcase FS_IOC_ADD_ENCRYPTION_KEY:")
        h_end = hmfs_file.index("\tcase F2FS_IOC_GARBAGE_COLLECT:", h_start)
        hmfs_cases = hmfs_file[h_start:h_end].replace("f2fs_ioc_", "hmfs_ioc_")
        subj_parts.extend(hmfs_fns)
        subj_parts.append(
            "static long subj_hmfs_fscrypt_ioctl(struct file *filp,\n"
            "\tunsigned int cmd, unsigned long arg)\n{\n"
            "\tswitch (cmd) {\n" + hmfs_cases +
            "\tdefault:\n\t\treturn -ENOTTY;\n\t}\n}\n")

    subject = "\n\n".join(subj_parts) + "\n"
    if args.mutation:
        old, new = MUTATIONS[args.mutation]
        cnt = subject.count(old)
        assert cnt == 1, (args.mutation, cnt)
        subject = subject.replace(old, new)
    (out / "subject.h").write_text(subject)
    (out / "uapi_host_shim.h").write_text(HOST_SHIM)

    cmd = [
        args.cc, "-std=gnu11", "-O1", "-g", "-Wall", "-Wextra", "-Werror",
        "-Wno-pointer-sign", "-Wno-unused-function", "-Wno-unused-parameter",
        "-Wno-unused-variable", "-Wno-sign-compare",
        "-fsanitize=address,undefined", "-fno-sanitize-recover=all",
        "-fno-omit-frame-pointer", "-pthread",
        "-I" + str(out),
    ] + extra_cflags + [
        str(here / "huawei_fscrypt_uapi_ioctl.c"), "-lcrypto",
        "-o", str(out / "test"),
    ]
    comp = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    (out / "compile.log").write_text(comp.stdout + comp.stderr)
    if comp.returncode != 0:
        print(comp.stderr)

    results = []
    if comp.returncode == 0:
        for case in CASES:
            if is_red_commit and case == "uapi-abi-parity":
                # Keep parity case runnable too; reports PASS unless mismatch.
                pass
            r = subprocess.run(
                [str(out / "test"), case],
                capture_output=True, text=True, timeout=20)
            (out / f"{case}.log").write_text(r.stdout + r.stderr)
            results.append({"case": case, "exit": r.returncode})
            print(case, "PASS" if r.returncode == 0 else "FAIL", flush=True)

    any_fail = any(r["exit"] != 0 for r in results)
    receipt = {
        "compiler": version,
        "command": cmd,
        "compile_exit": comp.returncode,
        "source_commit": subprocess.check_output(
            ["git", "-C", str(root), "rev-parse",
             args.source_commit or "HEAD"], text=True).strip(),
        "dirty": False if args.source_commit else bool(
            subprocess.check_output(
                ["git", "-C", str(root), "status", "--porcelain"], text=True)),
        "expect_red": args.expect_red,
        "mutation": args.mutation,
        "results": results,
        "sha256": {
            p: hashlib.sha256(t.encode()).hexdigest()
            for p, t in inputs.items() if t is not None
        },
        "test_sha256": {
            name: hashlib.sha256((here / name).read_bytes()).hexdigest()
            for name in ("huawei_fscrypt_uapi_ioctl.c",
                         "test_huawei_fscrypt_uapi_ioctl.py")
        },
    }
    (out / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")

    if comp.returncode != 0:
        raise SystemExit(1)
    if args.expect_red:
        # Every behavioral Stage 1B case (beyond synthetic struct sizes) must fail.
        red_failures = sum(
            1 for r in results
            if r["case"] != "uapi-abi-parity" and r["exit"] != 0
        )
        assert red_failures == len(CASES) - 1, results
        return
    if any_fail:
        raise SystemExit(1)


if __name__ == "__main__":
    main()

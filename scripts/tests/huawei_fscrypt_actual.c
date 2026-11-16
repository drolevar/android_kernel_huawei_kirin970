/* SPDX-License-Identifier: GPL-2.0 */
/* Executes extracted source; findings are characterized, not repaired. */
#include "huawei_fscrypt_host.h"
#include "crypto-subject.h"
#include "actual-subject.h"

static struct fscrypt_context saved;
static int save_context(struct inode *i, const void *p, size_t n, void *data)
{ CHECK(n == 108); memcpy(&saved, p, n); return 0; }
static struct operations ops = { .set_context = save_context };
static struct super_block sb = { .s_cop = &ops };
static struct inode ino = { .i_sb = &sb };
static struct fscrypt_policy policy = { .contents_encryption_mode = 1, .filenames_encryption_mode = 4 };
static struct user_key_payload ukp;
static struct key key;
static void setup(unsigned int size)
{
    memset(&ukp, 0, sizeof(ukp)); memset(&key, 0, sizeof(key));
    ukp.datalen = sizeof(struct fscrypt_key);
    struct fscrypt_key *p = (void *)ukp.data;
    p->size = size; p->raw[63] = 7;
    key.type = &key_type_logon; key.payload = &ukp; key.description = "synthetic-only";
    lookup_key = &key;
}
static void balanced(void)
{ CHECK(key.refs == 0 && key.sem.readers == 0 && tfm_live == 0 && request_live == 0); }

static void vector(void)
{
    /* crypto/testmgr.h AES-256-GCM 64-byte, zero-AAD vector, not self-generated. */
    static const u8 k[] = "\xfe\xff\xe9\x92\x86\x65\x73\x1c\x6d\x6a\x8f\x94\x67\x30\x83\x08"
                           "\xfe\xff\xe9\x92\x86\x65\x73\x1c\x6d\x6a\x8f\x94\x67\x30\x83\x08";
    u8 iv[16] = "\xca\xfe\xba\xbe\xfa\xce\xdb\xad\xde\xca\xf8\x88";
    u8 plain[80] = "\xd9\x31\x32\x25\xf8\x84\x06\xe5\xa5\x59\x09\xc5\xaf\xf5\x26\x9a"
                   "\x86\xa7\xa9\x53\x15\x34\xf7\xda\x2e\x4c\x30\x3d\x8a\x31\x8a\x72"
                   "\x1c\x3c\x0c\x95\x95\x68\x09\x53\x2f\xcf\x0e\x24\x49\xa6\xb5\x25"
                   "\xb1\x6a\xed\xf5\xaa\x0d\xe6\x57\xba\x63\x7b\x39\x1a\xaf\xd2\x55";
    const u8 want[] = "\x52\x2d\xc1\xf0\x99\x56\x7d\x07\xf4\x7f\x37\xa3\x2a\x84\x42\x7d"
                        "\x64\x3a\x8c\xdc\xbf\xe5\xc0\xc9\x75\x98\xa2\xbd\x25\x55\xd1\xaa"
                        "\x8c\xb0\x8e\x48\x59\x0d\xbb\x3d\xa7\xb0\x8b\x10\x56\x82\x88\x38"
                        "\xc5\xf6\x1e\x63\x93\xba\x7a\x0a\xbc\xc9\xf6\x62\x89\x80\x15\xad"
                        "\xb0\x94\xda\xc5\xd9\x34\x71\xbd\xec\x1a\x50\x22\x70\xe3\xcc\x6c";
    u8 cipher[80] = {0}, decoded[80] = {0};
    struct crypto_aead *t = crypto_alloc_aead("gcm(aes)", 0, 0);
    CHECK(fscrypt_set_gcm_key(t, k) == 0);
    CHECK(fscrypt_derive_gcm_key(t, plain, cipher, iv, 1) == 0);
    CHECK(!memcmp(cipher, want, 80));
    CHECK(fscrypt_derive_gcm_key(t, cipher, decoded, iv, 0) == 0);
    CHECK(!memcmp(decoded, plain, 64));
    iv[15] ^= 1; /* storage bytes 12..15 do not enter this gcm(aes) implementation */
    CHECK(fscrypt_derive_gcm_key(t, cipher, decoded, iv, 0) == 0);
    iv[0] ^= 1;
    CHECK(fscrypt_derive_gcm_key(t, cipher, decoded, iv, 0) == -EBADMSG);
    iv[0] ^= 1; cipher[79] ^= 1;
    CHECK(fscrypt_derive_gcm_key(t, cipher, decoded, iv, 0) == -EBADMSG);
    crypto_free_aead(t);
}

int main(int argc, char **argv)
{
    CHECK(argc == 2);
    const char *c = argv[1];
    setup(64);
    if (!strcmp(c, "gcm-vector")) vector();
    else if (!strcmp(c, "payload-writes")) {
        CHECK(create_encryption_context_from_policy(&ino, &policy) == 0);
        CHECK(((struct fscrypt_key *)ukp.data)->size == 32);
        CHECK(key.sem.down == 1 && key.sem.up == 1);
        setup(64);
        const struct fscrypt_key *p = NULL;
        struct key *got = find_and_lock_process_key(&saved, FS_KEY_DESC_PREFIX, saved.master_key_descriptor, 64, &p);
        CHECK(got == &key && p->size == 32 && key.sem.readers == 1);
        up_read(&key.sem); key_put(got);
        puts("REPRODUCED: both paths write size64->32 inside a read-lock interval");
    } else if (!strcmp(c, "policy-null")) {
        revoke_on_lock = true;
        (void)create_encryption_context_from_policy(&ino, &policy);
        CHECK(false); /* expected UBSan null payload fault in original source */
    } else if (!strcmp(c, "unwrap-revoked")) {
        const struct fscrypt_key *p = NULL;
        revoke_on_lock = true;
        CHECK(find_and_lock_process_key(&saved, FS_KEY_DESC_PREFIX, saved.master_key_descriptor, 64, &p) == ERR_PTR(-ENOKEY));
        CHECK(p == NULL && key.sem.underflow == 0);
    } else if (!strcmp(c, "double-unlock")) {
        struct fscrypt_info ci = {0}; u8 raw[64] = {0};
        fail_alloc = 1;
        CHECK(find_and_derive_key(&ino, &ci, &saved, raw, 64) == -ENOMEM);
        CHECK(key.sem.down == 1 && key.sem.up == 2 && key.sem.underflow == 1);
        puts("REPRODUCED: one down_read, two up_read on AEAD allocation failure");
    } else if (!strcmp(c, "errors")) {
        for (int f = 0; f < 4; f++) {
            setup(32); fail_alloc = fail_setkey = fail_unwrap = fail_request = 0;
            CHECK(create_encryption_context_from_policy(&ino, &policy) == 0);
            struct fscrypt_info ci = {0}; u8 raw[64] = {0};
            if (f == 0) fail_setkey = 1;
            if (f == 1) fail_unwrap = 1;
            if (f == 2) fail_request = 1;
            if (f == 3) saved.nonce[79] ^= 1;
            CHECK(find_and_derive_key(&ino, &ci, &saved, raw, 64) < 0);
            CHECK(ci.ci_gtfm == NULL && key.sem.underflow == 0); balanced();
        }
    } else if (!strcmp(c, "f2fs")) {
        setup(32); u8 plain[80] = {0}, cipher[80] = {0}, out[80] = {0}, iv[16] = {0}, desc[8] = {0};
        memset(plain, 0x27, 64);
        CHECK(f2fs_do_get_fek(desc, cipher, plain, iv, 1) == 0);
        CHECK(f2fs_do_get_fek(desc, cipher, out, iv, 0) == 0 && !memcmp(out, plain, 64));
        revoke_on_lock = true;
        CHECK(f2fs_do_get_fek(desc, cipher, out, iv, 0) == -EKEYREVOKED);
        setup(64);
        CHECK(f2fs_do_get_fek(desc, cipher, out, iv, 0) == -EKEYREVOKED);
        CHECK(((struct fscrypt_key *)ukp.data)->size == 64);
    } else CHECK(false);
    balanced(); return 0;
}

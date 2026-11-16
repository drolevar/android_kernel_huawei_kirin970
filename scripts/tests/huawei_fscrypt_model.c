/* SPDX-License-Identifier: GPL-2.0 */
/* Tests the new contract model, NOT an implemented kernel adapter. */
#include "huawei_fscrypt_host.h"
#include "crypto-subject.h"
#include "model-subject.h"

static struct environment env(void)
{
    struct environment e = {0};
    e.fs = (struct model_key){ .source = FILESYSTEM, .format = FILESYSTEM_RAW,
        .managed = true, .present = true, .raw_size = 64, .generation = 1 };
    e.legacy = (struct model_key){ .source = LOGON, .format = LEGACY_PAYLOAD, .raw_size = 64 };
    e.prefix = e.legacy;
    e.sdp = (struct model_key){ .source = VENDOR_SDP, .format = SDP_RAW,
        .present = true, .raw_size = 32, .generation = 1 };
    for (int i = 0; i < 64; i++) { e.fs.raw[i] = i; e.sdp.raw[i] = 0x80 + i; e.legacy.raw[i] = 0x40 + i; }
    e.fs.raw[63] = 29; e.legacy.raw[63] = 7;
    return e;
}
static void key_balanced(struct model_key *k, unsigned int owners)
{
    CHECK(k->refs == owners && k->enrolled == owners && k->readers == 0);
    CHECK(k->acquired == k->released + k->transferred);
}
static void balanced(struct environment *e)
{
    key_balanced(&e->fs, 0); key_balanced(&e->legacy, 0);
    key_balanced(&e->prefix, 0); key_balanced(&e->sdp, 0);
    CHECK(tfm_live == 0 && request_live == 0);
}
static struct fscrypt_context make_context(struct environment *e)
{
    struct fscrypt_context ctx = {0}; u8 plain[80] = {0}, iv[16] = {0};
    for (int i = 0; i < 64; i++) plain[i] = 0x30 + i;
    CHECK(create_context(e, &ctx, plain, iv) == 0);
    return ctx;
}
static void check_fek(const u8 *fek)
{ for (int i = 0; i < 64; i++) CHECK(fek[i] == 0x30 + i); }

int main(int argc, char **argv)
{
    CHECK(argc == 2);
    const char *c = argv[1]; struct environment e = env();
    if (!strcmp(c, "formats")) {
        u8 generic1[28] = {1}, generic2[40] = {2};
        struct fscrypt_context ctx = { .format = 2 };
        CHECK(sizeof(ctx) == 108);
        CHECK(context_validate(HUAWEI_108, &ctx, 108) == 0);
        CHECK(context_validate(HUAWEI_108, generic1, 28) == -EINVAL);
        CHECK(context_validate(HUAWEI_108, generic2, 40) == -EINVAL);
        CHECK(context_validate(GENERIC_V2, &ctx, 108) == -EOPNOTSUPP);
        CHECK(context_validate(GENERIC_V1, generic1, 28) == -EOPNOTSUPP);
        ctx.format = 1; CHECK(context_validate(HUAWEI_108, &ctx, 108) == -EINVAL);
    } else if (!strcmp(c, "immutable")) {
        u8 before[64]; memcpy(before, e.fs.raw, 64);
        struct lease t = {0}; CHECK(lookup_ce(&e, &t) == 0);
        struct secret_view v = lease_view(&t);
        CHECK(v.size == 32 && v.source == FILESYSTEM && v.format == FILESYSTEM_RAW);
        CHECK(!v.vendor.slot_valid && !memcmp(v.bytes, before, 32));
        CHECK(e.fs.raw_size == 64 && !memcmp(e.fs.raw, before, 64));
        CHECK(lease_get(&e.fs, false, &t) == -EBUSY);
        struct lease copy = t; CHECK(lease_put(&copy) == -EINVAL);
        CHECK(lease_put(&t) == 0 && lease_put(&t) == -EINVAL);
        CHECK(lease_view(&t).bytes == NULL);
        CHECK(e.fs.acquired == 1 && e.fs.released == 1);
        e.fs.vendor.slot_valid = true; e.fs.vendor.slot = 13;
        CHECK(lookup_ce(&e, &t) == 0);
        CHECK(lease_view(&t).vendor.slot == 13); CHECK(lease_put(&t) == 0);
        e.fs.present = false; e.fs.managed = false; e.allow_legacy = true; e.legacy.present = true;
        CHECK(lookup_ce(&e, &t) == 0);
        CHECK(lease_view(&t).vendor.slot_valid && lease_view(&t).vendor.slot == 7);
        CHECK(lease_put(&t) == 0);
        e.fs.present = e.fs.managed = true;
        e.fs.raw_size = 16; CHECK(lookup_ce(&e, &t) == -EINVAL);
        e.fs.raw_size = 65; CHECK(lookup_ce(&e, &t) == -EINVAL);
        e.fs.raw_size = 32; e.fs.null_payload = true; CHECK(lookup_ce(&e, &t) == -EKEYREVOKED);
        e.fs.null_payload = false; e.revoke_after_lookup = true;
        CHECK(lookup_ce(&e, &t) == -EKEYREVOKED);
    } else if (!strcmp(c, "consumers")) {
        struct fscrypt_context ctx = make_context(&e); /* policy: FS-only */
        CHECK(e.fs.acquired == 1 && e.fs.released == 1);
        struct candidate a = {0}; struct model_inode inode = {0};
        CHECK(unwrap_begin(&e, &ctx, &a) == 0); check_fek(a.fek); /* generic CE */
        CHECK(inode_publish(&a, &inode) == 0);
        CHECK(e.fs.enrolled == 1 && e.fs.transferred == 1); inode_detach(&inode);
        struct durable_sdp d = {0};
        CHECK(convert_sdp(&e, &ctx, &inode, &d, ECE, 0) == 0); /* F2FS CE->SDP */
        CHECK(d.context && d.flags && d.ce_erased && inode.owner == &e.sdp);
        CHECK(e.fs.acquired == 3 && e.legacy.acquired == 0);
        inode_detach(&inode);
    } else if (!strcmp(c, "errors")) {
        struct fscrypt_context ctx = make_context(&e);
        for (int f = 0; f < 5; f++) {
            struct candidate a = {0};
            fail_alloc = f == 0; fail_setkey = f == 1; fail_unwrap = f == 2; fail_request = f == 3;
            if (f == 4) ctx.nonce[79] ^= 1;
            CHECK(unwrap_begin(&e, &ctx, &a) < 0);
            CHECK(!a.lease.live);
            for (int i = 0; i < 80; i++) CHECK(a.fek[i] == 0);
            balanced(&e);
        }
        fail_alloc = fail_setkey = fail_unwrap = fail_request = 0;
        for (int f = 0; f < 3; f++) {
            struct fscrypt_context out; memset(&out, 0xa5, sizeof(out));
            u8 plain[80] = {0}, iv[16] = {0};
            fail_alloc = f == 0; fail_setkey = f == 1; fail_request = f == 2;
            CHECK(create_context(&e, &out, plain, iv) < 0);
            for (unsigned int i = 0; i < sizeof(out); i++) CHECK(((u8 *)&out)[i] == 0xa5);
            balanced(&e);
        }
    } else if (!strcmp(c, "fallback")) {
        struct lease t = {0}; e.allow_legacy = true; e.legacy.present = true;
        CHECK(lookup_ce(&e, &t) == 0 && lease_view(&t).source == FILESYSTEM); CHECK(lease_put(&t) == 0);
        CHECK(fs_remove(&e.fs) == 0);
        CHECK(fs_key_status(&e.fs) == ABSENT);
        CHECK(lookup_ce(&e, &t) == -ENOKEY); /* managed tombstone defeats duplicate downgrade */
        CHECK(e.legacy.present && e.legacy.acquired == 0);
        e.fs.managed = false;
        CHECK(lookup_ce(&e, &t) == 0 && lease_view(&t).source == LOGON); CHECK(lease_put(&t) == 0);
        e.legacy.revoked = true; e.prefix.present = true;
        CHECK(lookup_ce(&e, &t) == -EKEYREVOKED && e.prefix.acquired == 0);
        e.legacy.present = false; e.legacy.revoked = false;
        CHECK(lookup_ce(&e, &t) == 0 && t.key == &e.prefix); CHECK(lease_put(&t) == 0);
        e.fs_lookup_error = -EACCES;
        CHECK(lookup_ce(&e, &t) == -EACCES);
        e.fs_lookup_error = 0; e.allow_legacy = false;
        CHECK(lookup_ce(&e, &t) == -ENOKEY);
    } else if (!strcmp(c, "remove")) {
        struct fscrypt_context ctx = make_context(&e);
        struct candidate a = {0}; struct model_inode inode = { .busy = true, .dirty = true };
        CHECK(unwrap_begin(&e, &ctx, &a) == 0);
        CHECK(fs_remove(&e.fs) == -EAGAIN && fs_key_status(&e.fs) == PRESENT);
        CHECK(inode_publish(&a, &inode) == 0);
        CHECK(fs_remove(&e.fs) == 1 && fs_key_status(&e.fs) == INCOMPLETELY_REMOVED);
        CHECK(inode.owner == &e.fs && inode.cached); /* busy/dirty inode is retained */
        for (int i = 0; i < 64; i++) CHECK(e.fs.raw[i] == 0);
        u8 raw[64]; for (int i = 0; i < 64; i++) raw[i] = i;
        CHECK(fs_readd(&e.fs, raw) == 0 && fs_key_status(&e.fs) == PRESENT);
        CHECK(e.fs.enrolled == 1);
        CHECK(fs_remove(&e.fs) == 1); inode_detach(&inode);
        CHECK(fs_key_status(&e.fs) == ABSENT && fs_remove(&e.fs) == 0);
        CHECK(fs_readd(&e.fs, raw) == 0);
        struct candidate b = {0}; CHECK(unwrap_begin(&e, &ctx, &b) == 0); CHECK(lease_put(&b.lease) == 0);
    } else if (!strcmp(c, "publication")) {
        struct fscrypt_context ctx = make_context(&e);
        struct candidate a = {0}, b = {0}; struct model_inode inode = {0};
        CHECK(unwrap_begin(&e, &ctx, &a) == 0 && unwrap_begin(&e, &ctx, &b) == 0);
        CHECK(inode_publish(&a, &inode) == 0);
        CHECK(inode_publish(&b, &inode) == -EEXIST && !b.lease.live);
        CHECK(e.fs.refs == 1 && e.fs.enrolled == 1); inode_detach(&inode);
        CHECK(unwrap_begin(&e, &ctx, &a) == 0);
        /* Defensive guards tested independently: generation with present key,
         * and presence with matching generation. Deliberately broken lock schedules. */
        e.fs.generation++;
        CHECK(inode_publish(&a, &inode) == -ENOKEY && !inode.owner);
        CHECK(unwrap_begin(&e, &ctx, &a) == 0);
        e.fs.present = false;
        CHECK(inode_publish(&a, &inode) == -ENOKEY && !inode.owner);
    } else if (!strcmp(c, "sdp")) {
        for (enum inode_kind kind = ECE; kind <= SECE; kind++) {
            for (int step = 0; step <= 6; step++) {
                e = env(); struct fscrypt_context ctx = make_context(&e);
                struct candidate a = {0}; struct model_inode inode = {0}; struct durable_sdp d = {0};
                CHECK(unwrap_begin(&e, &ctx, &a) == 0 && inode_publish(&a, &inode) == 0);
                int err = convert_sdp(&e, &ctx, &inode, &d, kind, step);
                if (step == 1) {
                    CHECK(err == -EIO && !inode.quarantine && inode.cached && inode.owner == &e.fs);
                    CHECK(!d.context && !d.flags && !d.ce_erased);
                    inode_detach(&inode);
                } else if (step) {
                    CHECK(err == (step == 6 ? -ENOKEY : -EIO) && inode.quarantine && !inode.cached && !inode.owner);
                    CHECK(d.context == (step >= 3) && d.flags == (step >= 4) && d.ce_erased == (step >= 5));
                    CHECK(d.metadata_partial == (step == 3) && d.ce_partial == (step == 4));
                    CHECK(cached_access(&inode, true) == -EIO);
                    CHECK(d.wrapped[0] != 0); /* even a failed context write can persist bytes */
                } else {
                    CHECK(err == 0 && d.context && d.flags && d.ce_erased);
                    CHECK(inode.kind == kind && inode.owner == &e.sdp);
                    CHECK(e.fs.enrolled == 0 && e.sdp.enrolled == 1);
                    inode_detach(&inode);
                }
                balanced(&e);
            }
        }
    } else if (!strcmp(c, "sdp-preflight")) {
        for (int fault = 0; fault < 5; fault++) {
            e = env(); struct fscrypt_context ctx = make_context(&e);
            struct candidate a = {0}; struct model_inode inode = {0}; struct durable_sdp d = {0};
            CHECK(unwrap_begin(&e, &ctx, &a) == 0 && inode_publish(&a, &inode) == 0);
            if (fault == 0) e.sdp.revoked = true;
            if (fault == 1) e.sdp.raw_size = 16;
            if (fault == 2) fail_alloc = 1;
            if (fault == 3) fail_setkey = 1;
            if (fault == 4) fail_request = 1;
            CHECK(convert_sdp(&e, &ctx, &inode, &d, SECE, 0) < 0);
            CHECK(inode.owner == &e.fs && inode.cached && !inode.quarantine);
            CHECK(!d.context && !d.flags && !d.ce_erased);
            for (unsigned int i = 0; i < sizeof(d.wrapped); i++) CHECK(d.wrapped[i] == 0);
            inode_detach(&inode); balanced(&e);
            fail_alloc = fail_setkey = fail_request = 0;
        }
    } else if (!strcmp(c, "owners")) {
        for (enum inode_kind kind = CE; kind <= SECE; kind++) {
            struct model_inode inode = { .kind = kind };
            CHECK(!inode.owner && !inode.linked); inode_detach(&inode);
            struct candidate a = {0}; struct fscrypt_context ctx = make_context(&e);
            CHECK(unwrap_begin(&e, &ctx, &a) == 0 && inode_publish(&a, &inode) == 0);
            inode_detach(&inode); inode_detach(&inode); balanced(&e);
        }
    } else if (!strcmp(c, "cached")) {
        for (enum inode_kind kind = CE; kind <= SECE; kind++) {
            struct model_inode inode = { .cached = true, .kind = kind };
            CHECK(cached_access(&inode, true) == 0);
            CHECK(cached_access(&inode, false) == (kind == CE ? 0 : -EACCES));
        }
    } else if (!strcmp(c, "master-generation")) {
        struct candidate a = {0}; struct model_inode inode = {0};
        struct fscrypt_context ctx = make_context(&e); u8 raw[64];
        memcpy(raw, e.fs.raw, 64);
        CHECK(!unwrap_begin(&e,&ctx,&a) && !inode_publish(&a,&inode));
        CHECK(!cached_master_wrap_allowed(&inode));
        CHECK(fs_remove(&e.fs)==1);
        CHECK(!cached_access(&inode,true));
        CHECK(cached_master_wrap_allowed(&inode)==-ENOKEY);
        CHECK(!fs_readd(&e.fs,raw));
        CHECK(cached_master_wrap_allowed(&inode)==-ENOKEY);
        inode_detach(&inode);
        CHECK(!unwrap_begin(&e,&ctx,&a) && !inode_publish(&a,&inode));
        CHECK(!cached_master_wrap_allowed(&inode));
        inode_detach(&inode);
    } else CHECK(false);
    balanced(&e); return 0;
}

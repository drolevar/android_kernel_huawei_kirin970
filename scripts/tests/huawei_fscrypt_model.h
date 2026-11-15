/* SPDX-License-Identifier: GPL-2.0 */
/* Proposed contract MODEL ONLY. No production adapter or kernel key objects. */
enum key_source { FILESYSTEM, LOGON, VENDOR_SDP };
enum key_format { FILESYSTEM_RAW, LEGACY_PAYLOAD, SDP_RAW };
enum context_space { HUAWEI_108, GENERIC_V1, GENERIC_V2 };
enum inode_kind { CE, HWDPS, ECE, SECE };
enum fs_status { ABSENT, PRESENT, INCOMPLETELY_REMOVED };
struct vendor_metadata { bool slot_valid; unsigned int slot; u8 bytes[16]; };
struct model_key {
    enum key_source source;
    enum key_format format;
    bool managed, present, revoked, null_payload;
    unsigned int raw_size, generation, refs, readers, enrolled;
    unsigned int acquired, released, transferred;
    u8 raw[64];
    struct vendor_metadata vendor;
};
struct environment {
    struct model_key fs, legacy, prefix, sdp;
    int fs_lookup_error;
    bool allow_legacy, revoke_after_lookup;
};
struct secret_view {
    const u8 *bytes;
    size_t size;
    enum key_source source;
    enum key_format format;
    struct vendor_metadata vendor;
};
struct lease {
    struct lease *identity;
    struct model_key *key;
    unsigned int generation;
    bool live;
};
struct candidate { struct lease lease; u8 fek[80]; };
struct model_inode {
    enum inode_kind kind;
    struct model_key *owner;
    bool linked, cached, dirty, busy, quarantine;
};
struct durable_sdp { bool context, flags, ce_erased, metadata_partial, ce_partial; u8 wrapped[80]; };


/* Single-thread schedule model: each operation is an atomic lock interval.
 * readers pins immutable bytes through derivation/publication; removal retries.
 * An address-bound token cannot be copied, reacquired live, or released twice. */
static int context_validate(enum context_space ns, const void *ctx, size_t size)
{
    if (ns != HUAWEI_108) return -EOPNOTSUPP;
    if (!ctx || size != 108 || ((const u8 *)ctx)[0] != 2) return -EINVAL;
    return 0;
}
static int lease_get(struct model_key *key, bool revoke, struct lease *t)
{
    if (t->live) return -EBUSY;
    if (!key->present) return -ENOKEY;
    if (revoke || key->revoked || key->null_payload) return -EKEYREVOKED;
    if (!((key->source == FILESYSTEM && key->format == FILESYSTEM_RAW) ||
          (key->source == LOGON && key->format == LEGACY_PAYLOAD) ||
          (key->source == VENDOR_SDP && key->format == SDP_RAW))) return -EINVAL;
    if (key->raw_size != 32 && key->raw_size != 64) return -EINVAL;
    /* immutable input: never normalize the payload in place */
    *t = (struct lease){ .identity = t, .key = key, .generation = key->generation, .live = true };
    key->refs++; key->readers++; key->acquired++;
    return 0;
}
static int lookup_ce(struct environment *e, struct lease *t)
{
    struct model_key *key = &e->fs;
    if (e->fs_lookup_error) return e->fs_lookup_error;
    if (key->present || key->managed) return lease_get(key, e->revoke_after_lookup, t);
    if (!e->allow_legacy) return -ENOKEY;
    int err = lease_get(&e->legacy, e->revoke_after_lookup, t);
    if (err == -ENOKEY) err = lease_get(&e->prefix, e->revoke_after_lookup, t);
    return err;
}
static struct secret_view lease_view(struct lease *t)
{
    if (!t->live || t->identity != t) return (struct secret_view){0};
    struct model_key *key = t->key;
    struct secret_view v = { .bytes = key->raw, .size = 32,
        .source = key->source, .format = key->format, .vendor = key->vendor };
    if (key->format == LEGACY_PAYLOAD && key->source == LOGON) {
        /* Only this legacy ABI assigns raw[63] hardware-slot semantics. */
        v.vendor.slot_valid = key->raw_size == 64;
        v.vendor.slot = v.vendor.slot_valid ? key->raw[63] : 0;
    }
    return v;
}
static int lease_put(struct lease *t)
{
    if (!t->live || t->identity != t) return -EINVAL;
    t->key->refs--; t->key->readers--; t->key->released++;
    t->live = false; t->key = NULL;
    return 0;
}
static int model_gcm(struct lease *t, const u8 input[80], u8 output[80], const u8 iv[16], bool enc)
{
    struct crypto_aead *tfm = crypto_alloc_aead("gcm(aes)", 0, 0);
    if (IS_ERR(tfm)) return PTR_ERR(tfm);
    struct secret_view v = lease_view(t);
    int err = fscrypt_set_gcm_key(tfm, v.bytes);
    u8 local_iv[16]; memcpy(local_iv, iv, 16);
    if (!err) err = fscrypt_derive_gcm_key(tfm, input, output, local_iv, enc);
    crypto_free_aead(tfm);
    return err;
}
static int create_context(struct environment *e, struct fscrypt_context *ctx, const u8 plain[80], u8 iv[16])
{
    struct lease t = {0};
    struct fscrypt_context tmp = { .format = 2, .contents_encryption_mode = 1, .filenames_encryption_mode = 4 };
    int err = lookup_ce(e, &t);
    if (err) return err;
    memcpy(tmp.iv, iv, 16);
    err = model_gcm(&t, plain, tmp.nonce, tmp.iv, true);
    CHECK(lease_put(&t) == 0);
    if (!err) *ctx = tmp;
    memzero_explicit(&tmp, sizeof(tmp));
    return err;
}
static int unwrap_begin(struct environment *e, const struct fscrypt_context *ctx, struct candidate *c)
{
    if (c->lease.live) return -EBUSY;
    memzero_explicit(c->fek, sizeof(c->fek));
    int err = context_validate(HUAWEI_108, ctx, sizeof(*ctx));
    if (err) return err;
    err = lookup_ce(e, &c->lease);
    if (err) return err;
    err = model_gcm(&c->lease, ctx->nonce, c->fek, ctx->iv, false);
    if (err) {
        CHECK(lease_put(&c->lease) == 0);
        memzero_explicit(c->fek, sizeof(c->fek));
    }
    return err;
}
static int inode_publish(struct candidate *c, struct model_inode *inode)
{
    struct lease *t = &c->lease;
    if (!t->live || t->identity != t) return -EINVAL;
    int err = 0;
    if (!t->key->present || t->generation != t->key->generation) err = -ENOKEY;
    else if (inode->quarantine) err = -EIO;
    else if (inode->owner) err = -EEXIST;
    if (err) CHECK(lease_put(t) == 0);
    else {
        inode->owner = t->key; inode->linked = inode->cached = true;
        t->key->readers--; t->key->enrolled++; t->key->transferred++;
        t->live = false; t->key = NULL;
    }
    memzero_explicit(c->fek, sizeof(c->fek));
    return err;
}
static void inode_detach(struct model_inode *inode)
{
    if (inode->owner) {
        CHECK(inode->linked && inode->owner->refs && inode->owner->enrolled);
        inode->owner->refs--; inode->owner->enrolled--;
    }
    inode->owner = NULL; inode->linked = inode->cached = false;
}
static int fs_remove(struct model_key *key)
{
    if (key->readers) return -EAGAIN;
    key->present = false; key->managed = true;
    memzero_explicit(key->raw, sizeof(key->raw));
    return key->enrolled ? 1 : 0;
}
static enum fs_status fs_key_status(struct model_key *key)
{ return key->present ? PRESENT : key->enrolled ? INCOMPLETELY_REMOVED : ABSENT; }
static int fs_readd(struct model_key *key, const u8 raw[64])
{
    if (key->readers || key->present) return -EBUSY;
    key->generation++; memcpy(key->raw, raw, 64); key->raw_size = 64;
    key->present = key->managed = true; key->revoked = key->null_payload = false;
    return 0;
}
static int cached_access(struct model_inode *inode, bool authorized)
{
    if (inode->quarantine) return -EIO;
    if (!inode->cached) return -ENOKEY;
    if (inode->kind != CE && !authorized) return -EACCES;
    return 0;
}
static int convert_sdp(struct environment *e, const struct fscrypt_context *ctx,
                      struct model_inode *inode, struct durable_sdp *d,
                      enum inode_kind target, int fail_step)
{
    if (inode->quarantine) return -EIO;
    if (target != ECE && target != SECE) return -EINVAL;
    struct candidate ce = {0}, sdp = {0};
    u8 wrapped[80] = {0};
    int err = unwrap_begin(e, ctx, &ce);
    if (err) return err;
    err = lease_get(&e->sdp, false, &sdp.lease);
    if (!err) err = model_gcm(&sdp.lease, ce.fek, wrapped, ctx->iv, true);
    if (!err && fail_step == 1) err = -EIO; /* certified no persistence */
    if (err) goto out;
    /* Persistent callbacks can fail after changing bytes. Never claim rollback.
     * Steps 2..5 inject partial context, metadata, CE erase, post-durable failure.
     * Model ECE and SECE ownership only; SECE ECC/vendor wrapping is NOT modeled. */
    memcpy(d->wrapped, wrapped, fail_step == 2 ? 17 : 80);
    d->context = fail_step != 2;
    d->metadata_partial = fail_step == 3;
    if (fail_step == 2 || fail_step == 3) err = -EIO;
    if (!err) {
        d->flags = true;
        d->ce_erased = fail_step != 4;
        d->ce_partial = fail_step == 4;
        if (fail_step == 4 || fail_step == 5) err = -EIO;
    }
    if (!err) inode_detach(inode); /* CE release after durable writes */
    if (!err) {
        inode->kind = target;
        if (fail_step == 6) e->sdp.generation++; /* defensive stale publication */
        err = inode_publish(&sdp, inode);
    }
    if (err) {
        inode_detach(inode); inode->quarantine = true;
    }
out:
    if (sdp.lease.live) CHECK(lease_put(&sdp.lease) == 0);
    CHECK(lease_put(&ce.lease) == 0);
    memzero_explicit(ce.fek, sizeof(ce.fek));
    memzero_explicit(wrapped, sizeof(wrapped));
    return err;
}

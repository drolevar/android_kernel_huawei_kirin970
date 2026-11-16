/* SPDX-License-Identifier: GPL-2.0 */
/* Test bridge to the existing model. No production keyring or inode objects. */
#include "huawei_fscrypt_host.h"
#include "crypto-subject.h"
#include "model-subject.h"
#include "huawei_fscrypt_vold_model.h"

#define SLOTS 4
static struct environment state;
static struct fscrypt_context context;
static struct candidate pending[SLOTS];
static struct model_inode owners[SLOTS];
static struct lease inheritance;
static bool context_ready;

void model_reset(void)
{
    CHECK(!state.fs.refs && !state.fs.readers && !state.fs.enrolled);
    CHECK(!inheritance.live && !tfm_live && !request_live);
    memset(&state, 0, sizeof(state));
    memset(&context, 0, sizeof(context));
    memset(pending, 0, sizeof(pending));
    memset(owners, 0, sizeof(owners));
    context_ready = false;
    fail_alloc = fail_setkey = fail_unwrap = fail_request = 0;
    state.fs.source = FILESYSTEM;
    state.fs.format = FILESYSTEM_RAW;
    state.allow_legacy = true;
    /* Valid duplicate legacy key: a managed tombstone must still defeat it. */
    state.legacy = (struct model_key){ .source = LOGON,
        .format = LEGACY_PAYLOAD, .present = true, .raw_size = 64 };
    for (unsigned i = 0; i < 64; i++) state.legacy.raw[i] = i;
}

int model_add(const unsigned char *bytes, size_t size)
{
    if (size != 64) return -EINVAL;
    /* Descriptor ADD with an existing secret is idempotent in the reference.
     * This fixture is limited to the one descriptor checked by the C++ boundary. */
    if (state.fs.present) return 0;
    int err = fs_readd(&state.fs, bytes);
    if (err) return err;
    if (!context_ready) {
        u8 plain[80] = {0}, iv[16] = {0};
        for (unsigned i = 0; i < 64; i++) plain[i] = 0x30 + i;
        /* Construct a synthetic existing file, not an ADD kernel side effect. */
        CHECK(create_context(&state, &context, plain, iv) == 0);
        context_ready = true;
    }
    return 0;
}

int model_remove(void)
{
    /* Existing model uses EAGAIN to expose a held atomic admission interval.
     * Real production removal must wait on its chosen semaphore protocol. */
    return fs_remove(&state.fs);
}

unsigned model_status(void)
{
    switch (fs_key_status(&state.fs)) {
    case PRESENT: return 2; /* FSCRYPT_KEY_STATUS_PRESENT */
    case INCOMPLETELY_REMOVED: return 3;
    case ABSENT: return 1;
    }
    CHECK(false); return 0;
}

int model_begin(unsigned c)
{
    if (c >= SLOTS || !context_ready) return -EINVAL;
    return unwrap_begin(&state, &context, &pending[c]);
}
int model_publish(unsigned c, unsigned i)
{
    if (c >= SLOTS || i >= SLOTS) return -EINVAL;
    return inode_publish(&pending[c], &owners[i]);
}
int model_abort(unsigned c)
{
    if (c >= SLOTS) return -EINVAL;
    int err = lease_put(&pending[c].lease);
    memzero_explicit(pending[c].fek, sizeof(pending[c].fek));
    return err;
}
int model_inode_drop(unsigned i)
{
    if (i >= SLOTS) return -EINVAL;
    if (owners[i].busy || owners[i].dirty) return -EBUSY;
    inode_detach(&owners[i]);
    return 0;
}
void model_inode_flags(unsigned i, int busy, int dirty)
{
    CHECK(i < SLOTS && owners[i].owner);
    owners[i].busy = busy;
    owners[i].dirty = dirty;
}
int model_access(unsigned i)
{
    if (i >= SLOTS) return -EINVAL;
    return cached_access(&owners[i], true);
}
int model_wrap_allowed(unsigned i)
{
    if (i >= SLOTS) return -EINVAL;
    return cached_master_wrap_allowed(&owners[i]);
}
int model_inherit_begin(unsigned i)
{
    if (i >= SLOTS) return -EINVAL;
    int err = cached_master_wrap_allowed(&owners[i]);
    if (err) return err;
    return lease_get(owners[i].owner, false, &inheritance);
}
int model_inherit_end(void)
{
    if (!inheritance.live) return -EINVAL;
    struct fscrypt_context child = {0};
    u8 plain[80] = {0}, iv[16] = {0};
    int err = create_context(&state, &child, plain, iv);
    CHECK(lease_put(&inheritance) == 0);
    memzero_explicit(&child, sizeof(child));
    return err;
}
int model_lookup(void)
{
    struct lease temporary = {0};
    int err = lookup_ce(&state, &temporary);
    if (!err) CHECK(lease_put(&temporary) == 0);
    return err;
}
void model_failure(unsigned stage)
{
    CHECK(stage <= 4);
    fail_alloc = stage == 1;
    fail_setkey = stage == 2;
    fail_unwrap = stage == 3;
    fail_request = stage == 4;
}
struct model_stats model_get_stats(void)
{
    bool secret_zero = true;
    for (unsigned i = 0; i < 64; i++) secret_zero &= state.fs.raw[i] == 0;
    CHECK(!state.legacy.refs && !state.prefix.refs);
    CHECK(!tfm_live && !request_live);
    return (struct model_stats){
        .generation = state.fs.generation, .owners = state.fs.enrolled,
        .readers = state.fs.readers, .refs = state.fs.refs,
        .acquired = state.fs.acquired, .released = state.fs.released,
        .transferred = state.fs.transferred, .present = state.fs.present,
        .managed = state.fs.managed, .secret_zero = secret_zero,
    };
}

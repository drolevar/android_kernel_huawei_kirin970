# Internal managed fscrypt registry

This dependency is based on accepted admission/owner core `cf28bb3ad`. It adds
an internal filesystem namespace, not modern ioctls or managed CE consumers.
Legacy key format and lookup are unchanged. Registry creation is lazy; the
private key type is registered at fscrypt initialization.

## Contract and decision ledger

- `fscrypt_registry_add(sb, descriptor, raw, size)` requires initial-user-
  namespace `CAP_SYS_ADMIN` via `capable()`. Descriptor length is the existing
  eight-byte `FS_KEY_DESCRIPTOR_SIZE`; input is exactly 64 raw bytes. Internal
  callers supply valid, private/stable input buffers through the call. No
  wrapped keys, v2 identifiers, provisioning keys or per-user claims are added.
- The namespace is the live superblock object, not its textual `s_id`, mount
  path, process keyring, UID or descriptor alone. Bind mounts sharing a
  superblock share the registry. Different superblocks with identical names do
  not. An ADD mutex serializes lazy ring creation and lookup/link; readers do
  not acquire this mutex. Its scope follows the donor serialized ADD path.
- `fscrypt_registry_lookup()` returns a separately referenced core, including
  when its secret is removed. The caller puts it with `fscrypt_mk_put()`.
  **Only `-ENOENT` means genuine absence.** No ring and the private keyring's
  `-EAGAIN` miss map to that result. All other returned key-service errors,
  including `-ENOKEY`, `-EKEYREVOKED`, `-EKEYEXPIRED`, allocation and permission
  errors, are preserved. A NULL/nonpositive payload after successful search is
  `-EBADMSG`, not absence. This API does not acquire master-secret admission.
- The key payload pointer is immutable. Instantiation takes an independent
  core reference; ADD always drops its temporary reference. Lookup pins the
  payload under `key->sem` before releasing the searched key reference. Later
  secret/owner operations use the accepted core's separate secret semaphore.
- Duplicate ADD uses the existing core. Identical present material is
  idempotent; conflicting present/retained-owner material is rejected by the
  core. Re-add advances the existing object's generation. REMOVE is still
  only the internal core primitive: registry entries are never invalidated,
  unlinked, or expired for secret withdrawal or final owner retirement.
- Root-only descriptor keys use the donor's `KEY_ALLOC_NOT_IN_QUOTA` policy.
  There is no custom quota/tree implementation. Root can consume resources by
  adding descriptors; there is deliberately no claim of unprivileged quota
  accounting or a resource cap for privileged callers.
- A leading-dot key type prohibits userspace `add_key()`. Keys/rings grant no
  WRITE/LINK/SETATTR permissions. SEARCH permission alone would nevertheless
  permit `KEYCTL_INVALIDATE`: the ring has `KEY_FLAG_KEEP` before publication,
  and Linux `key_instantiate_and_link()` propagates KEEP to its entries. This
  also blocks keyctl revoke, clear, unlink-from-kept-ring and timeout paths
  where applicable. It does not prevent ordinary reference-based key GC.
- Registry APIs require a live caller-owned superblock reference; they do not
  race `destroy_super()`. Lookup's acquire load pairs with release publication
  of a fully initialized ring. ADD must not be called while holding a master
  lease. There is no registry lookup spinlock held across crypto or callbacks.

## Superblock and module lifetime

Unlike the pinned donor's boolean FS_ENCRYPTION, Huawei's option is tristate.
Each published ring owns one fscrypt module reference, even if its first ADD
fails or it contains only ownerless tombstones. This prevents unload/reload
from erasing a live filesystem's managed namespace. Failed ring allocation
releases the provisional module reference.

`destroy_super()` calls the inline VFS helper to drop the ring and then its
module reference, clearing both pointers. The helper requires no built-in
call into modular fscrypt and compiles away when encryption is disabled.
Final ring/key reclamation is the Linux key service's deferred GC: **unmount
return is not a synchronous secret-wipe guarantee**. The private key destroy
callback withdraws the core secret and drops the payload reference. Other
core references remain memory-safe, including retained owner references.

A core reference does not itself pin superblock or executable module text.
Future production consumers must keep their inode/superblock and normal
module dependency alive through every core operation. No asynchronous naked
core pointer may escape that contract. The host stable-reference case checks
allocation lifetime after simulated ring GC; it does not authorize use after
real module unload.

Module exit unregisters the key type before destroying fscrypt resources.
Huawei `unregister_key_type()` waits for `key_gc_keytype()` to reap its payload
callbacks, even for referenced keys, before returning. No custom callback is
left callable after module exit. Registration failure preserves its original
errno and unwinds all previously allocated init resources. Forced module
unloading is not covered.

## Provenance and validation

The separate donor-excerpt commit preserves Eric Biggers' original authorship
and trailers from `3a7ee916f32bcb0d204b3d1abc87751e974acbfb`, using selected
primitives as retained in pixel-msm-4.14
`bb17b7de4b570f2c0c32ddba0543cac03c58dd84`. It is explicitly a partial, unbuilt
extraction, not an unchanged cherry-pick. Huawei adaptation adds the accepted
core ownership contract, exact miss/error distinction, persistent tombstones,
KEEP protection and tristate lifetime wiring in a subsequent commit.

Run `scripts/tests/test_huawei_fscrypt_registry.py --cc /path/to/clang22
--output /fresh/output`. The fixture compiles complete production registry,
core, release helper and selected init/exit functions with synthetic Linux key
services, credentials, module references and deferred GC; POSIX locks/atomics
and OpenSSL provide host primitives. It also executes the exact selected
`keyctl_invalidate_key()` function against synthetic key lookup. Input values
and expected errno/generation/reference results are independently specified.

Seventeen ASan/UBSan cases and fifteen compile-valid semantic mutations cover
namespace isolation, eight concurrent first ADDs, duplicate ADD,
privilege/format checks, exact errors, tombstones/re-add, reference lifetime,
allocation/hash/link failures, module pins, registration/init failures and
invalidation rejection. Semantic mutations and receipts live in the ignored
workspace `logs/lineage-24.0/fscrypt-registry-20261116/` directory. Initial stub
RED and the real missing-KEEP RED are retained separately from compile setup
failures. Narrow kernel builds use isolated source/output and the existing
container runner. Normal (exact baseline config), REFCOUNT_FULL=n and encryption-
disabled narrow builds passed for VFS teardown and the fscrypt directory.
FS_ENCRYPTION=m compiled registry/core/crypto and VFS objects but the aggregate
failed in unchanged `fscrypt_extra_ctrl.c:444`, whose `fs_initcall` is not valid
in its module compilation. No claim of a linkable/loadable fscrypto module is
made; fixing vendor extra-control initialization/teardown is separate work.
No full kernel build was run for this candidate.

These tests do not execute the real Linux key service, LSM, RCU, module loader,
mount/unmount or kernel scheduling. They do not establish kernel race safety,
lockdep, inode ownership, on-device FBE or durability. Before consumer/ioctl
activation, the policy/inheritance filesystem lock-order gate, nested preload
avoidance, exact-generation admission, dirty/busy inode ownership and managed
CE-to-SDP exclusion remain mandatory. No active pins or device data change.

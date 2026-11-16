# Internal managed-key lifetime foundation

This candidate implements the internal `fscrypt_mk_*` admission and ownership
primitive in `fs/crypto/master_key.c`. It is linked into `fscrypto` but has no
registry, ioctl or inode consumer yet. It does **not** enable filesystem-managed
keys, FBE support, modern REMOVE/STATUS, or safe CE-to-SDP conversion.

The parent is `3c837d78e8730f7b7db1b94545dc9f1e3951b5ae`, containing the
legacy acquisition adapter and selected-vold ownership fixture. The new core is
original Huawei adaptation code, not a cherry-pick. Its separate secret guard and
retained-owner approach is informed by upstream fscrypt's Google-authored
keyring/keysetup implementation at maintained 4.14 reference
`bb17b7de4b570f2c0c32ddba0543cac03c58dd84`, including the introduction
`3a7ee916f32bcb0d204b3d1abc87751e974acbfb`. No upstream code was replaced.

## Implemented contract

- Exactly 64 raw bytes, matching the selected policy-v1 vold request. No policy
  v2, wrapped key, hardware-slot or legacy-tail interpretation is implied.
- One root reference is returned on allocation. A future filesystem registry
  must retain it even when absent, preserving its managed tombstone until
  teardown. Every concurrent caller must already hold a reference.
- A successful lease holds a read semaphore and a separate reference. Its secret
  view is immutable and valid only until release. Do not copy a token or pass a
  live token between threads. Owner enrollment holds a separate reference and
  retains the admitted generation; enrollment does not consume the lease.
- REMOVE takes the write semaphore, waits for leases to finish, wipes the raw
  secret and reports remaining owners. It does no inode reclaim or filesystem
  callbacks. PRESENT takes precedence over retained older owners in STATUS.
- Same-material ADD while present is idempotent. Re-add increments generation;
  cached inheritance must request its owner's exact generation. Old owners may
  retain FEKs but cannot obtain a new master-secret lease after re-add.
- SHA256 of all 64 bytes binds re-add to the prior material while owners remain.
  Different material is rejected while present or while old owners remain. A
  different key may be admitted after absence and final owner retirement. The
  fingerprint is not the fscrypt descriptor and is wiped on final release.
- Counter/generation exhaustion fails without wrapping. Allocation, hash setup
  and digest errors unwind without changing existing key state. Input buffers
  must remain private/stable for the duration of allocation/ADD.

Owner tokens will need inode associations and an owner list before eviction can
be implemented. The primitive currently counts owners; it does not identify,
evict, serialize publication of, or protect the lifetime of any VFS inode.

## Validation and limits

Run with the selected Android Clang22 host compiler:

```
python3 -B scripts/tests/test_huawei_fscrypt_master.py \
  --cc /path/to/clang-r596125/bin/clang --output /fresh/log/path
```

The runner compiles the complete production C and declarations after removing
only includes. POSIX rwlocks, C atomics, host allocations and OpenSSL SHA256
replace kernel services. Thirteen ASan/UBSan cases cover lifecycle, busy owners,
same/different-material re-add, generation checks, immutable input, exhaustion,
failure cleanup, exactly balanced tokens, final-reference ownership and a
threaded removal/admission interval. The thread test demonstrates the core's
ordering with POSIX locks, not Linux rwsem scheduling or lockdep correctness.

Ten compile-valid mutation controls cover removal/final wipes, generation,
identity, owner references/counts, stale admission, overflow, guard omission and
error-state corruption. An independent review exposed missing failure-state
assertions: the error-state mutant survived the original twelve cases, then
failed the added PRESENT/BUSY partial-digest/hash-allocation case.

No real syscall, kernel concurrency, keyring, inode, crypto driver, storage,
kernel boot or phone test is performed by this runner. Existing selected-vold
fixtures remain independent models; they do not yet invoke this production core.

## Required next integration gates

1. Filesystem-scoped registry with privilege/resource accounting, descriptor
   namespace, stable lookup references and tombstones. No ambiguous legacy
   fallback after a managed lookup, including absent/removed entries.
2. Admission through policy wrapping/persistence, generic CE derivation and
   publication, and the F2FS CE helper. Initialize owner fields in generic,
   HWDPS, F2FS and conditional HMFS constructors and release in all destructors.
3. Explicit lock order across policy xattr transactions and inheritance called
   inside F2FS operation/page locks or an ext4 journal transaction. Release or
   reuse admission before child preload; recursive read acquisition can deadlock
   behind a waiting writer. The outer key semaphore is not the secret semaphore.
4. Temporary managed GCM transforms and exact-generation inheritance admission;
   do not leave cached master-wrap capability in `ci_gtfm` after removal.
5. Inode ownership, dirty/busy eviction, removal retries and unmount teardown.
   Drop the secret write guard before reclaim or filesystem calls. Publish all
   ownership metadata before exposing a new ci to cached readers.
6. Managed CE conversion exclusion before any SDP preparation/persistence,
   serialized against generic publication, until live ownership transfer and
   durable conversion recovery are implemented. Checking only the final
   `f2fs_change_to_sdp_crypto()` call is insufficient.
7. Actual kernel concurrency/lockdep/KASAN and filesystem tests, then composition
   with the networking candidates and the device-readiness gates.

These are open dependencies, not optional waivers or evidence of an installable
Lineage image. Active manifest/kernel selection and the BPF override are unchanged.

# Inactive inode-owner foundation

The shared `fscrypt_mk_owner` contains an opaque core pointer and generation.
`fscrypt_mk_init_owner()` initializes fresh storage; it must never reset a live
owner. Existing `fscrypt_mk_enroll()` attaches an independent reference from a
borrowed admission lease and rejects empty leases, duplicate attachment and
owner-count overflow. `fscrypt_mk_drop_owner()` clears the token and retires the
reference without taking the secret guard or invoking filesystem operations.
Enroll/drop are GPL exports for filesystem-module linkage; the master-key
representation and lease definition stay private to fscrypt.

All six ci constructors initialize the token before fallible work. All three
slab destructors drop it after key/transform cleanup, including private failure
and losing-publication cleanup. Existing inode release reaches the generic
slab destructor. No production caller enrolls a ci in this change: legacy,
HWDPS and SDP tokens remain empty. No registry dispatch or public ioctl is added.

Run with selected host Clang22 and a fresh output directory:

```
python3 -B scripts/tests/test_huawei_fscrypt_owner.py --cc /path/to/clang --output /path/to/receipt
```

The fixture extracts the actual ci layout, the five generic/SDP allocation and
initialization blocks, the whole HWDPS constructor, all three complete slab
destructors, generic publication/out code and `fscrypt_put_encryption_info()`.
The production master-key core executes with the existing POSIX/OpenSSL service
shim. It poisons slab allocations and checks initialization, allocation errors,
HWDPS copy/cipher failures, empty cleanup, resource/owner retirement, attachment
errors, private failure, losing publication, final ci release, last-reference
release and independent parent/child owner retirement. The parent/child schedule
is not execution of production inheritance.

The baseline scaffold adds only the future owner member to the extracted old
layout so the old initialization/release bodies compile and fail semantically.
It does not initialize or drop that member. The first compile setup failure is
not semantic RED. After initialization was implemented, a separate RED run
reached all three missing-drop assertions. The final fixture supports twelve
compile-valid mutations: each constructor initialization, each destructor drop,
core owner retention/count, and generation initialization.

Allocation, crypto-resource cleanup, inode/slab and sequential cmpxchg services
are synthetic. Publication attachment and failure scheduling are fixture-driven;
production attachment remains inactive. These tests do not execute the complete
generic/SDP constructors, VFS eviction, kernel RCU/SMP, real filesystem locking,
registry consumers, encryption or hardware I/O. Object builds check selected
headers/configurations, not module unloading or a complete module link.

Required later gates remain unchanged: prepared F2FS/ext4 operations, ext4 EA
journal restart/forced-commit/eviction paths, same-lease inheritance/preload,
serialized managed conversion exclusion and conversion durability. A raw64
master is not a validated Huawei inline slot or metadata contract. No managed
consumer, public ADD, live CE-to-SDP conversion or durability claim is enabled.

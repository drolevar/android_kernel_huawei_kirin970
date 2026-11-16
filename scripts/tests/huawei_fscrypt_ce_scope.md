# Legacy CE use-scope extracted host test

This ASan/UBSan fixture extracts the production legacy CE scope, the real
`find_and_derive_key*()`, `put_crypt_info()`,
`fscrypt_{get,put}_encryption_info*()` constructors and teardown, policy and
inheritance call sites, plus the CE-only F2FS/HMFS helpers. Only kernel
primitives and crypto services are shimmed. Keyrings, inode lifetime and
filesystem persistence are modeled; AES-GCM uses OpenSSL. It performs no
kernel, mount, keyctl, hardware or phone operation.

Run with a fresh output directory:

```sh
python3 -B scripts/tests/test_huawei_fscrypt_ce_scope.py \
  --cc /path/to/clang22 --output /fresh/output
```

Before production implementation the runner supplies compile-valid failing
stubs, producing semantic RED rather than treating a compiler setup error as a
test. The GREEN cases cover immutable 32/64 material through crypto, legacy
slot byte 63, stack material and scope wiping, purpose/superblock/descriptor
matching, allocation cleanup, release before the filesystem callback, cached
CHILD_WRAP descriptor and hardware-encryption guards after revocation, private
preload without public child recursion or second acquisition, descendant
inheritance after parent eviction, and both filesystem CE helper routes.

Mutation choices are `purpose`, `scope-sb`, `scope-descriptor`, `scope-wipe`,
`material-wipe`, `lock-release`, `owner-ref`, `slot`, `preload-public`,
`cached-acquire`, `f2fs-purpose`, `hmfs-purpose`, `tfm-descriptor`, and
`hw-enc-guard`. A retained mutation receipt is valid only when compilation
succeeds and at least one behavior case fails.

The fixture does not prove VFS/SMP lifetime, crypto-provider concurrency,
filesystem lock order, ext4 journal behavior, F2FS checkpoint behavior,
managed registry admission, durable CE-to-SDP conversion or handset support.

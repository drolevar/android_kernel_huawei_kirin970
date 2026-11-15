# Huawei fscrypt synthetic contract fixture

This is a design model and host characterization harness, not an fscrypt
adapter. It changes no production source. All key bytes are synthetic.
The baseline is kernel commit `166e09649`; each run records the full current
commit, extracted source hashes, fixture hashes, compiler, commands and artifacts.

Run from this kernel checkout with the workspace's selected compiler:

```sh
python3 -B scripts/tests/test_huawei_fscrypt_contract.py \
  --cc /path/to/clang-r596125/bin/clang \
  --keep-output /new/empty/output-directory
```

Requires Clang 22, host OpenSSL development headers/library, ASan and UBSan.
No container or kernel is executed. Each C case is a separate subprocess.
`--suite model|actual` selects a suite. `--mutation` injects one deliberate
contract violation; a nonzero result with the relevant assertion failure is
expected. Compilation errors are not mutation success.

## Boundary and ownership decisions

* Context namespace is explicit. Huawei's packed 108-byte format 2 remains
  Huawei GCM, not generic fscrypt v2 (nor generic v1). The extracted GCM helper
  wraps 64 bytes with AES-256-GCM, no AAD, and a 16-byte tag. The stored IV is
  16 bytes; this source's GCM implementation consumes the first 12. An independent
  AES-256-GCM test vector and tag/IV tampering check this host boundary.
* The validated view exposes const bytes and a 32-byte GCM key length without
  rewriting a 32/64-byte payload. Source, payload format and vendor metadata
  are separate. Only legacy LOGON/LEGACY_PAYLOAD gives raw[63] slot meaning;
  a filesystem raw key can carry explicit vendor metadata instead.
* A lease is address-bound, initialized to zero, cannot be copied or acquired
  twice while live, and has one terminal action: release, or transfer into an
  inode owner. A saved view is borrowed only until that action. Readers prevent
  removal while derivation/publication is in flight. This is a sequential
  simulation of atomic lock intervals, not a pthread test or kernel lock proof.
* All three CE consumers use the same acquisition boundary: policy creation,
  generic CE unwrap, and F2FS CE lookup during CE-to-SDP conversion. The model
  uses real host GCM through the extracted helper for wrapping/unwrapping.
* Filesystem lookup takes precedence. Legacy fallback must be explicitly
  enabled, occurs only on an unmanaged miss, and only ENOKEY permits trying a
  second prefix. Managed removal leaves a tombstone that blocks downgrade.
* Publication has a single winner; losers release their lease and wipe candidate
  FEKs. Presence and generation are checked independently. Removal zeros raw
  secrets but retains busy/dirty cached inode owners as incompletely removed;
  re-add advances the generation without losing the retained owner count.
  Detachment is idempotent. Existing cached CE access is deliberately retained;
  cached HWDPS/ECE/SECE still require authorization. Quarantine overrides both.

## CE-to-SDP persistence and failures

CE and SDP acquisition leases remain live through preparation and persistence.
No live CE inode fields are changed during preparation. Both ECE and SECE run
this ownership state machine; the SECE ECC protocol is **not** implemented.

| Injected step | Persistence evidence | In-memory result |
| --- | --- | --- |
| 1 | Certified failure before writes | Existing CE owner/cache retained |
| 2 | First 17 wrapped-context bytes written, callback fails | Detach CE, release leases, quarantine |
| 3 | Context complete, vendor metadata partially written | Same quarantine rule |
| 4 | Context and enable flags complete, CE erasure partial | Same quarantine rule |
| 5 | All writes complete, subsequent failure | Same quarantine rule; no rollback claim |
| 6 | All writes complete, stale SDP publication generation | Same quarantine rule, ENOKEY |
| 0 | All writes and publication succeed | CE owner released, SDP lease transferred |

Preparation failures (revoked/malformed SDP key and allocation/setkey/request
faults) retain CE ownership and leave persistence untouched. Any potentially
partial write is treated as uncertain, not as an atomic no-op. Quarantine denies
cached access and repeated conversion. Actual recovery requires authoritative
persistent-state revalidation and filesystem transaction semantics; this model
supplies no recovery algorithm and cannot prove crash consistency. Flags and
metadata are abstract state, not serialized Huawei xattrs. A real adapter must
also serialize conversion against inode teardown, duplicate publishers and
vendor callbacks; simulated schedule guards do not prove those locks exist.

## Read-only source findings

The `actual` suite extracts functions unchanged from policy.c, crypto/keyinfo.c
and f2fs/keyinfo.c. Host boundary instrumentation characterizes:

* Policy creation dereferences a revoked NULL payload (an expected UBSan fault,
  narrowly accepted only for the policy-null subprocess).
* Policy and process-key lookup rewrite payload size from 64 to 32 under a
  read-lock interval.
* Generic CE unwrap's AEAD allocation failure has one down_read and two up_read
  operations. The host semaphore records underflow; it is not a real semaphore.
* F2FS CE lookup accepts a 32-byte payload, rejects a 64-byte payload and returns
  EKEYREVOKED for the simulated revoke boundary. Generic lookup's revoked path
  returns ENOKEY. These remain source characterization, not fixes.

Read-only inspection of `f2fs_change_to_sdp_crypto()` shows live ci fields
changed before update_sdp_context, then vendor metadata, flags and CE context
updates, with fscrypt_put_encryption_info on failure. An error return alone
cannot establish which writes persisted. Cached SDP paths call authorization
checks; generic cached shortcuts must not bypass these or HWDPS checks.

## Validation scope

The model cases are formats, immutable, consumers, errors, fallback, remove,
publication, sdp, sdp-preflight, owners and cached, plus a compile-negative const
view write. Seven extracted-source cases cover the vector and error paths above.
Six mutations cover fallback downgrade, stale publication, early CE release,
cached authorization bypass, raw[63] metadata confusion and payload rewriting.

This does not execute keyctl, mount, ioctl, a kernel, hardware inline crypto,
HWDPS/SECE cryptography, CONFIG_VMAP_STACK allocation paths or async crypto
completion. It does not establish full policy validation, descriptor lookup,
key identifier verification, generation wraparound behavior, kernel race
freedom, persistent recovery, boot success or device reproduction.

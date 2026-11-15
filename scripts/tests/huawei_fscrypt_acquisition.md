# Huawei legacy CE acquisition candidate

Parent: b6631cccfe0dd438aec88068bead52ffeff6d785. The historical synthetic
contract is reused with its original authorship from 5f35ed55. Its original
production probes remain explicitly pinned to 166e096; they characterize old
bugs, not the current implementation. The new acquisition runner extracts the
current production functions and hashes all inputs.

## Production boundary

`fscrypt_acquire_ce_key()` uses only the existing logon backend. A successful
lease owns one key reference and one read semaphore, plus a private copy of the
validated legacy `fscrypt_key` representation. Consumers never modify the
shared payload. Both size32 and size64 retain all 64 raw bytes and original
size. GCM consumes the first 32 bytes; generic CE unwrap retains raw[63]
exactly as before. That byte is vendor provenance, not validated hardware-slot
semantics. Existing downstream inline-crypto checks remain intact.

Only request_key's ENOKEY permits alternate-prefix lookup for the policy and
ordinary CE consumers. F2FS retains its primary-prefix-only policy. ENOKEY
can represent absence, a negative key, or a search that skipped expired keys;
this is explicitly a legacy alias policy, NOT true-miss-only fallback.
Other lookup errors and every post-lookup validation failure are terminal.
This tightens policy's previous fallback-on-any-error and unwrap's fallback
on malformed payload. No new backend, registry or managed tombstone exists
in production. The fixture's managed-state priority remains a future design.

A successful lease must not be copied, acquired over, or shared. The caller
releases it once on every path; release clears private material. Policy drops
the read lock after setkey, before derivation and filesystem set_context, as
before. Generic unwrap retains the lock through crypto; F2FS copies its GCM
key and releases before crypto, as before. This does not strengthen revocation
into revoking already instantiated AEAD transforms or file FEKs.

The F2FS helper requires an explicit CE/ECE/SECE class and destination capacity.
CE rejects SDP-shaped payloads. Non-V3 SECE accepts a 32-byte private key and
64-byte public key, or a public-only key for creating a new file key; unwrapping
requires the private key. Both source arrays and destination bounds are
validated before copying. V3 accepts only the selected class's 32-byte GCM key.
The 108-byte context, format2, GCM layout and CE-to-SDP persistence are unchanged.

## Validation and limitations

Run the historical contract runner first to obtain declaration headers, then:

```
python3 scripts/tests/test_huawei_fscrypt_acquisition.py --cc CLANG22 \
  --historical-output HISTORICAL_OUTPUT --keep-output NEW_DIRECTORY
```

The new suite executes extracted acquisition/release, policy, generic unwrap,
F2FS payload/FEK functions, and the original GCM wrapper. Key search, key
validation, read locks, allocation and revocation timing are host shims;
AES-GCM uses OpenSSL. It is not kernel keyring, RCU, concurrent revocation,
hardware keyslot, VMA, filesystem or phone validation. Mutations selectively
remove the guards and must fail actual assertions/sanitizers, not compilation.
The red probe reproduces original payload mutation, double unlock, NULL payload
and SECE destination overflow against historical extracted functions.

The synthetic generation test distinguishes retained CE-FEK access from the
cached master transform's authority to wrap a child after REMOVE/re-add. That
rule is not implemented in production here. Modern ADD/REMOVE/STATUS, inode
owner replacement and retiring ci_gtfm need a separate ownership design and
runtime validation. CE-to-SDP writes remain non-atomic; crash recovery remains
unresolved. No device tests or kernel full build are implied by host results.

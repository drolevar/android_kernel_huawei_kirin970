# Selected vold key-management consumer fixture

This host fixture executes extracted production functions from:

- `system/vold` at `11d8982f824d52e8122c7aa732207ba66b8f23c8`:
  `generateKeyRef`, `buildKeySpecifier`, `installKey`, `waitForBusyFiles`, `evictKey`.
- `system/extras` at `378b92d7f4511cb3f23a34fecc694b9704530374`:
  libfscrypt mode tables, `LookupModeByName`, `ParseOptionsForApiLevel`, and its
  public option/policy declarations.
- The supplied Android checkout's clean bionic fscrypt UAPI header; its revision
  and file hash are recorded and ABI structure sizes checked.

No production function body is edited except in an explicitly requested mutation
run. Generated source carries the upstream Apache notice. Namespace placement is
preserved for the option parser. OpenSSL supplies SHA-512; Python's independent
hashlib calculation checks descriptor bytes. This is not a new fscrypt
implementation or a hardware-key test.

## Reproduce

From the kernel candidate, with an existing Android checkout and its selected
Clang22 toolchain (no toolchain download, root access or device required):

```sh
python3 scripts/tests/test_huawei_fscrypt_vold.py \
  --android /path/to/lineage-24.0 \
  --cc /path/to/lineage-24.0/prebuilts/clang/host/linux-x86/clang-r596125/bin/clang++ \
  --keep-output /path/to/new-output-directory
```

The output directory must not exist. It retains source extraction, compiler
command/output, per-case logs and a JSON receipt with source/function/fixture and
binary hashes. Compilation uses ASan/UBSan. Each process is bounded; a mutation
run is expected to fail behavior, not compilation or dynamic loading. Run each
of `ignore-readd`, `remove-error`, `skip-worker`, `no-backoff`, `wrapped-flag`,
`default-v2`, and `specifier-tail` using `--mutation NAME` and a distinct directory.

## What executes and what is simulated

The selected option parsing, ADD argument creation and key-descriptor hashing,
REMOVE return decisions, STATUS cancellation and retry/backoff control flow are
production code. The harness replaces open/ioctl, fd ownership, worker scheduling,
sleep, logs and string splitting. Threads are queued until the caller returns;
workers then run sequentially. The KeyBuffer uses synthetic bytes in a vector,
not vold's secure allocator. There are no real fds, ioctls, keys, mounts, worker
threads or sleeps. The v2 returned identifier is deliberately synthetic; only its
copyout plumbing is tested. No filesystem registry is implemented by the scripted
ioctl replies, including the case named `readd-during-wait`.

Seventeen cases cover:

- API26 plus `aes-256-xts:aes-256-cts` selects v1/raw and the older padding flag;
  API30 selects v2, and an unknown option fails.
- Raw/v0-wrapped/modern-wrapped ADD argument and flag distinctions; v1 descriptor
  hashes and v2 returned-identifier propagation. Observing these userspace paths
  does not implement wrapped keys or generic policy-v2 on Huawei.
- Successful removal, FILES_BUSY worker creation, retries, PRESENT/ABSENT stopping
  the obsolete cleanup attempt, and mutex availability during the wait boundary.
- STATUS/REMOVE/open errors; OTHER_USERS priority over FILES_BUSY at initial
  removal; worker OTHER_USERS behavior; bounded exponential waits through51200ms.
- Invalid descriptor/identifier sizes and versions, zero reserved fields and
  unused specifier bytes (independent expected specifier), exact
  ioctl ordering, and balanced fd/worker cleanup.

The configured raw policy-v1 consumer still requires ADD/REMOVE/STATUS ioctls.
Huawei's108-byte GCM context and its format byte2 are a different namespace from
upstream fscrypt policy-v2. This fixture preserves that distinction; it neither
changes the context nor proves current firmware key-service compatibility.

## Remaining gates

Connect this consumer to the managed key/owner model, then implement and validate
filesystem-keyring admission and removal, old/new generations, busy/dirty owners,
losing inode publication, cached `ci_gtfm` retirement and denial of unintended
legacy fallback. Retained file FEKs and permission to wrap new child contexts
must remain separate. Production concurrency, inode/I/O lifetime, real ioctl
routing, filesystem teardown, vendor integration and CE-to-SDP durable conversion
and crash recovery remain unresolved. These host tests do not prove any of them.

## Consumer connected to the ownership model

`test_huawei_fscrypt_vold_model.py` accepts the same `--android`, `--cc` and
`--keep-output` arguments. It first runs the17-case consumer fixture and existing
historical model suite, then links the unchanged selected vold functions to
`huawei_fscrypt_model.h` through `huawei_fscrypt_vold_model.c`. The C bridge and
C++ consumer are both built with ASan/UBSan; extraction, commands, input hashes,
logs and results are retained. The original scripted suite remains available.

This backend handles one synthetic descriptor and64-byte raw keys. It is not a
keyring implementation: caller credentials, key quota, multiple descriptors,
wrapped/v2 keys, filesystem mount lifetime and production inode objects are not
implemented. Descriptor ADD while present leaves the current secret/generation
unchanged, following the reference's idempotent path. First ADD also constructs
an existing synthetic Huawei GCM file context as test setup; context construction
is not an actual ADD ioctl side effect. No production key bytes are used.

Eleven schedules now drive actual vold code using model state:

| Case | Connected behavior |
| --- | --- |
| clean | ADD, REMOVE, wiped secret, ABSENT and tombstone blocking a valid legacy duplicate |
| busy-retry | Dirty/busy owner retained; cleanup retries; external clean/close permits final removal |
| readd | ADD during worker sleep advances generation; PRESENT stops old cleanup; old/new owners remain separately accounted |
| admission | An in-flight unwrap pins admission; after abort, removal succeeds with balanced references |
| publication | Two candidates contend for one inode; losing publication releases its lease |
| errors | Allocation, setkey, unwrap and crypto-request failures leave no admission references |
| inheritance | Admission holds a master lease; removal disables new wraps; re-add does not authorize an old cached generation |
| duplicate-add | Existing secret and inode generation remain intact |
| scope | Wrapped/v2 requests are explicitly rejected by the fixture backend |
| dirty-only / busy-only | Each condition independently prevents teardown and preserves references until explicitly cleared |

`--mutation` accepts `tombstone`, `generation`, `busy-flag`, `owner-release`,
`readd-status`, `admission`, `master-retirement`, `dirty-owner`, and `busy-owner`.
Each must compile and fail
its relevant assertion. Mutation applies only to generated host inputs, never
production source. The unmutated model itself remains unchanged.

**Limits:** `fs_remove()` returns EAGAIN when a modeled reader is active. This is
an observable model scheduling boundary, not the proposed production ioctl ABI;
the production semaphore/wait protocol is still required. Worker execution is
sequential; no races, IRQ behavior or kernel locks execute. Cached access is a
model permission check, not I/O through a real retained FEK. Inheritance uses a
held model lease plus host GCM, not an actual cached Huawei `ci_gtfm`. These tests
do not implement or prove production transform retirement, managed registry
admission, inode teardown, CE-to-SDP persistence or crash recovery.

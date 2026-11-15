# Bounded CGROUP_SOCKOPT candidate

Parent: 6c0792b8b586da0bf624c2b389368274043ef3f0. Semantic donor:
Pixel 4.14 bb17b7de4b570f2c0c32ddba0543cac03c58dd84. Full original authors and
trailers are retained in sockopt-upstream.txt. This is a consolidated adaptation,
not a dependency-closed cherry-pick or a claim of general Linux 5.10 support.

## Selected consumer and admission

Connectivity 7c04d866538e6f689823b769fb5c1e614ca0e295, bpf/progs/netd.c,
getsockopt/prog$5_10_v and setsockopt/prog$5_10_v both emit helper 107.
The GET section loads ctx->sk, obtains storage, checks an eight-byte optval
range, reads and clears the u64 dropReasons field at storage offset 16, then
writes retval=0 and optlen=8. SET invokes helper 107 before writing optlen=0.
The pinned internal_net_api.h defines SO_ANDROID_DROP_REASON as 0x0ad01d01.

Canonical UAPI program type 25 and attach types 21/22 are supported. PROG_LOAD
prog_ifindex/expected_attach_type are at offsets 64/68. Nonzero offload ifindex
is rejected. SOCKOPT requires an explicit matching GET or SET expected type at
load, verifier entry and attach/detach. Query admits both hooks. Legacy zero
CGROUP_SOCK expected type is fixed to SOCK_CREATE; existing zero legacy modes
otherwise remain unspecified. Unsupported expected types remain rejected.

GET can read retval but cannot write level/optname; SET cannot read/write retval
and may write level/optname. Both may write optlen. Pointer fields are read-only
64-bit fields. Partial/interior pointer reads are rejected. ctx->sk is borrowed
PTR_TO_SOCKET and helper 107 uses the socket-argument storage prototype, never
the legacy CGROUP_SOCK context prototype. No other helper is exposed by this
program type. Return values must be scalar 0 or 1.

optval/end reuse the existing packet-range verifier and context conversion;
there is no JIT rewrite or BPF-to-BPF call addition. A context pointer overwrite
clears the destination's ownership ID without discharging another live alias's
obligation. Storage values acquire no socket ownership. Existing CGROUP_SKB
borrowed/owned routes and ring release admission are unchanged.

## Runtime contract

LSM runs first. GET runs after the protocol handler, including handler rejection
of the custom option. SET distinguishes deny (0 -> EPERM), consumption (optlen
-1), original-buffer passthrough (optlen 0), and bounded replacement. Replacement
restores the address limit and frees its allocation even on protocol errors.

The complete consolidated donor runners include PAGE_SIZE trimming, minimum
16-byte SET allocation, zero-optlen passthrough cleanup, GET output bounds and
NULL-optval count-only behavior. The caller's original large buffer remains
unchanged by the hook when optlen is zero. GET retval may only retain the
protocol result or become zero. Usercopy faults propagate through donor paths;
a copyout fault after the selected consumer clears storage does not roll back
that clear. Negative input lengths and invalid output lengths fail. Allocation
failure is ENOMEM. Zero-sized GET allocation follows kernel kzalloc semantics.

Donor NULL/count nuances are intentional: output length bounds apply only when
optval is non-NULL. A NULL optval can report count without copying bytes. The
initial count-snapshot macro ignores get_user's status and retains zero on
fault; the protocol result and hook then determine the returned error. For the
selected custom GET with a NULL count, the modeled zero-length snapshot causes
EPERM before storage is cleared. This is not a promise that every invalid count
pointer yields EFAULT. No new userspace ABI is invented to replace donor behavior.

Native hooks explicitly skip in_compat_syscall(); the existing separate
net/compat.c paths are untouched. ARM32 compat sockopt hooks are unsupported in
this candidate, matching the requested initial Linux 5.10 boundary.

## Evidence and limits

Run scripts/tests/test_sockopt_runtime.py with --cc, --connectivity and --output;
test_sockopt_load.py and test_sockopt_verifier.py take --cc and --output.
The runtime fixture extracts complete production native syscalls and runners,
plus exact pinned consumer functions and option definitions. Kernel usercopy,
allocation, locking, protocol callbacks, storage and BPF invocation are modeled.
The verifier fixture extracts context permissions, conversion, memory checks,
conditional branches, ownership and helper admission. Constant pointer-addition
state is modeled; its inherited ALU stubs deliberately abort and are not claimed
as executed production arithmetic. Conversion tests inspect emitted load/store
instructions; they do not execute a JIT. Load/query tests extract production
control flow while modeling allocation, verification, cgroup and fd services.

Evidence lives in logs/lineage-24.0/bpf-sockopt-20261116 in the enclosing workspace:
19 runtime cases, nine verifier/translation cases, load/query tests, six detected
production mutations, 18 inherited host suites, 37 unchanged loader snapshots,
and 33 loader policy checks. Ten runtime cases failed on the parent before the
implementation; a failing permission test caught interior pointer reads before
that adaptation was corrected. ARM64/ARM32 UAPI layout assertions compile.
Narrow -j4 builds compile 15 objects across normal, NET-off, CGROUP_BPF-off and
BPF_SYSCALL-off configurations using the existing image and source toolchains.

These are offline source and modeled-service results, not successful real BPF
loads, verifier/syscall/network execution, RCU concurrency or handset evidence.
Independent review and a coordinated full kernel link remain the next gates.
No source publication, manifest update or full build is performed by this task.

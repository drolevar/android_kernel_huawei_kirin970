# Measured socket-release attachment

Parent aa6865d3aad47a19c8a70bc06afe9d946de318ab. Pinned semantic donor
pixel-msm-4.14 bb17b7de4b570f2c0c32ddba0543cac03c58dd84; introduction
91e02017294f0b08d60c2caa1bd7fe19726aac75 by Stanislav Fomichev. Original
message, authors and trailers are retained in socket-release-upstream.txt.

Connectivity 7c04d866538e6f689823b769fb5c1e614ca0e295 emits the selected mandatory
cgroupsockrelease/inet_release$5_10_t section: program type9, attach34,
ten instruction slots. It calls helper46 with the context, spills the cookie
onto an eight-byte stack slot, skips deletion if zero, otherwise calls helper3
on cookie_tag_map and returns1. This is distinct from helper86, which releases
an acquired lookup reference. Original metadata selection is API3700 with a
hypothetical5.10.239 kernel, not an active version override.

## Runtime and admission boundary

Canonical BPF_CGROUP_INET_SOCK_RELEASE=34 expands existing cgroup arrays through
MAX_BPF_ATTACH_TYPE. inet_release invokes the existing cgroup socket runner only
for a non-NULL userspace socket, before Huawei release callbacks, multicast
cleanup, socket detachment and protocol close. inet6_release performs its existing
IPv6 multicast/anycast cleanup and delegates to inet_release, so it invokes the
hook once. NULL handling, linger, exiting-process behavior and kernel sockets
retain their existing semantics. The hook return is ignored: zero does not
prevent close. A socket already detached from struct socket is not run again.

The socket's own cgroup selects the RCU-protected program array. Existing socket
storage remains live during the release hook and protocol close; its existing
free operation remains in __sk_destruct. Close and final destruction are not
assumed synchronous. No storage, reference tracking or JIT implementation changes
are made. The selected consumer removes cookie tags, not socket storage.

Load admits CREATE(2) or RELEASE(34) for CGROUP_SOCK, rejects other expected types
and unsupported offload. Zero expected type is still fixed to CREATE before
verification. Attach/detach require matching expected type and query admits34.
Verifier entry checks the same two types. New release programs require scalar
Boolean returns, matching the donor; the legacy create return policy is retained.
No post-bind or other new attachment is implied by holes in the canonical enum.

Release reuses the existing bpf_sock context validator/converter and CGROUP_SOCK
helper dispatcher. The six existing four-byte fields are readable; bound_dev_if,
mark and priority retain existing write permissions. Helper46 uses ARG_PTR_TO_CTX,
not the skb cookie prototype. Helper3 checks the initialized stack key against
map key size. No new helper is exposed; existing helpers for the shared program
type remain present. Helper presence alone does not establish full-program load.

## Validation and limits

The three socket-release host suites extract production inet_release,
inet6_release, __sk_destruct, cgroup array runner, cookie helper, exact pinned
consumer, load/attach/detach/query control flow and verifier conditions. Kernel
map deletion, cookie service, protocol close/destruction scheduling, locking,
allocation and RCU services are modeled. Deferred destruction checks ordering,
not concurrency. Initial lifecycle and load assertions fail on the parent;
release-specific return/admission checks also fail before the adaptation.

The completed offline checks include16 runtime cases, load/admission tests,
nine verifier case groups, eight detected production mutations and27 inherited
host suites. Fifteen objects compile across normal, NET-off, CGROUP-off,
SYSCALL-off and IPv6-module configurations with at most four jobs. ARM64/ARM32
compile-only ABI assertions pass;37 loader snapshots and46 HHEE/JIT hashes
remain unchanged, and33 loader policy checks pass. Initial fixture extraction
and prototype-declaration errors are retained in the logs, not counted as RED
behavioral evidence. ARM32 layout assertions are not runtime validation.

Evidence and configuration receipts live under the enclosing workspace's
logs/lineage-24.0/bpf-socket-release-20261116. No source publication, full kernel
build, active pin update, version override or device operation is performed.
Independent exact-diff review, coordinated full link and real selected-consumer
VM loading/attachment/lifecycle tests remain separate validation gates. Neither
these fixtures nor the existence of attach34 proves acceptance of all six BPF
objects.

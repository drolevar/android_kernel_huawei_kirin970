# Measured CGROUP_SOCK_ADDR candidate

Parent: 18f3d7fa2fd87f3159ce792ea639c90f7d9f4758. Semantic donor:
pixel-msm-4.14 bb17b7de4b570f2c0c32ddba0543cac03c58dd84. Original commit
messages, authors and trailers are recorded in sockaddr-upstream.txt. This is
a bounded consolidated adaptation, not dependency-closed cherry-picks.

## Selection and admission

Connectivity 7c04d866538e6f689823b769fb5c1e614ca0e295 netd.c emits ten sockaddr
sections. Under the API37.0 / hypothetical 5.10.239 selection, eight apply:

| Hook | Selected suffix | Attach ID | Emitted helpers |
| --- | --- | --- | --- |
| bind4 / bind6 | inet4_bind$4_19_t / inet6_bind$4_19_t | 8 / 9 | 1 |
| connect4 / connect6 | inet4_connect$4_19_v / inet6_connect$4_19_v | 10 / 11 | none |
| sendmsg4 / sendmsg6 | udp4_sendmsg$4_19_v / udp6_sendmsg$4_19_v | 14 / 15 | none |
| recvmsg4 / recvmsg6 | udp4_recvmsg$4_19_v / udp6_recvmsg$4_19_v | 19 / 20 | none |

The bind$4_19 variants have exclusive maximum 5.15. The two bind$5_15 variants
remain in the inventory but are unselected. Helpers 14/15 and return value 3
(capability-check skipping) are deliberately unsupported. No version override
or active pin change is part of this candidate.

Program type 18 requires one of these eight explicit expected attach types at
load and verifier entry. Attach/detach must match; query admits all eight.
Offload remains rejected. Other sockaddr attachments and helpers are rejected.
The only helper exposed is map lookup (1). Bind/connect/send return scalar 0/1;
receive programs must return 1 because the runtime ignores their return value.

## Context and runtime

Canonical sockaddr context fields include family, type, protocol, destination
address/port, send-only source addresses and a borrowed socket pointer. Family
specific address fields are restricted to their corresponding hook family.
Scalar metadata and the complete 64-bit socket pointer are read-only. Padding,
partial socket pointers and cross-family/source-field misuse are rejected.
IPv6 arrays allow bounded aligned doubleword access. The conversion preserves
registers using the donor context scratch slot. Huawei packed socket type and
protocol fields reuse the existing mask/shift converter. No ownership or JIT
rewrite is introduced; the socket pointer carries no acquired reference.

Bind hooks run after minimum length validation and before existing address,
namespace capability and port allocation checks. Capability checks remain
unconditional. TCP and UDP have real IPv4/IPv6 pre-connect callbacks and actual
stream/datagram dispatch. Datagram disconnect bypasses connect hooks. UDP
IPv6 AF_INET delegation retains the IPv6-only guard and selects the IPv4 hook.

UDP send hooks run on unconnected destinations after ancillary processing,
before routing, and can rewrite destination/source addresses. Rewritten zero
ports are rejected. IPv6 mapped rewrites are rejected on the native IPv6 path;
existing IPv4 delegation remains. Early error paths release options/flowlabels
without releasing an uninitialized destination. Receive hooks rewrite copied
peer addresses only when the caller requested an address. The cgroup runner
uses the socket's cgroup, an RCU-protected program array and donor deny semantics.

## Evidence boundary

Evidence is retained under logs/lineage-24.0/bpf-sockaddr-20261116 in the enclosing
workspace. Host fixtures extract production functions, context conversion,
verifier checks and load/attach/query control flow. The bind fixture extracts
the exact pinned netd functions and executes the selected 4.19 branch.
Kernel allocation, locking, RCU, namespaces, map services, transport callbacks
and BPF execution are modeled. UDP fixtures execute extracted hook and cleanup
blocks, not complete transport functions. Conversion tests interpret emitted
instructions rather than running a JIT. These are not real BPF load, syscall,
network, concurrency or handset results.

The six sockaddr host suites cover 19 bind/consumer cases, 12 UDP cases,
the four production pre-connect callbacks and complete stream/datagram dispatch,
load/attach/query admission, context permissions/ownership/map-key checks, and
conversion across four layout/mask variants. Stream tests include denial before
Huawei MPTCP initialization, protocol errors, disconnect and deferred Fast Open
continuation. Map-key tests use the actual helper prototype and production stack
and map access checks. Twelve mutations compile and fail their runtime oracles.
An initial length-check mutation targeted the wrong function and was corrected;
its undetected result is retained rather than counted as validation.

All 21 inherited suites pass. The 37 loader snapshots and 46 protected HHEE/JIT
hashes match the parent evidence; all 33 loader policy checks pass. ARM64 and
ARM32 compile-only ABI assertions preserve the 72-byte sockaddr context, socket
pointer offset 64, canonical type/attach IDs and load attribute offsets 64/68.
These layout checks do not establish ARM32 runtime hook behavior.

The configuration matrix compiles 26 objects across normal, NET-off, CGROUP-off,
SYSCALL-off, IPv6-off and IPv6-module configurations using the existing image and
source tools, at most four jobs. Initial failed compiles and their diagnostics
are retained: IPv4 destination variable scope, IPv6 early cleanup label, and the
disabled cgroup static-key predicate. The final snapshot matches all production
source files in this candidate. Independent exact-diff review and a coordinated
full kernel link remain required; neither publication nor a full build is
performed by this task.

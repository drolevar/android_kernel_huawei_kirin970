# Bounded CGROUP_SKB owned socket lookup

Parent: f12e2ddad33bcf30907237a42cf2be29c77740dc. Candidate only.
Helpers84/85/86 expose TCP/UDP lookup and socket release only through
CGROUP_SKB with CONFIG_INET. Ordinary socket filter, XDP, sockopt and other
program types gain no new route. Huawei HHEE and both JIT sources are untouched.
No BPF-to-BPF calls, verifier-frame or JIT rewrite is introduced.

## Source and authorship

The consolidated source is LineageOS/android_kernel_google_msm-4.14
bb17b7de4b570f2c0c32ddba0543cac03c58dd84. The exact source commit messages,
authors and trailers are retained in owned-sockets-upstream.txt; these are
adapted portions, not dependency-closed cherry-picks. Joe Stringer's runtime
lookup series, Jon Maxwell/Antoine Tenart's request-socket fix, and Martin
KaFai Lau's independent nullable/ownership identity correction inform this port.
Existing single-frame reference tracking already incorporates generic tracking
and NOT_INIT invalidation. It is reused rather than importing donor frames.

The selected consumer is Connectivity7c04d866538e6f689823b769fb5c1e614ca0e295,
netd.c lines634-647: lookup, NULL check, storage lookup, conditional UID read,
socket release, then storage pointer check. Socket and storage lifetimes differ.
The existing CGROUP_SKB program-array RCU section and deferred storage freeing
are the source lifetime contract, not a real concurrency result.

## Ownership

A lookup return has a nullable acquisition identity and an outstanding reference.
Its NULL path cancels that obligation. Fullsock casts get fresh NULL identity
but retain the original ownership ID; failed casts cannot discharge the original.
Release consumes exactly one live nonnullable socket, returning an integer.
Borrowed sockets cannot be released. All matching register/spill aliases become
NOT_INIT. Ring-memory release remains a distinct allocation/void prototype.
Storage returns retain their map identity and never inherit socket ownership.

## Runtime contract

Only12-byte IPv4 or36-byte IPv6 tuples are accepted. Flags must be zero.
Negative signed32 namespace IDs use the caller namespace; nonnegative IDs must
fit signed32 and use get_net_ns_by_id/put_net. Caller namespace/interface comes
from skb->dev, otherwise skb->sk; missing both safely returns NULL.
TCPv6 lookup receives host-order destination port; UDPv6 receives network order.
The IPv6 callback table covers both protocols so built-in filter.o has no direct
IPv6 lookup-symbol dependency when IPv6 is modular. Publication follows existing
IPv6 successful-init stub publication; this IPv6 implementation has no module_exit.
No unavailable callback is invoked. Request sockets release their acquired
reference before returning an RCU-free listener. Timewait references are released
and rejected. Unreferenced non-RCU lookup results are rejected. Release drops
refcounted results and leaves RCU-free results to their existing lifetime.

## Validation boundary

scripts/tests/test_borrowed_sockets.py --owned executes extracted production
verifier/dispatch functions. Alignment, some unrelated services, socket layouts
and allocation are modeled; this is not a real verifier program load. The storage
case executes the real map bounds checker. test_owned_runtime.py executes the
production helper body against simulated lookup, namespace and refcount services.
It does not exercise socket tables, networking, RCU/SMP or syscalls. Existing
borrowed, ring, storage and loader snapshots must also pass. Configuration builds
establish compilation only; full link/build requires coordination with main.
ARM32 source compilation and real loader/kernel/handset execution remain untested.
No active manifest/kernel selection, override, phone operation or publication.

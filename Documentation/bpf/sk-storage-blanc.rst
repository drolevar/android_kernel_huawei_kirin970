Restricted socket storage candidate
===================================

This candidate is based on b6631ccc (not the selected handset kernel). It
implements the measured netd map contract: type 24, four-byte socket-fd keys,
128-byte values, max_entries zero and BPF_F_NO_PREALLOC only. Both BTF type IDs
are mandatory; the existing BTF fd/size validation applies. The key must be a
32-bit INT. Inline bpf_spin_lock definitions are rejected, including nested
struct/union/array definitions. The walk is bounded to depth 16 and 1024 nodes;
unsupported/deeper metadata is rejected, never treated as a supported lock.

Program access is restricted to sk_storage_get (107) in CGROUP_SOCK's existing
socket-create context. Its second argument is the original PTR_TO_CTX, not a
borrowed skb socket, acquired lookup result, or sockopt context. The optional
initializer must be scalar NULL or a fully initialized, in-bounds map-value
buffer. Map/helper compatibility is enforced in both directions. Generic map
lookup/update/delete helpers and sk_storage_delete are not exposed for this
map. CLONE and value spinlocks are not implemented. No BPF version override
is selected. The broader netd program set remains unsupported.

Ownership follows Martin KaFai Lau's original sk-storage design: each socket
owns its storage list and cache; map buckets index elements for teardown.
Socket optmem owns element/storage charges; map memlock owns wrapper/buckets.
Map precharge failure frees the wrapper. Replacement transfers the existing
charge; failed allocations leave the previous value intact. Cache eviction,
unlinking and deferred frees retain RCU readers' value lifetime. New list
nodes use hlist_add_head_rcu, including publication to an already live list.
Map-first and socket-first destruction use the original two grace-period
protocol; no map reference is held by a socket element to create a cycle.

Socket lifecycle audit: sk_alloc uses sk_prot_alloc with __GFP_ZERO. The only
sock_copy caller is sk_clone_lock; it clears sk_bpf_storage immediately after
copy, before early-failure exits, independently of clone support. __sk_destruct
releases storage before the existing optmem leak check and sk_prot_free.
Huawei Bastet's release hook, existing protocol destructor and cgroup cleanup
remain intact. A failed socket-create program eventually follows sk_free and
__sk_destruct. CGROUP_SOCK's BPF_PROG_RUN_ARRAY wraps program execution in RCU.
These are source observations, not executed socket lifecycle tests.

The syscall dispatcher invokes exactly one selected lookup callback, propagates
ERR_PTR, maps NULL to ENOENT and copies a valid value while still under RCU.
Socket-fd callbacks distinguish invalid/closed fd, non-socket fd, null sock and
non-full socket. Iteration is unsupported. Socket refs obtained via fd lookup
are released on every callback exit; helper creation temporarily obtains a
nonzero socket ref and releases it after update.

Provenance
----------

Exact donor patches are retained in sk-storage-history. bab234ba5612 is the
original implementation import, with its original author and trailers. The
Huawei adaptation closes dependencies against the older API without importing
new generic local storage or changing the JIT. f26ccb547b8a supplies the
context-helper contract; 21b246cdbf5e informs clone isolation (not clone data);
68b369497567 supplies minimum-two-buckets semantics; 900a16dd3f91 supplies
precharge with its wrapper leak corrected. 4218a83f4703's intended ERR_PTR
handling is adapted without its duplicated callback invocation. 5c37889345c0
is a reference for null/full-socket checks, not authorization of its broader
pointer routes.

Validation boundaries
---------------------

scripts/tests/test_sk_storage.py compiles the full production storage file,
actual map-BTF check and extracted clone-reset fragment. Kernel allocation,
RCU scheduling, locks, optmem, fd lookup, refcounts and cookie generation are
modeled. Deferred frees and injected sequential interleavings detect ownership
errors, not SMP ordering or real RCU correctness. The real recorded netd BTF
fixture exercises the production value walker; fixture indexing/type-size
resolution is a host boundary. The existing object-BTF suite separately runs
the actual parser and fd lifecycle. test_sk_storage_verifier.py executes the
actual argument/context/map checker with modeled stack/packet bounds and
register-read checks. It does not execute the full verifier. The dispatcher
suite extracts the exact RCU-protected lookup branch and checks callback count.

Actual BPF syscalls, full emitted-program acceptance, real socket teardown,
networking and Android loader behavior remain runtime gates. Complete kernel
and disabled-config builds are recorded separately in the workspace receipt.

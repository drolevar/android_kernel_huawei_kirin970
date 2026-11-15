# Huawei single-frame reference ownership candidate

Parent: b6631cccfe0dd438aec88068bead52ffeff6d785. Active selections unchanged.

The five exact reference patches in verifier-ownership-history preserve original
messages, authors and trailers. They are provenance archives, not production
cherry-picks. The Huawei adaptation follows Joe Stringer's acquisition/exit model,
Martin KaFai Lau's separation of nullable identity from reference identity,
Lorenz Bauer's generic argument ownership, Youlin Li's stale-pointer correction,
and Andrii Nakryiko's bounded allocated-memory contract. It deliberately retains
Kirin's single-frame verifier and does not change Huawei's HHEE/JIT code.

## Integration interface

- `PTR_TO_MEM_OR_NULL` / `PTR_TO_MEM`: `mem_size` in the register union;
  `id` distinguishes nullable views; `ref_obj_id` identifies the owned resource.
- `RET_PTR_TO_ALLOC_MEM_OR_NULL` acquires ownership and a nullable return.
- Exactly one `ARG_CONST_ALLOC_SIZE_OR_ZERO` supplies constant allocation bytes,
  at most `BPF_MAX_VAR_SIZ`. No buffer argument is consumed by this size argument.
- `ARG_PTR_TO_ALLOC_MEM` requires a nonnullable, live resource with zero fixed
  and variable offsets. A prototype with `releases_reference=true` must have
  exactly one such argument and return `RET_VOID`. Release invalidates all
  register and spilled aliases, even in privileged verification.
- State copying owns independent reference/stack arrays. Exit, tail-call and
  implicit LD_ABS/IND exits reject outstanding references. Pruning compares
  reference identities conservatively, independently of register liveness.
- Direct loads/stores and helper memory accesses enforce the allocation bound;
  null/stale access, out-of-bounds access and pointer stores are rejected.
- Only constant ADD/SUB pointer arithmetic is supported. Variable pointer ALU
  remains rejected pending a supported speculation/masking implementation.
- Nullable casts can share `ref_obj_id` while using a different `id`; a failed
  cast must not cancel the source resource. No cast helper is exposed here.

No reserve/submit/discard or socket-lookup provider is registered. Actual socket
pointer types, borrowed skb/context routes, acquired lookup return types and
helper-specific release rules remain separate integration work. Socket storage's
CGROUP_SOCK context helper does not acquire a socket reference.

## Test boundary

`python3 scripts/tests/test_verifier_ownership.py --cc CLANG --keep-output NEWDIR`
executes extracted production ownership, state-copy/pruning, memory-access,
helper-argument/call and NULL-branch handlers with ASan/UBSan. Allocation and
helper discovery are host doubles; unrelated map/context/packet/stack services
fail closed. Branch push uses production state-copy logic. This is not the full
`do_check()` instruction walker, a BPF syscall, actual helper execution, JIT,
RCU, memory mapping or phone validation. Stack alignment admission remains a host boundary; production spill/fill,
invalidation and branch propagation are executed.

The host-only provider table assigns existing helper slots to reserve/release
prototypes to exercise `check_call()`. That table is never compiled into the
kernel. Actual helper IDs and map compatibility must be integrated and tested
with the ring-buffer producer candidate. No version override is justified.

## Ring-buffer dependency boundary

The pinned donor is bb17b7de4b570f2c0c32ddba0543cac03c58dd84. The ring introduction
7b594c703b26 is not a closed series for this Huawei baseline. Ring type 27 and
helper IDs require UAPI/registry/dispatch; both map-to-helper and helper-to-map
checks (29243def6782) are mandatory. Cgroup-skb dispatch reaches Kirin's
`net/core/filter.c:bpf_base_func_proto()`, not just kernel/bpf/helpers.c.

Allocation must provide metadata pages plus twice-mapped data pages, page/size
limits, accounting, failure cleanup and deferred wakeup lifetime. Mapping needs
map-fd/VMA ownership and permission controls: only the consumer-position page
may be writable (543ea67c265e); later permission upgrades must also be denied.
The pending-reservation correction 336b4d1cdc1b prevents overlapping live records
when userspace changes the consumer position. Consumer/producer ordering,
reserve/submit/discard/full/wraparound, poll/irq_work teardown and concurrent
lifetimes remain producer/mmap integration work, not consequences of this
verifier candidate. The emitted 32/8/12-byte records need real reserve/write/
submit/discard acceptance, including the failed-cache-insertion discard branch.

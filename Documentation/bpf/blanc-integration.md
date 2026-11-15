# Combined BPF candidate for blanc

This merge retains both reviewed histories:

- Ring-buffer/mmap/reference-verifier head `1ea4ebef763d5c4c33dec558ee99da78200e042a`.
- Restricted socket-storage head `2c61a0dd7e9595c4e8bd1afb0ad6d970a9dc871c`.

Only the two verifier map/helper compatibility switches conflict. Keep both
restrictions in each direction: SK_STORAGE only accepts storage-get, RINGBUF
only accepts reserve, and DEVMAP_HASH remains syscall-only. Submit/discard use
owned memory. Existing socket context restrictions and the dedicated cookie
adapter remain unchanged; no borrowed/acquired/sockopt route is added.

The syscall merge preserves one selected lookup callback, ERR_PTR propagation,
NULL-to-ENOENT and copying under RCU. ARRAY-only freeze and syscall update/delete
write-active accounting remain intact. Canonical map/helper/command numbering,
map registration, prototypes and the optional initializer enum coexist with
reference ownership fields. Huawei HHEE/JIT is unchanged.

Integration regressions:

- `test_bpf_integration.py`: canonical UAPI and exhaustive bidirectional helper
  compatibility for these three map types; four missing-case mutation controls.
- `test_bpf_integration_verifier.py`: actual production routes/prototypes,
  argument/stack/context checking, call/branch ownership and alias tracking.
  Live ring reservations survive storage lookup, nullable storage branching and
  cookie calls. Releasing storage as owned memory, non-context sockets, offset
  contexts, owned-memory initializers, helper108 and SKB storage routes fail.
- `test_map_mmap.py`: existing mmap/freeze suite also executes syscall update/
  delete guards for modeled type24, including failure exits and ARRAY-only freeze.
- Existing socket dispatch tests enforce one callback under RCU and error-pointer
  propagation; the double-call mutation remains detected.

Three older fixtures needed model declarations for the combined implementation:
query's unrelated freeze command stub, BTF-map mutex/atomic64/VM declarations,
and the argument-only socket test's ownership fields/fail-closed services.
Those changes do not substitute for the combined production verifier test.

All host fixtures retain modeled kernel services. This does not demonstrate
real bpf syscalls, full emitted-program verification, SMP/RCU, VMA behavior,
networking, loader startup or handset boot. Existing map/helper scope limits,
external struct-sock ABI caveat and unselected BPF override remain unchanged.

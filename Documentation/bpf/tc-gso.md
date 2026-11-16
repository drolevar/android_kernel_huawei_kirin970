# TC GSO field candidate

Parent: 73ea00ea0cce1829772e6a559a11c8844443b614 (portable ARM64 test branch).
The real ARM64 guest rejected all eight selected offload.o programs at context
read offset164/size4. Existing cgroup-skb GSO support does not admit TC reads.
Pinned Connectivity7c04d866 also reads gso_size on those paths.

This candidate admits only aligned full-u32 TC reads of gso_segs164 and
new canonical gso_size176, translating both to zero-extended unsigned-short
skb_shared_info loads. The converter handles end offsets and end pointers,
including src==dst. Other modern TC fields, pointer access, narrow reads and
writes remain rejected; existing cgroup/socket-filter scopes are unchanged.

Donor references: LineageOS/android_kernel_google_msm-4.14
- 3a3bd3ec9beb04d8d0fb491babe0d78755ad4f40, Willem de Bruijn: canonical
  gso_size field and shared-info converter imported verbatim as an excerpt,
  retaining original author and trailers; not a complete cherry-pick.
- 72cae28aab0fde153030ea06e57efbc10481140c, Eric Dumazet: original gso_segs
  translation precedent; already adapted for this tree's cgroup route.
The separate Huawei adaptation scopes admission/conversion to TC and preserves
Huawei's HHEE/JIT sources. Appending UAPI field changes sizeof(__sk_buff) from
176 to184; the existing ABI fixture is updated, not its earlier field offsets.

Validation: scripts/tests/test_tc_gso.py extracts production access/conversion
functions and interprets their emitted loads/adds with modeled skb layouts.
It covers read/write/size/offset/scope controls, high ushort values, dst aliases,
TC ifindex and existing cgroup translation. It does not execute network traffic,
real verifier, real skb allocations or JIT. Separate recorded full kernel and VM
validation must establish those respective gates; no active selection change.

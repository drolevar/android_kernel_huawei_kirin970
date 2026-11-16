# Huawei queued-task migration pin balance

The retained Huawei source unpinned the source runqueue explicitly in
`move_queued_task()`, then called `rq_unlock()`, which unpinned it again.
The ARM64 virt guest on portable base
`73ea00ea0cce1829772e6a559a11c8844443b614` reported this through
`migration_cpu_stop -> move_queued_task -> lock_unpin_lock` before the test
start marker and during shutdown. The exact binary identified the second
unpin. This is an annotation defect, not evidence of a physical double-unlock.

Keep the first unpin: WALT's `double_lock_balance()` may temporarily drop and
reacquire the source lock. After the existing WALT accounting and destination
unlock, release the source physical lock directly. Destination locking/pinning
and caller cleanup retain their existing behavior. No scheduler interface,
configuration, lockdep policy or HHEE/JIT code changes are involved.

## Bounded local-reference provenance

The local pixel-msm-4.14 reference at
`bb17b7de4b570f2c0c32ddba0543cac03c58dd84` contains:

* `bfc525947c5686df850efb39c81aae3eb6a62ac3`, **ANDROID: sched/walt: Fix
  lockdep assert issue**, authored and signed off by Ke Wang
  `<ke.wang@spreadtrum.com>`, 2019-01-21. Its change uses explicit unpin before
  double locking and `raw_spin_unlock()` afterward. Original trailer:
  `Change-Id: Id3da7ad0dbc9d0d316cd7365b96c3686daba0340`; `Bug: 120440300`.
* `6fd50f70fd4ce832f3eebb3f1ec1742d7d281aaf`, **ANDROID: sched/walt: Fix the
  potential bad unlock issue**, authored and signed off by Ke Wang,
  2019-02-25. This later changes the donor's double-unlock handling for equal
  runqueues. It is related context, not the patch imported here.
* `c9f806c2a4a17d3a7331da1d062d2a8e40afd465`, **sched: core: Disable double
  lock/unlock balance in move_queued_task()**, authored and signed off by
  Miguel de Dios `<migueldedios@google.com>`, 2019-02-07. It separates WALT and
  non-WALT routes in that donor. Original trailer:
  `Change-Id: I8bff8550c4f79ca535556f6ec626f17ff5fce637`; `Bug: 123720375`.

This is a narrow Huawei correction supported by the first commit's annotation
sequence, not a verbatim cherry-pick or a claim that a matching Huawei corrective
commit was found. The retained baseline boundary already contains the defect;
the available history does not identify its original author. Full local commit
messages/diffs are retained in the enclosing workspace's
`logs/lineage-24.0/scheduler-unpin-20261116/`. No remote history was fetched.

## Verification boundary

`scripts/tests/test_sched_unpin.py` extracts the production migration functions,
runqueue wrappers and double-lock helpers. Eight cases cover WALT off in both
directions, nonpreemptible WALT keeping the source lock with and without a
successful trylock, WALT dropping/reacquiring it, and preemptible WALT in both
directions. Assertions distinguish the temporary source unlock from its single
final unlock, and require destination lock/pin plus balanced caller cleanup.

The raw locks, pin bookkeeping, IRQ state and scheduling/accounting services are
deterministic host models. ASan/UBSan execution does not establish real lockdep,
WALT accounting, scheduler concurrency, VM boot or handset behavior. The parent
compiles and fails the duplicate-unpin assertion in all eight cases; the
correction passes the unchanged oracle. An initial extraction-regex setup error
is retained separately and is not behavioral RED evidence. Mutations exercise
missing early unpin, missing/duplicate physical unlock, missing destination pin
and missing caller cleanup.

Focused compilation uses existing VM and handset configurations without changing
their contents and builds only `kernel/sched/core.o`, with at most four jobs.
Both existing kernel configurations have WALT disabled; WALT-on coverage is
limited to the extracted host cases. See the packet receipts for actual outcomes.
Independent review, a coordinated
full link and a same-config VM regression run remain separate gates.

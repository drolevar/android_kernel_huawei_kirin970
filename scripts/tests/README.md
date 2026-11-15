# Offline kernel regression fixtures

`test_skb_load_bytes_relative.py --cc /path/to/host/clang` extracts the actual
helper, prototype and SKB accessors from this checkout and runs their packet-copy
behavior under ASan/UBSan. `--keep-output NEW_DIRECTORY` retains the generated
translation unit and executable. It needs a Linux host Clang with sanitizer
runtimes; it does not need a configured kernel, root or a connected phone.

The fixture provides only the SKB fields these accessors read, using ARM64's
offset-form tail. It checks MAC/NET offsets, pulled headers, unset MAC behavior,
the 16-bit offset boundary, exact linear tail, nonlinear rejection, invalid
inputs and output clearing with adjacent canaries. It does not execute a BPF
program, the verifier, JIT, cgroup attachment or packet networking in a kernel.
Compile `net/core/filter.o` separately with the selected kernel configuration
to check integration with real headers and verifier dispatch tables.

The production slice retains the authorship of these reference commits from
LineageOS/android_kernel_google_msm-4.14:

- `f01401fc005397c8679c21f00fae9a9b3cd81148` adds helper68 and header-base UAPI.
- `09c1b5913d46eb17acb38463a92787906253c067` fixes length bounds after data pulls.
- `fc2760e0b3528f1b1ef1bf700cfe77abfb299c62` permits NET with an unset MAC header.

The original helper fails both pulled-header and unset-MAC/NET regressions;
the length fix resolves only the former. The third commit resolves the latter.
This slice leaves existing helper numbering and Huawei HHEE/JIT code unchanged.
It provides one helper, not a complete current Android BPF implementation.

`test_vdso_build_id.py --help` describes the separate small AArch64 ELF fixtures
for deterministic kernel debug paths. Its compiler/linker arguments must match
the selected kernel toolchain.

`test_bpf_prog_query.py --cc /path/to/host/clang --keep-output NEW_DIRECTORY`
extracts the production array length/copy/delete functions, cgroup query and
mutex wrapper, syscall query validation and full syscall dispatch. It uses the
checkout's UAPI, array/list structures and list iteration macros. The host C
fixture runs under ASan/UBSan with doubles for kernel allocation, RCU, usercopy,
fd references, capabilities and security hooks. Unrelated syscall commands are
stubbed out. It needs no configured kernel, root or device.

Twelve cases cover direct/effective IDs and flags for the four implemented
cgroup hooks, numeric command16 and query field offsets, empty/count-only/null-ID
requests, untrusted oversized capacity, exact and short buffers, full required
count with ENOSPC, leading/middle/trailing/all-dummy arrays, an effective array
with 70 synthetic ancestor entries, allocation/usercopy errors, unsupported
flags/types, bad fd, attribute-tail validation and reference/lock cleanup.
The fixture forbids allocation/usercopy under simulated RCU, reclaims array and
program storage at RCU unlock to catch late reads, checks zero padding after a
smaller snapshot, and interleaves the real safe-delete operation after a slot's
single read. Synthetic effective arrays check returned order; they do not test
kernel hierarchy construction or real concurrent replacement.

The first query patch fails nine of the original ten cases. The four subsequent
reference fixes leave false ENOSPC for trailing dummy slots and unnecessary work
for zero capacity. The final adaptation resolves those cases and reads each slot
once before inspecting its program. Query holds cgroup_mutex across count,
flags and IDs, including usercopy; callers of the generic array helpers must
stabilize the array pointer. Allocation is clamped to the measured cgroup count,
not the untrusted capacity. Effective arrays may include more than 64 programs
from ancestors, so no new per-query cap is imposed.

Source provenance is the archived query series from
LineageOS/android_kernel_google_msm-4.14:

- `e2440f58b90cafa64d2fab34d4fcd2521c80cd2b`: cgroup query command and helpers.
- `37d539e20596d7900250ab7dda7745efa0600fe2`: length skips dummy entries (core only).
- `eefdf97c14762a102859c943d6b1cda37b0f8a36`: ID copy skips dummies (core hunk only).
- `93ccd88efab243f0791f8a26c5446638b33355bd`: zeroed ID snapshot and usercopy outside RCU.
- `24c44ceff74845493144d0e0d5e3722ffed1a2dc`: allocation uses __GFP_NOWARN (core only).

No perf query, newer cgroup hooks or sysctl policy changes are included. Compile
kernel/bpf/{core,cgroup,syscall}.o and kernel/cgroup/cgroup.o separately with the
intended kernel toolchain/configuration. These host tests do not establish real
RCU grace periods, race freedom, kernel usercopy faults, actual authorization,
CGROUP_BPF-disabled kernel integration or device behavior. Candidate-kernel
runtime tests with lockdep/RCU checking are still required.

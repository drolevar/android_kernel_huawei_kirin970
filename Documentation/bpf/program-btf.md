# Single-frame program BTF candidate

This candidate extends the program-load ABI to accept object BTF with function
and source-line records. It is an unselected source candidate, not evidence that
the Android loader or a handset can boot. Donor authorship and correction history
are retained in `program-btf-upstream.txt` and the preceding donor-excerpt commits.

## Supported boundary

- Canonical load attributes through `line_info_cnt`, including the preceding
  `prog_ifindex` and `expected_attach_type` fields. Later nonzero fields remain
  rejected. No offload, attach-BTF, generated vmlinux BTF or CO-RE is introduced.
- One FUNC record at instruction zero, resolving to a valid FUNC_PROTO. Existing
  verifier admission remains authoritative; metadata does not grant new argument
  types or enable BPF-to-BPF calls. Multiple function records are rejected.
- Ordered line records covering the entry instruction, referring to real
  instruction starts and bounded BTF string offsets. Record sizes and unknown
  tails are checked; E2BIG size negotiation writes to the original user argument.
- A held BTF reference plus owned metadata arrays survive program reallocation
  and JIT image transfer. Failed validation rolls back unpublished state; final
  program destruction releases the reference and arrays.
- Core instruction expansion shifts subsequent source-line offsets. Program
  get-info reports canonical record sizes/counts and bounded copies, including
  interpreter programs. No JIT address-to-line mapping is implemented; its count
  and pointers are zero. Existing privileged program-info access is preserved.

## Validation and its limits

`scripts/tests/test_program_btf.py` extracts the production validators, relevant
allocation/free/RCU scheduling entry points, instruction patching and program
info code. The fixture retains the exact three selected CLAT program records
and can re-extract them from the pinned object using `--object`. Twenty-four
case groups cover records, fd errors, allocation/copy failures, ownership,
reallocation, expansion and get-info. Kernel memory, fd services, RCU/workqueues,
security hooks and verifier services are modeled. These tests do not execute a
kernel syscall or establish real concurrency, kernel verifier acceptance or JIT
behavior. The caller regression fixtures check original userspace-argument
forwarding independently of the copied syscall argument.

`scripts/tests/test_program_btf_abi.py` checks literal canonical offsets and
sizes with ARM64 and ARM32 cross-compilation. `--headers` supplies exported
kernel dependency headers; the actual bpf.h comes from this source tree.
`--header` permits an explicit baseline rejection control. This is compile-only
ABI evidence, not ARM32 syscall execution.

Example host commands (CC and HEADERS identify existing verified tool inputs):

```sh
python3 -B scripts/tests/test_program_btf.py --cc "$CC" --object "$CLATD_OBJECT" --output "$HOST_RESULTS"
python3 -B scripts/tests/test_program_btf_abi.py --cc "$CC" --headers "$HEADERS" --output "$ABI_RESULTS"
```

The orchestration workspace records source/input hashes and commands. Before
publication or a full kernel build, complete the independent exact-diff review,
retaining any unavailable review as an open gate. Then build clean generic and
handset kernels and replay the unchanged selected libbpf/CLAT consumer. A later
verifier rejection must be diagnosed, not hidden by stripping metadata or
forcing feature-probe results. Full Android networking and Huawei HHEE execution
remain separate runtime gates. No active manifest/kernel or BPF version override
is changed by this candidate.

# Offline object-BTF fixtures

These are raw little-endian BTF snapshots, not ELF files or kernel-load results.
`test_object_btf.py` compiles the selected kernel parser/logger and extracted map
and syscall paths with Clang 22, ASan and UBSan. Allocation, user copies, FDs,
IDR, RCU, locking, security, charging and map storage use host doubles. This
checks source behavior under simulation, not kernel execution, concurrency,
real BPF syscalls, Android boot, or handset compatibility.

## Corpus and expected boundaries

`data/parser-fixtures.json` hashes 29 snapshots from six Android ELF inputs.
`index.json` hashes four duplicate manual snapshots and four independent
synthetic normalization cases at this directory's top level. Those synthetic
bytes test producer normalization; the parser suite's malformed-input cases
are constructed independently in `object_btf_host/cases.c`.

* `manual/attempt1.btf` captures offload BTF after actual NetBpfLoad DATASEC
  size/VAR offset fixups, immediately before a simulated EINVAL. Global FUNC
  linkage remains; the current source parser returns -EINVAL.
* `manual/attempt2.btf` differs only by cleared FUNC linkage. The simulated
  retry succeeds; the source parser accepts these bytes.
* `manual-success/attempt1.btf` equals the first snapshot exactly. Its helper
  success is an injected result, not proof that the parser accepts it.
* `manual-pre510/attempt{1,2}.btf` captures the explicit old-kernel branch:
  VAR/DATASEC/FUNC_PROTO/FUNC become INT/STRUCT/ENUM/TYPEDEF. Both attempts are
  identical and accepted by the source parser. The branch is an assumption,
  not a measured kernel-version probe.
* `libbpf/*/open.btf` is actual public libbpf open-file processing before load.
  `all-supported`, `no-global-func`, and `no-func-datasec` run the exact extracted
  libbpf sanitizer with separate assumed feature answers. They are not feature
  probes or manual-loader results, even when bytes coincide. Open/all-supported
  are rejected for global FUNC linkage except `test.o`; other profiles pass.

The full `data/corpus-audit.json` records no CO-RE relocation records, typed
externs, internal maps, `.rodata`, or `.kconfig` sections in these inputs.
Consequently no internal-map initialization/freezing or CO-RE support is proven.
Eight ordinary offload HASH/ARRAY metadata requests pass the host map path.
`tether_dev_map` is DEVMAP_HASH (25), unsupported and explicitly excluded from
that path. The double models ordinary map storage, not a general map allocator.

## Reproduce without replacing receipts

From this kernel worktree, with the workspace at `$workspace`:

```sh
workspace=/home/drolevar/projects/huawei-blanc-los24
cc="$workspace/src/lineage-24.0/prebuilts/clang/host/linux-x86/clang-r596125/bin/clang"
helper="$workspace/logs/lineage-24.0/object-btf-20261115/loader-fixtures/build/btf_loader_host"
run=$(mktemp -d "$workspace/logs/lineage-24.0/object-btf-20261115/fixture-review-XXXXXXXX")
BTF_LOADER_HELPER="$helper" python3 -B scripts/tests/btf_loader_test.py -v
python3 -B scripts/tests/btf_loader_fixtures.py generate \
  --input "$workspace/out/lineage-24.0/bpf-elf-20261115" --helper "$helper" \
  --output "$run/producer" --parser-dir "$run/synthetic"
python3 -B scripts/tests/test_object_btf.py --cc "$cc" --keep-output "$run/parser-host"
python3 -B scripts/tests/test_btf_map_abi.py --cc "$cc"
```

The parser defaults to bundled `data`; pass `--fixtures "$run/producer"` to
consume regenerated snapshots. Compare every BTF hash against the bundled
indexes. `prepare --workspace "$workspace" --output "$run/helper"` then
`build --workspace "$workspace" --output "$run/helper"` rebuilds the producer
through the checked-in container runner and pinned image. Preparation requires
clean pinned Connectivity/libbpf sources. Prepare/generate require nonexistent
output directories; parser export must be fresh and disjoint. Build permits
one attempt per prepared directory, including failures. Choose a new run for
retries. Do not point generation at this checked-in corpus or old receipts.
The standalone helper itself expects caller-owned disposable output paths.

## Provenance and licensing

`data/source-provenance.json` retains loader source pins, hashes, extraction
spans and container image. Connectivity is
`7c04d866538e6f689823b769fb5c1e614ca0e295`; libbpf is
`9723b4de6459ab48b361aed3bae5df3c1bd20cb8`.
`elf-source-states.json` and `elf-compile-receipt.json` retain producer source
revisions, exact compile arguments, compiler identity and ELF hashes.
`helper-build-receipt.json` records the existing helper binary hash and build
container. Absolute paths and timestamps are historical observations, not
portable configuration. Generation writes fresh helper/generator hashes and
command receipts; parser builds hash source inputs and generated extracts.
Reproduction requires the recorded source trees and ELF inputs; the raw corpus
alone suffices for parser tests, not rebuilding the original Android ELFs.

The Android producers and host loader adapter use Apache-2.0; original notices
are retained in `NOTICE` and the license in `licenses/Apache-2.0.txt`.
Extracted libbpf routines retain their LGPL-2.1 OR BSD-2-Clause notice; the BSD
option is included in `licenses/libbpf-BSD-2-Clause.txt`. Kernel-source host
harness/tests retain GPL-2.0 SPDX tags and the kernel's root `COPYING` applies.
No binary helper or extracted production implementation is bundled here.
`data/libbpf/*.o/` are fixture directories, explicitly unignored locally.

Review validation (2026-11-15, before the production review fixes): 17 producer
contracts, 18 ASan+UBSan parser/map host tests, 2 ABI tests and 86 workspace
unit tests passed. All 37 indexed files reproduced byte-for-byte. These results
do not cover the subsequently reported DATASEC forward-VAR skipped-size and
kflag ENUM fixed-four-byte-size bugs. Main must rerun after those fixes; the
hashes in the run's parser build receipt identify the actual tested source.

Production-review follow-up: the DATASEC and enum regressions both failed
before the focused fixes and all 18 parser/map cases passed afterward.
The expanded cases include 96 invalid multi-VAR rows, 32 valid controls and
64 enum-size/member rows. Kernel compilation is recorded separately by the
orchestration workspace; host success does not establish kernel acceptance.

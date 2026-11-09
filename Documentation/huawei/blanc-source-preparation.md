# BLA-L29 kernel source preparation

Inspected on 2026-11-09 for the Huawei Mate 10 Pro (`blanc`, BLA-L29) running EMUI12 `.225`. This preparation adds documentation and a reference build helper. It does not modify kernel code or establish runtime compatibility.

## Development base

Retain this fork's hisi-oss history and start `blanc-lineage-24.0` from [hisi-oss lineage-22.2 commit f39fdf340fe2ee29db13cb8838653161d6ad7c57](https://github.com/hisi-oss/android_kernel_huawei_kirin970/tree/f39fdf340fe2ee29db13cb8838653161d6ad7c57). Preserve the official BLA EMUI10 archive separately as a pristine reference. No duplicate kernel repository or full source import is required for this preparation.

The common device tree's [BoardConfig at c6e08caaa721c82bc9b0723cc2aa203ca790ca9a](https://github.com/drolevar/android_device_huawei_kirin970-common/blob/c6e08caaa721c82bc9b0723cc2aa203ca790ca9a/BoardConfigCommon.mk) selects `merge_kirin970_defconfig`, Clang **r416183b** under `prebuilts/clang/kernel/linux-x86`, and `TARGET_KERNEL_LLVM_BINUTILS := false`. Preserve those settings for the donor's first reproduction build. The kernel Makefile's `LLVM=1` support does not by itself validate replacing the configured binutils.

## Official reference identity

| Field | Verified value |
|---|---|
| Source | [Huawei download supplied for this project](https://download-c1.huawei.com/download/downloadCenter?downloadId=50FCDCF62DD8AFADE7EB8DCCE5AB0971&version=474E0A4FBE05E1C1B9C6BD724C63071D&siteCode=worldwide) |
| Filename | `BLA-AL00B_10_EMUI10.0_opensource.tar.gz` |
| Bytes | `548702193` |
| SHA256 | `af91156db6d6ebff38c1ca3efcaf9de25db754324648032d4aadc1aa9b6308c0` |
| HTTP Last-Modified | `Mon, 03 Feb 2020 08:02:54 GMT` |
| README software version field | `2020-01-13` |
| Kernel and config | `4.14.116`; `arch/arm64/configs/merge_kirin970_defconfig` |

The complete archive was downloaded and hashed. Its kernel subtree contains 71,829 regular files totaling 997,428,604 bytes. Extraction checked for path traversal and found no symbolic or hard links in the kernel subtree. The archive also contains Android `external` and `vendor` sources; only `Code_Opensource/kernel/` was fully extracted for this comparison.

This package identifies **BLA-AL00B EMUI10.0**, not source explicitly matched to BLA-L29 EMUI12 `.225`. The README supplies a date, not an exact `.225` firmware identifier. See [official-source-provenance.json](official-source-provenance.json) for the machine-readable record.

## Differences that matter

Selected files were compared with the pinned development commit. This is not a complete source audit.

| Area | Finding and implication |
|---|---|
| Version | Both Makefiles identify `4.14.116`; that string does not describe their different patch content. |
| SoC register definitions | Kirin970 `soc_acpu_baseaddr_interface.h` and `soc_ufs_sysctrl_interface.h` are byte-identical. This supports a shared platform relationship. |
| Reserved DDR | `global_ddr_map.h` differs in fingerprint allocation, FAMA conditionals and secure regions. Compare the installed device tree and firmware before boot testing. |
| Partitions | `CONFIG_HISI_PARTITION_KIRIN970` selects official `kirin970_partition.h` but donor `aries_partition.h`. Later conditional tables replace `reserved7` with `kpatch`, and several variants shrink `super` by 32 MiB to add `prets`/`pretvs`. These tables do not measure the handset's GPT or boot slots. |
| Config | Official config is full; donor config is compact. Resolve each with its own Kconfig before treating absent declarations as disabled options. |
| Android support | Donor explicitly enables BPF JIT and contains accumulated compatibility changes worth preserving. HHEE symbols and implementations have also changed. |
| Licensing | `COPYING` is byte-identical and specifies GPLv2 unless explicitly otherwise stated. Preserve individual file notices and source correspondence when distributing binaries. |

No BLA/Kirin970 handset DTS was found by filename under official `arch/arm64/boot/dts`. Obtain and inspect the installed DT/DTO instead of assuming this package can rebuild the phone's full device tree. Detailed comparison hashes and diffs remain with the external source reference to avoid adding large generated inventories here.

## Reproducing the official reference

The package README names `aarch64-linux-android-4.9`; its Makefile additionally selects **Clang r346389c**, GNU cross tools, and GNU gold with Clang's `LLVMgold.so` for the enabled LTO/CFI configuration. This differs from the development tree's r416183b toolchain.

After obtaining the matching toolchains, run:

```bash
bash Documentation/huawei/build-official-reference.sh \
  /path/to/official-emui10-kernel \
  /path/to/clang-r346389c \
  /path/to/aarch64-linux-android-4.9 \
  /path/to/out-bla-emui10 \
  8
```

The helper checks reference Makefile/config hashes and required tool paths, keeps outputs outside the source, and records compiler identities and output hashes. It reconstructs settings observed in the source; it does not fetch toolchains or install dependencies. Expected output is `out-bla-emui10/arch/arm64/boot/Image.gz`, a raw kernel requiring separately verified device image packaging.

Validation completed: JSON parsing, shell syntax, and missing-input usage handling. **No kernel compilation or handset boot test has been performed.** Additional build dependencies or source defects may remain.

## Next gates

1. Reproduce the donor build with pinned toolchains and retain the resolved `.config`, logs and output hashes.
2. Compare live `.225` kernel configuration, DT/DTO, reserved memory, module ABI and partition names with both baselines.
3. Use the pristine official build separately to investigate BLA differences or isolate regressions.
4. Make confirmed device changes in small commits; construct a reversible test only after verifying image format and recovery procedures.

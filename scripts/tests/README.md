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

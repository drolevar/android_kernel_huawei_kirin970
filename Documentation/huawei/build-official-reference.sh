#!/usr/bin/env bash
# Reconstruct the unmodified BLA EMUI10 source build described by its README/Makefile.
# This script builds a raw kernel only. It performs no device operations.
set -euo pipefail

if [[ $# -lt 4 || $# -gt 5 ]]; then
  printf 'Usage: %s KERNEL_SOURCE CLANG_R346389C_ROOT GCC_AARCH64_ANDROID_4_9_ROOT OUTPUT_DIR [JOBS]\n' "$0" >&2
  exit 2
fi

bla_source=$(realpath "$1")
bla_clang=$(realpath "$2")
bla_gcc=$(realpath "$3")
bla_output=$(realpath -m "$4")
bla_jobs=${5:-8}
[[ "$bla_jobs" =~ ^[1-9][0-9]*$ ]] || { printf 'JOBS must be a positive integer.\n' >&2; exit 2; }
[[ "$bla_output" != "$bla_source" && "$bla_output" != "$bla_source/"* ]] || {
  printf 'Use an output directory outside the pristine kernel source.\n' >&2
  exit 2
}

for bla_tool in clang clang++ llvm-ar llvm-dis; do
  [[ -x "$bla_clang/bin/$bla_tool" ]] || { printf 'Missing executable: %s\n' "$bla_clang/bin/$bla_tool" >&2; exit 2; }
done
[[ -f "$bla_clang/lib64/LLVMgold.so" ]] || { printf 'Missing Clang LTO plugin: %s\n' "$bla_clang/lib64/LLVMgold.so" >&2; exit 2; }
for bla_tool in gcc as ld ld.gold ar nm strip objcopy objdump; do
  [[ -x "$bla_gcc/bin/aarch64-linux-android-$bla_tool" ]] || { printf 'Missing executable: %s\n' "$bla_gcc/bin/aarch64-linux-android-$bla_tool" >&2; exit 2; }
done
[[ -f "$bla_source/arch/arm64/configs/merge_kirin970_defconfig" ]] || { printf 'Missing expected defconfig.\n' >&2; exit 2; }

# Restrict this recipe to the inspected pristine BLA EMUI10 reference.
bla_make_hash=$(sha256sum -- "$bla_source/Makefile")
bla_config_hash=$(sha256sum -- "$bla_source/arch/arm64/configs/merge_kirin970_defconfig")
[[ "${bla_make_hash%% *}" == 9c5d4f83fee8fa6723451f8dd68d6e02d72ebf69b5b0ab0638004b4d4b76ce8e ]] || {
  printf 'Makefile differs from the inspected official reference.\n' >&2; exit 2;
}
[[ "${bla_config_hash%% *}" == 6572edf67de4aec0de0fd0a9266c0758f5816e85900f1e8584b0926ba43ea43b ]] || {
  printf 'Defconfig differs from the inspected official reference.\n' >&2; exit 2;
}

mkdir -p "$bla_output"
# PATH is extended using the toolchains requested by the source, not a host cross compiler.
export PATH="$bla_clang/bin:$bla_gcc/bin:$PATH"
bla_flags=(
  -C "$bla_source"
  ARCH=arm64
  O="$bla_output"
  CROSS_COMPILE="$bla_gcc/bin/aarch64-linux-android-"
  CLANG_TRIPLE=aarch64-linux-gnu-
  CLANG_PREBUILTS_PATH="$bla_clang/"
  GCC_TOOLCHAIN="$bla_gcc"
)
{
  date -u +%Y-%m-%dT%H:%M:%SZ
  "$bla_clang/bin/clang" --version
  "$bla_gcc/bin/aarch64-linux-android-gcc" --version
  "$bla_gcc/bin/aarch64-linux-android-ld.gold" --version
  sha256sum "$bla_source/Makefile" "$bla_source/arch/arm64/configs/merge_kirin970_defconfig"
} > "$bla_output/toolchain-and-source.txt"
make "${bla_flags[@]}" merge_kirin970_defconfig 2>&1 | tee "$bla_output/configure.log"
make "${bla_flags[@]}" -j"$bla_jobs" 2>&1 | tee "$bla_output/build.log"
sha256sum "$bla_output/arch/arm64/boot/Image.gz" "$bla_output/.config" > "$bla_output/build-sha256.txt"
printf 'Kernel build completed: %s\n' "$bla_output/arch/arm64/boot/Image.gz"

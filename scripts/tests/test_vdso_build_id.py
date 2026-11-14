#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Exercise vDSO and global kernel debug flags with tiny AArch64 ELF fixtures.

Run with --cc, --ld, --readelf and --make pointing at the selected toolchain.
No configured kernel or full build is required. Temporary outputs are isolated.
"""
import argparse
import contextlib
from pathlib import Path
import re
import shlex
import subprocess
import tempfile
import unittest


parser = argparse.ArgumentParser(description=__doc__)
for name in ("cc", "ld", "readelf", "make"):
    parser.add_argument("--" + name, required=True)
parser.add_argument("--keep-output", type=Path, help="retain fixtures in a new directory for inspection")
tools = parser.parse_args()
kernel = Path(__file__).resolve().parents[2]


def run(command, **kwargs):
    return subprocess.check_output(command, text=True, stderr=subprocess.STDOUT, **kwargs)


class VdsoBuildIdTest(unittest.TestCase):
    def fixture_directory(self):
        if tools.keep_output:
            output = tools.keep_output / self._testMethodName
            output.mkdir(parents=True, exist_ok=False)
            return contextlib.nullcontext(str(output))
        return tempfile.TemporaryDirectory(prefix="vdso-build-id-")

    def test_output_directory_only_changes_debug_metadata_and_is_normalized(self):
        with self.fixture_directory() as temporary:
            root = Path(temporary)
            source = root / "fixture.S"
            source.write_text(".text\n.globl fixture\n.type fixture,%function\nfixture:\n ret\n.size fixture,.-fixture\n")
            build_ids = {False: [], True: []}
            text_sections = []
            for output in (root / "first-output", root / "second-output"):
                output.mkdir()
                harness = "print-flags:\n\t@printf '%s\\n' '$(asflags-y)'\n"
                harness += "objtree := " + str(output) + "\n"
                harness += "include " + str(kernel / "arch/arm64/kernel/vdso/Makefile") + "\n"
                flags = shlex.split(run([tools.make, "--no-print-directory", "-f", "-", "print-flags"], input=harness))
                for normalized in (False, True):
                    obj = output / ("normalized.o" if normalized else "control.o")
                    command = [tools.cc, "--target=aarch64-linux-gnu", "-Wa,-gdwarf-2"]
                    command += flags if normalized else []
                    command += ["-c", str(source), "-o", obj.name]
                    run(command, cwd=output)
                    debug = run([tools.readelf, "--debug-dump=info", str(obj)])
                    if normalized:
                        self.assertIn("/kernel-build", debug)
                        self.assertNotIn(str(output), debug)
                    else:
                        self.assertIn(str(output), debug)
                    text_sections.append(run([tools.readelf, "-x", ".text", str(obj)]))
                    elf = output / ("normalized.so" if normalized else "control.so")
                    # The production vDSO link uses paths relative to objtree.
                    run([tools.ld, "-shared", "--build-id", "-o", elf.name, obj.name], cwd=output)
                    notes = run([tools.readelf, "-n", str(elf)])
                    build_ids[normalized].append(re.search(r"Build ID: ([0-9a-f]+)", notes).group(1))
            self.assertTrue(all(text == text_sections[0] for text in text_sections), "normalization must preserve machine code")
            print("control build IDs:", *build_ids[False])
            print("normalized build IDs:", *build_ids[True])
            self.assertNotEqual(*build_ids[False], "control must demonstrate output-directory-sensitive build IDs")
            self.assertEqual(*build_ids[True], "production vDSO flags must normalize the build ID")

    def test_global_c_and_assembly_debug_flags_normalize_build_ids(self):
        with self.fixture_directory() as temporary:
            root = Path(temporary)
            for language in ("c", "assembly"):
                with self.subTest(language=language):
                    source = root / ("fixture.c" if language == "c" else "fixture.S")
                    source.write_text("int fixture(void) { return 7; }\n" if language == "c" else
                                      ".text\n.globl fixture\n.type fixture,%function\nfixture:\n ret\n.size fixture,.-fixture\n")
                    build_ids = {False: [], True: []}
                    text_sections = []
                    for name in ("output-one", "output-two"):
                        output = root / language / name
                        output.mkdir(parents=True)
                        query = "check-repro-flags: ; @printf '%s\\n' '$(KBUILD_CFLAGS)' '$(KBUILD_AFLAGS)'"
                        lines = run([tools.make, "-s", "--no-print-directory", "-I", str(kernel),
                                     "-f", str(kernel / "Makefile"), "KBUILD_SRC=" + str(kernel),
                                     "ARCH=arm64", "CONFIG_ARM64=y", "CONFIG_DEBUG_INFO=y",
                                     "CC=" + tools.cc, "CROSS_COMPILE=" + tools.ld.removesuffix("ld"),
                                     "CLANG_TRIPLE=aarch64-linux-gnu-", "--eval", query,
                                     "check-repro-flags"], cwd=output).splitlines()
                        flags = shlex.split(lines[-2 if language == "c" else -1])
                        for normalized in (False, True):
                            obj = output / ("normalized.o" if normalized else "control.o")
                            used_flags = flags if normalized else [f for f in flags if not f.startswith("-fdebug-prefix-map=")]
                            run([tools.cc, *used_flags, "-c", str(source), "-o", obj.name], cwd=output)
                            debug = run([tools.readelf, "--debug-dump=info", str(obj)])
                            self.assertIn("/kernel-build" if normalized else str(output), debug)
                            if normalized:
                                self.assertNotIn(str(output), debug)
                            text_sections.append(run([tools.readelf, "-x", ".text", str(obj)]))
                            elf = "normalized.so" if normalized else "control.so"
                            run([tools.ld, "-shared", "--build-id", "-o", elf, obj.name], cwd=output)
                            notes = run([tools.readelf, "-n", str(output / elf)])
                            build_ids[normalized].append(re.search(r"Build ID: ([0-9a-f]+)", notes).group(1))
                    self.assertTrue(all(text == text_sections[0] for text in text_sections))
                    self.assertNotEqual(*build_ids[False])
                    self.assertEqual(*build_ids[True])
                    print(language, "control build IDs:", *build_ids[False])
                    print(language, "normalized build IDs:", *build_ids[True])


if __name__ == "__main__":
    unittest.main(argv=[__file__], verbosity=2)

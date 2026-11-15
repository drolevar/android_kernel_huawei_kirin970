#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Host regression fixture for the production cgroup BPF query path.

Extracts complete production functions without rewriting them. Host doubles
model allocation, RCU, usercopy, capability and fd boundaries, not a kernel.
"""
import argparse
from pathlib import Path
import re
import subprocess
import unittest

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--cc", required=True)
parser.add_argument("--keep-output", type=Path, required=True,
                    help="new directory for generated source, command and executable")
args = parser.parse_args()
kernel = Path(__file__).resolve().parents[2]


def required(pattern, source):
    match = re.search(pattern, source, re.S | re.M)
    if match is None:
        raise AssertionError("production query implementation missing: " + pattern)
    return match.group(0)


def function(source, name):
    return required(r"^(?:static )?(?:int|u32|void) " + name + r"\(.*?^\}", source)


def macro(source, name):
    return required(r"^#define " + name + r"\b[^\n]*(?:\n(?<=[\\]\n)[^\n]*)*", source)


class BpfProgQueryTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        core = (kernel / "kernel/bpf/core.c").read_text()
        cgroup = (kernel / "kernel/bpf/cgroup.c").read_text()
        syscall = (kernel / "kernel/bpf/syscall.c").read_text()
        cg_header = (kernel / "include/linux/bpf-cgroup.h").read_text()
        bpf_header = (kernel / "include/linux/bpf.h").read_text()
        lists = (kernel / "include/linux/list.h").read_text()
        types = (kernel / "include/linux/types.h").read_text()
        declarations = [required(r"^struct list_head \{.*?^\};", types),
                        required(r"^struct bpf_prog_array \{.*?^\};", bpf_header)]
        for name in ("bpf_prog_list", "cgroup_bpf"):
            declarations.append(required(r"^struct " + name + r" \{.*?^\};", cg_header))
        for name in ("list_entry", "list_first_entry", "list_next_entry", "list_for_each_entry"):
            declarations.append(macro(lists, name))
        parts = [function(core, name) for name in
                 ("bpf_prog_array_length", "bpf_prog_array_copy_to_user", "bpf_prog_array_delete_safe")]
        parts += [function(cgroup, name) for name in ("prog_list_length", "__cgroup_bpf_query")]
        parts.append(function((kernel / "kernel/cgroup/cgroup.c").read_text(), "cgroup_bpf_query"))
        parts += [macro(syscall, "CHECK_ATTR"), macro(syscall, "BPF_PROG_QUERY_LAST_FIELD"),
                  function(syscall, "bpf_prog_query")]
        parts.append(required(r"^SYSCALL_DEFINE3\(bpf,.*?^\}", syscall))
        args.keep_output.mkdir(parents=True, exist_ok=False)
        (args.keep_output / "declarations.h").write_text("\n\n".join(declarations) + "\n")
        (args.keep_output / "subject.h").write_text("\n\n".join(parts) + "\n")
        cls.binary = args.keep_output / "bpf-query"
        command = [args.cc, "-std=gnu11", "-O1", "-g", "-Wall", "-Wextra", "-Werror",
                   "-Wno-sign-compare", "-Wno-unused-function", "-fsanitize=address,undefined", "-fno-sanitize-recover=all",
                   "-fno-omit-frame-pointer", "-I" + str(args.keep_output),
                   '-DBPF_UAPI_HEADER="' + str(kernel / "include/uapi/linux/bpf.h") + '"',
                   str(kernel / "scripts/tests/bpf_prog_query.c"), "-o", str(cls.binary)]
        (args.keep_output / "compile-command.txt").write_text(repr(command) + "\n")
        result = subprocess.run(command, capture_output=True, text=True, timeout=60)
        if result.returncode:
            raise AssertionError("host compilation failed:\n" + result.stdout + result.stderr)

    def run_case(self, name):
        result = subprocess.run([str(self.binary), name], capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_empty_and_zero_capacity(self):
        self.run_case("empty")

    def test_dummy_length_and_ids(self):
        self.run_case("dummy")

    def test_exact_capacity_with_trailing_dummies(self):
        self.run_case("trailing")

    def test_live_slot_can_be_deleted_after_single_read(self):
        self.run_case("delete")

    def test_effective_arrays_can_exceed_per_cgroup_limit(self):
        self.run_case("ancestors")

    def test_short_buffer_and_full_count(self):
        self.run_case("short")

    def test_snapshot_survives_array_and_program_release(self):
        self.run_case("snapshot")

    def test_snapshot_zero_fills_shrunk_array(self):
        self.run_case("shrink")

    def test_allocation_and_usercopy_failures(self):
        self.run_case("errors")

    def test_direct_and_effective_query_ids_and_flags(self):
        self.run_case("queries")

    def test_count_only_and_untrusted_capacity(self):
        self.run_case("count")

    def test_syscall_validation_and_cleanup(self):
        self.run_case("validation")


if __name__ == "__main__":
    unittest.main(argv=[__file__], verbosity=2)

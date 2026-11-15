#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Run the actual object-BTF diagnostic writer with host usercopy doubles."""
import argparse
import contextlib
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--cc", required=True)
parser.add_argument("--keep-output", type=Path)
args = parser.parse_args()
kernel = Path(__file__).resolve().parents[2]


class BtfLogTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        source = kernel / "kernel/bpf/btf_log.c"
        if not source.exists():
            raise AssertionError("object BTF log implementation missing")
        header = (kernel / "include/linux/bpf_verifier.h").read_text()
        patterns = [r"#define BPF_VERIFIER_TMP_LOG_SIZE[^\n]*",
                    r"struct bpf_verifier_log \{.*?\n\};",
                    r"static inline bool bpf_verifier_log_full\(.*?\n\}",
                    r"static inline bool bpf_verifier_log_needed\(.*?\n\}"]
        pieces = []
        for pattern in patterns:
            match = re.search(pattern, header, re.S)
            if not match:
                raise AssertionError("missing log API: " + pattern)
            pieces.append(match.group())
        match = re.search(r"void bpf_verifier_vlog\(.*?\n\}", source.read_text(), re.S)
        if not match:
            raise AssertionError("missing actual diagnostic writer")
        pieces.append(match.group())
        cls.storage = (contextlib.nullcontext(str(args.keep_output)) if args.keep_output
                       else tempfile.TemporaryDirectory(prefix="btf-log-"))
        cls.output = Path(cls.storage.__enter__())
        cls.addClassCleanup(cls.storage.__exit__, None, None, None)
        if args.keep_output:
            cls.output.mkdir(parents=True, exist_ok=False)
        (cls.output / "subject.h").write_text("\n".join(pieces))
        cls.binary = cls.output / "btf-log"
        command = [args.cc, "-std=gnu11", "-O1", "-g", "-Wall", "-Wextra", "-Werror",
                   "-fsanitize=address,undefined", "-fno-sanitize-recover=all",
                   "-I" + str(cls.output), str(kernel / "scripts/tests/btf_log.c"),
                   "-o", str(cls.binary)]
        p = subprocess.run(command, capture_output=True, text=True, timeout=60)
        if p.returncode:
            raise AssertionError(p.stdout + p.stderr)

    def run_case(self, name):
        p = subprocess.run([str(self.binary), name], capture_output=True, text=True, timeout=10)
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)

    def test_formatted_appends_and_termination(self): self.run_case("append")
    def test_full_buffer_does_not_overwrite_canaries(self): self.run_case("full")
    def test_disabled_or_null_log_is_not_needed(self): self.run_case("disabled")
    def test_partial_usercopy_fault_is_sticky(self): self.run_case("fault")
    def test_long_line_is_bounded_by_temporary_buffer(self): self.run_case("long")
    def test_independent_logs_do_not_share_state(self): self.run_case("independent")


if __name__ == "__main__":
    unittest.main(argv=[__file__], verbosity=2)

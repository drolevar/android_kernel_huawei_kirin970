#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Run the real packet-copy helper with host SKB storage and sanitizers.

This exercises copy/bounds behavior, not kernel verifier/JIT/attachment paths.
Use --cc with a host Clang supporting ASan/UBSan. No kernel or phone runs.
"""
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


def required(pattern, text):
    match = re.search(pattern, text, re.S)
    if match is None:
        raise AssertionError("kernel implementation missing: " + pattern)
    return match.group(0)


class RelativePacketReadTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        source = (kernel / "net/core/filter.c").read_text()
        skb = (kernel / "include/linux/skbuff.h").read_text()
        # Copy complete production functions verbatim, not a reimplementation.
        parts = [required(r"static inline [^\n]+?\b" + name + r"\([^\n]+\)\n\{.*?\n\}", skb)
                 for name in ("skb_tail_pointer", "skb_network_header", "skb_mac_header",
                              "skb_mac_header_was_set", "skb_headlen")]
        parts.append(required(r"BPF_CALL_5\(bpf_skb_load_bytes_relative,.*?\n\}", source))
        parts.append(required(r"static const struct bpf_func_proto bpf_skb_load_bytes_relative_proto = \{.*?\n\};", source))
        cls.storage = (contextlib.nullcontext(str(args.keep_output)) if args.keep_output
                       else tempfile.TemporaryDirectory(prefix="skb-relative-"))
        cls.output = Path(cls.storage.__enter__())
        cls.addClassCleanup(cls.storage.__exit__, None, None, None)
        if args.keep_output:
            cls.output.mkdir(parents=True, exist_ok=False)
        (cls.output / "subject.h").write_text("\n\n".join(parts) + "\n")
        cls.binary = cls.output / "skb-relative"
        command = [args.cc, "-std=gnu11", "-O1", "-g", "-Wall", "-Wextra", "-Werror",
                   "-Wno-unused-function", "-fsanitize=address,undefined", "-fno-sanitize-recover=all",
                   "-fno-omit-frame-pointer", "-I" + str(cls.output),
                   '-DBPF_UAPI_HEADER="' + str(kernel / "include/uapi/linux/bpf.h") + '"',
                   str(kernel / "scripts/tests/skb_load_bytes_relative.c"), "-o", str(cls.binary)]
        result = subprocess.run(command, capture_output=True, text=True, timeout=60)
        if result.returncode:
            raise AssertionError("host fixture compilation failed:\n" + result.stdout + result.stderr)

    def run_case(self, name):
        result = subprocess.run([str(self.binary), name], capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_mac_and_network_offsets(self):
        self.run_case("headers")

    def test_headers_still_readable_after_data_pulled(self):
        self.run_case("pulled")

    def test_network_read_does_not_require_mac_header(self):
        self.run_case("unset-net")

    def test_unset_mac_fails_and_clears_output(self):
        self.run_case("unset-mac")

    def test_exact_linear_tail_is_allowed(self):
        self.run_case("tail")

    def test_maximum_16_bit_offset_is_allowed(self):
        self.run_case("max-offset")

    def test_nonlinear_bytes_are_not_read(self):
        self.run_case("nonlinear")

    def test_invalid_base_offset_and_length_clear_only_output(self):
        self.run_case("invalid")


if __name__ == "__main__":
    unittest.main(argv=[__file__], verbosity=2)

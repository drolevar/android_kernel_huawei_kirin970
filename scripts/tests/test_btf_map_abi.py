#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Compile actual UAPI and MAP_CREATE tail validation against literal ABI bytes."""
import argparse
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--cc", required=True)
args = parser.parse_args()
kernel = Path(__file__).resolve().parents[2]


class MapBtfAbiTest(unittest.TestCase):
    def compile_and_run(self, abi):
        source = (kernel / "kernel/bpf/syscall.c").read_text()
        check = re.search(r"#define CHECK_ATTR\(CMD\).*?(?=\n\n)", source, re.S).group()
        last = re.search(r"#define BPF_MAP_CREATE_LAST_FIELD[^\n]*", source).group()
        program = r'''
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include BPF_UAPI_HEADER
static void *memchr_inv(const void *p, int value, size_t n) {
    const unsigned char *b=p;
    for(size_t i=0;i<n;i++) if(b[i]!=(unsigned char)value) return (void *)(b+i);
    return NULL;
}
CHECK
LAST
int main(void) {
    union bpf_attr storage={0}, *attr=&storage;
    uint32_t fd=7,key=3,value=9;
    memcpy((char *)attr+48,&fd,4);
    memcpy((char *)attr+52,&key,4);
    memcpy((char *)attr+56,&value,4);
    if (CHECK_ATTR(BPF_MAP_CREATE)) {
        fputs("MAP_CREATE rejects defined BTF attribute bytes\n",stderr);return 1;
    }
    ((unsigned char *)attr)[60]=1;
    if (!(CHECK_ATTR(BPF_MAP_CREATE))) {
        fputs("MAP_CREATE accepts unsupported attribute tail\n",stderr);return 1;
    }
    ABI
    return 0;
}
'''.replace("CHECK\n", check + "\n").replace("LAST\n", last + "\n")
        assertions = r'''
_Static_assert(BPF_PROG_QUERY==16 && BPF_RAW_TRACEPOINT_OPEN==17 && BPF_BTF_LOAD==18 && BPF_BTF_GET_FD_BY_ID==19,"commands");
_Static_assert(offsetof(union bpf_attr,map_ifindex)==44,"map_ifindex");
_Static_assert(offsetof(union bpf_attr,btf_fd)==48,"btf_fd");
_Static_assert(offsetof(union bpf_attr,btf_key_type_id)==52,"key type");
_Static_assert(offsetof(union bpf_attr,btf_value_type_id)==56,"value type");
_Static_assert(offsetof(union bpf_attr,btf_log_buf)==8 && offsetof(union bpf_attr,btf_size)==16 && offsetof(union bpf_attr,btf_log_level)==24,"BTF load");
_Static_assert(offsetof(struct bpf_map_info,btf_id)==64 && offsetof(struct bpf_map_info,btf_key_type_id)==68 && offsetof(struct bpf_map_info,btf_value_type_id)==72,"map info");
_Static_assert(sizeof(struct bpf_btf_info)==16,"BTF info");
'''
        program = program.replace("    ABI\n", assertions if abi else "")
        with tempfile.TemporaryDirectory(prefix="btf-abi-") as directory:
            path = Path(directory)
            (path / "case.c").write_text(program)
            command = [args.cc, "-std=gnu11", "-Wall", "-Wextra", "-Werror",
                       '-DBPF_UAPI_HEADER="' + str(kernel / "include/uapi/linux/bpf.h") + '"',
                       str(path / "case.c"), "-o", str(path / "case")]
            p = subprocess.run(command, capture_output=True, text=True, timeout=30)
            self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
            p = subprocess.run([str(path / "case")], capture_output=True, text=True, timeout=10)
            self.assertEqual(p.returncode, 0, p.stdout + p.stderr)

    def test_defined_btf_bytes_pass_tail_check_unknown_tail_fails(self):
        self.compile_and_run(False)

    def test_numeric_commands_offsets_and_layout(self):
        self.compile_and_run(True)


if __name__ == "__main__":
    unittest.main(argv=[__file__], verbosity=2)

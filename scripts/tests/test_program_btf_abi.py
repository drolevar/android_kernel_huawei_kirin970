#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Compile canonical program-BTF ABI on ARM64/ARM32; no runtime claim."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

p = argparse.ArgumentParser(description=__doc__)
p.add_argument("--cc", required=True)
p.add_argument("--headers", type=Path, required=True,
               help="Exported kernel dependency headers; bpf.h itself comes from this tree")
p.add_argument("--header", type=Path, help="Explicit baseline header for rejection control")
p.add_argument("--output", type=Path, required=True)
a = p.parse_args()
root = Path(__file__).resolve().parents[2]
header = (a.header or root / "include/uapi/linux/bpf.h").resolve()
a.output.mkdir(parents=True, exist_ok=False)
src = '#include <stddef.h>\n#include BPF_UAPI_HEADER\n'
layouts = {
    "union bpf_attr": {"prog_ifindex":64, "expected_attach_type":68,
        "prog_btf_fd":72, "func_info_rec_size":76, "func_info":80,
        "func_info_cnt":88, "line_info_rec_size":92, "line_info":96,
        "line_info_cnt":104},
    "struct bpf_prog_info": {"ifindex":80, "netns_dev":88, "netns_ino":96,
        "nr_jited_ksyms":104, "nr_jited_func_lens":108, "jited_ksyms":112,
        "jited_func_lens":120, "btf_id":128, "func_info_rec_size":132,
        "func_info":136, "nr_func_info":144, "nr_line_info":148,
        "line_info":152, "jited_line_info":160, "nr_jited_line_info":168,
        "line_info_rec_size":172, "jited_line_info_rec_size":176},
}
for typ, fields in layouts.items():
    for name, offset in fields.items():
        src += f'_Static_assert(offsetof({typ}, {name}) == {offset}, "{name}");\n'
for typ, size in [("struct bpf_func_info",8),("struct bpf_line_info",16),
                  ("struct bpf_prog_info",184),("union bpf_attr",112)]:
    src += f'_Static_assert(sizeof({typ}) == {size}, "{typ} size");\n'
source = a.output / "abi.c"
source.write_text(src)
receipts = []
for target in ["aarch64-linux-gnu", "arm-linux-gnueabi"]:
    cmd = [a.cc, "--target="+target, "-ffreestanding", "-fsyntax-only", "-Werror",
           "-I"+str(a.headers.resolve()), '-DBPF_UAPI_HEADER="'+str(header)+'"', str(source)]
    run = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    receipts.append({"target":target,"command":cmd,"exit":run.returncode,
                     "output":run.stdout+run.stderr})
result = {"scope":__doc__,"header":str(header),
          "header_sha256":hashlib.sha256(header.read_bytes()).hexdigest(),
          "source_sha256":hashlib.sha256(source.read_bytes()).hexdigest(),"runs":receipts}
(a.output/"receipt.json").write_text(json.dumps(result,indent=2)+"\n")
print(json.dumps({r["target"]:r["exit"] for r in receipts}))
raise SystemExit(int(any(r["exit"] for r in receipts)))

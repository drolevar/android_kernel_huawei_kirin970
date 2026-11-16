#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Extract program blinding, line adjustment and clone ownership for host checks."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import resource
import subprocess
from test_program_btf import add_blinding_state_to_aux_model, function


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cc", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    args.output.mkdir(parents=True, exist_ok=False)
    root = Path(__file__).resolve().parents[2]
    core = (root / "kernel/bpf/core.c").read_text()
    model = (root / "scripts/tests/program_btf_host.c").read_text().split("/* FIXTURES */")[0]
    model = add_blinding_state_to_aux_model(model)
    model += "\nstatic void btf_put(struct btf *b) { if (b) b->refcnt--; }\n"
    names = ["__bpf_prog_free", "bpf_prog_alloc", "bpf_prog_realloc",
             "bpf_is_jmp_and_has_target", "bpf_adj_delta_to_off",
             "bpf_adj_branches", "bpf_adj_linfo", "bpf_patch_insn_single",
             "bpf_jit_blind_insn", "bpf_prog_clone_create",
             "bpf_prog_clone_free", "bpf_jit_prog_release_other",
             "bpf_jit_blind_constants"]
    if "bpf_prog_blind_begin" in core:
        names[8:8] = ["bpf_prog_blind_begin", "bpf_prog_blind_finish"]
    subjects = [function(core, name) for name in names]
    fixture = (root / "scripts/tests/program_btf_blinding_host.c").read_text()
    source_text = fixture.replace("/* MODEL */", model).replace(
        "/* SUBJECT */", "\n\n".join(subjects))
    source = args.output / "host.c"
    source.write_text(source_text)
    command = [args.cc, "-std=gnu11", "-O1", "-g", "-Wall", "-Werror",
               "-Wno-unused-function", "-Wno-unused-variable",
               "-fsanitize=address,undefined", "-fno-sanitize-recover=all",
               '-DBPF_UAPI_HEADER="' + str(root / "include/uapi/linux/bpf.h") + '"',
               '-DBTF_UAPI_HEADER="' + str(root / "include/uapi/linux/btf.h") + '"',
               str(source), "-o", str(args.output / "host")]
    built = subprocess.run(command, capture_output=True, text=True)
    receipt = {"scope": __doc__, "command": command,
               "compile_exit": built.returncode,
               "compile_output": built.stdout + built.stderr,
               "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
               "cases": []}
    if not built.returncode:
        run_env = os.environ.copy()
        run_env["ASAN_OPTIONS"] = "detect_leaks=0"
        for case in range(5):
            result = subprocess.run([str(args.output / "host"), str(case)],
                                    capture_output=True, text=True, env=run_env)
            receipt["cases"].append({"case": case, "exit": result.returncode,
                                     "output": result.stdout + result.stderr})
    (args.output / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps(receipt, indent=2))
    return int(built.returncode != 0 or
               any(case["exit"] for case in receipt["cases"]))


if __name__ == "__main__":
    raise SystemExit(main())

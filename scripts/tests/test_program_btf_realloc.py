#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Extract real program reallocation/patch/verifier cleanup path with host services."""
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
    a = parser.parse_args()
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    a.output.mkdir(parents=True, exist_ok=False)
    root = Path(__file__).resolve().parents[2]
    core = (root / "kernel/bpf/core.c").read_text()
    verifier = (root / "kernel/bpf/verifier.c").read_text()
    model = (root / "scripts/tests/program_btf_host.c").read_text().split("/* FIXTURES */")[0]
    model = add_blinding_state_to_aux_model(model)
    model = model.replace("struct bpf_verifier_env {struct bpf_prog *prog;};",
        "struct bpf_insn_aux_data { bool seen; unsigned tag; };\n"
        "struct bpf_verifier_env {struct bpf_prog *prog; struct bpf_insn_aux_data *insn_aux_data;};")
    subjects = ["static void btf_put(struct btf *b) { if(b) { assert(b->refcnt > 1); b->refcnt--; } }"]
    subjects += [function(core, n) for n in ["__bpf_prog_free", "bpf_prog_alloc", "bpf_prog_realloc", "bpf_is_jmp_and_has_target", "bpf_adj_delta_to_off", "bpf_adj_branches", "bpf_adj_linfo", "bpf_patch_insn_single"]]
    subjects += [function(verifier, n) for n in ["adjust_insn_aux_data", "bpf_patch_insn_data"]]
    text = (root / "scripts/tests/program_btf_realloc_host.c").read_text().replace("/* MODEL */", model).replace("/* SUBJECT */", "\n\n".join(subjects))
    source = a.output / "host.c"; source.write_text(text)
    cmd = [a.cc, "-std=gnu11", "-O1", "-g", "-Wall", "-Werror", "-Wno-unused-function", "-Wno-unused-variable", "-fsanitize=address,undefined", "-fno-sanitize-recover=all",
           '-DBPF_UAPI_HEADER="'+str(root / "include/uapi/linux/bpf.h")+'"',
           '-DBTF_UAPI_HEADER="'+str(root / "include/uapi/linux/btf.h")+'"', str(source), "-o", str(a.output / "host")]
    run = subprocess.run(cmd, capture_output=True, text=True)
    receipt = {"scope": __doc__, "command": cmd, "compile_exit": run.returncode, "compile_output": run.stdout+run.stderr, "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(), "cases": []}
    if not run.returncode:
        run_env = os.environ.copy()
        run_env["ASAN_OPTIONS"] = "detect_leaks=0"
        for case in range(6):
            result = subprocess.run([str(a.output / "host"), str(case)],
                                    capture_output=True, text=True, env=run_env)
            receipt["cases"].append({"case": case, "exit": result.returncode, "output": result.stdout+result.stderr})
    (a.output / "receipt.json").write_text(json.dumps(receipt, indent=2)+"\n")
    print(json.dumps(receipt, indent=2))
    return int(run.returncode != 0 or any(c["exit"] for c in receipt["cases"]))

if __name__ == "__main__":
    raise SystemExit(main())

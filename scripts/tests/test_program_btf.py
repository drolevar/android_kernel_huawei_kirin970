#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Program BTF production-code host checks; kernel services are modeled."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import resource
import subprocess
from program_btf_fixture import c_fixture, extract


def function(text, name):
    match = re.search(r"^(?:static )?[\w *]+\s*\b" + name + r"\([^;]*?\)\s*\{", text, re.M)
    assert match, name
    end = text.index("{", match.start()) + 1
    depth = 1
    while depth:
        depth += (text[end] == "{") - (text[end] == "}")
        end += 1
    return text[match.start():end]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cc", required=True)
    parser.add_argument("--red-stub", action="store_true", help="Replace absent new validator only; not production coverage")
    parser.add_argument("--object", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    args.output.mkdir(parents=True, exist_ok=False)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    syscall = (root / "kernel/bpf/syscall.c").read_text()
    tail = function(syscall, "check_uarg_tail_zero")
    source = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <errno.h>
#include <stddef.h>
#include <string.h>
#include BPF_UAPI_HEADER
#define __user
#define unlikely(x) (x)
#define PAGE_SIZE 4096
#define VERIFY_READ 0
#define access_ok(mode,p,n) ((void)(mode),(void)(n),(p)!=NULL)
#define get_user(v,p) ((v)=*(p),0)
/* SUBJECT */
int main(void) {
 unsigned char attr[148] = {0};
 uint32_t fd = 3;
 memcpy(attr + 72, &fd, sizeof(fd));
 /* Actual libbpf submits a 148-byte attr; its metadata starts at72. */
 assert(check_uarg_tail_zero(attr, sizeof(union bpf_attr), sizeof(attr)) == 0);
 attr[147] = 1;
 assert(check_uarg_tail_zero(attr, sizeof(union bpf_attr), sizeof(attr)) == -E2BIG);
 return 0;
}
'''.replace("/* SUBJECT */", tail)
    path = args.output / "attr.c"
    path.write_text(source)
    command = [args.cc, "-std=gnu11", "-O1", "-g", "-Wall", "-Werror",
               "-fsanitize=address,undefined", "-fno-sanitize-recover=all",
               '-DBPF_UAPI_HEADER="' + str(root / "include/uapi/linux/bpf.h") + '"',
               str(path), "-o", str(args.output / "attr")]
    result = subprocess.run(command, capture_output=True, text=True)
    receipt = {"boundary": __doc__, "command": command, "compile_exit": result.returncode,
               "compile_output": result.stdout + result.stderr,
               "source_sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
    if not result.returncode:
        result = subprocess.run([str(args.output / "attr")], capture_output=True, text=True)
        receipt.update(run_exit=result.returncode, output=result.stdout + result.stderr)
    (args.output / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    results = {"attr": receipt}
    fixture = json.loads((root / "scripts/tests/program_btf_clatd.json").read_text())
    if args.object:
        assert extract(args.object.read_bytes()) == fixture
    core = (root / "kernel/bpf/core.c").read_text()
    btf = (root / "kernel/bpf/btf.c").read_text()
    subjects = [tail, "int bpf_check_uarg_tail_zero(void *p,size_t e,size_t a){return check_uarg_tail_zero(p,e,a);}"]
    subjects += [function(btf, n) for n in ["btf_name_by_offset", "btf_type_by_id", "btf_get_by_fd", "btf_put"]]
    if args.red_stub:
        subjects.append("static int check_btf_info(struct bpf_verifier_env*e,const union bpf_attr*a,union bpf_attr*u){return -EOPNOTSUPP;}")
    else:
        subjects += [(root / ("kernel/bpf/"+n)).read_text() for n in ["prog_btf_func.inc", "prog_btf_line.inc", "prog_btf_info.inc"]]
    subjects += [function(core,n) for n in ["__bpf_prog_free", "bpf_prog_alloc", "bpf_prog_realloc", "bpf_prog_clone_free", "bpf_jit_prog_release_other", "bpf_prog_free_deferred", "bpf_prog_free", "bpf_is_jmp_and_has_target", "bpf_adj_delta_to_off", "bpf_adj_branches"]]
    if "static void bpf_adj_linfo" in core:
        subjects.append(function(core,"bpf_adj_linfo"))
    subjects.append(function(core,"bpf_patch_insn_single"))
    subjects += [function(syscall,n) for n in ["__bpf_prog_put_rcu", "__bpf_prog_put", "bpf_prog_put"]]
    if "static int set_info_rec_size" in syscall:
        subjects.append(function(syscall,"set_info_rec_size"))
    subjects.append(function(syscall,"bpf_prog_get_info_by_fd"))
    host = (root / "scripts/tests/program_btf_host.c").read_text().replace("/* FIXTURES */",c_fixture(fixture)).replace("/* SUBJECT */", "\n\n".join(subjects))
    hp = args.output / "host.c"
    hp.write_text(host)
    cmd = command[:]
    cmd[-3:] = [str(hp), "-o", str(args.output / "host")]
    cmd.insert(1, '-DBTF_UAPI_HEADER="'+str(root / "include/uapi/linux/btf.h")+'"')
    cmd.append('-Wno-unused-function')
    run = subprocess.run(cmd,capture_output=True,text=True)
    h = {"command":cmd,"compile_exit":run.returncode,"compile_output":run.stdout+run.stderr,"source_sha256":hashlib.sha256(hp.read_bytes()).hexdigest(),"red_stub":args.red_stub,"cases":[]}
    if not run.returncode:
        for case in range(24):
            r = subprocess.run([str(args.output / "host"),str(case)],capture_output=True,text=True)
            h["cases"].append({"case":case,"exit":r.returncode,"output":r.stdout+r.stderr})
    results["host"] = h
    (args.output / "receipt.json").write_text(json.dumps(results,indent=2)+"\n")
    print(json.dumps({"attr_exit":receipt.get("run_exit"),"host_compile":h["compile_exit"],"compile_output":h["compile_output"],"cases":[(c["case"],c["exit"]) for c in h["cases"]]},indent=2))
    return int(receipt.get("run_exit",1)!=0 or run.returncode!=0 or any(c["exit"] for c in h["cases"]))


if __name__ == "__main__":
    raise SystemExit(main())

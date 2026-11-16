#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Execute extracted scheduler migration/lock wrappers with modeled kernel services.

This checks annotation and physical-lock balance, not real scheduling, lockdep,
WALT accounting, interrupts, memory ordering, or concurrent execution.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import resource
import subprocess


def functions(source, name):
    pattern = r"^(?:static )?(?:inline )?[\w *]+\s*\b" + name + r"\([^;]*?\)\s*(?:__\w+\([^\n]*\)\s*)*\{"
    result = []
    for match in re.finditer(pattern, source, re.M):
        pos = source.index("{", match.start()) + 1
        depth = 1
        while depth:
            depth += (source[pos] == "{") - (source[pos] == "}")
            pos += 1
        result.append(source[match.start():pos])
    assert result, name
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cc", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    args.output.mkdir(parents=True, exist_ok=False)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    header = (root / "kernel/sched/sched.h").read_text()
    core = (root / "kernel/sched/core.c").read_text()
    subject = "\n".join(functions(header, name)[0] for name in
                        ["rq_pin_lock", "rq_unpin_lock", "rq_lock", "rq_unlock",
                         "double_rq_lock"])
    double = functions(header, "_double_lock_balance")
    assert len(double) == 2
    subject += "\n#ifdef CONFIG_PREEMPT\n" + double[0]
    subject += "\n#else\n" + double[1] + "\n#endif\n"
    subject += "\n".join(functions(header, name)[0] for name in
                         ["double_lock_balance", "double_unlock_balance"])
    subject += "\n" + functions(core, "move_queued_task")[0]
    subject += "\n" + functions(core, "__migrate_task")[0]
    subject += "\n" + functions(core, "migration_cpu_stop")[0]
    template = (root / "scripts/tests/sched_unpin_host.c").read_text()
    source = args.output / "production.c"
    source.write_text(template.replace("/* PRODUCTION */", subject))
    cases = [
        ("off-forward", 0, 0, 0, 0),
        ("off-reverse", 0, 0, 1, 0),
        ("off-preempt", 0, 1, 0, 0),
        ("walt-keep", 1, 0, 0, 0),
        ("walt-contended-keep", 1, 0, 0, 1),
        ("walt-drop", 1, 0, 1, 1),
        ("walt-preempt-forward", 1, 1, 0, 0),
        ("walt-preempt-reverse", 1, 1, 1, 0),
    ]
    receipt = {"boundary": __doc__, "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
               "inputs": {name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in
                          ["kernel/sched/core.c", "kernel/sched/sched.h", "scripts/tests/sched_unpin_host.c"]},
               "builds": [], "cases": {}}
    for walt, preempt in sorted({(c[1], c[2]) for c in cases}):
        binary = args.output / f"test-{walt}-{preempt}"
        command = [args.cc, "-std=gnu11", "-O1", "-g", "-Wall", "-Wextra", "-Werror",
                   "-Wno-unused-function", "-fsanitize=address,undefined", "-fno-sanitize-recover=all",
                   str(source), "-o", str(binary)]
        if walt:
            command.append("-DCONFIG_SCHED_WALT")
        if preempt:
            command.append("-DCONFIG_PREEMPT")
        build = subprocess.run(command, capture_output=True, text=True)
        receipt["builds"].append({"command": command, "exit": build.returncode,
                                  "output": build.stdout + build.stderr})
        if build.returncode:
            print(build.stderr)
            continue
        for name, cw, cp, src, contention in cases:
            if (cw, cp) != (walt, preempt):
                continue
            command = [str(binary), str(src), str(contention)]
            result = subprocess.run(command, capture_output=True, text=True)
            receipt["cases"][name] = {"command": command, "exit": result.returncode,
                                       "output": result.stdout + result.stderr}
            print(name, result.returncode, result.stderr.strip())
    (args.output / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    return int(any(x["exit"] for x in receipt["builds"]) or
               any(x["exit"] for x in receipt["cases"].values()) or len(receipt["cases"]) != len(cases))


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Compile actual printk timer declarations with both scheduler-clock branches."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--cc', required=True)
p.add_argument('--output', type=Path, required=True)
a = p.parse_args()
k = Path(__file__).resolve().parents[2]
out = a.output.resolve()
out.mkdir(parents=True, exist_ok=False)
paths = ('include/linux/printk.h', 'include/linux/sched/clock.h', 'kernel/printk/printk.c')
inputs = {name: (k / name).read_text() for name in paths}
text = inputs[paths[0]]
start = text.index('#ifdef CONFIG_HISI_TIME\n')
lines = text[start:].splitlines(True)
depth = 0
end = 0
for line in lines:
    end += len(line)
    if re.match(r'#\s*if', line):
        depth += 1
    elif re.match(r'#\s*endif', line):
        depth -= 1
        if depth == 0:
            break
declaration = text[start:start+end]
clocks = re.findall(r'static inline u64 local_clock\(void\)\n\{.*?\n\}', inputs[paths[1]], re.S)
assert len(clocks) == 2
definition = re.search(r'#ifndef CONFIG_HISI_TIME\nu64 hisi_getcurtime\(void\)\n\{.*?\n#endif', inputs[paths[2]], re.S)
definition = definition.group() if definition else ''
results = []
for mode in ('stable', 'unstable', 'hisi'):
    for order in ('printk-first', 'clock-first'):
        name = mode + '-' + order
        prefix = '''#include <assert.h>
#include <stddef.h>
typedef unsigned long long u64;
typedef unsigned int u32;
typedef unsigned short u16;
typedef unsigned char u8;
#define notrace
#define EXPORT_SYMBOL_GPL(x)
unsigned long long sched_clock(void) { return 9; }
u64 sched_clock_cpu(int cpu) { return 100 + cpu; }
int raw_smp_processor_id(void) { return 2; }
'''
        if mode == 'hisi':
            prefix += '#define CONFIG_HISI_TIME\n'
        clock = clocks[mode == 'unstable'] + '\n'
        body = declaration + clock if order == 'printk-first' else clock + declaration
        body += definition
        if mode == 'hisi':
            body += '\nu64 hisi_getcurtime(void) { return 23; }\n'
        expected = {'stable': 9, 'unstable': 102, 'hisi': 23}[mode]
        source = out / (name + '.c')
        source.write_text(prefix + body + f'\nint main(void) {{ assert(hisi_getcurtime() == {expected}); }}\n')
        cmd = [a.cc, '-std=gnu11', '-Wall', '-Wextra', '-Werror', '-Wno-unused-function',
               '-fsanitize=address,undefined', '-fno-sanitize-recover=all', str(source), '-o', str(out / name)]
        build = subprocess.run(cmd, text=True, capture_output=True, timeout=30)
        run = None
        if not build.returncode:
            run = subprocess.run([str(out / name)], text=True, capture_output=True, timeout=10)
        (out / (name + '.log')).write_text(build.stdout + build.stderr + (run.stdout + run.stderr if run else ''))
        ok = build.returncode == 0 and run.returncode == 0
        results.append({'case': name, 'command': cmd, 'compile_exit': build.returncode,
                        'run_exit': run.returncode if run else None, 'passed': ok})
        print(name, 'PASS' if ok else 'FAIL', flush=True)
(out / 'receipt.json').write_text(json.dumps({'source_sha256': {p: hashlib.sha256(s.encode()).hexdigest() for p,s in inputs.items()},
    'results': results, 'limits': 'Extracted production declarations/inline wrappers; scheduler timer values simulated, not hardware timekeeping'}, indent=2)+'\n')
raise SystemExit(int(not all(r['passed'] for r in results)))

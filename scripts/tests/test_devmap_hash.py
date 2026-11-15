#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Whole devmap.c + verbatim verifier/map-info functions with host boundaries."""
import argparse, hashlib, json, re, subprocess
from pathlib import Path
p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--cc', required=True)
p.add_argument('--output', type=Path, required=True)
a = p.parse_args()
k = Path(__file__).resolve().parents[2]
a.output.mkdir(parents=True, exist_ok=False)
def fun(path, name):
    s = (k/path).read_text()
    m = re.search(r'^static int '+name+r'\(.*?^\}', s, re.M|re.S)
    assert m, name
    return m[0]
s = (k/'kernel/bpf/devmap.c').read_text()
s = re.sub(r'^#include.*$', '', s, flags=re.M)
s += '\n'+fun('kernel/bpf/verifier.c','check_map_func_compatibility')
s += '\n'+fun('kernel/bpf/syscall.c','bpf_map_get_info_by_fd')
(a.output/'subject.h').write_text(s)
# Real registry, omitting unrelated ops; absent native type produces a runtime RED.
registry = (k/'include/linux/bpf_types.h').read_text()
entries = re.findall(r'BPF_MAP_TYPE\((BPF_MAP_TYPE_DEVMAP\w*), (\w+)\)', registry)
(a.output/'registry.h').write_text('static const struct bpf_map_ops *registry(unsigned type) { switch(type) {\n'+''.join('case '+t+': return &'+o+';\n' for t,o in entries)+'default: return NULL; }}\n')
cmd = [a.cc, '-std=gnu11','-O1','-g','-Wall','-Wextra','-Werror','-Wno-unused-function','-Wno-unused-parameter','-Wno-sign-compare','-fsanitize=address,undefined','-fno-sanitize-recover=all','-fno-omit-frame-pointer','-I'+str(a.output),'-DBPF_UAPI_HEADER="'+str(k/'include/uapi/linux/bpf.h')+'"',str(k/'scripts/tests/devmap_hash_host.c'),'-o',str(a.output/'test')]
r = subprocess.run(cmd, capture_output=True, text=True)
receipt = {'source_sha256':hashlib.sha256(s.encode()).hexdigest(),'command':cmd,'compile_exit':r.returncode,'compile_output':r.stdout+r.stderr,'cases':{}}
print(r.stdout+r.stderr,end='')
if r.returncode == 0:
    for case in ['attributes','crud','full','faults','namespace','iteration','unregister','replace_unregister','deferred','interleave','helpers','array']:
        r = subprocess.run([str(a.output/'test'),case],capture_output=True,text=True)
        receipt['cases'][case]={'exit':r.returncode,'output':r.stdout+r.stderr}
        print(case, r.returncode, r.stdout+r.stderr,end='\n')
(a.output/'receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
raise SystemExit(bool(receipt['compile_exit'] or any(v['exit'] for v in receipt['cases'].values())))

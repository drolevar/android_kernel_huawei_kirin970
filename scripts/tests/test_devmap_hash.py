#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Whole devmap.c + verbatim verifier/map-info functions with host boundaries."""
import argparse, hashlib, json, re, subprocess, shutil
from pathlib import Path
p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--cc', required=True)
p.add_argument('--mutation', choices=['helper','barrier','capacity','exist','bitmap','unregister','writer-lock'])
p.add_argument('--output', type=Path, required=True)
a = p.parse_args()
k = Path(__file__).resolve().parents[2]
a.output.mkdir(parents=True, exist_ok=False)
def fun(path, name):
    s = (k/path).read_text()
    m = re.search(r'^(?:static )?[^\n]*\b'+name+r'\(.*?^\}', s, re.M|re.S)
    assert m, name
    return m[0]
s = (k/'kernel/bpf/devmap.c').read_text()
s = s.replace('#include \"devmap_hash.inc\"', (k/'kernel/bpf/devmap_hash.inc').read_text())
s = re.sub(r'^#include.*$', '', s, flags=re.M)
s += '\n'+fun('kernel/bpf/verifier.c','check_map_func_compatibility')
s += '\n'+fun('kernel/bpf/syscall.c','bpf_map_get_info_by_fd')
s += '\n'+fun('kernel/bpf/syscall.c','bpf_get_file_flag')
s += '\n'+fun('kernel/bpf/map_in_map.c','bpf_map_meta_alloc')
for name in ('ld_imm64_to_map_ptr', 'check_ld_imm', 'mark_map_reg'):
    s += '\n'+fun('kernel/bpf/verifier.c', name)
mutations = {
 'helper': ('case BPF_MAP_TYPE_DEVMAP_HASH:\n\t\t/* Control', 'case BPF_MAP_TYPE_DEVMAP_HASH:\n\t\treturn 0;\n\t\t/* Control'),
 'barrier': ('\trcu_barrier();', '\t/* injected missing barrier */'),
 'capacity': ('dtab->items >= dtab->map.max_entries', 'dtab->items > dtab->map.max_entries'),
 'exist': ('!old_dev && map_flags == BPF_EXIST', '0 && !old_dev && map_flags == BPF_EXIST'),
 'bitmap': ('static void __dev_map_hash_entry_free(struct rcu_head *rcu)', 'static void dev_map_flush_old(struct bpf_dtab_netdev *dev);\nstatic void __dev_map_hash_entry_free(struct rcu_head *rcu)'),
 'unregister': ('dev_map_hash_remove_netdev(dtab, netdev);', '(void)netdev;'),
 'writer-lock': ('\tspin_lock_irqsave(&dtab->index_lock, flags);\n\n\told_dev = __dev_map_hash_lookup_elem(map, idx);', '\told_dev = __dev_map_hash_lookup_elem(map, idx);\n\tspin_lock_irqsave(&dtab->index_lock, flags);'),
}
if a.mutation:
    old, new = mutations[a.mutation]
    assert old in s, a.mutation
    s = s.replace(old,new,1)
    if a.mutation == 'bitmap':
        old = 'dev = container_of(rcu, struct bpf_dtab_netdev, rcu);'
        s = s.replace(old,old+'\n\tdev_map_flush_old(dev);',1)
(a.output/'subject.h').write_text(s)
# Real registry, omitting unrelated ops; absent native type produces a runtime RED.
registry = (k/'include/linux/bpf_types.h').read_text()
entries = re.findall(r'BPF_MAP_TYPE\((BPF_MAP_TYPE_DEVMAP\w*), (\w+)\)', registry)
(a.output/'registry.h').write_text('static const struct bpf_map_ops *registry(unsigned type) { switch(type) {\n'+''.join('case '+t+': return &'+o+';\n' for t,o in entries)+'default: return NULL; }}\n')
cmd = [a.cc, '-std=gnu11','-O1','-g','-Wall','-Wextra','-Werror','-Wno-unused-function','-Wno-unused-parameter','-Wno-sign-compare','-fsanitize=address,undefined','-fno-sanitize-recover=all','-fno-omit-frame-pointer','-I'+str(a.output),'-DBPF_UAPI_HEADER="'+str(k/'include/uapi/linux/bpf.h')+'"',str(k/'scripts/tests/devmap_hash_host.c'),'-o',str(a.output/'test')]
r = subprocess.run(cmd, capture_output=True, text=True)
compiler = Path(shutil.which(a.cc) or a.cc).resolve()
inputs = ['kernel/bpf/devmap.c', 'kernel/bpf/devmap_hash.inc', 'kernel/bpf/verifier.c',
          'kernel/bpf/map_in_map.c', 'kernel/bpf/syscall.c', 'include/uapi/linux/bpf.h',
          'include/linux/bpf_types.h', 'scripts/tests/devmap_hash_host.c',
          'scripts/tests/test_devmap_hash.py']
receipt = {'compiler': {'path': str(compiler),
           'version': subprocess.check_output([a.cc, '--version'], text=True),
           'sha256': hashlib.sha256(compiler.read_bytes()).hexdigest()},
           'source_commit': subprocess.check_output(['git','-C',str(k),'rev-parse','HEAD'],text=True).strip(),
           'inputs_sha256': {n:hashlib.sha256((k/n).read_bytes()).hexdigest() for n in inputs},
           'mutation': a.mutation, 'source_sha256':hashlib.sha256(s.encode()).hexdigest(),'command':cmd,'compile_exit':r.returncode,'compile_output':r.stdout+r.stderr,'cases':{}}
print(r.stdout+r.stderr,end='')
if r.returncode == 0:
    for case in ['attributes','crud','full','faults','namespace','iteration','unregister','mixed_unregister','replace_unregister','deferred','interleave','update_interleave','unregister_interleave','helpers','map_pointers','array']:
        r = subprocess.run([str(a.output/'test'),case],capture_output=True,text=True,timeout=10)
        receipt['cases'][case]={'exit':r.returncode,'output':r.stdout+r.stderr}
        print(case, r.returncode, r.stdout+r.stderr,end='\n')
(a.output/'receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
raise SystemExit(bool(receipt['compile_exit'] or any(v['exit'] for v in receipt['cases'].values())))

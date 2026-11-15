#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Compile the entire production ringbuf core with explicit host service models."""
import argparse, hashlib, json, re, subprocess
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--cc',required=True); p.add_argument('--output',required=True,type=Path)
p.add_argument('--mutation', choices=['pending','power2','consumer-write','maywrite','reserve-size','unwind','irq-sync','rcu-sync','counterwrap','helper-deny'])
a=p.parse_args(); root=Path(__file__).resolve().parents[2]
a.output.mkdir(parents=True,exist_ok=False)
source=root/'kernel/bpf/ringbuf.c'
if not source.exists():
 print('FAIL: production ringbuf core is absent'); raise SystemExit(1)
s=source.read_text(); s=re.sub(r'^#include.*$','',s,flags=re.M)
s+='\n'+re.search(r'^static int check_map_func_compatibility\(.*?^\}',(root/'kernel/bpf/verifier.c').read_text(),re.M|re.S)[0]
mutations={
 'counterwrap': ('while (pend_pos != prod_pos)', 'while (pend_pos < prod_pos)'),
 'helper-deny': ('case BPF_MAP_TYPE_RINGBUF:', 'case 999:'),
 'pending': ('new_prod_pos - pend_pos > rb->mask', '0'),
 'power2': ('!is_power_of_2(attr->max_entries)', '0'),
 'consumer-write': ('vma->vm_pgoff != 0 ||', 'false ||'),
 'maywrite': ('vma->vm_flags &= ~VM_MAYWRITE;', '(void)vma;'),
 'reserve-size': ('size > RINGBUF_MAX_RECORD_SZ', 'false'),
 'unwind': ('\t\t__free_page(pages[i]);', '\t\t(void)pages[i];'),
 'irq-sync': ('\tirq_work_sync(&rb_map->rb->work);', '\t/* missing drain */'),
 'rcu-sync': ('\tsynchronize_rcu();', '\t/* missing grace period */'),
}
if a.mutation:
 old,new=mutations[a.mutation]; assert old in s,a.mutation; s=s.replace(old,new,1)
(a.output/'subject.h').write_text(s)
cmd=[a.cc,'-std=gnu11','-O1','-g','-Wall','-Wextra','-Werror','-Wno-unused-function','-Wno-unused-parameter','-Wno-sign-compare','-Wno-tautological-constant-out-of-range-compare','-fsanitize=address,undefined','-fno-sanitize-recover=all','-fno-omit-frame-pointer','-I'+str(a.output),'-DBPF_UAPI_HEADER="'+str(root/'include/uapi/linux/bpf.h')+'"',str(root/'scripts/tests/ringbuf_host.c'),'-o',str(a.output/'test')]
r=subprocess.run(cmd,capture_output=True,text=True)
receipt={'source_commit':subprocess.check_output(['git','-C',str(root),'rev-parse','HEAD'],text=True).strip(),'dirty':bool(subprocess.check_output(['git','-C',str(root),'status','--porcelain'],text=True)),'inputs_sha256':{n:hashlib.sha256((root/n).read_bytes()).hexdigest() for n in ['kernel/bpf/ringbuf.c','kernel/bpf/verifier.c','include/uapi/linux/bpf.h','scripts/tests/ringbuf_host.c','scripts/tests/test_ringbuf.py']},'compiler_sha256':hashlib.sha256(Path(a.cc).resolve().read_bytes()).hexdigest(),'source_sha256':hashlib.sha256(source.read_bytes()).hexdigest(),'extracted_sha256':hashlib.sha256(s.encode()).hexdigest(),'command':cmd,'compiler':subprocess.check_output([a.cc,'--version'],text=True),'compile_exit':r.returncode,'compile_output':r.stdout+r.stderr,'mutation':a.mutation,'cases':{}}
print(r.stdout+r.stderr,end='')
if not r.returncode:
 for case in ['attributes','faults','records','full','wrap','counterwrap','pending','ordering','wakeups','nmi','mmap','poll','destroy','unsupported']:
  r=subprocess.run([str(a.output/'test'),case],capture_output=True,text=True,timeout=20)
  receipt['cases'][case]={'exit':r.returncode,'output':r.stdout+r.stderr}; print(case,r.returncode,r.stdout+r.stderr)
(a.output/'receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
raise SystemExit(bool(receipt['compile_exit'] or any(v['exit'] for v in receipt['cases'].values())))

#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Compile the entire production ringbuf core with explicit host service models."""
import argparse, hashlib, json, re, subprocess
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--cc',required=True); p.add_argument('--output',required=True,type=Path)
p.add_argument('--mutation', choices=['pending','power2','consumer-write','maywrite','reserve-size','unwind','irq-sync','rcu-sync','counterwrap','helper-deny','compat-forward','compat-reverse','release-contract','dispatch','mmap-range'])
a=p.parse_args(); root=Path(__file__).resolve().parents[2]
a.output.mkdir(parents=True,exist_ok=False)
source=root/'kernel/bpf/ringbuf.c'
if not source.exists():
 print('FAIL: production ringbuf core is absent'); raise SystemExit(1)
s=source.read_text(); s=re.sub(r'^#include.*$','',s,flags=re.M)
vm=(root/'mm/vmalloc.c').read_text()
remap='\n'.join(re.search(r'^int '+name+r'\(.*?^\}',vm,re.M|re.S)[0] for name in ['remap_vmalloc_range_partial','remap_vmalloc_range'])
s=remap+'\n'+s
integrated='bpf_ringbuf_reserve_proto' in s
if integrated:s='#define RINGBUF_PRODUCERS_REGISTERED 1\n'+s
s+='\n'+re.search(r'^static int check_map_func_compatibility\(.*?^\}',(root/'kernel/bpf/verifier.c').read_text(),re.M|re.S)[0]
if integrated:
 f=(root/'net/core/filter.c').read_text()
 dispatch='\n'.join(re.search(r'^static const struct bpf_func_proto \*\n'+name+r'\(.*?^\}',f,re.M|re.S)[0] for name in ['bpf_base_func_proto','sk_filter_func_proto'])
 assert re.search(r'cg_skb_prog_ops = \{\s*\.get_func_proto\s*= sk_filter_func_proto,',f)
 others=sorted(set(re.findall(r'return &(\w+);',dispatch))-{'bpf_ringbuf_reserve_proto','bpf_ringbuf_submit_proto','bpf_ringbuf_discard_proto'})
 s+='\n'+''.join('static const struct bpf_func_proto '+n+'={0};\n' for n in others)
 s+='static const struct bpf_func_proto *bpf_get_trace_printk_proto(void) {return NULL;}\n'+dispatch
 sys=(root/'kernel/bpf/syscall.c').read_text()
 for name in ['bpf_map_write_active_inc','bpf_map_write_active_dec','bpf_map_mmap_open','bpf_map_mmap_close']:
  s+='\n'+re.search(r'^static [^\n]*\b'+name+r'\(.*?^\}',sys,re.M|re.S)[0]
 s+='\nstatic const struct vm_operations_struct bpf_map_default_vmops = {.open=bpf_map_mmap_open,.close=bpf_map_mmap_close};\n'
 for name in ['bpf_map_mmap','bpf_map_poll']:
  s+='\n'+re.search(r'^static [^\n]*\b'+name+r'\(.*?^\}',sys,re.M|re.S)[0]
mutations={
 'mmap-range': ('!PAGE_ALIGNED(size) || vma->vm_pgoff >= user_pages ||\n\t    (size >> PAGE_SHIFT) > user_pages - vma->vm_pgoff', '!PAGE_ALIGNED(size) || !user_pages'),
 'dispatch': ('return &bpf_ringbuf_reserve_proto;', 'return NULL;'),
 'compat-forward': ('if (func_id != BPF_FUNC_ringbuf_reserve)', 'if (0)'),
 'compat-reverse': ('if (map->map_type != BPF_MAP_TYPE_RINGBUF)', 'if (0)'),
 'release-contract': ('.releases_reference = true,', '.releases_reference = false,'),
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
receipt={'source_commit':subprocess.check_output(['git','-C',str(root),'rev-parse','HEAD'],text=True).strip(),'dirty':bool(subprocess.check_output(['git','-C',str(root),'status','--porcelain'],text=True)),'inputs_sha256':{n:hashlib.sha256((root/n).read_bytes()).hexdigest() for n in ['kernel/bpf/ringbuf.c','kernel/bpf/verifier.c','net/core/filter.c','kernel/bpf/syscall.c','mm/vmalloc.c','include/uapi/linux/bpf.h','scripts/tests/ringbuf_host.c','scripts/tests/test_ringbuf.py']},'compiler_sha256':hashlib.sha256(Path(a.cc).resolve().read_bytes()).hexdigest(),'source_sha256':hashlib.sha256(source.read_bytes()).hexdigest(),'extracted_sha256':hashlib.sha256(s.encode()).hexdigest(),'command':cmd,'compiler':subprocess.check_output([a.cc,'--version'],text=True),'compile_exit':r.returncode,'compile_output':r.stdout+r.stderr,'mutation':a.mutation,'cases':{}}
print(r.stdout+r.stderr,end='')
if not r.returncode:
 for case in ['attributes','faults','records','full','wrap','counterwrap','pending','ordering','wakeups','nmi','mmap','poll','destroy','unsupported','helpers','fd-lifetime','foreign-region','mmap-boundary']:
  r=subprocess.run([str(a.output/'test'),case],capture_output=True,text=True,timeout=20)
  receipt['cases'][case]={'exit':r.returncode,'output':r.stdout+r.stderr}; print(case,r.returncode,r.stdout+r.stderr)
(a.output/'receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
raise SystemExit(bool(receipt['compile_exit'] or any(v['exit'] for v in receipt['cases'].values())))

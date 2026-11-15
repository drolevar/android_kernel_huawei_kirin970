#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Extract production ARRAY allocation/mmap and map-fd callbacks; simulate VM services."""
import argparse, hashlib, json, re, subprocess
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--nommu',action='store_true');p.add_argument('--mutation',choices=['offset','maywrite','rollback','split','write-exit','freeze-write','metadata','unlocked','usermap','zero']);p.add_argument('--cc',required=True);p.add_argument('--output',type=Path,required=True)
a=p.parse_args();k=Path(__file__).resolve().parents[2];a.output.mkdir(parents=True,exist_ok=False)
def fun(path,name):
 s=(k/path).read_text();m=re.search(r'^(?:static )?[^\n]*\b'+name+r'\(.*?^\}',s,re.M|re.S)
 assert m,name
 return m[0]
s=(k/'kernel/bpf/arraymap.c').read_text()
mask=re.search(r'#define ARRAY_CREATE_FLAG_MASK \\\n[^\n]+',s)[0]
body=fun('kernel/bpf/syscall.c','bpf_map_area_mmapable_alloc')+'\n'+mask+'\n'+fun('kernel/bpf/arraymap.c','array_map_alloc')
for name in ['array_map_vmalloc_addr','array_map_free','array_map_mmap']:
 body+='\n'+fun('kernel/bpf/arraymap.c',name)
for name in ['bpf_map_write_active_inc','bpf_map_write_active_dec','bpf_map_write_active','map_write_begin','bpf_map_mmap_open','bpf_map_mmap_close']:
 body+='\n'+fun('kernel/bpf/syscall.c',name)
body+='\nstatic const struct vm_operations_struct bpf_map_default_vmops = {.open=bpf_map_mmap_open,.close=bpf_map_mmap_close};\n'
for name in ['bpf_map_mmap','map_freeze','bpf_map_poll','map_update_elem','map_delete_elem']:
 body+='\n'+fun('kernel/bpf/syscall.c',name)
mutations={
 'usermap':('PAGE_KERNEL, VM_USERMAP, numa_node','PAGE_KERNEL, 0, numa_node'),
 'zero':('GFP_KERNEL | __GFP_ZERO | __GFP_NOWARN | __GFP_NORETRY','GFP_KERNEL | __GFP_NOWARN | __GFP_NORETRY'),
 'offset':('vma->vm_pgoff + pgoff','pgoff'),
 'maywrite':('vma->vm_flags &= ~VM_MAYWRITE;',';'),
 'rollback':('if (vma->vm_flags & VM_WRITE)\n\t\t\tbpf_map_write_active_dec(map);','if (0)\n\t\t\tbpf_map_write_active_dec(map);'),
 'split':('if (vma->vm_flags & VM_MAYWRITE)\n\t\tbpf_map_write_active_inc(map);','if (0)\n\t\tbpf_map_write_active_inc(map);'),
 'write-exit':('err_put:\n\tbpf_map_write_active_dec(map);','err_put:'),
 'freeze-write':('map->frozen || bpf_map_write_active(map)','map->frozen'),
 'metadata':('vma->vm_pgoff + pgoff','vma->vm_pgoff'),
 'unlocked':('err = map->ops->map_mmap(map, vma);','mutex_lock(&map->freeze_mutex);\n\terr = map->ops->map_mmap(map, vma);\n\tmutex_unlock(&map->freeze_mutex);'),
}
if a.mutation:
 old,new=mutations[a.mutation];assert old in body,a.mutation;body=body.replace(old,new,1)
# Wiring checks complement execution; they are source checks, not VM execution.
syscall=(k/'kernel/bpf/syscall.c').read_text()
for text in ['.mmap\t\t= bpf_map_mmap','.poll\t\t= bpf_map_poll','mutex_init(&map->freeze_mutex)','atomic64_set(&map->writecnt, 0)','case BPF_MAP_FREEZE:']:
 assert text in syscall,text
assert '.map_mmap = array_map_mmap' in (k/'kernel/bpf/arraymap.c').read_text()
(a.output/'subject.h').write_text(body)
cmd=[a.cc,'-std=gnu11','-g','-O1','-fsanitize=address,undefined','-fno-sanitize-recover=all','-I'+str(a.output),'-DBPF_UAPI_HEADER="'+str(k/'include/uapi/linux/bpf.h')+'"',str(k/'scripts/tests/map_mmap_host.c'),'-o',str(a.output/'test')]
if a.nommu:cmd.insert(1,"-DTEST_NOMMU")
r=subprocess.run(cmd,capture_output=True,text=True)
receipt={'nommu':a.nommu,'mutation':a.mutation,'source_commit':subprocess.check_output(['git','-C',str(k),'rev-parse','HEAD'],text=True).strip(),'source_dirty':bool(subprocess.check_output(['git','-C',str(k),'status','--porcelain'],text=True)),'input_hashes':{str(x.relative_to(k)):hashlib.sha256(x.read_bytes()).hexdigest() for x in [k/'kernel/bpf/arraymap.c',k/'kernel/bpf/syscall.c',k/'include/linux/bpf.h',k/'include/uapi/linux/bpf.h',Path(__file__),k/'scripts/tests/map_mmap_host.c']},'command':cmd,'compile_exit':r.returncode,'compile_output':r.stdout+r.stderr,'subject_sha256':hashlib.sha256(body.encode()).hexdigest()}
print(receipt['compile_output'])
if not r.returncode:
 r=subprocess.run([str(a.output/'test')],capture_output=True,text=True);receipt.update(test_exit=r.returncode,test_output=r.stdout+r.stderr);print(receipt['test_output'])
(a.output/'receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
raise SystemExit(r.returncode!=0)

#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Combined map/helper compatibility from production; no kernel execution."""
import argparse,hashlib,json,re,subprocess
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--cc',required=True);p.add_argument('--output',type=Path,required=True)
p.add_argument('--mutation',choices=['socket-forward','socket-reverse','ring-forward','ring-reverse'])
a=p.parse_args();root=Path(__file__).resolve().parents[2];a.output.mkdir(parents=True,exist_ok=False)
s=(root/'kernel/bpf/verifier.c').read_text();s=re.search(r'^static int check_map_func_compatibility\(.*?^\}',s,re.M|re.S)[0]
if a.mutation:
 t,f=('SK_STORAGE','sk_storage_get') if a.mutation.startswith('socket') else ('RINGBUF','ringbuf_reserve')
 pattern=(r'case BPF_MAP_TYPE_'+t+r':.*?break;' if a.mutation.endswith('forward') else r'case BPF_FUNC_'+f+r':.*?break;')
 s,n=re.subn(pattern,'',s,count=1,flags=re.S);assert n==1
src='''#include <assert.h>
#include <stdio.h>
#include <errno.h>
#include BPF_UAPI_HEADER
#define verbose(...) ((void)0)
struct bpf_map {int map_type;};
'''+s+r'''
int main(void) {
 _Static_assert(BPF_MAP_TYPE_SK_STORAGE==24,"storage UAPI");
 _Static_assert(BPF_MAP_TYPE_DEVMAP_HASH==25,"devmap UAPI");
 _Static_assert(BPF_MAP_TYPE_RINGBUF==27,"ring UAPI");
 _Static_assert(BPF_FUNC_sk_storage_get==107,"storage helper");
 _Static_assert(BPF_FUNC_ringbuf_reserve==131,"ring helper");
 _Static_assert(BPF_FUNC_ringbuf_submit==132,"submit helper");
 _Static_assert(BPF_FUNC_ringbuf_discard==133,"discard helper");
 _Static_assert(BPF_MAP_FREEZE==22,"freeze command");
 struct bpf_map m;
 for(int t=0;t<=27;t++) {
  m.map_type=t;
  assert(check_map_func_compatibility(&m,107)==(t==24?0:-EINVAL));
  assert(check_map_func_compatibility(&m,131)==(t==27?0:-EINVAL));
 }
 for(int f=0;f<__BPF_FUNC_MAX_ID;f++) {
  m.map_type=24;assert(check_map_func_compatibility(&m,f)==(f==107?0:-EINVAL));
  m.map_type=27;assert(check_map_func_compatibility(&m,f)==(f==131?0:-EINVAL));
  m.map_type=25;assert(check_map_func_compatibility(&m,f)==-EINVAL);
 }
 puts("PASS: canonical UAPI and bidirectional ring/storage/devmap helper matrix");
}
'''
f=a.output/'production.c';f.write_text(src)
cmd=[a.cc,'-std=gnu11','-g','-O1','-Wall','-Werror','-fsanitize=address,undefined','-fno-sanitize-recover=all','-DBPF_UAPI_HEADER="'+str(root/'include/uapi/linux/bpf.h')+'"',str(f),'-o',str(a.output/'test')]
r=subprocess.run(cmd,capture_output=True,text=True,timeout=60);receipt={'command':cmd,'mutation':a.mutation,'compile_exit':r.returncode,'compile_output':r.stdout+r.stderr,'extracted_sha256':hashlib.sha256(s.encode()).hexdigest()}
if not r.returncode:
 r=subprocess.run([str(a.output/'test')],capture_output=True,text=True,timeout=20);receipt.update(run_exit=r.returncode,output=r.stdout+r.stderr)
(a.output/'receipt.json').write_text(json.dumps(receipt,indent=2)+'\n');print(json.dumps(receipt,indent=2));raise SystemExit(bool(receipt['compile_exit'] or receipt.get('run_exit',1)))

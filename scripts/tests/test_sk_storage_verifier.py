#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Extract optional initializer/context/map checker; model boundary access checks."""
import argparse,json,re,subprocess,hashlib
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--cc',required=True);p.add_argument('--output',required=True,type=Path);a=p.parse_args();k=Path(__file__).resolve().parents[2];a.output.mkdir(exist_ok=False,parents=True)
def fun(path,name):
 s=(k/path).read_text();m=re.search(r'^static [^\n]*\b'+name+r'\([^\{]*?\n\{.*?^\}',s,re.M|re.S);assert m,name;return m[0]
s=(k/'include/linux/bpf.h').read_text();prefix=''
for name in ['bpf_arg_type','bpf_reg_type']:
 m=re.search(r'enum '+name+r' \{.*?\n\};',s,re.S);prefix+=m[0]+'\n'
(a.output/'enums.h').write_text(prefix)
names=['type_is_borrowed_socket','type_is_nullable_socket','register_is_null','check_ctx_reg','check_func_arg','check_map_func_compatibility'];subject='\n'.join(fun('kernel/bpf/verifier.c',n) for n in names)
(a.output/'subject.h').write_text(subject)
cmd=[a.cc,'-std=gnu11','-O1','-g','-Wall','-Werror','-Wno-unused-function','-Wno-unused-variable','-fsanitize=address,undefined','-fno-sanitize-recover=all','-I'+str(a.output),'-DBPF_UAPI_HEADER="'+str(k/'include/uapi/linux/bpf.h')+'"',str(k/'scripts/tests/sk_storage_verifier_host.c'),'-o',str(a.output/'test')]
r=subprocess.run(cmd,capture_output=True,text=True);rec={'command':cmd,'compile_exit':r.returncode,'compile_output':r.stdout+r.stderr,'subject_sha256':hashlib.sha256(subject.encode()).hexdigest()};print(r.stdout+r.stderr)
if not r.returncode:
 r=subprocess.run([str(a.output/'test')],capture_output=True,text=True,timeout=10);rec['run_exit']=r.returncode;rec['output']=r.stdout+r.stderr;print(rec['output'])
(a.output/'receipt.json').write_text(json.dumps(rec,indent=2)+'\n');raise SystemExit(bool(rec['compile_exit'] or rec.get('run_exit',1)))

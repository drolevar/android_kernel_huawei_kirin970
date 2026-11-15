#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Production load/attach admission and canonical UAPI with modeled fd services."""
import argparse,hashlib,json,re,subprocess
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--cc',required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();r=Path(__file__).resolve().parents[2];a.output.mkdir(parents=True,exist_ok=False)
s=(r/'kernel/bpf/syscall.c').read_text()
def fun(n):
 m=re.search(r'^static [\w *]+\b'+n+r'\([^;]*?\)\n\{.*?^\}',s,re.M|re.S);assert m,n
 return m[0]
inc=r/'kernel/bpf/syscall_sockopt.inc'
assert inc.exists(),'load/expected-attach admission absent'
subject=inc.read_text()+'\n'+fun('bpf_prog_attach')+'\n'+fun('bpf_prog_detach')+'\n'+fun('bpf_prog_query')+'\n'+fun('bpf_prog_load')
f=a.output/'production.c';f.write_text((r/'scripts/tests/sockopt_load_host.c').read_text().replace('/* SUBJECT */',subject))
cmd=[a.cc,'-std=gnu11','-O1','-g','-Wall','-Werror','-Wno-unused-function','-Wno-unused-parameter','-fsanitize=address,undefined','-fno-sanitize-recover=all','-DBPF_UAPI_HEADER="'+str(r/'include/uapi/linux/bpf.h')+'"',str(f),'-o',str(a.output/'test')]
x=subprocess.run(cmd,capture_output=True,text=True);d={'command':cmd,'compile_exit':x.returncode,'compile_output':x.stdout+x.stderr,'boundary':__doc__,'source_sha256':hashlib.sha256(f.read_bytes()).hexdigest()}
if not x.returncode:x=subprocess.run([str(a.output/'test')],capture_output=True,text=True);d.update(run_exit=x.returncode,output=x.stdout+x.stderr)
(a.output/'receipt.json').write_text(json.dumps(d,indent=2)+'\n');print(json.dumps(d,indent=2));raise SystemExit(x.returncode)

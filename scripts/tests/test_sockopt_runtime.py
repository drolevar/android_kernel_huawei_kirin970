#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Extracted production syscall/hook runners and pinned netd consumer.
Usercopy, allocation, locks, protocol handlers and BPF invocation are modeled;
this is not live syscall, verifier, socket, RCU or concurrency evidence.
"""
import argparse, hashlib, json, re, subprocess
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--cc',required=True);p.add_argument('--output',type=Path,required=True)
p.add_argument('--connectivity',type=Path,required=True);p.add_argument('--source',type=Path)
a=p.parse_args();here=Path(__file__).resolve().parent;r=a.source or here.parents[1]
a.output.mkdir(parents=True,exist_ok=False)
def function(s,name):
 m=re.search(r'^(?:static |function )?[\w *]+\b'+name+r'\([^;]*?\)\s*\{',s,re.M);assert m,name
 i=s.index('{',m.start());end=i+1;depth=1
 while depth:depth+=(s[end]=='{')-(s[end]=='}');end+=1
 return s[m.start():end]
def syscall(s,name):
 m=re.search(r'^SYSCALL_DEFINE5\('+name+r',.*?^\}',s,re.M|re.S);assert m,name
 return m[0]
def macro(s,name):
 m=re.search(r'^#define '+name+r'\b[^\n]*(?:\n(?<=[\\]\n)[^\n]*)*',s,re.M);assert m,name
 return m[0]
netd=(a.connectivity/'bpf/progs/netd.c').read_text();pin=subprocess.check_output(['git','-C',str(a.connectivity),'rev-parse','HEAD'],text=True).strip();assert pin=='7c04d866538e6f689823b769fb5c1e614ca0e295'
consumer='\n'.join(function(netd,n) for n in ['inet_getsockopt','inet_setsockopt'])
headers=(r/'include/linux/bpf-cgroup.h').read_text();subject=''
inc=r/'kernel/bpf/cgroup_sockopt.inc'
if inc.exists():
 subject+=inc.read_text()+'\n'
 for n in ['BPF_CGROUP_RUN_PROG_SETSOCKOPT','BPF_CGROUP_GETSOCKOPT_MAX_OPTLEN','BPF_CGROUP_RUN_PROG_GETSOCKOPT']:
  subject+=macro(headers,n)+'\n'
source=(r/'net/socket.c').read_text();subject+='\n'.join(syscall(source,n) for n in ['setsockopt','getsockopt'])
text=(here/'sockopt_runtime_host.c').read_text().replace('/* CONSUMER_API */',(a.connectivity/'bpf/progs/include/internal_net_api.h').read_text().replace('#pragma once','')).replace('/* CONSUMER */',consumer).replace('/* SUBJECT */',subject)
f=a.output/'production.c';f.write_text(text)
cmd=[a.cc,'-std=gnu11','-O1','-g','-Wall','-Werror','-Wno-unused-function','-Wno-unused-variable','-Wno-unused-parameter','-Wno-pointer-sign','-fsanitize=address,undefined','-fno-sanitize-recover=all',str(f),'-o',str(a.output/'test')]
x=subprocess.run(cmd,capture_output=True,text=True);rec={'boundary':__doc__,'source':str(r),'consumer_pin':pin,'consumer_sha256':hashlib.sha256(netd.encode()).hexdigest(),'extracted_sha256':hashlib.sha256(text.encode()).hexdigest(),'command':cmd,'compile_exit':x.returncode,'compile_output':x.stdout+x.stderr,'cases':{}}
if not x.returncode:
 for case in ['get-custom','get-pass','set-pass','deny','consume','replace','lengths','copy-faults','alloc-failure','disabled','lsm','compat','null-value','short-buffer','missing-storage','get-copyin','get-count-fault','set-lengths','null-count']:
  x=subprocess.run([str(a.output/'test'),case],capture_output=True,text=True);rec['cases'][case]={'exit':x.returncode,'output':x.stdout+x.stderr};print(case,x.returncode,x.stderr)
else:print(x.stderr)
(a.output/'receipt.json').write_text(json.dumps(rec,indent=2)+'\n');raise SystemExit(bool(rec['compile_exit'] or any(v['exit'] for v in rec['cases'].values())))

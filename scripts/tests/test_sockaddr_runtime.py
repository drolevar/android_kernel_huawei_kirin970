#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Extracted production bind/runner and exact netd functions; modeled kernel services."""
import argparse,hashlib,json,re,subprocess
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--cc',required=True);p.add_argument('--connectivity',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
a=p.parse_args();r=Path(__file__).resolve().parents[2];a.output.mkdir(parents=True,exist_ok=False)
def fun(s,n):
 m=re.search(r'^(?:static |function )?[\w *]+\b'+n+r'\([^;]*?\)\s*\{',s,re.M);assert m,n
 b=s.index('{',m.start());i=b+1;depth=1
 while depth:depth+=(s[i]=='{')-(s[i]=='}');i+=1
 return s[m.start():i]
assert subprocess.check_output(['git','-C',str(a.connectivity),'rev-parse','HEAD'],text=True).strip()=='7c04d866538e6f689823b769fb5c1e614ca0e295'
netd=(a.connectivity/'bpf/progs/netd.c').read_text();consumer='\n'.join(fun(netd,n) for n in ['block_bind_port','is_netd','is_root_or_shell','is_unpriv_tcp_port','is_unpriv_udp_port','is_unpriv_port','inet_bind']).replace('int inet_bind(','int netd_inet_bind(')
subject='#define CONFIG_CGROUP_BPF 1\n#define unlikely(x) (x)\n';runner=r/'kernel/bpf/cgroup_sockaddr.inc'
if runner.exists():
 header=(r/'include/uapi/linux/bpf.h').read_text()
 subject+=re.search(r'enum bpf_attach_type \{.*?\n\};',header,re.S)[0]+'\n'
 bpf=(r/'include/linux/bpf.h').read_text();subject+=bpf[bpf.index('#define __BPF_PROG_RUN_ARRAY('):bpf.index('#ifdef CONFIG_BPF_SYSCALL',bpf.index('#define __BPF_PROG_RUN_ARRAY('))]+'\n'
 subject+=runner.read_text()+'\n'
 subject+=(r/'include/linux/bpf_sockaddr_hooks.h').read_text()+'\n'
subject+='\n'.join(fun((r/'net/ipv4/af_inet.c').read_text(),n) for n in ['inet_bind','inet_dgram_connect'])+'\n'+fun((r/'net/ipv6/af_inet6.c').read_text(),'inet6_bind')
s=(r/'scripts/tests/sockaddr_runtime_host.c').read_text().replace('/* CONSUMER */',consumer).replace('/* SUBJECT */',subject)
f=a.output/'production.c';f.write_text(s);cmd=[a.cc,'-std=gnu11','-O1','-g','-fsanitize=address,undefined','-fno-sanitize-recover=all',str(f),'-o',str(a.output/'test')];x=subprocess.run(cmd,capture_output=True,text=True);d={'boundary':__doc__,'command':cmd,'compile_exit':x.returncode,'compile_output':x.stdout+x.stderr,'source_sha256':hashlib.sha256(s.encode()).hexdigest(),'cases':{}}
if not x.returncode:
 for case in ['blocked','privileged-port','legacy-cap','deny-dominates','short','collision','netd-dns','wrong-netd','connect-denied','disconnect','blocked6','cap6','short6','mapped-v6only','scope-missing','device-missing','nonlocal6','collision6','allow6']:
  x=subprocess.run([str(a.output/'test'),case],capture_output=True,text=True);d['cases'][case]={'exit':x.returncode,'output':x.stdout+x.stderr};print(case,x.returncode)
else:print(x.stderr)
(a.output/'receipt.json').write_text(json.dumps(d,indent=2)+'\n');raise SystemExit(bool(d['compile_exit'] or any(x['exit'] for x in d['cases'].values())))

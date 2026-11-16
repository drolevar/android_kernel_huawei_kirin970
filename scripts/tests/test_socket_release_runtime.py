#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Exact netd consumer and production release/destruction functions; services modeled.
No real cgroup/socket syscall, protocol lifetime or RCU concurrency is exercised.
"""
import argparse,json,hashlib,re,subprocess
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--cc',required=True);p.add_argument('--connectivity',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();a.output.mkdir(parents=True,exist_ok=False);r=Path(__file__).resolve().parents[2]
def fun(s,n):
 m=re.search(r'^[A-Za-z_][\w *]+\b'+n+r'\([^;]*?\)\s*\{',s,re.M);assert m,n
 i=s.index('{',m.start())+1;d=1
 while d:d+=(s[i]=='{')-(s[i]=='}');i+=1
 return s[m.start():i]
assert subprocess.check_output(['git','-C',str(a.connectivity),'rev-parse','HEAD'],text=True).strip()=='7c04d866538e6f689823b769fb5c1e614ca0e295'
netd=(a.connectivity/'bpf/progs/netd.c').read_text();start=netd.index('DEFINE_NETD_T_BPF_PROG_KVER(cgroupsockrelease, inet_release, 5_10)');consumer=netd[start:netd.index('\n}',start)+2].replace('DEFINE_NETD_T_BPF_PROG_KVER(cgroupsockrelease, inet_release, 5_10)\n','static int netd_release')
header=(r/'include/linux/bpf-cgroup.h').read_text();begin=header.index('#define BPF_CGROUP_RUN_SK_PROG(') if '#define BPF_CGROUP_RUN_SK_PROG(' in header else header.index('#define BPF_CGROUP_RUN_PROG_INET_SOCK(');macros=header[begin:header.index('#define BPF_CGROUP_RUN_PROG_SOCK_OPS(',begin)]
bpf=(r/'include/linux/bpf.h').read_text();array=bpf[bpf.index('#define __BPF_PROG_RUN_ARRAY('):bpf.index('#ifdef CONFIG_BPF_SYSCALL',bpf.index('#define __BPF_PROG_RUN_ARRAY('))]
subject=array+'\n'+fun((r/'kernel/bpf/cgroup.c').read_text(),'__cgroup_bpf_run_filter_sk')+'\n'+macros
subject+='\n'+fun((r/'net/ipv4/af_inet.c').read_text(),'inet_release')+'\n'+fun((r/'net/ipv6/af_inet6.c').read_text(),'inet6_release')+'\n'+fun((r/'net/core/sock.c').read_text(),'__sk_destruct')
f=(r/'net/core/filter.c').read_text();cookie=re.search(r'BPF_CALL_1\(bpf_get_socket_cookie_sock,.*?^\}',f,re.S|re.M)[0]
s=(r/'scripts/tests/socket_release_runtime_host.c').read_text().replace('/* COOKIE */',cookie).replace('/* CONSUMER */',consumer).replace('/* SUBJECT */',subject);path=a.output/'production.c';path.write_text(s)
cmd=[a.cc,'-std=gnu11','-O1','-g','-fsanitize=address,undefined','-fno-sanitize-recover=all','-DBPF_UAPI_HEADER="'+str(r/'include/uapi/linux/bpf.h')+'"',str(path),'-o',str(a.output/'test')];x=subprocess.run(cmd,capture_output=True,text=True);rec={'boundary':__doc__,'source_sha256':hashlib.sha256(s.encode()).hexdigest(),'command':cmd,'compile_exit':x.returncode,'compile_output':x.stdout+x.stderr,'cases':{}}
if not x.returncode:
 for case in ['create-route','v4','v6','kernel','disabled','empty','zero-cookie','missing-tag','verdict-zero','multi','linger','exiting','deferred','null-v4','null-v6','double-release']:
  x=subprocess.run([str(a.output/'test'),case],capture_output=True,text=True);rec['cases'][case]={'exit':x.returncode,'output':x.stdout+x.stderr};print(case,x.returncode)
else:print(x.stderr)
(a.output/'receipt.json').write_text(json.dumps(rec,indent=2)+'\n');raise SystemExit(bool(rec['compile_exit'] or any(x['exit'] for x in rec['cases'].values())))

#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Test real CGROUP_SOCK helper dispatcher and socket-cookie context adapter."""
import argparse,re,subprocess,json,hashlib
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--cc',required=True);p.add_argument('--output',required=True,type=Path);a=p.parse_args();k=Path(__file__).resolve().parents[2];a.output.mkdir(parents=True,exist_ok=False)
s=(k/'net/core/filter.c').read_text();start=s.index('static const struct bpf_func_proto *\nsock_filter_func_proto');end=s.index('\n}',start)+2;route=s[start:end]
helper=re.search(r'BPF_CALL_1\(bpf_get_socket_cookie_sock,.*?^};',s,re.M|re.S)
body=(helper[0]+'\n' if helper else '')+route
(a.output/'subject.h').write_text(body)
cmd=[a.cc,'-std=gnu11','-O1','-g','-Wall','-Werror','-Wno-unused-variable','-Wno-unused-function','-fsanitize=address,undefined','-fno-sanitize-recover=all','-I'+str(a.output),'-DBPF_UAPI_HEADER="'+str(k/'include/uapi/linux/bpf.h')+'"',str(k/'scripts/tests/sk_storage_routes_host.c'),'-o',str(a.output/'test')]
r=subprocess.run(cmd,capture_output=True,text=True);rec={'command':cmd,'compile_exit':r.returncode,'compile_output':r.stdout+r.stderr,'subject_sha256':hashlib.sha256(body.encode()).hexdigest()};print(r.stdout+r.stderr)
if not r.returncode:
 r=subprocess.run([str(a.output/'test')],capture_output=True,text=True);rec['run_exit']=r.returncode;rec['output']=r.stdout+r.stderr;print(rec['output'])
# Dispatch source invariant: CGROUP_SOCK and the separately tested CGROUP_SKB route expose helper107.
rec['storage_dispatch_count']=len(re.findall(r'case BPF_FUNC_sk_storage_get:',s))
rec['cg_sock_binding']=bool(re.search(r'cg_sock_prog_ops = \{\s*\.get_func_proto\s*= sock_filter_func_proto',s))
(a.output/'receipt.json').write_text(json.dumps(rec,indent=2)+'\n');raise SystemExit(bool(rec['compile_exit'] or rec.get('run_exit',1) or rec['storage_dispatch_count']!=2 or not rec['cg_sock_binding']))

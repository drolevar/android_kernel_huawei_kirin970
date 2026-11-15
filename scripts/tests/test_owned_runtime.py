#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Production lookup helpers with simulated lookup/netns/reference services.
Not syscall, real socket-table, concurrency, RCU, verifier, or network evidence.
"""
import argparse, hashlib, json, subprocess
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--mutation',choices=['tcp6-port','request-release','namespace-put'])
p.add_argument('--cc',required=True);p.add_argument('--output',type=Path,required=True)
a=p.parse_args();r=Path(__file__).resolve().parents[2]
a.output.mkdir(parents=True,exist_ok=False)
source=r/'net/core/filter_owned_sockets.inc'
assert source.exists(), 'production owned lookup helpers absent'
if a.mutation:
 changes={'tcp6-port':('ntohs(tuple->ipv6.dport)', 'tuple->ipv6.dport'), 'request-release':('sock_gen_put(sk);', '(void)sk;'), 'namespace-put':('put_net(net);', '(void)net;')}
 old,new=changes[a.mutation];body=source.read_text();assert old in body
 source=a.output/'mutated.inc';source.write_text(body.replace(old,new,1))
cmd=[a.cc,'-std=gnu11','-g','-O1','-Wall','-Werror','-Wno-unused-function','-Wno-unused-variable','-Wno-unused-parameter','-fsanitize=address,undefined','-fno-sanitize-recover=all','-DSOURCE="'+str(source)+'"',str(r/'scripts/tests/owned_runtime_host.c'),'-o',str(a.output/'test')]
x=subprocess.run(cmd,capture_output=True,text=True)
rec={'boundary':__doc__,'command':cmd,'source_sha256':hashlib.sha256(source.read_bytes()).hexdigest(),'compile_exit':x.returncode,'compile_output':x.stdout+x.stderr}
if not x.returncode:
 x=subprocess.run([str(a.output/'test')],capture_output=True,text=True);rec.update(run_exit=x.returncode,output=x.stdout+x.stderr)
(a.output/'receipt.json').write_text(json.dumps(rec,indent=2)+'\n');print(json.dumps(rec,indent=2));raise SystemExit(x.returncode)

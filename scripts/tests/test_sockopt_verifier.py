#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Extracted production context permissions, pointer bounds and helper admission.
Kernel layout/alignment/services are modeled; no real verifier/JIT execution.
"""
import argparse,hashlib,json,re,subprocess
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--cc',required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();r=Path(__file__).resolve().parents[2];a.output.mkdir(parents=True,exist_ok=False)
v=(r/'kernel/bpf/verifier.c').read_text();f=r/'net/core/filter_sockopt.inc';assert f.exists(),'sockopt verifier route absent'
def fun(s,n):
 m=re.search(r'^(?:static )?[\w *]+\n?\b'+n+r'\([^;]*?\)\s*\{',s,re.M);assert m,n
 i=s.index('{',m.start());end=i+1;depth=1
 while depth:depth+=(s[end]=='{')-(s[end]=='}');end+=1
 return s[m.start():end]
with (a.output/'foundation.log').open('w') as log:subprocess.run(['python3','-B',str(r/'scripts/tests/test_borrowed_sockets.py'),'--cc',a.cc,'--output',str(a.output/'foundation')],stdout=log,stderr=subprocess.STDOUT,check=True)
s=(a.output/'foundation/production.c').read_text();s=s[:s.index('int main(int argc,')]
s=s.replace('struct bpf_prog {struct bpf_prog_aux *aux;bool gpl_compatible;};','struct bpf_prog {struct bpf_prog_aux *aux;bool gpl_compatible;enum bpf_prog_type type;enum bpf_attach_type expected_attach_type;};')
s=s.replace('int ctx_field_size;','int ctx_field_size;enum bpf_attach_type expected_attach_type;')
s=s.replace('static struct bpf_verifier_ops ops={route};','static struct bpf_verifier_ops ops={.get_func_proto=route};')
s=s.replace('static struct bpf_prog prog={&aux,true};','static struct bpf_prog prog={.aux=&aux,.gpl_compatible=true};')
s=s.replace('static struct bpf_prog_aux aux={&ops,0};','static struct bpf_prog_aux aux={.ops=&ops};')
s=s.replace('struct bpf_verifier_ops {const struct bpf_func_proto *(*get_func_proto)(int);};','struct bpf_insn_access_aux;struct bpf_verifier_ops {const struct bpf_func_proto *(*get_func_proto)(int);bool (*is_valid_access)(int,int,enum bpf_access_type,struct bpf_insn_access_aux*);};')
s=s.replace('int stack_depth;','int stack_depth;int max_ctx_offset;').replace('int sanitize_stack_off;','int sanitize_stack_off;int ctx_field_size;').replace('u32 id_gen; bool allow_ptr_leaks;', 'u32 id_gen; bool allow_ptr_leaks;bool seen_direct_write;void *analyzer_ops;')
ctx=fun(f.read_text(),'cg_sockopt_is_valid_access');dispatch=fun(f.read_text(),'cg_sockopt_func_proto')
s=s.replace(fun(s,'check_ctx_access'),ctx+'\n'+fun(v,'check_ctx_access'))
s=s.replace('#define may_access_direct_pkt_data(...) false',fun(v,'may_access_direct_pkt_data'))
s=s.replace('#define check_packet_access(...) (-EACCES)',fun(v,'__check_packet_access')+'\n'+fun(v,'check_packet_access'))
s=s.replace('#define find_good_pkt_pointers(...) abort()', '#define MAX_PACKET_OFF 0xffff\n#define max(a,b) ((a)>(b)?(a):(b))\ntypedef uint16_t u16;\n'+fun(v,'find_good_pkt_pointers'))
translation=f.read_text()[f.read_text().index('#define CG_SOCKOPT_ACCESS_FIELD'):f.read_text().index('const struct bpf_verifier_ops')]
layout=re.search(r'struct bpf_sockopt_kern \{.*?\n\};',(r/'include/linux/filter.h').read_text(),re.S)[0]
s+='\n'+layout+r"""
#define BPF_FIELD_SIZEOF(T,F) (sizeof(((T*)0)->F)==8?BPF_DW:BPF_W)
#define BPF_LDX_MEM(S,D,R,O) ((struct bpf_insn){.code=BPF_LDX|BPF_MEM|(S),.dst_reg=D,.src_reg=R,.off=O})
#define BPF_STX_MEM(S,D,R,O) ((struct bpf_insn){.code=BPF_STX|BPF_MEM|(S),.dst_reg=D,.src_reg=R,.off=O})
"""+'\n'+translation
s+='\n'+dispatch+'\n'+fun(v,'check_sockopt_return')+'\n'+(r/'scripts/tests/sockopt_verifier_host.c').read_text()
f=a.output/'production.c';f.write_text(s);base=json.loads((a.output/'foundation/receipt.json').read_text());cmd=[str(f) if x==str(a.output/'foundation/production.c') else str(a.output/'test') if x==str(a.output/'foundation/test') else x for x in base['command']]
x=subprocess.run(cmd,capture_output=True,text=True);rec={'boundary':__doc__,'command':cmd,'compile_exit':x.returncode,'compile_output':x.stdout+x.stderr,'cases':{},'extracted_sha256':hashlib.sha256(s.encode()).hexdigest()};print(x.stderr)
if not x.returncode:
 for case in ['permissions','get-storage','set-storage','bounds','aliases','negative','return-range','translation','optval-ownership']:
  x=subprocess.run([str(a.output/'test'),case],capture_output=True,text=True);rec['cases'][case]={'exit':x.returncode,'output':x.stdout+x.stderr};print(case,x.returncode,x.stderr)
(a.output/'receipt.json').write_text(json.dumps(rec,indent=2)+'\n');raise SystemExit(bool(rec['compile_exit'] or any(v['exit'] for v in rec['cases'].values())))

#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Actual network helper route/prototypes into extracted verifier call/branch logic.
Backend functions abort if called: this validates verifier integration, not running
BPF bytecode, helper execution, JIT, kernel syscalls or concurrency.
"""
import argparse,hashlib,json,re,subprocess
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--cc',required=True);p.add_argument('--output',required=True,type=Path)
a=p.parse_args();root=Path(__file__).resolve().parents[2];a.output.mkdir(parents=True,exist_ok=False)
cmd=['python3',str(root/'scripts/tests/test_verifier_ownership.py'),'--cc',a.cc,'--keep-output',str(a.output/'foundation')]
with (a.output/'foundation.log').open('w') as f:subprocess.run(cmd,stdout=f,stderr=subprocess.STDOUT,check=True)
s=(a.output/'foundation/production.c').read_text();core=(root/'kernel/bpf/ringbuf.c').read_text();net=(root/'net/core/filter.c').read_text()
protos='\n'.join(re.search(r'^const struct bpf_func_proto bpf_ringbuf_'+n+r'_proto = \{.*?^\};',core,re.M|re.S)[0] for n in ['reserve','submit','discard'])
dispatch='\n'.join(re.search(r'^static const struct bpf_func_proto \*\n'+n+r'\(.*?^\}',net,re.M|re.S)[0] for n in ['bpf_base_func_proto','sk_filter_func_proto'])
assert re.search(r'cg_skb_prog_ops = \{\s*\.get_func_proto\s*= sk_filter_func_proto,',net)
others=sorted(set(re.findall(r'return &(\w+);',dispatch))-{'bpf_ringbuf_reserve_proto','bpf_ringbuf_submit_proto','bpf_ringbuf_discard_proto'})
stubs='#define CONFIG_BPF_SYSCALL 1\n#define capable(x) true\n'+''.join('static u64 bpf_ringbuf_'+n+'(u64 a,u64 b,u64 c,u64 d,u64 e){abort();}\n' for n in ['reserve','submit','discard'])
stubs+=''.join('static const struct bpf_func_proto '+n+'={0};\n' for n in others)+'static const struct bpf_func_proto *bpf_get_trace_printk_proto(void){abort();}\n'
x=s.index('static const struct bpf_func_proto reserve_proto=');y=s.index('static struct bpf_prog_aux aux=',x)
s=s[:x]+stubs+protos+'\n'+dispatch+'\nstatic const struct bpf_func_proto *route(int id){return sk_filter_func_proto(id);}\nstatic struct bpf_verifier_ops ops={route};\n'+s[y:]
s=s[:s.index('int main(int argc,')]+r'''
static void scalar(int r,u64 x){__mark_reg_known(&state.regs[r],x);state.regs[r].type=SCALAR_VALUE;}
int main(int argc,char **argv){assert(argc==2);const char *c=argv[1];struct bpf_map map={.map_type=BPF_MAP_TYPE_RINGBUF};
 unsigned bytes=!strcmp(c,"submit8")?8:!strcmp(c,"discard12")?12:32;
 if(!strcmp(c,"unsupported")){assert(check_call(&env,BPF_FUNC_ringbuf_output,0)==-EINVAL);assert(check_call(&env,BPF_FUNC_ringbuf_query,0)==-EINVAL);puts("PASS");return 0;}
 state.regs[1].type=CONST_PTR_TO_MAP;state.regs[1].map_ptr=&map;scalar(2,bytes);scalar(3,0);
 if(!strcmp(c,"wrongmap")){map.map_type=BPF_MAP_TYPE_ARRAY;assert(check_call(&env,131,0)==-EINVAL);/* Late compatibility failure discards the explored state. */free_verifier_state(&state,false);assert(!allocations);puts("PASS");return 0;}
 assert(check_call(&env,131,0)==0);assert(state.acquired_refs==1&&state.regs[0].type==PTR_TO_MEM_OR_NULL&&state.regs[0].mem_size==bytes);
 if(!strcmp(c,"nullable")){state.regs[1]=state.regs[0];scalar(2,0);assert(check_call(&env,132,1)==-EINVAL);goto done;}
 assert(check_mem_access(&env,1,0,0,BPF_W,BPF_WRITE,-1,false)==-EACCES);
 state.regs[6]=state.regs[0];spill(0,0);
 struct bpf_insn branch={.code=BPF_JMP|BPF_JEQ|BPF_K,.dst_reg=0,.off=2};int pc=0;
 assert(!check_cond_jmp_op(&env,&branch,&pc));
 struct bpf_verifier_state *live=state.acquired_refs?&state:&pushed,*null=state.acquired_refs?&pushed:&state;
 assert(!null->acquired_refs&&null->regs[0].type==SCALAR_VALUE);env.cur_state=live;
 assert(!check_stack_read(live,-8,8,7));assert(live->regs[7].type==PTR_TO_MEM);
 assert(!check_mem_access(&env,2,7,bytes-4,BPF_W,BPF_WRITE,-1,false));
 assert(check_mem_access(&env,2,7,bytes-3,BPF_W,BPF_WRITE,-1,false)==-EACCES);
 live->regs[1]=live->regs[7];__mark_reg_known_zero(&live->regs[2]);live->regs[2].type=SCALAR_VALUE;
 if(!strcmp(c,"offset")){live->regs[1].off=4;assert(check_call(&env,132,3)==-EINVAL);goto done;}
 if(!strcmp(c,"varoffset")){live->regs[1].var_off=tnum_const(4);assert(check_call(&env,133,3)==-EINVAL);goto done;}
 if(!strcmp(c,"leak")){assert(check_reference_leak(&env)==-EINVAL);goto done;}
 assert(!check_call(&env,!strcmp(c,"discard12")?133:132,3));
 assert(!live->acquired_refs&&live->regs[6].type==NOT_INIT&&live->regs[7].type==NOT_INIT);
 assert(!check_stack_read(live,-8,8,8));assert(check_reg_arg(&env,8,SRC_OP)==-EACCES);
 assert(check_call(&env,132,4)<0);assert(check_reference_leak(&env)==0);
done:
 env.cur_state=&state;free_verifier_state(&state,false);free_verifier_state(&pushed,false);assert(!allocations);puts("PASS");return 0;
}
'''
f=a.output/'production.c';f.write_text(s)
base=json.loads((a.output/'foundation/receipt.json').read_text());compilecmd=base['command'];compilecmd=[str(f) if x==str(a.output/'foundation/production.c') else str(a.output/'test') if x==str(a.output/'foundation/test') else x for x in compilecmd]
r=subprocess.run(compilecmd,capture_output=True,text=True,timeout=60);(a.output/'compile.log').write_text(r.stdout+r.stderr)
receipt={'source_commit':subprocess.check_output(['git','-C',str(root),'rev-parse','HEAD'],text=True).strip(),'command':compilecmd,'compile_exit':r.returncode,'boundary':__doc__,'sources_sha256':{n:hashlib.sha256((root/n).read_bytes()).hexdigest() for n in ['kernel/bpf/ringbuf.c','kernel/bpf/verifier.c','kernel/bpf/verifier_refs.inc','net/core/filter.c','include/linux/bpf.h','include/linux/bpf_verifier.h','include/uapi/linux/bpf.h']},'cases':{}}
print(r.stdout+r.stderr,end='')
if not r.returncode:
 for case in ['submit32','submit8','discard12','wrongmap','unsupported','nullable','offset','varoffset','leak']:
  r=subprocess.run([str(a.output/'test'),case],capture_output=True,text=True,timeout=20);receipt['cases'][case]={'exit':r.returncode,'output':r.stdout+r.stderr};print(case,r.returncode,r.stdout+r.stderr)
(a.output/'receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
raise SystemExit(bool(receipt['compile_exit'] or any(v['exit'] for v in receipt['cases'].values())))

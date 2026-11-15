#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Execute combined production helper routes/call tracking with modeled services.
Not actual BPF loading, kernel concurrency or JIT execution.
"""
import argparse,hashlib,json,re,subprocess
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--cc',required=True);p.add_argument('--output',type=Path,required=True)
a=p.parse_args();root=Path(__file__).resolve().parents[2];a.output.mkdir(parents=True,exist_ok=False)
with (a.output/'foundation.log').open('w') as f:
 subprocess.run(['python3',str(root/'scripts/tests/test_verifier_ownership.py'),'--cc',a.cc,'--keep-output',str(a.output/'foundation')],stdout=f,stderr=subprocess.STDOUT,check=True)
s=(a.output/'foundation/production.c').read_text();v=(root/'kernel/bpf/verifier.c').read_text();net=(root/'net/core/filter.c').read_text()
def function(text,name):return re.search(r'^static [^\n]*\b'+name+r'\([^\{]*?\n\{.*?^\}',text,re.M|re.S)[0]
# Use actual context and stack checking; retain the foundation's declared modeled
# allocation/packet/context-access services and scalar branch boundary.
s=s.replace('#define check_ctx_reg(...) (-EACCES)','static int check_ctx_reg(struct bpf_verifier_env *,const struct bpf_reg_state *,int);').replace('#define check_stack_boundary(...) (-EACCES)','static int check_stack_boundary(struct bpf_verifier_env *,int,int,bool,struct bpf_call_arg_meta *);')
s=s.replace('static int check_func_arg(',function(v,'check_ctx_reg')+'\n'+function(v,'check_stack_boundary')+'\nstatic int check_func_arg(',1)
s=s.replace('static struct tnum tnum_const(', 'static void tnum_strn(char *p,size_t n,struct tnum t){(void)p;(void)n;(void)t;}\nstatic struct tnum tnum_const(',1)
protos=[]
for path,names in [('kernel/bpf/ringbuf.c',['bpf_ringbuf_reserve_proto','bpf_ringbuf_submit_proto','bpf_ringbuf_discard_proto']),('net/core/bpf_sk_storage.c',['bpf_sk_storage_get_cg_sock_proto']),('net/core/filter.c',['bpf_get_socket_cookie_sock_proto'])]:
 text=(root/path).read_text()
 for name in names:protos.append(re.search(r'^(?:static )?const struct bpf_func_proto '+name+r' = \{.*?^\};',text,re.M|re.S)[0])
dispatch='\n'.join(re.search(r'^static const struct bpf_func_proto \*\n'+name+r'\(.*?^\}',net,re.M|re.S)[0] for name in ['bpf_base_func_proto','sk_filter_func_proto','sock_filter_func_proto'])
known={re.search(r'bpf_func_proto (\w+)',x)[1] for x in protos}
others=set(re.findall(r'return &(\w+);',dispatch))-known
stubs='#define CONFIG_BPF_SYSCALL 1\n#define capable(x) true\n'
for name in ['bpf_ringbuf_reserve','bpf_ringbuf_submit','bpf_ringbuf_discard','bpf_sk_storage_get','bpf_get_socket_cookie_sock']:
 stubs+='static u64 '+name+'(u64 a,u64 b,u64 c,u64 d,u64 e){abort();}\n'
stubs+=''.join('static const struct bpf_func_proto '+n+'={0};\n' for n in sorted(others))+'static const struct bpf_func_proto *bpf_get_trace_printk_proto(void){abort();}\n'
x=s.index('static const struct bpf_func_proto reserve_proto=');y=s.index('static struct bpf_prog_aux aux=',x)
s=s[:x]+stubs+'\n'.join(protos)+'\n'+dispatch+'\nstatic const struct bpf_func_proto *sock_route(int id){return sock_filter_func_proto(id); }\nstatic const struct bpf_func_proto *skb_route(int id){return sk_filter_func_proto(id); }\nstatic struct bpf_verifier_ops ops={sock_route};\n'+s[y:]
s=s[:s.index('int main(int argc,')]+r'''
static void scalar(int r,u64 n){__mark_reg_known(&state.regs[r],n);state.regs[r].type=SCALAR_VALUE;}
static struct bpf_map storage={.map_type=24,.key_size=4,.value_size=128},ring={.map_type=27};
static void storage_args(void){state.regs[1]=(struct bpf_reg_state){.type=CONST_PTR_TO_MAP,.map_ptr=&storage};state.regs[2]=(struct bpf_reg_state){.type=PTR_TO_CTX};scalar(3,0);scalar(4,1);}
int main(int argc,char **argv){assert(argc==2);const char *c=argv[1];
 state.regs[1]=(struct bpf_reg_state){.type=CONST_PTR_TO_MAP,.map_ptr=&ring};scalar(2,32);scalar(3,0);
 assert(!check_call(&env,131,0));assert(state.acquired_refs==1);nonnull();state.regs[6]=state.regs[0];spill(0,6);
 unsigned owned=state.regs[6].ref_obj_id;storage_args();
 if(!strcmp(c,"ctx-offset")){state.regs[2].off=4;assert(check_call(&env,107,1)==-EACCES);goto done;}
 if(!strcmp(c,"ctx-borrowed")){state.regs[2]=state.regs[6];assert(check_call(&env,107,1)==-EACCES);goto done;}
 if(!strcmp(c,"owned-initializer")){state.regs[3]=state.regs[6];assert(check_call(&env,107,1)==-EACCES);goto done;}
 if(!strcmp(c,"skb-route")){ops.get_func_proto=skb_route;assert(check_call(&env,107,1)==-EINVAL);goto done;}
 if(!strcmp(c,"delete-route")){assert(check_call(&env,108,1)==-EINVAL);goto done;}
 if(!strcmp(c,"stack-init")||!strcmp(c,"short-init")){
  for(int off=-136;off<-8;off++)assert(!check_stack_write(&env,&state,off,1,-1,0));
  state.regs[3]=(struct bpf_reg_state){.type=PTR_TO_STACK,.off=-136};
  if(!strcmp(c,"short-init")){state.stack[16].slot_type[7]=STACK_INVALID;assert(check_call(&env,107,1)==-EACCES);goto done;}
 }
 assert(!check_call(&env,107,1));assert(state.acquired_refs==1&&state.regs[6].ref_obj_id==owned);
 assert(state.regs[0].type==PTR_TO_MAP_VALUE_OR_NULL&&!state.regs[0].ref_obj_id);state.regs[7]=state.regs[0];
 if(!strcmp(c,"null-storage")){
  struct bpf_insn branch={.code=BPF_JMP|BPF_JEQ|BPF_K,.dst_reg=0,.off=1};int pc=1;
  assert(!check_cond_jmp_op(&env,&branch,&pc));
  assert(state.acquired_refs==1&&pushed.acquired_refs==1);assert(state.regs[6].ref_obj_id==owned&&pushed.regs[6].ref_obj_id==owned);
 }else mark_map_regs(&state,0,false);
 if(!strcmp(c,"release-storage")){state.regs[1]=state.regs[7];scalar(2,0);assert(check_call(&env,132,2)==-EINVAL);goto done;}
 if(!strcmp(c,"cookie")){state.regs[1]=(struct bpf_reg_state){.type=PTR_TO_CTX};assert(!check_call(&env,46,2));assert(state.acquired_refs==1);}
 assert(!check_stack_read(&state,-8,8,8));assert(state.regs[8].ref_obj_id==owned);
 state.regs[1]=state.regs[8];scalar(2,0);assert(!check_call(&env,132,3));assert(!state.acquired_refs&&state.regs[6].type==NOT_INIT);
 assert(state.regs[7].type==PTR_TO_MAP_VALUE||state.regs[7].type==SCALAR_VALUE||state.regs[7].type==PTR_TO_MAP_VALUE_OR_NULL);
 assert(!check_reference_leak(&env));
done:free_verifier_state(&state,false);free_verifier_state(&pushed,false);assert(!allocations);puts("PASS");return 0;}
'''
f=a.output/'production.c';f.write_text(s);base=json.loads((a.output/'foundation/receipt.json').read_text());cmd=[str(f) if x==str(a.output/'foundation/production.c') else str(a.output/'test') if x==str(a.output/'foundation/test') else x for x in base['command']]
r=subprocess.run(cmd,capture_output=True,text=True,timeout=60);rec={'command':cmd,'compile_exit':r.returncode,'compile_output':r.stdout+r.stderr,'extracted_sha256':hashlib.sha256(s.encode()).hexdigest(),'boundary':__doc__,'cases':{}};print(r.stdout+r.stderr)
if not r.returncode:
 for case in ['coexist','null-storage','cookie','stack-init','short-init','ctx-offset','ctx-borrowed','owned-initializer','skb-route','delete-route','release-storage']:
  r=subprocess.run([str(a.output/'test'),case],capture_output=True,text=True,timeout=20);rec['cases'][case]={'exit':r.returncode,'output':r.stdout+r.stderr};print(case,r.returncode,r.stdout+r.stderr)
(a.output/'receipt.json').write_text(json.dumps(rec,indent=2)+'\n');raise SystemExit(bool(rec['compile_exit'] or any(x['exit'] for x in rec['cases'].values())))

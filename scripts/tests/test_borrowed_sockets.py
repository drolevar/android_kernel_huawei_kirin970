#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Borrowed socket integration: production verifier and network translation,
with modeled kernel services. Not a kernel loader, concurrency or JIT test.
"""
import argparse, hashlib, json, re, subprocess
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--mutation',choices=['identity','ownership','mixed','alu']);p.add_argument('--cc',required=True);p.add_argument('--output',required=True,type=Path)
a=p.parse_args();root=Path(__file__).resolve().parents[2]
a.output.mkdir(parents=True,exist_ok=False)
v=(root/'kernel/bpf/verifier.c').read_text(); net=(root/'net/core/filter.c').read_text()
u=(root/'include/uapi/linux/bpf.h').read_text()
assert re.search(r'__u32\s+gso_segs;',u), 'canonical skb GSO ABI absent'
assert 'PTR_TO_SOCK_COMMON_OR_NULL' in v, 'borrowed socket verifier absent'
def function(text,name):
 m=re.search(r'^(?:static )?[\w *]+\n?\b'+name+r'\([^;]*?\)\n\{',text,re.M);assert m,name
 start=m.start();b=text.index('{',start);depth=1;i=b+1
 while depth: depth+=(text[i]=='{')-(text[i]=='}');i+=1
 return text[start:i]
with (a.output/'foundation.log').open('w') as f:
 subprocess.run(['python3','-B',str(root/'scripts/tests/test_verifier_ownership.py'),'--cc',a.cc,'--keep-output',str(a.output/'foundation')],stdout=f,stderr=subprocess.STDOUT,check=True)
s=(a.output/'foundation/production.c').read_text()
# Execute actual context validation and typed socket access, with deliberately
# fail-closed unrelated packet/map services inherited from the foundation.
network='\n'.join(function(net,n) for n in ['bpf_skb_is_valid_access','sk_filter_is_valid_access','cg_skb_is_valid_access','bpf_sock_is_valid_access'])
pre=r'''
#define offsetofend(T,F) (offsetof(T,F)+sizeof(((T*)0)->F))
#define bpf_ctx_range(T,F) offsetof(T,F) ... offsetofend(T,F)-1
#define bpf_ctx_range_till(T,F,L) offsetof(T,F) ... offsetofend(T,L)-1
#define bpf_ctx_record_field_size(I,S) ((I)->ctx_field_size=(S))
struct bpf_insn_access_aux {enum bpf_reg_type reg_type;int ctx_field_size;};
/* Narrow old skb access is outside this fixture. */
#define bpf_ctx_narrow_access_ok(O,S,D) ((S)==(D))
static void tnum_strn(char*p,size_t n,struct tnum t){(void)p;(void)n;(void)t;}
'''
s=s.replace('#define bpf_sock_is_valid_access(...) false','')
s=s.replace('#define check_ctx_reg(...) (-EACCES)',pre+network+'\n#define check_ctx_reg(...) (-EACCES)')
s=s.replace('#define check_ctx_reg(...) (-EACCES)',function(v,'check_ctx_reg'))
s=s.replace('#define check_ctx_access(...) (-EACCES)',r'''
static int check_ctx_access(struct bpf_verifier_env *e,int idx,int off,int size,enum bpf_access_type t,enum bpf_reg_type *rt){
 struct bpf_insn_access_aux info={.reg_type=SCALAR_VALUE};
 if(!cg_skb_is_valid_access(off,size,t,&info))return -EACCES;
 *rt=info.reg_type;return 0;
}
''')
# Use the actual register bounds validator for malformed instruction cases.
s=s.replace('static int check_reg_arg(struct bpf_verifier_env*e,int r,int k){return k==SRC_OP&&e->cur_state->regs[r].type==NOT_INIT?-EACCES:0;}', 'static int check_reg_arg(struct bpf_verifier_env *,unsigned int,int);')
validator=function(v,'check_reg_arg').replace('enum reg_arg_type t','int t')
s=s.replace('static int check_mem_access(', '#define DST_OP 2\n'+function(v,'mark_reg_read')+'\n'+validator+'\nstatic int check_mem_access(',1)
# These are the real dispatches and helper prototypes. Backend calls abort:
# check_call validates them but does not execute a BPF helper.
protos=[]
for path,names in [('kernel/bpf/ringbuf.c',['bpf_ringbuf_reserve_proto','bpf_ringbuf_submit_proto','bpf_ringbuf_discard_proto']),('net/core/bpf_sk_storage.c',['bpf_sk_storage_get_borrowed_proto','bpf_sk_storage_get_cg_sock_proto']),('net/core/filter.c',['bpf_sk_fullsock_proto'])]:
 text=(root/path).read_text()
 for name in names:protos.append(re.search(r'^(?:static )?const struct bpf_func_proto '+name+r' = \{.*?^\};',text,re.M|re.S)[0])
dispatch='\n'.join(function(net,n) for n in ['bpf_base_func_proto','sk_filter_func_proto','cg_skb_func_proto','sock_filter_func_proto'])
known={re.search(r'bpf_func_proto (\w+)',x)[1] for x in protos}
others=set(re.findall(r'return &(\w+);',dispatch))-known
stubs='#define CONFIG_BPF_SYSCALL 1\n#define capable(x) true\n'
for name in ['bpf_ringbuf_reserve','bpf_ringbuf_submit','bpf_ringbuf_discard','bpf_sk_storage_get','bpf_sk_fullsock']:stubs+='static u64 '+name+'(u64 a,u64 b,u64 c,u64 d,u64 e){abort();}\n'
stubs+=''.join('static const struct bpf_func_proto '+n+'={0};\n' for n in sorted(others))+'static const struct bpf_func_proto *bpf_get_trace_printk_proto(void){abort();}\n'
x=s.index('static const struct bpf_func_proto reserve_proto=');y=s.index('static struct bpf_prog_aux aux=',x)
s=s[:x]+stubs+'\n'.join(protos)+'\n'+dispatch+'\nstatic const struct bpf_func_proto *route(int id){return cg_skb_func_proto(id);}\nstatic struct bpf_verifier_ops ops={route};\n'+s[y:]
# Both real shared-instruction checks must use the tested class predicate.
assert 'incompatible_mem_types(*prev_src_type, src_reg_type)' in v
assert 'incompatible_mem_types(*prev_dst_type, dst_reg_type)' in v
assert 'cnt = bpf_sock_convert_ctx_access' in function(v,'convert_ctx_accesses')
assert re.search(r'cg_skb_prog_ops = \{\s*\.get_func_proto\s*= cg_skb_func_proto,\s*\.is_valid_access\s*= cg_skb_is_valid_access,\s*\.convert_ctx_access\s*= cg_skb_convert_ctx_access,',net)
# Execute the entire actual ALU pointer handler; services outside the rejected
# socket path deliberately abort (not alternate implementations).
alu=function(v,'adjust_ptr_min_max_vals')+'\n'+function(v,'check_alu_op')
stubs=r'''
struct bpf_sanitize_info {int unused;};
#define DST_OP 2
#define adjust_reg_min_max_vals(...) (abort(),0)
#define check_reg_sane_offset(...) (abort(),false)
#define sanitize_needed(...) (abort(),false)
#define sanitize_ptr_alu(...) (abort(),0)
#define sanitize_err(...) (abort(),0)
#define signed_add_overflows(...) (abort(),false)
#define signed_sub_overflows(...) (abort(),false)
#define sanitize_check_bounds(...) (abort(),0)
#define __update_reg_bounds(...) abort()
#define __reg_deduce_bounds(...) abort()
#define __reg_bound_offset(...) abort()
#define tnum_add(...) (abort(),tnum_const(0))
#define tnum_sub(...) (abort(),tnum_const(0))
'''
s=s[:s.index('int main(int argc,')]+stubs+alu+r'''
static void scalar(int r,u64 n){__mark_reg_not_init(&state.regs[r]);__mark_reg_known(&state.regs[r],n);state.regs[r].type=SCALAR_VALUE;}
static void load(int dst){state.regs[9]=(struct bpf_reg_state){.type=PTR_TO_CTX};assert(!check_mem_access(&env,0,9,168,BPF_DW,BPF_READ,dst,false));}
static void branch(int reg){struct bpf_insn i={.code=BPF_JMP|BPF_JEQ|BPF_K,.dst_reg=reg,.off=1};int pc=0;assert(!check_cond_jmp_op(&env,&i,&pc));}
static void owned(void){reserve(32);nonnull();state.regs[8]=state.regs[0];}
int main(int argc,char **argv){assert(argc==2);const char *c=argv[1];
 assert(offsetof(struct __sk_buff,data_meta)==140&&offsetof(struct __sk_buff,flow_keys)==144&&offsetof(struct __sk_buff,tstamp)==152&&offsetof(struct __sk_buff,wire_len)==160&&offsetof(struct __sk_buff,gso_segs)==164&&offsetof(struct __sk_buff,sk)==168&&sizeof(struct __sk_buff)==176);
 assert(BPF_FUNC_sk_fullsock==95&&BPF_FUNC_sk_storage_get==107);
 if(!strcmp(c,"independent")){load(6);load(7);assert(state.regs[6].id!=state.regs[7].id);branch(6);assert(state.regs[6].type==PTR_TO_SOCK_COMMON&&pushed.regs[6].type==SCALAR_VALUE);assert(state.regs[7].type==PTR_TO_SOCK_COMMON_OR_NULL&&pushed.regs[7].type==PTR_TO_SOCK_COMMON_OR_NULL);}
 else if(!strcmp(c,"spill-fullsock")){load(6);spill(0,6);branch(6);assert(!check_stack_read(&state,-8,8,1));assert(state.regs[1].type==PTR_TO_SOCK_COMMON);assert(!check_call(&env,95,0));assert(state.regs[0].type==PTR_TO_SOCKET_OR_NULL&&!state.regs[0].ref_obj_id);spill(1,0);branch(0);assert(state.stack[1].spilled_ptr.type==PTR_TO_SOCKET);assert(!check_mem_access(&env,0,0,12,BPF_W,BPF_READ,7,false));}
 else if(!strcmp(c,"ring-overwrite")){owned();load(0);assert(!state.regs[0].ref_obj_id&&state.acquired_refs==1);branch(0);assert(state.acquired_refs==1&&pushed.acquired_refs==1);assert(check_reference_leak(&env)==-EINVAL);assert(!release_reference_reg(&env,&state.regs[8]));}
 else if(!strcmp(c,"storage-live")){owned();load(2);struct bpf_map map={.map_type=24,.key_size=4,.value_size=128};state.regs[1]=(struct bpf_reg_state){.type=CONST_PTR_TO_MAP,.map_ptr=&map};scalar(3,0);scalar(4,1);assert(!check_call(&env,107,1));assert(state.regs[0].type==PTR_TO_MAP_VALUE_OR_NULL&&!state.regs[0].ref_obj_id&&state.acquired_refs==1);assert(!release_reference_reg(&env,&state.regs[8]));}
 else if(!strcmp(c,"mismatch")){enum bpf_reg_type types[]={PTR_TO_MAP_VALUE,PTR_TO_STACK,PTR_TO_MEM,PTR_TO_CTX};for(unsigned i=0;i<4;i++){assert(incompatible_mem_types(PTR_TO_SOCKET,types[i]));assert(incompatible_mem_types(types[i],PTR_TO_SOCKET));}assert(!incompatible_mem_types(PTR_TO_SOCKET,PTR_TO_SOCKET));}
 else if(!strcmp(c,"typed-access")){load(6);assert(check_mem_access(&env,0,6,4,BPF_W,BPF_READ,7,false)==-EACCES);branch(6);assert(!check_mem_access(&env,0,6,4,BPF_W,BPF_READ,7,false));assert(check_mem_access(&env,0,6,12,BPF_W,BPF_READ,7,false)==-EACCES);state.regs[1]=state.regs[6];assert(!check_call(&env,95,0));branch(0);for(int off=0;off<24;off+=4){assert(!check_mem_access(&env,0,0,off,BPF_W,BPF_READ,7,false));assert(check_mem_access(&env,0,0,off,BPF_W,BPF_WRITE,-1,false)==-EACCES);}assert(check_mem_access(&env,0,0,24,BPF_W,BPF_READ,7,false)==-EACCES);assert(check_mem_access(&env,0,0,0,BPF_DW,BPF_READ,7,false)==-EACCES);}
 else if(!strcmp(c,"arithmetic")){load(6);struct bpf_reg_state off={.type=SCALAR_VALUE,.var_off={0,0}};struct bpf_insn i={.code=BPF_ALU64|BPF_ADD,.dst_reg=6};for(int allow=0;allow<2;allow++){env.allow_ptr_leaks=allow;assert(adjust_ptr_min_max_vals(&env,&i,&state.regs[6],&off)==-EACCES);}branch(6);assert(adjust_ptr_min_max_vals(&env,&i,&state.regs[6],&off)==-EACCES);}
 else if(!strcmp(c,"alu-entry")){load(6);state.regs[7]=state.regs[6];env.allow_ptr_leaks=true;struct bpf_insn i={.code=BPF_ALU64|BPF_SUB|BPF_X,.dst_reg=6,.src_reg=7};assert(check_alu_op(&env,&i)==-EACCES);i.code=BPF_ALU|BPF_MOV|BPF_X;assert(check_alu_op(&env,&i)==-EACCES);i.code=BPF_ALU64|BPF_NEG;i.src_reg=0;assert(check_alu_op(&env,&i)==-EACCES);}
 else if(!strcmp(c,"bad-registers")){scalar(0,0);scalar(1,1);for(int reg=11;reg<16;reg++){struct bpf_insn i={.code=BPF_ALU64|BPF_ADD|BPF_K,.dst_reg=reg,.imm=1};assert(check_alu_op(&env,&i)==-EINVAL);i=(struct bpf_insn){.code=BPF_ALU|BPF_MOV|BPF_X,.dst_reg=0,.src_reg=reg};assert(check_alu_op(&env,&i)==-EINVAL);}}
 else if(!strcmp(c,"reserved")){scalar(0,0);scalar(1,1);struct bpf_insn i={.code=BPF_ALU64|BPF_MOV|BPF_X,.dst_reg=0,.src_reg=1,.imm=1};assert(check_alu_op(&env,&i)==-EINVAL);i.imm=0;i.off=1;assert(check_alu_op(&env,&i)==-EINVAL);i=(struct bpf_insn){.code=BPF_ALU64|BPF_NEG,.dst_reg=0,.src_reg=1};assert(check_alu_op(&env,&i)==-EINVAL);i=(struct bpf_insn){.code=BPF_ALU64|BPF_END,.dst_reg=0,.imm=32};assert(check_alu_op(&env,&i)==-EINVAL);}
 else if(!strcmp(c,"reject-routes")){assert(!sk_filter_func_proto(95)&&!sk_filter_func_proto(107));assert(!cg_skb_func_proto(84)&&!cg_skb_func_proto(85)&&!cg_skb_func_proto(86)&&!cg_skb_func_proto(108));load(1);assert(check_call(&env,95,0)==-EACCES);branch(1);scalar(2,0);assert(check_call(&env,132,0)==-EINVAL);assert(!sock_filter_func_proto(95));}
 else if(!strcmp(c,"offsets")){struct bpf_call_arg_meta m={0};load(2);state.regs[2].off=1;assert(check_func_arg(&env,2,ARG_PTR_TO_SOCK_COMMON_OR_NULL,&m)==-EACCES);state.regs[2].off=0;state.regs[2].var_off=tnum_const(1);assert(check_func_arg(&env,2,ARG_PTR_TO_SOCK_COMMON_OR_NULL,&m)==-EACCES);state.regs[2].var_off=tnum_const(0);state.regs[2].ref_obj_id=1;assert(check_func_arg(&env,2,ARG_PTR_TO_SOCK_COMMON_OR_NULL,&m)==-EACCES);}
 else if(!strcmp(c,"context")){struct bpf_insn_access_aux i={0};assert(cg_skb_is_valid_access(168,8,BPF_READ,&i)&&i.reg_type==PTR_TO_SOCK_COMMON_OR_NULL);assert(cg_skb_is_valid_access(164,4,BPF_READ,&i));assert(!cg_skb_is_valid_access(168,4,BPF_READ,&i)&&!cg_skb_is_valid_access(168,8,BPF_WRITE,&i)&&!cg_skb_is_valid_access(164,4,BPF_WRITE,&i));for(int off=140;off<176;off+=4){assert(!sk_filter_is_valid_access(off,4,BPF_READ,&i));if(off!=164)assert(!cg_skb_is_valid_access(off,4,BPF_READ,&i));}}
 else if(!strcmp(c,"overflow")){env.id_gen=INT_MAX;assert(set_borrowed_socket(&env,&state.regs[0],PTR_TO_SOCKET_OR_NULL)==-E2BIG);}
 else abort();
 free_verifier_state(&state,false);free_verifier_state(&pushed,false);assert(!allocations);puts("PASS");return 0;}
'''
if a.mutation:
 mutations={
  'identity':('reg->id = ++env->id_gen;', 'reg->id = 1;'),
  'ownership':('memset(reg, 0, sizeof(*reg));', 'u32 old_ref = reg->ref_obj_id; memset(reg, 0, sizeof(*reg)); reg->ref_obj_id = old_ref;'),
  'mixed':('return old != NOT_INIT && old != new &&', 'return false && old != NOT_INIT && old != new &&'),
  'alu':('if (opcode != BPF_MOV &&', 'if (false && opcode != BPF_MOV &&'),
 }
 old,new=mutations[a.mutation];assert old in s;s=s.replace(old,new,1)
f=a.output/'production.c';f.write_text(s);base=json.loads((a.output/'foundation/receipt.json').read_text());cmd=[str(f) if x==str(a.output/'foundation/production.c') else str(a.output/'test') if x==str(a.output/'foundation/test') else x for x in base['command']]
r=subprocess.run(cmd,capture_output=True,text=True,timeout=60);rec={'command':cmd,'compile_exit':r.returncode,'compile_output':r.stdout+r.stderr,'extracted_sha256':hashlib.sha256(s.encode()).hexdigest(),'boundary':__doc__,'cases':{}};print(r.stdout+r.stderr)
if not r.returncode:
 for case in ['independent','spill-fullsock','ring-overwrite','storage-live','mismatch','typed-access','arithmetic','alu-entry','bad-registers','reserved','reject-routes','offsets','context','overflow']:
  r=subprocess.run([str(a.output/'test'),case],capture_output=True,text=True,timeout=20);rec['cases'][case]={'exit':r.returncode,'output':r.stdout+r.stderr};print(case,r.returncode,r.stdout+r.stderr)
(a.output/'receipt.json').write_text(json.dumps(rec,indent=2)+'\n');raise SystemExit(bool(rec['compile_exit'] or any(x['exit'] for x in rec['cases'].values())))

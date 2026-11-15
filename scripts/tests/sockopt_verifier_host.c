/* SPDX-License-Identifier: GPL-2.0 */
static const struct bpf_func_proto *sockopt_route(int id){return cg_sockopt_func_proto(id);}
static void context_load(int off,int dst){state.regs[9]=(struct bpf_reg_state){.type=PTR_TO_CTX};assert(!check_mem_access(&env,0,9,off,BPF_DW,BPF_READ,dst,false));}
int main(int argc,char**argv){assert(argc==2);const char*c=argv[1];prog.type=BPF_PROG_TYPE_CGROUP_SOCKOPT;prog.expected_attach_type=BPF_CGROUP_GETSOCKOPT;ops.get_func_proto=sockopt_route;ops.is_valid_access=cg_sockopt_is_valid_access;
 if(!strcmp(c,"permissions")){
  for(int hook=21;hook<=22;hook++)for(int off=-1;off<=40;off++)for(int size=1;size<=8;size*=2)for(int write=0;write<=1;write++){
   struct bpf_insn_access_aux a={.expected_attach_type=hook};
   bool want=!write?((size==8&&(off==0||off==8||off==16))||(size==4&&(off==24||off==28||off==32||(off==36&&hook==21)))):(size==4&&(off==32||(hook==21&&off==36)||(hook==22&&(off==24||off==28))));
   assert(cg_sockopt_is_valid_access(off,size,write?BPF_WRITE:BPF_READ,&a)==want);
  }
 }else if(!strcmp(c,"get-storage")||!strcmp(c,"set-storage")){
  prog.expected_attach_type=!strcmp(c,"set-storage")?22:21;
  reserve(8);nonnull();state.regs[6]=state.regs[0];context_load(0,0);
  assert(state.regs[0].type==PTR_TO_SOCKET&&!state.regs[0].ref_obj_id&&state.acquired_refs==1);
  state.regs[2]=state.regs[0];struct bpf_map map={.map_type=24,.value_size=128,.key_size=4};state.regs[1]=(struct bpf_reg_state){.type=CONST_PTR_TO_MAP,.map_ptr=&map};scalar(3,0);scalar(4,0);
  assert(!check_call(&env,107,1)&&state.regs[0].type==PTR_TO_MAP_VALUE_OR_NULL&&!state.regs[0].ref_obj_id);
  assert(!release_reference_reg(&env,&state.regs[6]));
  for(int n=0;n<135;n++)if(n!=107)assert(!cg_sockopt_func_proto(n));
 }else if(!strcmp(c,"bounds")||!strcmp(c,"aliases")||!strcmp(c,"negative")){
  /* Selected Android loader is privileged; retain legacy pointer policy. */
  env.allow_ptr_leaks=true;
  context_load(8,6);context_load(16,7);assert(state.regs[6].type==PTR_TO_PACKET&&state.regs[7].type==PTR_TO_PACKET_END);
  assert(check_mem_access(&env,0,6,0,BPF_DW,BPF_WRITE,-1,false)==-EACCES);
  /* Constant addition state is modeled; branch and range checks are production.
   * The inherited fixture deliberately aborts on its unextracted ALU path. */
  state.regs[8]=state.regs[6];state.regs[8].off=!strcmp(c,"negative")?-1:8;spill(0,6);
  struct bpf_insn i={.code=BPF_JMP|BPF_JGT|BPF_X,.dst_reg=8,.src_reg=7,.off=1};int pc=0;assert(!check_cond_jmp_op(&env,&i,&pc));
  if(!strcmp(c,"negative")){assert(!state.regs[6].range);}
  else {assert(state.regs[6].range==8&&state.stack[0].spilled_ptr.range==8&&!pushed.regs[6].range);assert(!check_mem_access(&env,0,6,0,BPF_DW,BPF_WRITE,-1,false));assert(check_mem_access(&env,0,6,1,BPF_DW,BPF_WRITE,-1,false)==-EACCES);assert(check_mem_access(&env,0,6,-1,BPF_DW,BPF_READ,0,false)==-EACCES);}
 }else if(!strcmp(c,"optval-ownership")){
  reserve(8);nonnull();state.regs[6]=state.regs[0];context_load(8,0);
  assert(state.regs[0].type==PTR_TO_PACKET&&!state.regs[0].ref_obj_id&&state.acquired_refs==1);
  assert(check_reference_leak(&env)==-EINVAL);assert(!release_reference_reg(&env,&state.regs[6]));
 }else if(!strcmp(c,"translation")){
  int uoff[]={0,8,16,24,28,32,36};
  int koff[]={offsetof(struct bpf_sockopt_kern,sk),offsetof(struct bpf_sockopt_kern,optval),offsetof(struct bpf_sockopt_kern,optval_end),offsetof(struct bpf_sockopt_kern,level),offsetof(struct bpf_sockopt_kern,optname),offsetof(struct bpf_sockopt_kern,optlen),offsetof(struct bpf_sockopt_kern,retval)};
  for(int h=21;h<=22;h++)for(int write=0;write<2;write++)for(int n=0;n<7;n++){
   struct bpf_insn_access_aux a={.expected_attach_type=h};int size=n<3?8:4;
   if(!cg_sockopt_is_valid_access(uoff[n],size,write?BPF_WRITE:BPF_READ,&a))continue;
   for(int dst=1;dst<=2;dst++){
    struct bpf_insn in={.src_reg=1,.dst_reg=dst,.off=uoff[n]},out[2]={0};u32 target=0;
    assert(cg_sockopt_convert_ctx_access(write?BPF_WRITE:BPF_READ,&in,out,&prog,&target)==1);
    assert(out[0].off==koff[n]&&out[0].dst_reg==dst&&out[0].src_reg==1);
    assert(out[0].code==((write?BPF_STX:BPF_LDX)|BPF_MEM|(n<3?BPF_DW:BPF_W)));
   }
  }
 }else if(!strcmp(c,"return-range")){
  scalar(0,0);assert(!check_sockopt_return(&env));scalar(0,1);assert(!check_sockopt_return(&env));scalar(0,2);assert(check_sockopt_return(&env)==-EINVAL);scalar(0,UINT64_MAX);assert(check_sockopt_return(&env)==-EINVAL);context_load(0,0);assert(check_sockopt_return(&env)==-EINVAL);
 }else abort();free_verifier_state(&state,false);free_verifier_state(&pushed,false);assert(!allocations);puts("PASS extracted verifier; modeled services");return 0;}

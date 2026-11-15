/* SPDX-License-Identifier: GPL-2.0 */
/* Extracted production verifier and dispatch, NOT live kernel execution. */
static void lookup(int helper)
{
 /* Use an existing checked allocation for tuple input to exercise real memory
  * argument validation without substituting a successful stack checker. */
 reserve(36);nonnull();state.regs[9]=state.regs[0];
 state.regs[1]=(struct bpf_reg_state){.type=PTR_TO_CTX};
 state.regs[2]=state.regs[9];scalar(3,12);scalar(4,UINT64_MAX);scalar(5,0);
 assert(!check_call(&env,helper,0));
 assert(state.regs[0].type==PTR_TO_SOCKET_OR_NULL);
 assert(state.regs[0].id && state.regs[0].ref_obj_id==state.regs[0].id);
 assert(state.regs[0].ref_obj_id!=state.regs[9].ref_obj_id);
 assert(!release_reference_reg(&env,&state.regs[9]));
}
static void release_socket(int r)
{
 state.regs[1]=state.regs[r];assert(!check_call(&env,86,1));
 assert(state.regs[0].type==SCALAR_VALUE);
}
int main(int argc,char **argv)
{
 assert(argc==2);const char *c=argv[1];
 if(!strcmp(c,"admission")) {
  struct bpf_func_proto p={.ret_type=RET_INTEGER,.arg1_type=ARG_PTR_TO_SOCK_COMMON,.releases_reference=true};
  assert(!check_reference_proto(&p));
  p.ret_type=RET_VOID;assert(check_reference_proto(&p)==-EINVAL);
  p.ret_type=RET_INTEGER;p.arg2_type=ARG_PTR_TO_ALLOC_MEM;assert(check_reference_proto(&p)==-EINVAL);
  p.arg2_type=ARG_PTR_TO_SOCK_COMMON;assert(check_reference_proto(&p)==-EINVAL);
  assert(cg_skb_func_proto(84)&&cg_skb_func_proto(85)&&cg_skb_func_proto(86));
  assert(!sk_filter_func_proto(84)&&!sk_filter_func_proto(85)&&!sk_filter_func_proto(86));
  assert(!sock_filter_func_proto(84)&&!sock_filter_func_proto(86));
 } else if(!strcmp(c,"nullable")) {
  lookup(84);state.regs[6]=state.regs[0];spill(0,0);
  assert(check_reference_leak(&env)==-EINVAL);
  state.regs[1]=state.regs[0];assert(check_call(&env,86,1)<0);
  branch(6);assert(state.acquired_refs==1&&!pushed.acquired_refs);
  assert(pushed.regs[0].type==SCALAR_VALUE&&!pushed.regs[0].ref_obj_id);
  assert(!pushed.stack[0].spilled_ptr.ref_obj_id);
  release_socket(6);assert(!state.acquired_refs);
 } else if(!strcmp(c,"cast")) {
  lookup(85);branch(0);state.regs[6]=state.regs[0];
  state.regs[1]=state.regs[6];assert(!check_call(&env,95,1));
  assert(state.regs[0].ref_obj_id==state.regs[6].ref_obj_id);
  assert(state.regs[0].id!=state.regs[0].ref_obj_id);
  spill(0,0);branch(0);
  assert(pushed.acquired_refs==1&&!pushed.regs[0].ref_obj_id);
  assert(pushed.regs[6].type==PTR_TO_SOCKET);
  env.cur_state=&pushed;
  assert(check_reference_leak(&env)==-EINVAL);
  pushed.regs[1]=pushed.regs[6];assert(!check_call(&env,86,1));
  assert(!pushed.acquired_refs);env.cur_state=&state;
  assert(state.acquired_refs==1);release_socket(6);
  assert(state.stack[0].spilled_ptr.type==NOT_INIT);
 } else if(!strcmp(c,"aliases")) {
  lookup(84);branch(0);state.regs[6]=state.regs[0];spill(0,0);
  assert(!check_stack_read(&state,-8,8,7));release_socket(7);
  assert(state.regs[6].type==NOT_INIT&&state.regs[7].type==NOT_INIT);
  assert(state.stack[0].spilled_ptr.type==NOT_INIT&&!state.acquired_refs);
  assert(check_mem_access(&env,1,6,12,BPF_W,BPF_READ,8,false)<0);
  state.regs[1]=state.regs[6];assert(check_call(&env,86,1)<0);
 } else if(!strcmp(c,"release-errors")) {
  load(6);branch(6);state.regs[1]=state.regs[6];assert(check_call(&env,86,1)<0);
  lookup(85);branch(0);state.regs[6]=state.regs[0];
  state.regs[1]=state.regs[6];state.regs[1].off=1;assert(check_call(&env,86,1)<0);
  state.regs[1]=state.regs[6];state.regs[1].var_off=tnum_const(1);assert(check_call(&env,86,1)<0);
  state.regs[1]=state.regs[6];scalar(2,0);assert(check_call(&env,132,1)<0);
  assert(state.acquired_refs==1);release_socket(6);
 } else if(!strcmp(c,"mixed")) {
  lookup(84);branch(0);state.regs[6]=state.regs[0];
  reserve(12);nonnull();state.regs[7]=state.regs[0];
  state.regs[1]=state.regs[7];assert(check_call(&env,86,1)<0);
  assert(state.acquired_refs==2);release_socket(6);
  assert(state.acquired_refs==1&&state.regs[7].type==PTR_TO_MEM);
  assert(check_reference_leak(&env)==-EINVAL);
  assert(!release_reference_reg(&env,&state.regs[7]));
 } else if(!strcmp(c,"storage")) {
  lookup(84);branch(0);state.regs[6]=state.regs[0];
  struct bpf_map map={.map_type=24,.key_size=4,.value_size=128};
  state.regs[1]=(struct bpf_reg_state){.type=CONST_PTR_TO_MAP,.map_ptr=&map};
  state.regs[2]=state.regs[6];scalar(3,0);scalar(4,0);
  assert(!check_call(&env,107,1));state.regs[7]=state.regs[0];
  assert(state.regs[7].type==PTR_TO_MAP_VALUE_OR_NULL&&!state.regs[7].ref_obj_id);
  /* netd.c 644-647: conditional UID load at byte12, release, pointer test.
   * The selected privileged loader has allow_ptr_leaks set. */
  env.allow_ptr_leaks=true;
  branch(7);
  assert(!check_mem_access(&env,1,7,12,BPF_W,BPF_READ,8,false));
  /* Execute the storage-NULL branch too: no read, release, known-NULL test. */
  env.cur_state=&pushed;pushed.regs[1]=pushed.regs[6];
  assert(!check_call(&env,86,1)&&!pushed.acquired_refs);
  assert(pushed.regs[7].type==SCALAR_VALUE&&!pushed.regs[7].ref_obj_id);
  struct bpf_insn test_null={.code=BPF_JMP|BPF_JEQ|BPF_K,.dst_reg=7,.off=2};
  int pc=0;assert(!check_cond_jmp_op(&env,&test_null,&pc)&&pc==2);
  env.cur_state=&state;
  release_socket(6);assert(!state.acquired_refs);
  assert(state.regs[7].type==PTR_TO_MAP_VALUE&&!state.regs[7].ref_obj_id);
  assert(state.regs[8].type==SCALAR_VALUE);
  branch(7);
 } else abort();
 free_verifier_state(&state,false);free_verifier_state(&pushed,false);
 assert(!allocations);puts("PASS");return 0;
}

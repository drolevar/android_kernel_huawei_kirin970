/* SPDX-License-Identifier: GPL-2.0 */
static const struct bpf_func_proto *sockaddr_route(int id){return sock_addr_func_proto(id);}
static const struct bpf_func_proto *release_route(int id){return sock_filter_func_proto(id);}
int main(int argc,char**argv){assert(argc==2);const char*c=argv[1];prog.type=BPF_PROG_TYPE_CGROUP_SOCK_ADDR;prog.expected_attach_type=BPF_CGROUP_INET4_BIND;ops.get_func_proto=sockaddr_route;ops.is_valid_access=sock_addr_is_valid_access;
 if(!strcmp(c,"release-context")){
  struct bpf_insn_access_aux a={.expected_attach_type=34};
  for(int off=-1;off<=24;off++)for(int n=1;n<=8;n*=2)for(int wr=0;wr<2;wr++){
   bool valid=off>=0&&off<24&&off%4==0&&n==4&&(!wr||off==0||off==16||off==20);
   assert(sock_filter_is_valid_access(off,n,wr?BPF_WRITE:BPF_READ,&a)==valid);
  }
 }else if(!strcmp(c,"release-helpers")){
  prog.type=BPF_PROG_TYPE_CGROUP_SOCK;prog.expected_attach_type=34;ops.get_func_proto=release_route;
  assert(release_route(46)->arg1_type==ARG_PTR_TO_CTX&&release_route(46)->ret_type==RET_INTEGER);
  assert(release_route(3)->arg1_type==ARG_CONST_MAP_PTR&&release_route(3)->arg2_type==ARG_PTR_TO_MAP_KEY);
  scalar(1,99);assert(check_call(&env,46,0)<0);
  state.regs[1]=(struct bpf_reg_state){.type=PTR_TO_CTX};assert(!check_call(&env,46,0));assert(state.regs[0].type==SCALAR_VALUE&&!state.acquired_refs);
  struct bpf_map map={.map_type=BPF_MAP_TYPE_HASH,.key_size=8,.value_size=16};
  state.regs[1]=(struct bpf_reg_state){.type=CONST_PTR_TO_MAP,.map_ptr=&map};state.regs[2]=(struct bpf_reg_state){.type=PTR_TO_STACK,.off=-8};assert(check_call(&env,3,0)<0);
  state.regs[9]=(struct bpf_reg_state){.type=PTR_TO_STACK,.off=-8};scalar(3,99);assert(!check_mem_access(&env,0,9,0,BPF_DW,BPF_WRITE,3,false));
  state.regs[1]=(struct bpf_reg_state){.type=CONST_PTR_TO_MAP,.map_ptr=&map};state.regs[2]=(struct bpf_reg_state){.type=PTR_TO_STACK,.off=-8};assert(!check_call(&env,3,0)&&state.regs[0].type==SCALAR_VALUE&&!state.acquired_refs);
 }else if(!strcmp(c,"release-return")){
  prog.type=BPF_PROG_TYPE_CGROUP_SOCK;prog.expected_attach_type=34;
  for(int n=-1;n<4;n++){scalar(0,(uint64_t)(int64_t)n);assert((check_sockopt_return(&env)==0)==(n==0||n==1));}
  prog.expected_attach_type=2;scalar(0,2);assert(!check_sockopt_return(&env));
 }else if(!strcmp(c,"release-admission")){
  struct bpf_prog *ptr=&prog;prog.type=BPF_PROG_TYPE_CGROUP_SOCK;
  for(int h=0;h<40;h++){prog.expected_attach_type=h;assert((release_admission(&ptr)==0)==(h==2||h==34));}
 }else if(!strcmp(c,"permissions")){
  const int hooks[]={8,9,10,11,14,15,19,20};
  for(unsigned h=0;h<8;h++)for(int off=-1;off<=72;off++)for(int size=1;size<=8;size*=2)for(int wr=0;wr<2;wr++){
   bool v6=hooks[h]==9||hooks[h]==11||hooks[h]==15||hooks[h]==20;
   bool array=(v6&&off>=8&&off+size<=24)||(hooks[h]==15&&off>=44&&off+size<=60);
   bool word=(!v6&&off==4)||(off==24)||(hooks[h]==14&&off==40);
   bool want=false;
   if(off>=0&&off%size==0){
    if(array)want=wr?(size==4||size==8):(size==8||(off%4==0&&size<=4));
    if(word)want=wr?size==4:size<=4;
    if(!wr&&size==4&&(off==0||off==28||off==32||off==36))want=true;
    if(!wr&&size==8&&off==64)want=true;
   }
   struct bpf_insn_access_aux a={.expected_attach_type=hooks[h]};
   assert(sock_addr_is_valid_access(off,size,wr?BPF_WRITE:BPF_READ,&a)==want);
  }
 }else if(!strcmp(c,"helpers")){
  assert(sock_addr_func_proto(1)==&bpf_map_lookup_elem_proto);
  for(int i=0;i<135;i++)if(i!=1)assert(!sock_addr_func_proto(i));
 }else if(!strcmp(c,"map-key")){
  /* The selected blocked-port bitmap uses a four-byte stack key and
   * eight-byte map value. Exercise actual helper/stack checks, including
   * rejection before key initialization and bounds after null refinement. */
  struct bpf_map map={.map_type=BPF_MAP_TYPE_ARRAY,.key_size=4,.value_size=8};
  state.regs[1]=(struct bpf_reg_state){.type=CONST_PTR_TO_MAP,.map_ptr=&map};
  state.regs[2]=(struct bpf_reg_state){.type=PTR_TO_STACK,.off=-4};
  assert(check_call(&env,1,0)==-EACCES);
  state.regs[9]=(struct bpf_reg_state){.type=PTR_TO_STACK,.off=-4};scalar(3,80);
  assert(!check_mem_access(&env,0,9,0,BPF_W,BPF_WRITE,3,false));
  state.regs[1]=(struct bpf_reg_state){.type=CONST_PTR_TO_MAP,.map_ptr=&map};
  state.regs[2]=(struct bpf_reg_state){.type=PTR_TO_STACK,.off=-4};
  assert(!check_call(&env,1,0));assert(state.regs[0].type==PTR_TO_MAP_VALUE_OR_NULL);
  assert(!state.regs[0].ref_obj_id&&!state.acquired_refs);
  assert(check_mem_access(&env,0,0,0,BPF_DW,BPF_READ,6,false)<0);
  nonnull();assert(!check_mem_access(&env,0,0,0,BPF_DW,BPF_READ,6,false));
  assert(check_mem_access(&env,0,0,8,BPF_DW,BPF_READ,6,false)<0);
 }else if(!strcmp(c,"borrowed")){
  reserve(8);nonnull();state.regs[6]=state.regs[0];state.regs[9]=(struct bpf_reg_state){.type=PTR_TO_CTX};
  assert(!check_mem_access(&env,0,9,64,BPF_DW,BPF_READ,0,false));
  assert(state.regs[0].type==PTR_TO_SOCKET&&!state.regs[0].ref_obj_id&&state.acquired_refs==1);
  assert(!release_reference_reg(&env,&state.regs[6]));assert(check_call(&env,86,1)==-EINVAL);
 }else if(!strcmp(c,"returns")){
  const int hooks[]={8,9,10,11,14,15,19,20};
  for(unsigned h=0;h<8;h++)for(int n=-1;n<4;n++){
   prog.expected_attach_type=hooks[h];scalar(0,(uint64_t)(int64_t)n);
   bool valid=n==1||(n==0&&hooks[h]!=19&&hooks[h]!=20);
   assert((check_sockopt_return(&env)==0)==valid);
  }
 }else abort();free_verifier_state(&state,false);free_verifier_state(&pushed,false);assert(!allocations);return 0;
}

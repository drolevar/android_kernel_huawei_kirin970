/* SPDX-License-Identifier: GPL-2.0 */
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <stdio.h>
#include <limits.h>
#include <errno.h>
#include BPF_UAPI_HEADER
#define BPF_MAP_PTR_POISON ((void*)1)
typedef uint8_t u8; typedef uint16_t u16; typedef uint32_t u32; typedef int32_t s32;
typedef uint64_t u64; typedef int64_t s64;
#define BPF_REG_SIZE 8
#define BPF_REG_FP BPF_REG_10
#define CALLER_SAVED_REGS 6
static const int caller_saved[]={0,1,2,3,4,5};
#define SRC_OP 0
#define DST_OP_NO_MARK 1
#define WARN_ON(x) (!!(x))
#define MAX_BPF_STACK 512
#define ID_MAP_SIZE (MAX_BPF_REG + MAX_BPF_STACK / BPF_REG_SIZE)
struct idpair {u32 old,cur;};
#define BPF_REG_SIZE 8
#define BPF_MAX_VAR_SIZ (1<<29)
#define BPF_MAX_VAR_OFF (1<<29)
#define BPF_MAXINSNS 4096
#define GFP_KERNEL 0
#define S64_MIN INT64_MIN
#define S64_MAX INT64_MAX
#define U64_MAX UINT64_MAX
#define WARN_ON_ONCE(x) (!!(x))
#define __maybe_unused
#define verbose(...) ((void)0)
#define log_level 0
#define print_verifier_state(...) ((void)0)
struct tnum { u64 value, mask; };
static const struct tnum tnum_unknown={0,UINT64_MAX};
static struct tnum tnum_const(u64 v) { return (struct tnum){v,0}; }
static bool tnum_equals_const(struct tnum t,u64 x) { return !t.mask&&t.value==x; }
static bool tnum_in(struct tnum a, struct tnum b) {return !(b.mask & ~a.mask) && (b.value & ~a.mask)==a.value;}
static bool tnum_is_const(struct tnum t) { return !t.mask; }
struct bpf_map { struct bpf_map *inner_map_meta; int map_type,key_size,value_size; };

/* TYPES */
struct bpf_verifier_ops {const struct bpf_func_proto *(*get_func_proto)(int);};
struct bpf_prog_aux {struct bpf_verifier_ops *ops;int stack_depth;};
struct bpf_prog {struct bpf_prog_aux *aux;bool gpl_compatible;};
struct bpf_insn_aux_data {struct bpf_map *map_ptr;};
struct bpf_verifier_env { struct bpf_verifier_state *cur_state; u32 id_gen; bool allow_ptr_leaks;struct bpf_prog *prog;struct bpf_insn_aux_data *insn_aux_data; };
static int fail_alloc=-1, allocations;
static void *kmalloc_array(size_t n,size_t s,int g) {
 (void)g; if(fail_alloc==0) return NULL; if(fail_alloc>0) fail_alloc--;
 if(n&&s>SIZE_MAX/n)return NULL;
 void*p=malloc(n*s);if(p)allocations++;return p;
}
static void kfree(void*p){if(p){allocations--;free(p);}}
static void *kcalloc(size_t n,size_t z,int g){void*p=kmalloc_array(n,z,g);if(p)memset(p,0,n*z);return p;}
static void __mark_reg_not_init(struct bpf_reg_state*);
static void __mark_reg_known_zero(struct bpf_reg_state*);
static struct bpf_reg_state *cur_regs(struct bpf_verifier_env*e){return e->cur_state->regs;}
static struct tnum tnum_cast(struct tnum t,u8 sz){u64 m=(1ULL<<(sz*8))-1;t.value&=m;t.mask&=m;return t;}
/* Unrelated map/context/packet/stack services fail closed in this harness. */
#define check_map_access(...) (-EACCES)
#define check_ctx_reg(...) (-EACCES)
#define check_ctx_access(...) (-EACCES)
#define check_stack_access(...) (-EACCES)
#define check_stack_write(...) (-EACCES)
#define check_stack_read(...) (-EACCES)
#define check_packet_access(...) (-EACCES)
#define check_stack_boundary(...) (-EACCES)
#define may_access_direct_pkt_data(...) false
/* Alignment is tested separately in kernel compilation; no actual bytes are accessed. */
#define check_ptr_alignment(...) 0
#define bpf_helper_changes_pkt_data(...) false
static int check_reg_arg(struct bpf_verifier_env*e,int r,int k){return k==SRC_OP&&e->cur_state->regs[r].type==NOT_INIT?-EACCES:0;}
static int bpf_size_to_bytes(int s){switch(s){case BPF_B:return 1;case BPF_H:return 2;case BPF_W:return 4;case BPF_DW:return 8;}return -EINVAL;}
static struct bpf_verifier_state pushed;
static int copy_verifier_state(struct bpf_verifier_state*,const struct bpf_verifier_state*);
static struct bpf_verifier_state *push_stack(struct bpf_verifier_env*e,int i,int j,bool spec){if(copy_verifier_state(&pushed,e->cur_state))return NULL;pushed.speculative=spec;return &pushed;}
/* Scalar/packet branch propagation is outside this fixture. Abort if exercised. */
#define reg_set_min_max(...) abort()
#define reg_set_min_max_inv(...) abort()
#define reg_combine_min_max(...) abort()
#define find_good_pkt_pointers(...) abort()
/* CORE */
static const struct bpf_func_proto reserve_proto={.ret_type=RET_PTR_TO_ALLOC_MEM_OR_NULL,.arg2_type=ARG_CONST_ALLOC_SIZE_OR_ZERO};
static const struct bpf_func_proto release_proto={.ret_type=RET_VOID,.arg1_type=ARG_PTR_TO_ALLOC_MEM,.releases_reference=true};
static const struct bpf_func_proto tail_proto={.ret_type=RET_VOID};
static const struct bpf_func_proto *test_proto(int id){if(id==BPF_FUNC_map_lookup_elem)return &reserve_proto;if(id==BPF_FUNC_map_delete_elem)return &release_proto;if(id==BPF_FUNC_tail_call)return &tail_proto;return NULL;}
static struct bpf_verifier_ops ops={test_proto};
static struct bpf_prog_aux aux={&ops,0};
static struct bpf_prog prog={&aux,true};
static struct bpf_insn_aux_data insn_aux[20];
static struct bpf_verifier_state state;
static struct bpf_verifier_env env={.cur_state=&state,.prog=&prog,.insn_aux_data=insn_aux};
static struct bpf_reg_state *reserve(u32 bytes) {
 struct bpf_reg_state*r=&state.regs[0];
 assert(set_alloc_mem_return(&env,r,bytes,17)==0);return r;
}
static void nonnull(void) {mark_map_regs(&state,0,false);}
static void spill(int slot,int reg) {
 assert(realloc_verifier_state(&state,(slot+1)*8,true)==0);
 state.stack[slot].spilled_ptr=state.regs[reg];memset(state.stack[slot].slot_type,STACK_SPILL,8);
}
int main(int argc,char**argv){assert(argc==2);const char*c=argv[1];struct bpf_reg_state*r;struct bpf_verifier_state other={0};
 if(!strcmp(c,"leak")){reserve(32);assert(check_reference_leak(&env)==-EINVAL);state.regs[0].type=SCALAR_VALUE;assert(check_reference_leak(&env)==-EINVAL);}
 else if(!strcmp(c,"release")){r=reserve(32);nonnull();state.regs[6]=*r;assert(release_reference_reg(&env,r)==0);assert(state.regs[6].type==NOT_INIT);assert(check_reference_leak(&env)==0);}
 else if(!strcmp(c,"spill")){r=reserve(32);nonnull();spill(0,0);assert(release_reference_reg(&env,r)==0);assert(state.stack[0].spilled_ptr.type==NOT_INIT);}
 else if(!strcmp(c,"borrowed")){r=&state.regs[0];r->type=PTR_TO_MEM;r->mem_size=32;assert(release_reference_reg(&env,r)==-EINVAL);}
 else if(!strcmp(c,"double")){r=reserve(32);nonnull();u32 id=r->ref_obj_id;assert(release_reference_reg(&env,r)==0);assert(release_reference(&env,id)==-EINVAL);}
 else if(!strcmp(c,"null")){r=reserve(32);state.regs[6]=*r;spill(0,0);mark_map_regs(&state,0,true);assert(!state.acquired_refs);assert(!state.regs[6].ref_obj_id);assert(state.stack[0].spilled_ptr.type==SCALAR_VALUE);}
 else if(!strcmp(c,"cast_null")){r=reserve(32);nonnull();state.regs[6]=*r;state.regs[6].type=PTR_TO_MEM_OR_NULL;state.regs[6].id=++env.id_gen;mark_map_regs(&state,6,true);assert(state.acquired_refs==1);assert(release_reference_reg(&env,r)==0);}
 else if(!strcmp(c,"copy")){r=reserve(12);spill(0,0);assert(copy_verifier_state(&other,&state)==0);assert(other.refs!=state.refs&&other.stack!=state.stack);mark_map_regs(&state,0,true);assert(other.acquired_refs==1);env.cur_state=&other;mark_map_regs(&other,0,false);assert(release_reference_reg(&env,&other.regs[0])==0);env.cur_state=&state;free_verifier_state(&other,false);}
 else if(!strcmp(c,"copy_fail")){reserve(8);spill(0,0);for(int n=0;n<2;n++){fail_alloc=n;assert(copy_verifier_state(&other,&state)==-ENOMEM);free_verifier_state(&other,false);memset(&other,0,sizeof(other));}fail_alloc=-1;assert(state.acquired_refs==1);}
 else if(!strcmp(c,"acquire_fail")){fail_alloc=0;assert(acquire_reference_state(&env,0)==-ENOMEM);assert(!state.acquired_refs&&!env.id_gen);}
 else if(!strcmp(c,"bounds")){r=reserve(32);nonnull();assert(!check_reference_mem_access(&env,r,28,4,false));assert(check_reference_mem_access(&env,r,29,4,false)==-EACCES);assert(check_reference_mem_access(&env,r,-1,4,false)==-EACCES);r->smin_value=0;r->umax_value=4;assert(!check_reference_mem_access(&env,r,24,4,false));assert(check_reference_mem_access(&env,r,25,4,false)==-EACCES);r->smin_value=-1;assert(check_reference_mem_access(&env,r,0,4,false)==-EACCES);}
 else if(!strcmp(c,"release_offsets")){r=reserve(8);nonnull();r->off=1;assert(release_reference_reg(&env,r)==-EINVAL);r->off=0;r->var_off=tnum_const(1);assert(release_reference_reg(&env,r)==-EINVAL);r->var_off=tnum_const(0);assert(!release_reference_reg(&env,r));}
 else if(!strcmp(c,"sizes")){struct bpf_call_arg_meta m={0};r=&state.regs[1];r->type=SCALAR_VALUE;r->var_off=tnum_const(32);assert(!check_alloc_mem_size(r,&m)&&m.mem_size==32);m.alloc_size_set=false;r->var_off.mask=1;assert(check_alloc_mem_size(r,&m)==-EINVAL);r->var_off=tnum_const(UINT64_MAX);assert(check_alloc_mem_size(r,&m)==-EINVAL);r->var_off=tnum_const(0);assert(!check_alloc_mem_size(r,&m));}
 else if(!strcmp(c,"prune")){reserve(32);assert(!refsafe(&other,&state));assert(!copy_verifier_state(&other,&state));assert(refsafe(&other,&state));other.refs[0].id++;assert(!refsafe(&other,&state));free_verifier_state(&other,false);}
 else if(!strcmp(c,"stale")){r=reserve(32);nonnull();struct bpf_reg_state stale=*r;assert(!release_reference_reg(&env,r));assert(check_reference_mem_access(&env,&stale,0,4,false)==-EACCES);}
 else if(!strcmp(c,"overflow")){env.id_gen=INT_MAX;assert(acquire_reference_state(&env,0)==-E2BIG);assert(!state.acquired_refs);}
 else if(!strcmp(c,"multi")){r=reserve(8);nonnull();state.regs[6]=*r;reserve(12);nonnull();state.regs[7]=state.regs[0];assert(state.acquired_refs==2);assert(!release_reference_reg(&env,&state.regs[6]));assert(state.acquired_refs==1&&state.regs[7].type==PTR_TO_MEM);assert(!release_reference_reg(&env,&state.regs[7]));}
 else if(!strcmp(c,"nullable_access")){r=reserve(8);assert(check_reference_mem_access(&env,r,0,4,false)==-EACCES);assert(release_reference_reg(&env,r)==-EINVAL);}
 else if(!strcmp(c,"arithmetic")){r=reserve(32);nonnull();struct bpf_reg_state off={.type=SCALAR_VALUE,.var_off={4,0}};struct bpf_insn i={.code=BPF_ADD,.dst_reg=6};assert(!adjust_reference_min_max_vals(&env,&i,r,&off));assert(state.regs[6].off==4&&state.regs[6].ref_obj_id==r->ref_obj_id);assert(release_reference_reg(&env,&state.regs[6])==-EINVAL);i.code=BPF_SUB;assert(!adjust_reference_min_max_vals(&env,&i,&state.regs[6],&off));assert(!release_reference_reg(&env,&state.regs[6]));}
 else if(!strcmp(c,"prototype")){struct bpf_func_proto fn={.ret_type=RET_PTR_TO_ALLOC_MEM_OR_NULL,.arg2_type=ARG_CONST_ALLOC_SIZE_OR_ZERO};assert(!check_reference_proto(&fn));fn.arg3_type=ARG_CONST_ALLOC_SIZE_OR_ZERO;assert(check_reference_proto(&fn)==-EINVAL);fn=(struct bpf_func_proto){.ret_type=RET_VOID,.arg1_type=ARG_PTR_TO_ALLOC_MEM,.releases_reference=true};assert(!check_reference_proto(&fn));fn.arg1_type=ARG_PTR_TO_CTX;assert(check_reference_proto(&fn)==-EINVAL);}
 else if(!strcmp(c,"prune_alias")){r=reserve(8);nonnull();state.regs[6]=*r;assert(!copy_verifier_state(&other,&state));assert(states_equal(&env,&other,&state));other.acquired_refs=0;assert(!states_equal(&env,&other,&state));other.acquired_refs=1;state.regs[6].ref_obj_id=0;assert(!states_equal(&env,&other,&state));free_verifier_state(&other,false);}
 else if(!strcmp(c,"prune_bounds")){r=reserve(8);nonnull();r->live=REG_LIVE_READ;assert(!copy_verifier_state(&other,&state));r->mem_size=4;assert(!states_equal(&env,&other,&state));r->mem_size=8;r->off=4;assert(!states_equal(&env,&other,&state));free_verifier_state(&other,false);}
 else if(!strcmp(c,"zero_access")){r=reserve(0);nonnull();assert(check_reference_mem_access(&env,r,0,1,false)==-EACCES);assert(!check_reference_mem_access(&env,r,0,0,true));assert(check_reference_mem_access(&env,r,0,0,false)==-EACCES);}
 else if(!strcmp(c,"null_spill_release")){r=reserve(12);nonnull();state.regs[6]=*r;state.regs[6].id=++env.id_gen;state.regs[6].type=PTR_TO_MEM_OR_NULL;spill(0,6);assert(!release_reference_reg(&env,r));assert(state.stack[0].spilled_ptr.type==NOT_INIT);}
 else if(!strcmp(c,"calls")){state.regs[2].type=SCALAR_VALUE;state.regs[2].var_off=tnum_const(32);assert(!check_call(&env,BPF_FUNC_map_lookup_elem,0));assert(state.regs[0].type==PTR_TO_MEM_OR_NULL&&state.regs[0].mem_size==32);nonnull();state.regs[1]=state.regs[0];state.regs[6]=state.regs[0];spill(0,0);assert(!check_call(&env,BPF_FUNC_map_delete_elem,1));assert(!state.acquired_refs&&state.regs[6].type==NOT_INIT&&state.stack[0].spilled_ptr.type==NOT_INIT);}
 else if(!strcmp(c,"bad_call")){state.regs[2].type=SCALAR_VALUE;state.regs[2].var_off=tnum_unknown;assert(check_call(&env,BPF_FUNC_map_lookup_elem,0)==-EINVAL);}
 else if(!strcmp(c,"access_handler")){r=reserve(12);assert(check_mem_access(&env,0,0,0,BPF_W,BPF_WRITE,-1,false)==-EACCES);nonnull();assert(!check_mem_access(&env,0,0,8,BPF_W,BPF_WRITE,-1,false));assert(check_mem_access(&env,0,0,9,BPF_W,BPF_WRITE,-1,false)==-EACCES);assert(!check_mem_access(&env,0,0,0,BPF_W,BPF_READ,6,false));assert(state.regs[6].type==SCALAR_VALUE&&state.regs[6].umax_value==UINT32_MAX);}
 else if(!strcmp(c,"helper_bounds")){r=reserve(8);nonnull();assert(!check_helper_mem_access(&env,0,8,false,NULL));assert(check_helper_mem_access(&env,0,9,false,NULL)==-EACCES);struct bpf_call_arg_meta m={0};assert(!check_func_arg(&env,0,ARG_PTR_TO_ALLOC_MEM,&m));assert(m.ref_obj_id==r->ref_obj_id);assert(check_func_arg(&env,0,ARG_PTR_TO_ALLOC_MEM,&m)==-EINVAL);}
 else if(!strcmp(c,"pointer_write")){r=reserve(8);nonnull();state.regs[6]=*r;assert(check_mem_access(&env,0,0,0,BPF_DW,BPF_WRITE,6,false)==-EACCES);}
 else if(!strcmp(c,"release_call_offset")){r=reserve(8);nonnull();state.regs[1]=*r;state.regs[1].off=1;assert(check_call(&env,BPF_FUNC_map_delete_elem,0)==-EINVAL);assert(state.acquired_refs==1);}
 else if(!strcmp(c,"tailcall_leak")){reserve(8);assert(check_call(&env,BPF_FUNC_tail_call,0)==-EINVAL);}
 else if(!strcmp(c,"unknown_helper")){assert(check_call(&env,BPF_FUNC_get_prandom_u32,0)==-EINVAL);}
 else if(!strcmp(c,"default_proto")){struct bpf_func_proto fn={0};assert(check_reference_proto(&fn)==0);assert(fn.ret_type==RET_INTEGER);}
 else if(!strcmp(c,"branch_eq")||!strcmp(c,"branch_ne")){r=reserve(12);state.regs[6]=*r;spill(0,0);struct bpf_insn i={.code=BPF_JMP|(!strcmp(c,"branch_eq")?BPF_JEQ:BPF_JNE)|BPF_K,.dst_reg=0,.off=2};int pc=0;assert(!check_cond_jmp_op(&env,&i,&pc));struct bpf_verifier_state *live=state.acquired_refs?&state:&pushed,*null=state.acquired_refs?&pushed:&state;assert(live->acquired_refs==1&&live->regs[0].type==PTR_TO_MEM);assert(!null->acquired_refs&&null->regs[6].type==SCALAR_VALUE&&null->stack[0].spilled_ptr.type==SCALAR_VALUE);env.cur_state=live;assert(!release_reference_reg(&env,&live->regs[6]));env.cur_state=&state;free_verifier_state(&pushed,false);}
 else abort();
 free_verifier_state(&state,false);assert(!allocations);puts("PASS");return 0;}

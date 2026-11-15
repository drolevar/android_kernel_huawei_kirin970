/* SPDX-License-Identifier: GPL-2.0 */
#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <errno.h>
#include BPF_UAPI_HEADER
#include "enums.h"
typedef uint32_t u32;typedef uint64_t u64;
struct bpf_map {int map_type;u32 key_size,value_size;};
struct tnum {u64 value,mask;};
struct bpf_reg_state {enum bpf_reg_type type;struct bpf_map *map_ptr;struct tnum var_off;int off;int64_t smin_value;u64 umin_value,umax_value;int initialized_bytes;};
struct bpf_verifier_env {struct bpf_reg_state regs[11];};
struct bpf_call_arg_meta {struct bpf_map *map_ptr;bool raw_mode,pkt_access;};
#define cur_regs(e) ((e)->regs)
#define verbose(...) ((void)0)
#define SRC_OP 0
#define BPF_READ 0
#define BPF_MAX_VAR_SIZ 4096
#define func_id_name(i) "helper"
static bool tnum_is_const(struct tnum t) {return !t.mask;}
static bool tnum_equals_const(struct tnum t,u64 v) {return !t.mask&&t.value==v;}
static void tnum_strn(char *p,size_t n,struct tnum t) {(void)p;(void)n;(void)t;}
static int check_reg_arg(struct bpf_verifier_env *e,u32 r,int op) {return r<11&&e->regs[r].type!=NOT_INIT?0:-EACCES;}
static bool is_pointer_value(struct bpf_verifier_env *e,u32 r) {return e->regs[r].type!=SCALAR_VALUE;}
static bool may_access_direct_pkt_data(struct bpf_verifier_env *e,struct bpf_call_arg_meta *m,int mode) {return false;}
static int check_stack_boundary(struct bpf_verifier_env *e,u32 r,int n,bool zero,void *meta) {return e->regs[r].off<=-n && e->regs[r].off>=-512 && e->regs[r].initialized_bytes>=n?0:-EACCES;}
static int check_packet_access(struct bpf_verifier_env *e,u32 r,int off,int n) {return -EACCES;}
static int check_helper_mem_access(struct bpf_verifier_env *e,u32 r,int n,bool zero,struct bpf_call_arg_meta *m) {return check_stack_boundary(e,r,n,zero,m);}
#include "subject.h"
int main(void) {
 struct bpf_map m={24,4,128};struct bpf_call_arg_meta meta={.map_ptr=&m};struct bpf_verifier_env e={0};
 /* Optional NULL is scalar zero; arbitrary or uninitialized scalars are rejected. */
 assert(check_func_arg(&e,3,ARG_PTR_TO_MAP_VALUE_OR_NULL,&meta)==-EACCES);
 e.regs[3].type=SCALAR_VALUE;assert(!check_func_arg(&e,3,ARG_PTR_TO_MAP_VALUE_OR_NULL,&meta));
 e.regs[3].var_off.value=1;assert(check_func_arg(&e,3,ARG_PTR_TO_MAP_VALUE_OR_NULL,&meta)==-EACCES);
 e.regs[3].var_off=(struct tnum){0,1};assert(check_func_arg(&e,3,ARG_PTR_TO_MAP_VALUE_OR_NULL,&meta)==-EACCES);
 e.regs[3]=(struct bpf_reg_state){.type=PTR_TO_STACK,.off=-128,.initialized_bytes=128};assert(!check_func_arg(&e,3,ARG_PTR_TO_MAP_VALUE_OR_NULL,&meta));
 e.regs[3].initialized_bytes=127;assert(check_func_arg(&e,3,ARG_PTR_TO_MAP_VALUE_OR_NULL,&meta)==-EACCES);
 e.regs[3].initialized_bytes=128;e.regs[3].off=-64;assert(check_func_arg(&e,3,ARG_PTR_TO_MAP_VALUE_OR_NULL,&meta)==-EACCES);
 e.regs[3]=(struct bpf_reg_state){.type=SCALAR_VALUE};meta.map_ptr=NULL;assert(check_func_arg(&e,3,ARG_PTR_TO_MAP_VALUE_OR_NULL,&meta)==-EACCES);meta.map_ptr=&m;
 e.regs[2].type=PTR_TO_CTX;assert(!check_func_arg(&e,2,ARG_PTR_TO_CTX,&meta));
 e.regs[2].off=4;assert(check_func_arg(&e,2,ARG_PTR_TO_CTX,&meta)==-EACCES);e.regs[2].off=0;e.regs[2].var_off.mask=1;assert(check_func_arg(&e,2,ARG_PTR_TO_CTX,&meta)==-EACCES);
 e.regs[2]=(struct bpf_reg_state){.type=PTR_TO_MAP_VALUE};assert(check_func_arg(&e,2,ARG_PTR_TO_CTX,&meta)==-EACCES);
 e.regs[2].type=SCALAR_VALUE;assert(check_func_arg(&e,2,ARG_PTR_TO_CTX,&meta)==-EACCES);
 for(int f=0;f<__BPF_FUNC_MAX_ID;f++)assert(check_map_func_compatibility(&m,f)==(f==BPF_FUNC_sk_storage_get?0:-EINVAL));
 for(int type=0;type<=25;type++){m.map_type=type;assert(check_map_func_compatibility(&m,BPF_FUNC_sk_storage_get)==(type==24?0:-EINVAL));}
 puts("PASS: optional initializer/context provenance/two-way helper-map compatibility");return 0;
}

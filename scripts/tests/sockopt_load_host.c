/* SPDX-License-Identifier: GPL-2.0 */
#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include BPF_UAPI_HEADER
typedef uint32_t u32;
struct bpf_prog_aux {int refcnt;unsigned long load_time;char name[16];};
struct bpf_prog {enum bpf_prog_type type;enum bpf_attach_type expected_attach_type;struct bpf_prog_aux *aux;unsigned len;struct bpf_insn insns[2];void *orig_prog;bool jited,gpl_compatible;};
struct cgroup {int unused;};
static struct bpf_prog program;static struct cgroup group;
static int references,attaches,detaches,fd_gets;
#define CAP_NET_ADMIN 0
#define capable(x) true
#define CHECK_ATTR(x) 0
#define BPF_F_ATTACH_MASK (BPF_F_ALLOW_OVERRIDE|BPF_F_ALLOW_MULTI)
#define ERR_PTR(e) ((void*)(intptr_t)(e))
#define IS_ERR(p) ((uintptr_t)(p)>=(uintptr_t)-4095)
#define PTR_ERR(p) ((int)(intptr_t)(p))
static int sockmap_get_from_fd(const union bpf_attr*a,bool b){return -EINVAL;}
static struct bpf_prog *bpf_prog_get_type(u32 fd,enum bpf_prog_type t){if(t!=program.type)return ERR_PTR(-EINVAL);references++;return &program;}
static void bpf_prog_put(struct bpf_prog*p){references--;}
static struct cgroup *cgroup_get_from_fd(u32 fd){fd_gets++;return &group;}
static void cgroup_put(struct cgroup*c){fd_gets--;}
static int cgroup_bpf_attach(struct cgroup*c,struct bpf_prog*p,enum bpf_attach_type t,u32 f){attaches++;references--;return 0;}
static int cgroup_bpf_detach(struct cgroup*c,struct bpf_prog*p,enum bpf_attach_type t,u32 f){detaches++;return 0;}
/* These services deliberately model allocation, verification and fd installation.
 * Only load/admission/dispatch control flow below is production code. */
#define __user
#define CAP_SYS_ADMIN 1
#define GFP_USER 0
#define LINUX_VERSION_CODE 0x040e00
#define u64_to_user_ptr(n) ((void *)(uintptr_t)(n))
#define atomic_set(p,n) (*(p)=(n))
static struct bpf_prog_aux aux;
static int allocated,verified,queries,verify_error,copy_error;
static long strncpy_from_user(char*d,const char*s,size_t n){strncpy(d,s,n);return strlen(s);}
static bool license_is_gpl_compatible(const char*s){return !strcmp(s,"GPL");}
static size_t bpf_prog_size(unsigned n){return sizeof(program);}
static struct bpf_prog *bpf_prog_alloc(size_t n,int flags){allocated++;program=(struct bpf_prog){.aux=&aux};return &program;}
static int security_bpf_prog_alloc(struct bpf_prog_aux*a){return 0;}
static int bpf_prog_charge_memlock(struct bpf_prog*p){return 0;}
static unsigned copy_from_user(void*d,const void*s,size_t n){if(copy_error)return 1;memcpy(d,s,n);return 0;}
static size_t bpf_prog_insn_size(struct bpf_prog*p){return p->len*sizeof(struct bpf_insn);}
static int find_prog_type(enum bpf_prog_type t,struct bpf_prog*p){p->type=t;return 0;}
static unsigned long ktime_get_boot_ns(void){return 1;}
static int bpf_obj_name_cpy(char*d,const char*s){memcpy(d,s,16);return 0;}
static union bpf_attr user_load_attr;
static int bpf_check(struct bpf_prog**p,union bpf_attr*a,union bpf_attr*u){assert(u==&user_load_attr && u!=a);verified++;assert((*p)->expected_attach_type==a->expected_attach_type);assert((*p)->type==a->prog_type);return verify_error;}
static struct bpf_prog *bpf_prog_select_runtime(struct bpf_prog*p,int*err){*err=0;return p;}
static int bpf_prog_alloc_id(struct bpf_prog*p){return 0;}
static void bpf_prog_kallsyms_add(struct bpf_prog*p){}
static void trace_bpf_prog_load(struct bpf_prog*p,int e){}
static int bpf_prog_new_fd(struct bpf_prog*p){allocated--;return 42;}
static void free_used_maps(struct bpf_prog_aux*a){}
static void bpf_prog_uncharge_memlock(struct bpf_prog*p){}
static void security_bpf_prog_free(struct bpf_prog_aux*a){}
static void bpf_prog_free(struct bpf_prog*p){allocated--;}
static int cgroup_bpf_query(struct cgroup*c,const union bpf_attr*a,union bpf_attr*u){queries++;u->query.prog_cnt=1;return 0;}
/* SUBJECT */
int main(void){
 assert(offsetof(union bpf_attr,prog_ifindex)==64&&offsetof(union bpf_attr,expected_attach_type)==68);
 assert(BPF_PROG_TYPE_CGROUP_SOCKOPT==25&&BPF_CGROUP_GETSOCKOPT==21&&BPF_CGROUP_SETSOCKOPT==22);
 assert(offsetof(struct bpf_sockopt,sk)==0&&offsetof(struct bpf_sockopt,optval)==8&&offsetof(struct bpf_sockopt,optval_end)==16&&offsetof(struct bpf_sockopt,level)==24&&offsetof(struct bpf_sockopt,retval)==36&&sizeof(struct bpf_sockopt)==40);
 union bpf_attr a={.prog_type=BPF_PROG_TYPE_CGROUP_SOCK};bpf_prog_load_fixup_attach_type(&a);assert(a.expected_attach_type==2);
 assert(!bpf_prog_load_check_attach(a.prog_type,a.expected_attach_type,0));
 assert(bpf_prog_load_check_attach(25,0,0)==-EINVAL);
 assert(!bpf_prog_load_check_attach(25,21,0)&&!bpf_prog_load_check_attach(25,22,0));
 assert(bpf_prog_load_check_attach(25,21,1)==-EOPNOTSUPP);
 assert(bpf_prog_load_check_attach(1,21,0)==-EINVAL);
 assert(!bpf_prog_load_check_attach(8,0,0)&&!bpf_prog_load_check_attach(8,1,0));
 for(int type=21;type<=22;type++){
  program=(struct bpf_prog){.type=25,.expected_attach_type=type};a=(union bpf_attr){.attach_type=type,.attach_bpf_fd=3,.target_fd=4};
  assert(!bpf_prog_attach(&a)&&!references&&!fd_gets);
  assert(!bpf_prog_detach(&a)&&!references&&!fd_gets);
  a.attach_type=43-type;int count=attaches;assert(bpf_prog_attach(&a)==-EINVAL&&attaches==count&&!references&&!fd_gets);
  count=detaches;assert(bpf_prog_detach(&a)==-EINVAL&&detaches==count&&!references&&!fd_gets);
 }
 program=(struct bpf_prog){.type=9,.expected_attach_type=2};a=(union bpf_attr){.attach_type=2};assert(!bpf_prog_attach(&a));
 union bpf_attr reply={0};
 for(int hook=21;hook<=22;hook++){
  a=(union bpf_attr){.query={.attach_type=hook,.target_fd=4}};
  assert(!bpf_prog_query(&a,&reply)&&reply.query.prog_cnt==1&&!fd_gets);
 }
 a.query.attach_type=23;assert(bpf_prog_query(&a,&reply)==-EINVAL&&queries==2&&!fd_gets);
 a.query.attach_type=21;a.query.query_flags=2;assert(bpf_prog_query(&a,&reply)==-EINVAL&&queries==2);
 struct bpf_insn instructions[2]={{0}};
 for(int hook=21;hook<=22;hook++){
  a=(union bpf_attr){.prog_type=25,.expected_attach_type=hook,.insn_cnt=2,.insns=(uintptr_t)instructions,.license=(uintptr_t)"GPL"};
  assert(bpf_prog_load(&a,&user_load_attr)==42&&program.expected_attach_type==hook&&!allocated);
 }
 a.expected_attach_type=0;int count=verified;assert(bpf_prog_load(&a,&user_load_attr)==-EINVAL&&verified==count&&!allocated);
 a.expected_attach_type=21;a.prog_ifindex=1;assert(bpf_prog_load(&a,&user_load_attr)==-EOPNOTSUPP&&verified==count&&!allocated);
 a.prog_ifindex=0;verify_error=-EACCES;assert(bpf_prog_load(&a,&user_load_attr)==-EACCES&&!allocated);verify_error=0;
 copy_error=1;assert(bpf_prog_load(&a,&user_load_attr)==-EFAULT&&!allocated);copy_error=0;
 a.prog_type=9;a.expected_attach_type=0;assert(bpf_prog_load(&a,&user_load_attr)==42&&a.expected_attach_type==2&&!allocated);
 assert(!references&&!fd_gets);puts("PASS load admission, ABI and real attach dispatch");return 0;
}

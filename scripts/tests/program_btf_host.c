/* SPDX-License-Identifier: GPL-2.0 */
/* Extracted production functions; user memory, allocations, fds, RCU/workqueues
 * and verifier/runtime services are deterministic models, not kernel behavior. */
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <limits.h>
#include <errno.h>
#include BPF_UAPI_HEADER
#include BTF_UAPI_HEADER
#define __user
#define unlikely(x) (x)
#define GFP_KERNEL 0
#define GFP_USER 0
#define __GFP_NOWARN 0
#define __GFP_ZERO 0
#define PAGE_KERNEL 0
#define CONFIG_BPF_SYSCALL 1
#define PAGE_SIZE 4096
#define VERIFY_READ 0
#define CAP_SYS_ADMIN 1
#define S16_MAX INT16_MAX
#define S16_MIN INT16_MIN
#define WARN_ON_ONCE(x) assert(!(x))
#define BUG_ON(x) assert(!(x))
#define min_t(t,a,b) ((t)(a)<(t)(b)?(t)(a):(t)(b))
#define round_up(n,d) (((n)+(d)-1)&~((d)-1))
#define u64_to_user_ptr(n) ((void *)(uintptr_t)(n))
#define ERR_PTR(e) ((void *)(intptr_t)(e))
#define IS_ERR(p) ((uintptr_t)(p)>=(uintptr_t)-4095)
#define PTR_ERR(p) ((int)(intptr_t)(p))
#define container_of(p,t,m) ((t *)((char *)(p)-offsetof(t,m)))
typedef uint32_t u32; typedef uint64_t u64; typedef uint8_t u8;
typedef int16_t s16; typedef int32_t s32; typedef int gfp_t;
static const void *bad_read, *bad_write;
static bool overlaps(const void *p,size_t n,const void *bad) {
 return !p || (bad && (uintptr_t)bad >= (uintptr_t)p && (uintptr_t)bad-(uintptr_t)p < n);
}
#define access_ok(mode,p,n) ((void)(mode),!overlaps(p,n,bad_read))
static unsigned copy_from_user(void *d,const void *s,size_t n) {if(n&&overlaps(s,n,bad_read))return 1;memcpy(d,s,n);return 0;}
static unsigned copy_to_user(void *d,const void *s,size_t n) {if(n&&overlaps(d,n,bad_write))return 1;memcpy(d,s,n);return 0;}
#define get_user(v,p) copy_from_user(&(v),(p),sizeof(*(p)))
#define put_user(v,p) ({__typeof__(*(p)) value=(v);copy_to_user((p),&value,sizeof(value));})
static int alloc_fail, alloc_calls, live;
static void *allocate(size_t n) {if(++alloc_calls==alloc_fail)return NULL;void*p=calloc(1,n);assert(p);live++;return p;}
static void release(void*p){if(p){assert(live>0);live--;free(p);}}
#define kzalloc(n,f) allocate(n)
#define kcalloc(n,s,f) allocate((size_t)(n)*(s))
#define kvcalloc(n,s,f) kcalloc(n,s,f)
#define kvmalloc_array(n,s,f) kcalloc(n,s,f)
#define kfree(p) release(p)
#define kvfree(p) release(p)
#define vfree(p) release(p)
#define __vmalloc(n,f,p) ((void)(f),(void)(p),allocate(n))
struct rcu_head {void(*fn)(struct rcu_head*);};
struct work_struct {void(*fn)(struct work_struct*);};
static struct rcu_head *rcu_queue[16];static int rcu_count;
static struct work_struct *work_queue[16];static int work_count;
static void call_rcu(struct rcu_head *r,void(*fn)(struct rcu_head*)){r->fn=fn;rcu_queue[rcu_count++]=r;assert(rcu_count<16);}
#define INIT_WORK(w,f) ((w)->fn=(f))
static void schedule_work(struct work_struct*w){work_queue[work_count++]=w;assert(work_count<16);}
static void drain_rcu(void){while(rcu_count){struct rcu_head*r=rcu_queue[0];memmove(rcu_queue,rcu_queue+1,--rcu_count*sizeof(*rcu_queue));r->fn(r);}}
static void drain_work(void){while(work_count){struct work_struct*w=work_queue[0];memmove(work_queue,work_queue+1,--work_count*sizeof(*work_queue));w->fn(w);}}
static void refcount_inc(int*p){assert(*p>0);++*p;}
static bool refcount_dec_and_test(int*p){assert(*p>0);return !--*p;}
#define atomic_set(p,n) (*(p)=(n))
#define atomic_dec_and_test(p) refcount_dec_and_test(p)
struct btf {struct btf_header hdr;char*strings;struct btf_type **types;u32 nr_types,id;int refcnt;struct rcu_head rcu;};
struct file {const void*f_op;void*private_data;};struct fd {struct file*file;};
static const int btf_fops, other_fops;
static struct file btf_file,other_file={.f_op=&other_fops};
static int fd_refs, btf_freed, btf_id_removed;
static struct fd fdget(int fd){struct file*f=fd==3?&btf_file:fd==4?&other_file:NULL;if(f)fd_refs++;return(struct fd){f};}
static void fdput(struct fd f){assert(f.file);fd_refs--;}
static void btf_free_id(struct btf*b){assert(!b->refcnt);btf_id_removed++;}
static void btf_free_rcu(struct rcu_head*r){struct btf*b=container_of(r,struct btf,rcu);assert(!b->refcnt);btf_freed++;}
static u32 btf_id(const struct btf*b){return b->id;}
struct user_struct {int uid;};struct bpf_map {u32 id;};
struct bpf_prog;
struct bpf_prog_aux {int refcnt;u32 id,used_map_cnt;struct bpf_map**used_maps;struct user_struct*user;u64 load_time;char name[16];struct bpf_prog*prog;struct btf*btf;struct bpf_func_info*func_info;u32 func_info_cnt;struct bpf_line_info*linfo;u32 nr_linfo;union {struct rcu_head rcu;struct work_struct work;};};
struct bpf_prog {struct bpf_prog_aux*aux;u32 len,pages;enum bpf_prog_type type;enum bpf_attach_type expected_attach_type;unsigned jited,jited_len,gpl_compatible;void*orig_prog;void*bpf_func;unsigned char tag[8];union{struct bpf_insn insns[0];struct bpf_insn insnsi[0];};};
struct bpf_verifier_env {struct bpf_prog *prog;};
#define verbose(...) ((void)0)
static bool admin=true;
#define capable(x) admin
#define current_user_ns() NULL
#define from_kuid_munged(ns,uid) (uid)
static size_t bpf_prog_size(unsigned n){return sizeof(struct bpf_prog)+n*sizeof(struct bpf_insn);}
static size_t bpf_prog_insn_size(struct bpf_prog*p){return p->len*sizeof(struct bpf_insn);}
static int charge_fail,charges;
static int __bpf_prog_charge(struct user_struct*u,u32 n){if(charge_fail)return -EPERM;charges+=n;return 0;}
static void __bpf_prog_uncharge(struct user_struct*u,u32 n){charges-=n;}
#define INIT_LIST_HEAD_RCU(p) ((void)0)
static void __bpf_prog_free(struct bpf_prog*p);
static void bpf_jit_free(struct bpf_prog*p){__bpf_prog_free(p);}
static int map_frees,sec_frees,prog_ids_removed;
static void free_used_maps(struct bpf_prog_aux*a){map_frees++;}
static void bpf_prog_uncharge_memlock(struct bpf_prog*p){charges-=p->pages;}
static void security_bpf_prog_free(struct bpf_prog_aux*a){sec_frees++;}
static void bpf_prog_free_id(struct bpf_prog*p,bool lock){prog_ids_removed++;}
static void bpf_prog_kallsyms_del(struct bpf_prog*p){}
#define trace_bpf_prog_put_rcu(p) ((void)0)
/* FIXTURES */
/* SUBJECT */
static struct btf test_btf;static struct btf_type*type_ptrs[1024];
static struct user_struct user={.uid=1000};
static struct bpf_prog *make_prog(unsigned n){struct bpf_prog*p=bpf_prog_alloc(bpf_prog_size(n),0);assert(p);p->len=n;p->aux->user=&user;p->aux->refcnt=1;charges+=p->pages;for(unsigned i=0;i<n;i++)p->insnsi[i].code=0xb7;return p;}
static union bpf_attr metadata(struct bpf_func_info*f,struct bpf_line_info*l,unsigned n){return(union bpf_attr){.prog_btf_fd=3,.func_info_rec_size=8,.func_info=(uintptr_t)f,.func_info_cnt=1,.line_info_rec_size=16,.line_info=(uintptr_t)l,.line_info_cnt=n};}
static int validate(struct bpf_prog*p,union bpf_attr*a,union bpf_attr*u){struct bpf_verifier_env e={p};return check_btf_info(&e,a,u);}
static void destroy(struct bpf_prog*p){bpf_prog_uncharge_memlock(p);bpf_prog_free(p);drain_work();drain_rcu();}
static void reset_btf(void){for(unsigned i=0;i<sizeof(fixture_types)/sizeof(*fixture_types);i++)type_ptrs[i]=&fixture_types[i];test_btf=(struct btf){.hdr.str_len=sizeof(fixture_strings),.strings=fixture_strings,.types=type_ptrs,.nr_types=sizeof(fixture_types)/sizeof(*fixture_types)-1,.id=37,.refcnt=1};btf_file=(struct file){&btf_fops,&test_btf};}
static void balanced(struct bpf_prog*p,int expected){assert(test_btf.refcnt==expected&&!fd_refs);destroy(p);assert(test_btf.refcnt==1&&!live&&!charges);}
static void valid_fixtures(void){for(unsigned i=0;i<3;i++){struct bpf_prog*p=make_prog(fixtures[i].size/8);memcpy(p->insnsi,fixtures[i].code,fixtures[i].size);union bpf_attr a=metadata(fixtures[i].func,fixtures[i].line,fixtures[i].lines),u=a;assert(validate(p,&a,&u)==0);assert(p->aux->func_info_cnt==1&&p->aux->nr_linfo==fixtures[i].lines&&test_btf.refcnt==2);assert(!memcmp(p->aux->linfo,fixtures[i].line,fixtures[i].lines*16));assert(!memcmp(p->aux->func_info,fixtures[i].func,8));balanced(p,2);}}
static void invalid_records(int which){struct bpf_func_info f=func0[0];struct bpf_line_info l[2]={line0[0],line0[1]};struct bpf_prog*p=make_prog(383);union bpf_attr a=metadata(&f,l,2),u=a;int expected=-EINVAL;
 switch(which){case 0:a.func_info_cnt=2;break;case 1:f.insn_off=1;break;case 2:f.type_id=0;break;case 3:f.type_id=UINT_MAX;break;case 4:f.type_id=fixture_types[f.type_id].type;break;case 5:l[0].insn_off=1;break;case 6:l[1].insn_off=0;break;case 7:l[1].insn_off=383;break;case 8:p->insnsi[l[1].insn_off].code=0;break;case 9:l[1].file_name_off=sizeof(fixture_strings);break;case 10:l[1].line_off=UINT_MAX;break;case 11:a.line_info_cnt=UINT_MAX;break;case 12:a.prog_btf_fd=7;expected=-EBADF;break;case 13:a.prog_btf_fd=4;break;case 14:{u32 saved=fixture_types[f.type_id].type;fixture_types[f.type_id].type=UINT_MAX;assert(validate(p,&a,&u)==-EINVAL);fixture_types[f.type_id].type=saved;balanced(p,1);return;} }
 assert(validate(p,&a,&u)==expected);balanced(p,1);}
static void sizes_tails(void){unsigned sizes[]={0,4,7,9,12,16,20,252,256,UINT_MAX};for(unsigned kind=0;kind<2;kind++)for(unsigned i=0;i<sizeof(sizes)/sizeof(*sizes);i++){unsigned char record[256]={0};struct bpf_prog*p=make_prog(383);union bpf_attr a={.prog_btf_fd=3},u;unsigned min=kind?16:8;memcpy(record,kind?(void*)line0:(void*)func0,min);if(kind){a.line_info_cnt=1;a.line_info=(uintptr_t)record;a.line_info_rec_size=sizes[i];}else{a.func_info_cnt=1;a.func_info=(uintptr_t)record;a.func_info_rec_size=sizes[i];}u=a;bool valid=sizes[i]>=min&&sizes[i]<=252&&sizes[i]%4==0;assert(validate(p,&a,&u)==(valid?0:-EINVAL));balanced(p,valid?2:1);}
 for(unsigned kind=0;kind<2;kind++)for(unsigned fault=0;fault<4;fault++){unsigned char record[256]={0};unsigned min=kind?16:8;memcpy(record,kind?(void*)line0:(void*)func0,min);record[min]=1;struct bpf_prog*p=make_prog(383);union bpf_attr a={.prog_btf_fd=3},u={0};if(kind){a.line_info_cnt=1;a.line_info=(uintptr_t)record;a.line_info_rec_size=252;}else{a.func_info_cnt=1;a.func_info=(uintptr_t)record;a.func_info_rec_size=252;}if(fault==1)bad_read=record+min;if(fault==2)bad_write=kind?(void*)&u.line_info_rec_size:(void*)&u.func_info_rec_size;if(fault==3){record[min]=0;bad_read=record;}assert(validate(p,&a,&u)==(fault?-EFAULT:-E2BIG));bad_read=bad_write=NULL;if(!fault)assert((kind?u.line_info_rec_size:u.func_info_rec_size)==min);balanced(p,1);}}
static void allocation_failures(void){for(int i=1;i<=2;i++){struct bpf_prog*p=make_prog(383);union bpf_attr a=metadata(func0,line0,106),u=a;alloc_fail=alloc_calls+i;assert(validate(p,&a,&u)==-ENOMEM);alloc_fail=0;balanced(p,1);}}
static void legacy(void){struct bpf_prog*p=make_prog(2);union bpf_attr a={.prog_btf_fd=UINT_MAX,.func_info_rec_size=1,.line_info_rec_size=1},u=a;assert(!validate(p,&a,&u));assert(!p->aux->btf);balanced(p,1);}
static void lifetime(void){struct bpf_prog*p=make_prog(383);union bpf_attr a=metadata(func0,line0,106),u=a;assert(!validate(p,&a,&u));btf_put(&test_btf);assert(test_btf.refcnt==1&&!btf_freed);bpf_prog_put(p);assert(test_btf.refcnt==1&&!btf_freed&&rcu_count==1);drain_rcu();assert(work_count==1&&test_btf.refcnt==1);drain_work();assert(!test_btf.refcnt&&rcu_count==1&&!btf_freed);drain_rcu();assert(btf_freed==1&&btf_id_removed==1&&!live&&!charges&&prog_ids_removed==1);assert(map_frees==1&&sec_frees==1);}
static void realloc_clone(void){struct bpf_prog*p=make_prog(383);union bpf_attr a=metadata(func0,line0,106),u=a;assert(!validate(p,&a,&u));struct bpf_prog_aux*aux=p->aux;charge_fail=1;assert(!bpf_prog_realloc(p,8192,0));charge_fail=0;alloc_fail=alloc_calls+1;assert(!bpf_prog_realloc(p,8192,0));alloc_fail=0;assert(p->aux==aux&&test_btf.refcnt==2);struct bpf_prog*q=bpf_prog_realloc(p,8192,0);assert(q&&q!=p&&q->aux==aux&&aux->prog==q&&test_btf.refcnt==2);struct bpf_prog*clone=allocate(8192);memcpy(clone,q,8192);bpf_jit_prog_release_other(clone,q);assert(aux->prog==clone&&test_btf.refcnt==2);balanced(clone,2);}
static void expansion(void){struct bpf_prog*p=make_prog(383);union bpf_attr a=metadata(func0,line0,106),u=a;assert(!validate(p,&a,&u));struct bpf_insn patch[4]={{.code=0xb7},{.code=0xb7},{.code=0xb7},{.code=0xb7}};u32 off=line0[10].insn_off;struct bpf_prog*q=bpf_patch_insn_single(p,off,patch,4);assert(q&&q->len==386);for(unsigned i=0;i<106;i++)assert(q->aux->linfo[i].insn_off==line0[i].insn_off+(line0[i].insn_off>off?3:0));assert(!q->aux->func_info[0].insn_off);p=q;q=bpf_patch_insn_single(p,0,patch,2);assert(q&&q->len==387&&q->aux->linfo[0].insn_off==0);for(unsigned i=1;i<106;i++)assert(q->aux->linfo[i].insn_off==line0[i].insn_off+1+(line0[i].insn_off>off?3:0));q=bpf_patch_insn_single(q,0,patch,1);assert(q&&q->len==387&&q->aux->linfo[0].insn_off==0);balanced(q,2);}
static int info_get(struct bpf_prog*p,void*i,unsigned n,union bpf_attr*u){union bpf_attr a={0};a.info.info=(uintptr_t)i;a.info.info_len=n;return bpf_prog_get_info_by_fd(p,&a,u);}
static void info_contract(void){struct bpf_prog*p=make_prog(383);union bpf_attr a=metadata(func0,line0,106),u=a;assert(!validate(p,&a,&u));struct bpf_prog_info i={0};assert(!info_get(p,&i,sizeof(i),&u));assert(i.btf_id==37&&i.nr_func_info==1&&i.nr_line_info==106&&i.func_info_rec_size==8&&i.line_info_rec_size==16&&i.jited_line_info_rec_size==8&&!i.nr_jited_line_info);struct bpf_func_info f[2]={{0}};struct bpf_line_info l[108]={0};i=(struct bpf_prog_info){.func_info_rec_size=8,.line_info_rec_size=16,.nr_func_info=2,.nr_line_info=2,.func_info=(uintptr_t)f,.line_info=(uintptr_t)l,.nr_jited_line_info=3,.jited_line_info_rec_size=8,.jited_line_info=123,.ifindex=99,.netns_dev=99,.netns_ino=99,.nr_jited_ksyms=99,.nr_jited_func_lens=99,.jited_ksyms=123,.jited_func_lens=123};assert(!info_get(p,&i,sizeof(i),&u));assert(!memcmp(f,func0,8)&&!f[1].type_id&&!memcmp(l,line0,32)&&!l[2].line_col);assert(i.nr_func_info==1&&i.nr_line_info==106&&!i.nr_jited_line_info&&!i.jited_line_info&&!i.ifindex&&!i.netns_dev&&!i.netns_ino&&!i.nr_jited_ksyms&&!i.nr_jited_func_lens&&!i.jited_ksyms&&!i.jited_func_lens);for(unsigned len=0;len<=sizeof(i);len++){unsigned char shortinfo[sizeof(i)];memset(shortinfo,0,sizeof(shortinfo));assert(!info_get(p,shortinfo,len,&u));assert(u.info.info_len==len);for(unsigned k=len;k<sizeof(i);k++)assert(!shortinfo[k]);}unsigned char longer[sizeof(i)+8]={0};assert(!info_get(p,longer,sizeof(longer),&u)&&u.info.info_len==sizeof(i));memset(longer,0,sizeof(longer));longer[sizeof(i)]=1;assert(info_get(p,longer,sizeof(longer),&u)==-E2BIG);admin=false;i=(struct bpf_prog_info){.nr_func_info=1,.func_info_rec_size=8,.func_info=123,.nr_line_info=1,.line_info_rec_size=16,.line_info=123,.btf_id=99};assert(!info_get(p,&i,sizeof(i),&u)&&!i.btf_id&&!i.nr_func_info&&!i.nr_line_info);admin=true;balanced(p,2);}
static void info_faults(void){struct bpf_prog*p=make_prog(383);union bpf_attr a=metadata(func0,line0,106),u=a;assert(!validate(p,&a,&u));for(unsigned k=0;k<3;k++){struct bpf_prog_info i={0};if(k==0)i.nr_func_info=1;if(k==1)i.nr_line_info=1;if(k==2)i.nr_jited_line_info=1;assert(info_get(p,&i,sizeof(i),&u)==-EINVAL);}struct bpf_prog_info i={0};bad_read=&i;assert(info_get(p,&i,sizeof(i),&u)==-EFAULT);bad_read=NULL;bad_write=&i;assert(info_get(p,&i,sizeof(i),&u)==-EFAULT);bad_write=&u.info.info_len;i=(struct bpf_prog_info){0};assert(info_get(p,&i,sizeof(i),&u)==-EFAULT);bad_write=NULL;for(unsigned k=0;k<2;k++){i=(struct bpf_prog_info){0};if(k==0){i.nr_func_info=1;i.func_info_rec_size=8;}else{i.nr_line_info=1;i.line_info_rec_size=16;}assert(info_get(p,&i,sizeof(i),&u)==-EFAULT);}balanced(p,2);}
int main(int argc,char**argv){assert(argc==2);reset_btf();int c=atoi(argv[1]);switch(c){case 0:valid_fixtures();break;case 1:legacy();break;case 2:sizes_tails();break;case 3:allocation_failures();break;case 4:lifetime();break;case 5:realloc_clone();break;case 6:expansion();break;case 7:info_contract();break;case 8:info_faults();break;default:invalid_records(c-9);break;}assert(!live&&!charges&&!fd_refs);printf("PASS case%d\n",c);return 0;}

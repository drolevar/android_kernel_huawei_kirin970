/* SPDX-License-Identifier: GPL-2.0 */
/* Host scheduler/RCU, allocation, netdev and usercopy boundaries. */
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include BPF_UAPI_HEADER
#include BTF_UAPI_HEADER
#define CHECK(x) do { if (!(x)) { fprintf(stderr,"%d: %s\n",__LINE__,#x); exit(1); } } while(0)
typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef unsigned long ulong;
#define __percpu
#define __user
#define __init
#define GFP_USER 1
#define GFP_KERNEL 2
#define GFP_ATOMIC 4
#define __GFP_NOWARN 8
#define CAP_NET_ADMIN 1
#define U32_MAX UINT32_MAX
#define PAGE_SIZE 4096
#define PAGE_SHIFT 12
#define BITS_TO_LONGS(x) (((x)+63)/64)
#define round_up(x,y) (((x)+(y)-1)&~((y)-1))
#define container_of(p,t,m) ((t *)((char *)(p)-offsetof(t,m)))
#define likely(x) (x)
#define unlikely(x) (x)
static int explicit_reads;
#define READ_ONCE(x) (explicit_reads++, (x))
#define WRITE_ONCE(x,y) ((x)=(y))
#define ERR_PTR(e) ((void *)(intptr_t)(e))
#define PTR_ERR(p) ((int)(intptr_t)(p))
#define IS_ERR(p) ((uintptr_t)(p)>=(uintptr_t)-4095)
#define xchg(p,v) ({ __typeof__(*(p)) old=*(p); *(p)=(v); old; })
static void (*before_cmpxchg)(void);
#define cmpxchg(p,o,n) ({ if(before_cmpxchg) {void (*f)(void)=before_cmpxchg;before_cmpxchg=NULL;f();} __typeof__(*(p)) old=*(p); if(old==(o)) *(p)=(n); old; })
static int allocations, fail_alloc, alloc_live, admin=1, charge_error;
static void *allocate(size_t n) { allocations++; if(allocations==fail_alloc) return NULL; void *p=calloc(1,n); if(p)alloc_live++; return p; }
static void kfree(void *p) { if(p) { alloc_live--; free(p); } }
#define kzalloc(n,f) allocate(n)
#define kmalloc_node(n,f,node) allocate(n)
#define bpf_map_area_alloc(n,node) allocate(n)
#define bpf_map_area_free(p) kfree(p)
#define __alloc_percpu_gfp(n,a,f) allocate(n)
#define free_percpu(p) kfree(p)
#define num_possible_cpus() 1
#define for_each_online_cpu(c) for((c)=0;(c)<1;(c)++)
#define per_cpu_ptr(p,c) (p)
#define this_cpu_ptr(p) (p)
static void __set_bit(u32 bit, unsigned long *p) { CHECK(bit<64 && p); *p|=1UL<<bit; }
static void __clear_bit(u32 bit, unsigned long *p) { CHECK(bit<64 && p); *p&=~(1UL<<bit); }
#define bitmap_empty(p,n) (*(p)==0)
#define for_each_set_bit(b,p,n) for((b)=0;(b)<(n);(b)++) if(*(p)&(1UL<<(b)))
#define cond_resched() CHECK(0)
typedef int spinlock_t;
#define DEFINE_SPINLOCK(n) spinlock_t n
static void (*before_lock)(void);
static void spin_lock(spinlock_t *p) { if(before_lock) { void (*f)(void)=before_lock; before_lock=NULL; f(); } CHECK(!*p); *p=1; }
static void spin_unlock(spinlock_t *p) { CHECK(*p==1); *p=0; }
#define spin_lock_init(p) (*(p)=0)
#define spin_lock_irqsave(p,f) do {(f)=0;spin_lock(p);}while(0)
#define spin_unlock_irqrestore(p,f) do {(void)(f);spin_unlock(p);}while(0)
#define lockdep_is_held(p) (*(p))
struct list_head { struct list_head *next,*prev; };
#define LIST_HEAD(n) struct list_head n={&n,&n}
static void list_add_tail_rcu(struct list_head *n,struct list_head *h) { n->prev=h->prev;n->next=h;h->prev->next=n;h->prev=n; }
static void list_del_rcu(struct list_head *n) { n->prev->next=n->next;n->next->prev=n->prev; }
#define list_for_each_entry_rcu(p,h,m) for(p=container_of((h)->next,__typeof__(*p),m); &(p)->m!=(h); p=container_of((p)->m.next,__typeof__(*p),m))
struct hlist_node { struct hlist_node *next,**pprev; };
struct hlist_head { struct hlist_node *first; };
#define INIT_HLIST_HEAD(h) ((h)->first=NULL)
#define hlist_entry_safe(p,t,m) ((p)?container_of(p,t,m):NULL)
#define hlist_for_each_entry_rcu(p,h,m,...) for(p=hlist_entry_safe((h)->first,__typeof__(*p),m);p;p=hlist_entry_safe((p)->m.next,__typeof__(*p),m))
#define hlist_for_each_entry(p,h,m) hlist_for_each_entry_rcu(p,h,m)
#define hlist_for_each_entry_safe(p,n,h,m) for(p=hlist_entry_safe((h)->first,__typeof__(*p),m);p && ((n)=(p)->m.next,1);p=hlist_entry_safe(n,__typeof__(*p),m))
static void hlist_add_head_rcu(struct hlist_node *n,struct hlist_head *h) { n->next=h->first;n->pprev=&h->first;if(n->next)n->next->pprev=&n->next;h->first=n; }
static void hlist_del_rcu(struct hlist_node *n) { *n->pprev=n->next;if(n->next)n->next->pprev=n->pprev;n->pprev=NULL; }
#define hlist_del_init_rcu(n) hlist_del_rcu(n)
#define hlist_next_rcu(n) ((n)->next)
#define hlist_first_rcu(h) ((h)->first)
#define rcu_dereference_raw(p) (p)
struct rcu_head { struct rcu_head *next; void (*fn)(struct rcu_head *); };
static struct rcu_head *pending;
static int rcu_depth;
static void rcu_read_lock(void) { rcu_depth++; }
static void rcu_read_unlock(void) { CHECK(rcu_depth);rcu_depth--; }
static void call_rcu(struct rcu_head *r,void (*f)(struct rcu_head *)) { r->fn=f;r->next=pending;pending=r; }
static void drain(void) { CHECK(!rcu_depth);while(pending) {struct rcu_head *r=pending;pending=r->next;r->fn(r);} }
static void synchronize_rcu(void) { CHECK(!rcu_depth); }
static void rcu_barrier(void) { drain(); }

#define __rcu
#define __aligned(n) __attribute__((aligned(n)))
#define ____cacheline_aligned __attribute__((aligned(64)))
#define CAP_SYS_ADMIN 1
#define U16_MAX UINT16_MAX
#define KMALLOC_MAX_SIZE 1048576
#define MAX_BPF_STACK 512
#define ENOTSUPP 524
#define rcu_dereference(p) (CHECK_RCU(), (p))
#define CHECK_RCU() check_rcu()
static void check_rcu(void) {CHECK(rcu_depth);}
#define rcu_access_pointer(p) (p)
#define RCU_INIT_POINTER(p,v) ((p)=(v))
#define rcu_assign_pointer(p,v) ((p)=(v))
#define cond_resched_rcu() CHECK(rcu_depth)
#define hlist_add_head hlist_add_head_rcu
#define hlist_unhashed(n) (!(n)->pprev)
#define hlist_empty(h) (!(h)->first)
#define hlist_is_singular_node(n,h) ((h)->first==(n) && !(n)->next)
typedef int raw_spinlock_t;
#define raw_spin_lock_init spin_lock_init
#define raw_spin_lock_bh spin_lock
#define raw_spin_unlock_bh spin_unlock
#define kvzalloc(n,f) allocate(n)
#define kvfree kfree
#define max_t(t,a,b) ((t)(a)>(t)(b)?(t)(a):(t)(b))
static unsigned roundup_pow_of_two(unsigned v) { unsigned n=1;while(n<v)n*=2;return n; }
static unsigned ilog2(unsigned v) { unsigned n=0;while(v>>=1)n++;return n; }
static unsigned hash_ptr(void *p,unsigned bits) { CHECK(bits>0);return ((uintptr_t)p/64)&((1u<<bits)-1); }
typedef int atomic_t;
static int atomic_read(atomic_t *v) {return *v;}
static void atomic_add(int n,atomic_t *v) {*v+=n;}
static void atomic_sub(int n,atomic_t *v) {CHECK(*v>=n);*v-=n;}
static int atomic_inc_return(atomic_t *v) {return ++*v;}
static int sysctl_optmem_max=65536;
struct bpf_sk_storage;
struct sock {struct bpf_sk_storage *sk_bpf_storage;atomic_t sk_omem_alloc;int sk_refcnt;int full;};
struct socket {struct sock *sk;int refs;bool closed;};
static struct sock socks[3]={{.sk_refcnt=1,.full=1},{.sk_refcnt=1,.full=1},{.sk_refcnt=1,.full=0}};
static struct socket sockets[4]={{&socks[0],0,0},{&socks[1],0,0},{&socks[2],0,0},{NULL,0,0}};
static struct socket *sockfd_lookup(int fd,int *err) { if(fd<0||fd>4){*err=-EBADF;return NULL;}if(fd==4){*err=-ENOTSOCK;return NULL;}if(sockets[fd].closed){*err=-EBADF;return NULL;}sockets[fd].refs++;return &sockets[fd]; }
static void sockfd_put(struct socket *s) {CHECK(s->refs);s->refs--;}
static bool sk_fullsock(struct sock *s) {CHECK(s);return s->full;}
static bool refcount_inc_not_zero(int *r) {if(!*r)return false;(*r)++;return true;}
static void sock_put(struct sock *s) {CHECK(s->sk_refcnt>1);s->sk_refcnt--;}
struct bpf_map_ops;
struct bpf_map {unsigned map_type,key_size,value_size,max_entries,map_flags,pages;const struct bpf_map_ops *ops;};
struct btf {};
struct bpf_map_ops {struct bpf_map *(*map_alloc)(union bpf_attr *);void (*map_free)(struct bpf_map *);int (*map_get_next_key)(struct bpf_map *,void *,void *);void *(*map_lookup_elem)(struct bpf_map *,void *);int (*map_update_elem)(struct bpf_map *,void *,void *,u64);int (*map_delete_elem)(struct bpf_map *,void *);int (*map_check_btf)(const struct bpf_map *,const struct btf *,const struct btf_type *,const struct btf_type *);};
static void bpf_map_init_from_attr(struct bpf_map *m,union bpf_attr *a) {m->map_type=a->map_type;m->key_size=a->key_size;m->value_size=a->value_size;m->max_entries=a->max_entries;m->map_flags=a->map_flags;}
#define bpf_map_precharge_memlock(p) (charge_error)
#define capable(c) (admin)
/* Deferred frees are queued and drained explicitly after all reader sections. */
static void *freelist[1024];static int nfrees;
#define kfree_rcu(p,m) do {CHECK(nfrees<1024);freelist[nfrees++]=(p);}while(0)
static void drain_frees(void) {CHECK(!rcu_depth);while(nfrees)kfree(freelist[--nfrees]);}
#define BPF_CALL_4(n,t1,a1,t2,a2,t3,a3,t4,a4) static unsigned long n(t1 a1,t2 a2,t3 a3,t4 a4)
enum { RET_PTR_TO_MAP_VALUE_OR_NULL, ARG_CONST_MAP_PTR, ARG_PTR_TO_CTX, ARG_PTR_TO_SOCK_COMMON_OR_NULL, ARG_PTR_TO_MAP_VALUE_OR_NULL, ARG_ANYTHING };
struct bpf_func_proto {void *func;bool gpl_only;int ret_type,arg1_type,arg2_type,arg3_type,arg4_type;};
static const struct btf_type *types[2048];
static bool corpus_mode;
#include "fixture.h"
static const struct btf_type *btf_type_by_id(const struct btf *b,u32 id) {return id<2048?types[id]:NULL;}
static const char *btf_name_by_offset(const struct btf *b,u32 off) {return corpus_mode?corpus_strings+off:off==1?"bpf_spin_lock":"";}
static const struct btf_type *btf_type_id_size(const struct btf *b,u32 *id,u32 *sz) {const struct btf_type *t=btf_type_by_id(b,*id);int n=0;while(t && BTF_INFO_KIND(t->info)>=BTF_KIND_TYPEDEF && BTF_INFO_KIND(t->info)<=BTF_KIND_RESTRICT && n++<16){*id=t->type;t=btf_type_by_id(b,*id);}if(t)*sz=t->size;return t;}
#define CONFIG_BPF_SYSCALL 1
static void sock_copy(struct sock *d,const struct sock *s) {memcpy(d,s,sizeof(*d));}
#include "subject.h"
static union bpf_attr attr={.map_type=24,.key_size=4,.value_size=128,.map_flags=1,.btf_fd=5,.btf_key_type_id=1,.btf_value_type_id=2};
static int alloc_error(union bpf_attr *a) {struct bpf_map *m=sk_storage_map_ops.map_alloc(a);if(IS_ERR(m))return PTR_ERR(m);sk_storage_map_ops.map_free(m);return 0;}
static struct bpf_map *newmap(void) {CHECK(!alloc_error(&attr));struct bpf_map *m=sk_storage_map_ops.map_alloc(&attr);CHECK(!IS_ERR(m));m->ops=&sk_storage_map_ops;return m;}
static int update(struct bpf_map *m,int fd,unsigned char byte,u64 flags) {unsigned char v[128];memset(v,byte,sizeof(v));rcu_read_lock();int r=m->ops->map_update_elem(m,&fd,v,flags);rcu_read_unlock();return r;}
static int lookup(struct bpf_map *m,int fd) {rcu_read_lock();void *p=m->ops->map_lookup_elem(m,&fd);int r=IS_ERR(p)?PTR_ERR(p):p?*(unsigned char *)p:-ENOENT;rcu_read_unlock();return r;}
static int del(struct bpf_map *m,int fd) {rcu_read_lock();int r=m->ops->map_delete_elem(m,&fd);rcu_read_unlock();return r;}
static void destroy(struct bpf_map *m) {m->ops->map_free(m);drain_frees();}
static struct bpf_map *race_map;
static void competing_publish(void) {CHECK(!update(race_map,0,9,0));}
static void competing_delete(void) {CHECK(!del(race_map,0));}
static void competing_destroy(void) {bpf_sk_storage_free(&socks[0]);}
int main(int argc,char **argv) {
 CHECK(argc==2);const char *c=argv[1];
 if(!strcmp(c,"lockless_prechecks")) {
  struct bpf_sk_storage_elem element={0};struct hlist_node *dummy=NULL;
  element.snode.pprev=&dummy;element.map_node.pprev=&dummy;
  explicit_reads=0;CHECK(selem_linked_to_sk(&element));CHECK(explicit_reads==1);
  explicit_reads=0;CHECK(selem_linked_to_map(&element));CHECK(explicit_reads==1);
  element.snode.pprev=NULL;element.map_node.pprev=NULL;
  explicit_reads=0;CHECK(!selem_linked_to_sk(&element));CHECK(explicit_reads==1);
  explicit_reads=0;CHECK(!selem_linked_to_map(&element));CHECK(explicit_reads==1);return 0;
 }
 if(!strcmp(c,"corpus_btf")) {
  corpus_mode=true;for(unsigned i=1;i<sizeof(offsets)/sizeof(offsets[0]);i++)types[i]=(const struct btf_type *)(corpus+offsets[i]);
  CHECK(!strcmp(corpus_strings+types[70]->name_off,"SkStorageValue"));CHECK(types[70]->type==71);CHECK(types[71]->size==128);
  struct btf b;struct bpf_map m={.map_type=24,.key_size=4,.value_size=128,.ops=&sk_storage_map_ops};CHECK(!map_check_btf(&m,&b,3,70));return 0;
 }
 if(!strcmp(c,"map_btf")) {
  struct {struct btf_type t;u32 encoding;} key={{.info=BTF_KIND_INT<<24,.size=4},32};struct btf_type val={.info=BTF_KIND_STRUCT<<24,.size=128};types[1]=&key.t;types[2]=&val;
  struct btf b;struct bpf_map m={.map_type=24,.key_size=4,.value_size=128,.ops=&sk_storage_map_ops};CHECK(!map_check_btf(&m,&b,1,2));
  CHECK(map_check_btf(&m,&b,0,2)==-EINVAL);CHECK(map_check_btf(&m,&b,1,0)==-EINVAL);CHECK(map_check_btf(&m,&b,7,2)==-EINVAL);CHECK(map_check_btf(&m,&b,1,7)==-EINVAL);val.size=127;CHECK(map_check_btf(&m,&b,1,2)==-EINVAL);val.size=128;key.t.size=8;CHECK(map_check_btf(&m,&b,1,2)==-EINVAL);return 0;
 }
 if(!strcmp(c,"btf")) {
  struct {struct btf_type t;u32 encoding;} key={{.info=BTF_KIND_INT<<24,.size=4},32};
  struct {struct btf_type t;struct btf_member m;} v={{.info=(BTF_KIND_STRUCT<<24)|1,.size=128},{.type=1}};
  struct btf_type lock={.name_off=1,.info=BTF_KIND_STRUCT<<24,.size=4};
  struct btf b;struct bpf_map m={.key_size=4,.value_size=128};types[1]=&key.t;types[2]=&v.t;types[3]=&lock;
  CHECK(!bpf_sk_storage_map_check_btf(&m,&b,&key.t,&v.t));
  v.m.type=3;CHECK(bpf_sk_storage_map_check_btf(&m,&b,&key.t,&v.t)==-EOPNOTSUPP);
  CHECK(bpf_sk_storage_map_check_btf(&m,&b,&key.t,&lock)==-EOPNOTSUPP);
  key.encoding=16;CHECK(bpf_sk_storage_map_check_btf(&m,&b,&key.t,&v.t)==-EINVAL);
  return 0;
 }
 if(!strcmp(c,"attributes")) {
  CHECK(BPF_MAP_TYPE_SK_STORAGE==24);CHECK(!alloc_error(&attr));struct bpf_map *m=newmap();CHECK(m->map_type==24&&m->key_size==4&&m->value_size==128&&!m->max_entries&&m->map_flags==1&&m->pages);destroy(m);
  for(int i=0;i<7;i++){union bpf_attr a=attr;switch(i){case 0:a.key_size=8;break;case 1:a.value_size=4;break;case 2:a.max_entries=1;break;case 3:a.map_flags=0;break;case 4:a.map_flags=513;break;case 5:a.btf_key_type_id=0;break;case 6:a.btf_value_type_id=0;break;}CHECK(alloc_error(&a)==-EINVAL);}
  admin=0;CHECK(alloc_error(&attr)==-EPERM);return 0;
 }
 if(!strcmp(c,"alloc")) {for(int i=1;i<=2;i++){allocations=0;fail_alloc=i;struct bpf_map *m=sk_storage_map_ops.map_alloc(&attr);CHECK(IS_ERR(m));CHECK(!alloc_live);}return 0;}
 if(!strcmp(c,"precharge")){charge_error=-EPERM;struct bpf_map *m=sk_storage_map_ops.map_alloc(&attr);CHECK(PTR_ERR(m)==-EPERM);CHECK(!alloc_live);return 0;}
 struct bpf_map *m=newmap();CHECK(((struct bpf_sk_storage_map *)m)->bucket_log>=1);
 if(!strcmp(c,"clone")) {
  CHECK(!update(m,0,3,0));struct sock child;test_clone_init(&child,&socks[0]);CHECK(!child.sk_bpf_storage);child.sk_omem_alloc=0;bpf_sk_storage_free(&child);CHECK(lookup(m,0)==3);
 } else if(!strcmp(c,"cache_collision")) {
  struct bpf_map *maps[17];for(int i=0;i<17;i++){maps[i]=newmap();CHECK(!update(maps[i],0,i+1,0));}
  for(int round=0;round<2;round++)for(int i=0;i<17;i++)CHECK(lookup(maps[i],0)==i+1);
  CHECK(!del(maps[0],0));CHECK(lookup(maps[16],0)==17);for(int i=0;i<17;i++)destroy(maps[i]);
 } else if(!strcmp(c,"publish_race")) {
  race_map=m;before_cmpxchg=competing_publish;CHECK(update(m,0,1,0)==-EAGAIN);CHECK(lookup(m,0)==9);CHECK(!del(m,0));CHECK(!socks[0].sk_omem_alloc);
 } else if(!strcmp(c,"delete_race")) {
  CHECK(!update(m,0,3,0));race_map=m;before_lock=competing_delete;CHECK(lookup(m,0)==3);CHECK(lookup(m,0)==-ENOENT);drain_frees();CHECK(lookup(m,0)==-ENOENT);
 } else if(!strcmp(c,"empty_race")) {
  CHECK(!update(m,0,3,0));race_map=m;before_lock=competing_delete;CHECK(update(m,0,4,0)==-EAGAIN);CHECK(lookup(m,0)==-ENOENT);
 } else if(!strcmp(c,"destroy_race")) {
  CHECK(!update(m,0,3,0));before_lock=competing_destroy;destroy(m);m=NULL;CHECK(!socks[0].sk_bpf_storage);
 } else if(!strcmp(c,"fd")) {
  CHECK(lookup(m,-1)==-EBADF);CHECK(lookup(m,4)==-ENOTSOCK);sockets[0].closed=true;CHECK(lookup(m,0)==-EBADF);CHECK(update(m,0,1,0)==-EBADF);CHECK(del(m,0)==-EBADF);sockets[0].closed=false;
  for(int fd=2;fd<=3;fd++){CHECK(lookup(m,fd)==-EINVAL);CHECK(update(m,fd,1,0)==-EINVAL);CHECK(del(m,fd)==-EINVAL);}
  CHECK(lookup(m,0)==-ENOENT);CHECK(update(m,-1,1,0)==-EBADF);CHECK(del(m,-1)==-EBADF);CHECK(update(m,4,1,0)==-ENOTSOCK);CHECK(del(m,4)==-ENOTSOCK);
  int next;CHECK(m->ops->map_get_next_key(m,NULL,&next)==-ENOTSUPP);
 } else if(!strcmp(c,"replace")) {
  CHECK(update(m,0,1,BPF_EXIST)==-ENOENT);CHECK(update(m,0,1,3)==-EINVAL);CHECK(!update(m,0,7,0));int charge=socks[0].sk_omem_alloc;
  CHECK(update(m,0,3,BPF_NOEXIST)==-EEXIST);CHECK(!update(m,0,8,BPF_EXIST));CHECK(lookup(m,0)==8);CHECK(socks[0].sk_omem_alloc==charge);CHECK(nfrees==1);CHECK(!del(m,0));CHECK(del(m,0)==-ENOENT);CHECK(!socks[0].sk_omem_alloc);
 } else if(!strcmp(c,"optmem")) {
  sysctl_optmem_max=1;CHECK(update(m,0,1,0)==-ENOMEM);CHECK(!socks[0].sk_omem_alloc);sysctl_optmem_max=65536;
  for(int i=1;i<=2;i++){fail_alloc=allocations+i;CHECK(update(m,0,1,0)==-ENOMEM);CHECK(!socks[0].sk_omem_alloc);CHECK(!socks[0].sk_bpf_storage);fail_alloc=0;}
  CHECK(!update(m,0,1,0));int charge=socks[0].sk_omem_alloc;fail_alloc=allocations+1;CHECK(update(m,0,2,0)==-ENOMEM);CHECK(lookup(m,0)==1);CHECK(socks[0].sk_omem_alloc==charge);fail_alloc=0;
 } else if(!strcmp(c,"helper")) {
  CHECK(bpf_sk_storage_get_cg_sock_proto.arg2_type==ARG_PTR_TO_CTX);CHECK(bpf_sk_storage_get_cg_sock_proto.arg3_type==ARG_PTR_TO_MAP_VALUE_OR_NULL);
  rcu_read_lock();CHECK(!bpf_sk_storage_get(m,NULL,NULL,1));CHECK(!bpf_sk_storage_get(m,&socks[2],NULL,1));CHECK(!bpf_sk_storage_get(m,&socks[0],NULL,2));CHECK(!bpf_sk_storage_get(m,&socks[0],NULL,0));
  socks[0].sk_refcnt=0;CHECK(!bpf_sk_storage_get(m,&socks[0],NULL,1));socks[0].sk_refcnt=1;
  unsigned char *v=(void *)bpf_sk_storage_get(m,&socks[0],NULL,1);CHECK(v);for(int i=0;i<128;i++)CHECK(!v[i]);v[7]=6;CHECK((void *)bpf_sk_storage_get(m,&socks[0],NULL,0)==v);CHECK(socks[0].sk_refcnt==1);rcu_read_unlock();
 } else if(!strcmp(c,"cache")) {
  CHECK(!update(m,0,3,0));CHECK(lookup(m,0)==3);CHECK(!del(m,0));CHECK(lookup(m,0)==-ENOENT);CHECK(!update(m,0,4,0));CHECK(lookup(m,0)==4);
 } else if(!strcmp(c,"socket_first")) {
  CHECK(!update(m,0,3,0));bpf_sk_storage_free(&socks[0]);CHECK(!socks[0].sk_bpf_storage);CHECK(!socks[0].sk_omem_alloc);CHECK(lookup(m,0)==-ENOENT);
 } else if(!strcmp(c,"map_first")) {
  CHECK(!update(m,0,3,0));CHECK(!update(m,1,4,0));destroy(m);m=NULL;CHECK(!socks[0].sk_bpf_storage&&!socks[1].sk_bpf_storage);bpf_sk_storage_free(&socks[0]);bpf_sk_storage_free(&socks[1]);
 } else if(!strcmp(c,"multi")) {
  struct bpf_map *n=newmap();CHECK(!update(m,0,3,0));CHECK(!update(n,0,4,0));CHECK(!update(n,1,5,0));destroy(m);m=NULL;CHECK(lookup(n,0)==4);bpf_sk_storage_free(&socks[0]);CHECK(lookup(n,1)==5);destroy(n);
 } else if(!strcmp(c,"interleave")) {
  CHECK(!update(m,0,3,0));rcu_read_lock();struct bpf_sk_storage_data *old=sk_storage_lookup(&socks[0],m,true);CHECK(!update(m,0,4,0));CHECK(old->data[0]==3);CHECK(lookup(m,0)==4);CHECK(!del(m,0));CHECK(old->data[0]==3);rcu_read_unlock();
 } else CHECK(0);
 if(m)destroy(m);drain_frees();CHECK(!alloc_live);for(int i=0;i<3;i++)CHECK(!socks[i].sk_omem_alloc&&!socks[i].sk_bpf_storage);for(int i=0;i<4;i++)CHECK(!sockets[i].refs);CHECK(!rcu_depth);puts("PASS");return 0;
}

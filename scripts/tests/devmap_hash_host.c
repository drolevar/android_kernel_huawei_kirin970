/* SPDX-License-Identifier: GPL-2.0 */
/* Host scheduler/RCU, allocation, netdev and usercopy boundaries. */
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include BPF_UAPI_HEADER
#define CHECK(x) do { if (!(x)) { fprintf(stderr,"%d: %s\n",__LINE__,#x); exit(1); } } while(0)
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
#define READ_ONCE(x) (x)
#define WRITE_ONCE(x,y) ((x)=(y))
#define ERR_PTR(e) ((void *)(intptr_t)(e))
#define PTR_ERR(p) ((int)(intptr_t)(p))
#define IS_ERR(p) ((uintptr_t)(p)>=(uintptr_t)-4095)
#define xchg(p,v) ({ __typeof__(*(p)) old=*(p); *(p)=(v); old; })
#define cmpxchg(p,o,n) ({ __typeof__(*(p)) old=*(p); if(old==(o)) *(p)=(n); old; })
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
static int rcu_depth, barriers;
static void rcu_read_lock(void) { rcu_depth++; }
static void rcu_read_unlock(void) { CHECK(rcu_depth);rcu_depth--; }
static void call_rcu(struct rcu_head *r,void (*f)(struct rcu_head *)) { r->fn=f;r->next=pending;pending=r; }
static void drain(void) { CHECK(!rcu_depth);while(pending) {struct rcu_head *r=pending;pending=r->next;r->fn(r);} }
static void synchronize_rcu(void) { CHECK(!rcu_depth); }
static void rcu_barrier(void) { barriers++; drain(); }
struct net { int id; };
struct net_device;
struct net_device_ops { void (*ndo_xdp_flush)(struct net_device *); };
struct net_device { int ifindex,refs,registered; struct net *net; const struct net_device_ops *netdev_ops; };
static int flushes;
static void flush(struct net_device *d) { CHECK(d->refs);flushes++; }
static const struct net_device_ops ndops={flush};
static struct net nets[2]={{1},{2}};
static struct net_device devices[3]={{7,0,1,&nets[0],&ndops},{8,0,1,&nets[0],&ndops},{7,0,1,&nets[1],&ndops}};
struct nsproxy { struct net *net_ns; };
static struct nsproxy ns={&nets[0]};
static struct { struct nsproxy *nsproxy; } task={&ns}, *current=&task;
static struct net_device *dev_get_by_index(struct net *n,u32 idx) { for(int i=0;i<3;i++)if(devices[i].net==n && devices[i].ifindex==idx && devices[i].registered) {devices[i].refs++;return &devices[i];} return NULL; }
static void dev_put(struct net_device *d) { CHECK(d->refs>0);d->refs--; }
#define NETDEV_UNREGISTER 1
#define NOTIFY_OK 0
struct notifier_block { int (*notifier_call)(struct notifier_block *,ulong,void *); };
#define netdev_notifier_info_to_dev(p) (p)
#define register_netdevice_notifier(p) ((void)(p))
#define subsys_initcall(f)
struct bpf_map_ops;
struct bpf_map { unsigned map_type,key_size,value_size,max_entries,map_flags,pages,id; int numa_node; char name[16]; void *btf; unsigned btf_key_type_id,btf_value_type_id; };
struct bpf_map_ops { struct bpf_map *(*map_alloc)(union bpf_attr *); void (*map_free)(struct bpf_map *); int (*map_get_next_key)(struct bpf_map *,void *,void *); void *(*map_lookup_elem)(struct bpf_map *,void *); int (*map_update_elem)(struct bpf_map *,void *,void *,u64); int (*map_delete_elem)(struct bpf_map *,void *); };
#define bpf_map_attr_numa_node(a) (-1)
#define bpf_map_precharge_memlock(p) (charge_error)
#define capable(c) (admin)
#define verbose(...) ((void)0)
#define func_id_name(f) "helper"
#define u64_to_user_ptr(p) ((void *)(uintptr_t)(p))
#define min_t(t,a,b) ((t)(a)<(t)(b)?(t)(a):(t)(b))
#define btf_id(p) 1
static int check_uarg_tail_zero(void *p,size_t n,size_t sz) { return sz>n?-E2BIG:0; }
static int copy_to_user(void *d,const void *s,size_t n) { memcpy(d,s,n);return 0; }
#define put_user(v,p) (*(p)=(v),0)
#include "subject.h"
#include "registry.h"
static const struct bpf_map_ops *ops;
static struct bpf_map *newmap(unsigned type) { union bpf_attr a={.map_type=type,.key_size=4,.value_size=4,.max_entries=64};ops=registry(type);CHECK(ops);struct bpf_map *m=ops->map_alloc(&a);CHECK(!IS_ERR(m));return m; }
static int update(struct bpf_map *m,u32 k,u32 v,u64 f) { rcu_read_lock();int r=ops->map_update_elem(m,&k,&v,f);rcu_read_unlock();return r; }
static int del(struct bpf_map *m,u32 k) { rcu_read_lock();int r=ops->map_delete_elem(m,&k);rcu_read_unlock();return r; }
static int lookup(struct bpf_map *m,u32 k) {rcu_read_lock();int *p=ops->map_lookup_elem(m,&k);int v=p?*p:-1;rcu_read_unlock();return v;}
static int next(struct bpf_map *m,void *k,u32 *v) {rcu_read_lock();int r=ops->map_get_next_key(m,k,v);rcu_read_unlock();return r;}
static void unreg(int i) { devices[i].registered=0;dev_map_notification(NULL,NETDEV_UNREGISTER,&devices[i]); }
static struct bpf_map *inter_map;
static void replace_before_lock(void) { CHECK(update(inter_map,0xffffffff,8,0)==0); }
int main(int argc,char **argv) {
 CHECK(argc==2); const char *c=argv[1];
 if(!strcmp(c,"helpers")) {struct bpf_map m={.map_type=25};for(int f=0;f<256;f++)CHECK(check_map_func_compatibility(&m,f)==-EINVAL);m.map_type=BPF_MAP_TYPE_DEVMAP;CHECK(check_map_func_compatibility(&m,BPF_FUNC_redirect_map)==0);CHECK(check_map_func_compatibility(&m,BPF_FUNC_map_lookup_elem)==-EINVAL);return 0;}
 struct bpf_map *m=newmap(!strcmp(c,"array")?BPF_MAP_TYPE_DEVMAP:25);
 if(!strcmp(c,"attributes")) {
  struct bpf_map_info info={0};union bpf_attr a={.info={.info=(uintptr_t)&info,.info_len=sizeof(info)}};
  CHECK(bpf_map_get_info_by_fd(m,&a,&a)==0);CHECK(info.type==25 && info.key_size==4 && info.value_size==4 && info.max_entries==64 && info.map_flags==128);
  union bpf_attr attr={.map_type=25,.key_size=4,.value_size=4,.max_entries=64};
  for(int i=0;i<6;i++) { union bpf_attr bad=attr; if(i==0)bad.key_size=8;if(i==1)bad.value_size=8;if(i==2)bad.max_entries=0;if(i==3)bad.max_entries=65;if(i==4)bad.map_flags=BPF_F_RDONLY;if(i==5)bad.map_flags=128;CHECK(PTR_ERR(ops->map_alloc(&bad))==-EINVAL); }
  admin=0;CHECK(PTR_ERR(ops->map_alloc(&attr))==-EPERM);admin=1;
  CHECK(update(m,UINT32_MAX,7,0)==0);
 } else if(!strcmp(c,"crud")) {
  CHECK(update(m,0,7,0)==0);CHECK(update(m,64,8,0)==0);CHECK(update(m,UINT32_MAX,7,0)==0);CHECK(lookup(m,0)==7 && lookup(m,64)==8 && lookup(m,UINT32_MAX)==7);
  CHECK(update(m,64,7,BPF_NOEXIST)==-EEXIST);CHECK(update(m,128,7,BPF_EXIST)==-ENOENT);CHECK(update(m,64,7,BPF_EXIST)==0);CHECK(del(m,64)==0);CHECK(del(m,64)==-ENOENT);CHECK(lookup(m,64)==-1);
 } else if(!strcmp(c,"full")) {
  for(u32 i=0;i<64;i++)CHECK(update(m,i*64,7,BPF_NOEXIST)==0);
  CHECK(update(m,4096,8,0)==-E2BIG);CHECK(update(m,0,8,BPF_EXIST)==0);CHECK(lookup(m,0)==8);CHECK(del(m,64)==0);CHECK(update(m,UINT32_MAX,8,0)==0);
 } else if(!strcmp(c,"faults")) {
  union bpf_attr a={.map_type=25,.key_size=4,.value_size=4,.max_entries=64};
  for(int i=1;i<=2;i++){int live=alloc_live;fail_alloc=allocations+i;CHECK(PTR_ERR(ops->map_alloc(&a))==-ENOMEM);CHECK(alloc_live==live);fail_alloc=0;}
  charge_error=-EPERM;CHECK(PTR_ERR(ops->map_alloc(&a))==-EPERM);charge_error=0;
  CHECK(update(m,5,7,0)==0);fail_alloc=allocations+1;CHECK(update(m,5,8,0)==-ENOMEM);fail_alloc=0;CHECK(lookup(m,5)==7);
  CHECK(update(m,6,999,0)==-EINVAL);CHECK(update(m,6,0,0)==-EINVAL);CHECK(update(m,6,7,3)==-EINVAL);CHECK(devices[0].refs==1 && devices[1].refs==0);
 } else if(!strcmp(c,"namespace")) {
  CHECK(update(m,999,7,0)==0);CHECK(devices[0].refs==1 && devices[2].refs==0);
  ns.net_ns=&nets[1];CHECK(lookup(m,999)==7);CHECK(devices[0].refs==1 && devices[2].refs==0);
  CHECK(update(m,999,7,0)==0);CHECK(devices[0].refs==1 && devices[2].refs==1);drain();CHECK(devices[0].refs==0 && devices[2].refs==1);
  unreg(0);CHECK(lookup(m,999)==7);ns.net_ns=&nets[0];CHECK(update(m,3,7,0)==-EINVAL);CHECK(lookup(m,999)==7);
 } else if(!strcmp(c,"iteration")) {
  u32 n,k=123;CHECK(next(m,NULL,&n)==-ENOENT);for(u32 i=0;i<64;i++)CHECK(update(m,i*64,7,0)==0);
  CHECK(next(m,&k,&n)==0);bool seen[64]={0};unsigned count=0;
  do {CHECK(n%64==0 && n/64<64 && !seen[n/64]);seen[n/64]=true;count++;k=n;}while(next(m,&k,&n)==0);CHECK(count==64);
  for(count=0;next(m,NULL,&n)==0;count++)CHECK(del(m,n)==0);CHECK(count==64);
 } else if(!strcmp(c,"unregister")) {
  for(u32 i=0;i<64;i++)CHECK(update(m,i*64,7,0)==0);unreg(0);u32 n;CHECK(next(m,NULL,&n)==-ENOENT);CHECK(devices[0].refs==64);drain();CHECK(devices[0].refs==0);CHECK(update(m,UINT32_MAX,8,0)==0);
 } else if(!strcmp(c,"replace_unregister")) {
  CHECK(update(m,UINT32_MAX,7,0)==0);CHECK(update(m,UINT32_MAX,8,0)==0);unreg(0);CHECK(lookup(m,UINT32_MAX)==8);drain();CHECK(devices[0].refs==0 && devices[1].refs==1);
 } else if(!strcmp(c,"deferred")) {
  CHECK(update(m,UINT32_MAX,7,0)==0);u32 k=UINT32_MAX;rcu_read_lock();int *old=ops->map_lookup_elem(m,&k);CHECK(update(m,k,8,0)==0);CHECK(*old==7);CHECK(del(m,k)==0);CHECK(*old==7);rcu_read_unlock();CHECK(devices[0].refs==1 && devices[1].refs==1);
 } else if(!strcmp(c,"interleave")) {
  CHECK(update(m,UINT32_MAX,7,0)==0);inter_map=m;before_lock=replace_before_lock;CHECK(del(m,UINT32_MAX)==0);CHECK(lookup(m,UINT32_MAX)==-1);drain();CHECK(!devices[0].refs && !devices[1].refs);
 } else if(!strcmp(c,"array")) {
  CHECK(update(m,63,7,0)==0);CHECK(update(m,64,7,0)==-E2BIG);CHECK(update(m,0,7,BPF_NOEXIST)==-EEXIST);CHECK(lookup(m,63)==7);__dev_map_insert_ctx(m,63);CHECK(del(m,63)==0);drain();CHECK(flushes==1);CHECK(update(m,2,8,0)==0);unreg(1);drain();CHECK(lookup(m,2)==-1);u32 n;CHECK(next(m,NULL,&n)==0 && n==0);
 } else CHECK(0);
 ops->map_free(m);CHECK(barriers==1);CHECK(!pending);CHECK(!alloc_live);for(int i=0;i<3;i++)CHECK(!devices[i].refs);if(strcmp(c,"array"))CHECK(flushes==0);puts("PASS");return 0;
}

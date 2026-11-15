/* SPDX-License-Identifier: GPL-2.0 */
/* Whole production core; simulated kernel allocation/VM/IRQ/RCU boundaries.
 * POSIX shared mappings give real double-alias data bytes, not kernel VMA proof. */
#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include BPF_UAPI_HEADER
#define CHECK(x) do { if (!(x)) { fprintf(stderr,"%d: %s\n",__LINE__,#x); exit(1); } } while(0)
typedef uint32_t u32; typedef uint64_t u64; typedef unsigned gfp_t;
#define CONFIG_64BIT 1
#define CONFIG_BPF_SYSCALL 1
#define capable(x) true
#define __aligned(x) __attribute__((aligned(x)))
#define __maybe_unused __attribute__((unused))
#define ____cacheline_aligned_in_smp __aligned(64)
#define GFP_KERNEL 1
#define GFP_USER 2
#define __GFP_RETRY_MAYFAIL 4
#define __GFP_NOWARN 8
#define __GFP_ZERO 16
#define VM_MAP 1
#define VM_USERMAP 2
#define PAGE_KERNEL 0
#define PAGE_SHIFT 12
#define PAGE_SIZE (1UL<<PAGE_SHIFT)
#define PAGE_MASK (~(PAGE_SIZE-1))
#define PAGE_ALIGNED(x) (!((uintptr_t)(x)&(PAGE_SIZE-1)))
#define PAGE_ALIGN(x) (((x)+PAGE_SIZE-1)&PAGE_MASK)
#define NUMA_NO_NODE -1
#define U32_MAX UINT32_MAX
#define ENOTSUPP 524
#define VM_WRITE 1
#define VM_MAYWRITE 2
#define VM_SHARED 4
#define VM_EXEC 8
#define VM_MAYEXEC 16
#define VM_DONTEXPAND 32
#define VM_DONTDUMP 64
#define FMODE_READ 1
#define FMODE_WRITE 2
#define POLLERR 8
#define POLLIN 1
#define POLLRDNORM 64
#define round_up(x,y) (((x)+(y)-1)&~((__typeof__(x))(y)-1))
#define DIV_ROUND_UP(n,d) (((n)+(d)-1)/(d))
#define is_power_of_2(x) ((x)&&!((x)&((x)-1)))
#define container_of(p,t,m) ((t *)((char *)(p)-offsetof(t,m)))
#define unlikely(x) (x)
#define READ_ONCE(x) (x)
#define smp_load_acquire(p) (*(p))
#define smp_store_release(p,v) (*(p)=(v))
#define xchg(p,v) ({ __typeof__(*(p)) old=*(p); *(p)=(v); old; })
#define ERR_PTR(e) ((void *)(intptr_t)(e))
#define PTR_ERR(p) ((int)(intptr_t)(p))
#define IS_ERR(p) ((uintptr_t)(p)>=(uintptr_t)-4095)
static int allocations,fail_alloc,alloc_live,page_live,vmap_live,charge_error,rcu_syncs;
static void *allocate(size_t n) { if(++allocations==fail_alloc)return NULL;void *p=calloc(1,n);if(p)alloc_live++;return p; }
static void kfree(void *p) { if(p){alloc_live--;free(p);} }
#define kzalloc(n,f) allocate(n)
#define kmalloc_node(n,f,node) allocate(n)
#define vmalloc_node(n,node) allocate(n)
#define kvfree(p) kfree(p)
static int memfd=-1;static size_t next_page;
struct page { size_t index; };
static struct page *alloc_pages_node(int node,gfp_t flags,int order) { struct page *p=allocate(sizeof(*p)); if(!p)return NULL;p->index=next_page++;CHECK(!ftruncate(memfd,next_page*PAGE_SIZE));page_live++;return p; }
static void __free_page(struct page *p) { page_live--;kfree(p); }
struct vm_struct {void *addr;size_t size;unsigned flags;struct page **pages;};
static struct vm_struct regions[8];
static struct vm_struct *find_vm_area(const void *p) {uintptr_t x=(uintptr_t)p;for(int i=0;i<8;i++)if(regions[i].addr&&x>=(uintptr_t)regions[i].addr&&x<(uintptr_t)regions[i].addr+regions[i].size)return &regions[i];return NULL;}
static size_t get_vm_area_size(struct vm_struct *v){return v->size;}
static void *vmap(struct page **pages,int nr,unsigned flags,int prot) {
 if(++allocations==fail_alloc)return NULL;int slot=0;while(slot<8&&regions[slot].addr)slot++;CHECK(slot<8);
 size_t size=nr*PAGE_SIZE;void *base=mmap(NULL,size,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);CHECK(base!=MAP_FAILED);
 for(int i=0;i<nr;i++)CHECK(mmap((char *)base+i*PAGE_SIZE,PAGE_SIZE,PROT_READ|PROT_WRITE,MAP_SHARED|MAP_FIXED,memfd,pages[i]->index*PAGE_SIZE)!=MAP_FAILED);
 regions[slot]=(struct vm_struct){base,size,flags,pages};vmap_live++;return base;
}
static void vunmap(void *p) {struct vm_struct *v=find_vm_area(p);CHECK(v&&v->addr==p);CHECK(!munmap(p,v->size));memset(v,0,sizeof(*v));vmap_live--;}
#define kmemleak_not_leak(p) ((void)(p))
static int bpf_map_precharge_memlock(u32 pages) { CHECK(pages>0);return charge_error; }
static void synchronize_rcu(void) { rcu_syncs++; }
typedef int spinlock_t;
static bool nmi,deny_trylock;
#define in_nmi() (nmi)
#define spin_lock_init(p) (*(p)=0)
static void lock(spinlock_t *p) { CHECK(!*p);*p=1; }
static void unlock(spinlock_t *p) { CHECK(*p);*p=0; }
#define spin_lock_irqsave(p,f) do{(f)=0;lock(p);}while(0)
#define spin_unlock_irqrestore(p,f) do{(void)(f);unlock(p);}while(0)
#define spin_trylock_irqsave(p,f) ((f)=0,deny_trylock?false:(lock(p),true))
typedef int wait_queue_head_t;
struct irq_work { void (*cb)(struct irq_work *);bool pending; };
static struct irq_work *queued;static int wakeups,syncs,pollwaits;
#define init_waitqueue_head(p) (*(p)=0)
#define init_irq_work(w,f) ((w)->cb=(f))
static void wake_up_all(wait_queue_head_t *q) { wakeups++; }
static void irq_work_queue(struct irq_work *w) { CHECK(!queued||queued==w);queued=w;w->pending=true; }
static void irq_work_sync(struct irq_work *w) { syncs++;if(w->pending){w->pending=false;w->cb(w);queued=NULL;} }
struct vm_area_struct;
struct vm_operations_struct {void (*open)(struct vm_area_struct *);void (*close)(struct vm_area_struct *);};
struct file {struct bpf_map *private_data;unsigned f_mode,refs;};
struct vm_area_struct { unsigned long vm_flags,vm_pgoff,vm_start,vm_end;struct file *vm_file;const struct vm_operations_struct *vm_ops;void *vm_private_data; };
struct mutex {int locked;};
static void mutex_lock(struct mutex *m){CHECK(!m->locked);m->locked=1;}
static void mutex_unlock(struct mutex *m){CHECK(m->locked);m->locked=0;}
typedef long atomic64_t;
static void atomic64_inc(atomic64_t *p){++*p;}
static void atomic64_dec(atomic64_t *p){CHECK(*p>0);--*p;}
struct poll_table_struct {int unused;};
static int remap_error,remap_calls;static unsigned long mapped_offset;static size_t remapped_length;
static struct vm_struct *remapped_region;
static struct page *vmalloc_to_page(void *p){struct vm_struct *v=find_vm_area(p);CHECK(v);mapped_offset=((uintptr_t)p-(uintptr_t)v->addr)/PAGE_SIZE;remapped_region=v;return v->pages[mapped_offset];}
static int vm_insert_page(struct vm_area_struct *v,unsigned long addr,struct page *p){remap_calls++;remapped_length=v->vm_end-v->vm_start;return remap_error;}
#define poll_wait(f,q,p) ((void)(q),pollwaits++)
struct bpf_map {const struct bpf_map_ops *ops;bool frozen;struct mutex freeze_mutex;atomic64_t writecnt;u32 map_type,key_size,value_size,max_entries,map_flags,pages;int numa_node;};
struct bpf_map_ops {struct bpf_map *(*map_alloc)(union bpf_attr *);void(*map_free)(struct bpf_map *);int(*map_mmap)(struct bpf_map *,struct vm_area_struct *);unsigned(*map_poll)(struct bpf_map *,struct file *,struct poll_table_struct *);void *(*map_lookup_elem)(struct bpf_map *,void *);int(*map_update_elem)(struct bpf_map *,void *,void *,u64);int(*map_delete_elem)(struct bpf_map *,void *);int(*map_get_next_key)(struct bpf_map *,void *,void *);};
static int bpf_map_attr_numa_node(union bpf_attr *a) { return (a->map_flags&BPF_F_NUMA_NODE)?a->numa_node:NUMA_NO_NODE; }
enum bpf_arg_type { ARG_CONST_MAP_PTR,ARG_CONST_ALLOC_SIZE_OR_ZERO,ARG_ANYTHING,ARG_PTR_TO_ALLOC_MEM };
enum bpf_return_type { RET_PTR_TO_ALLOC_MEM_OR_NULL,RET_VOID };
struct bpf_func_proto {void *func;enum bpf_return_type ret_type;enum bpf_arg_type arg1_type,arg2_type,arg3_type;bool releases_reference;};
#define BPF_CALL_3(n,t1,a1,t2,a2,t3,a3) u64 n(t1 a1,t2 a2,t3 a3)
#define BPF_CALL_2(n,t1,a1,t2,a2) u64 n(t1 a1,t2 a2)
#define verbose(...) ((void)0)
#include "subject.h"
static union bpf_attr attr(unsigned n) {union bpf_attr a={0};a.map_type=BPF_MAP_TYPE_RINGBUF;a.max_entries=n;return a;}
static struct bpf_ringbuf_map *make(unsigned n) {union bpf_attr a=attr(n);struct bpf_map *m=ringbuf_map_alloc(&a);CHECK(!IS_ERR(m));m->ops=&ringbuf_map_ops;return container_of(m,struct bpf_ringbuf_map,map);}
static void finish(struct bpf_ringbuf_map *m) {ringbuf_map_free(&m->map);CHECK(!page_live&&!alloc_live&&!vmap_live&&!queued);}
static struct bpf_ringbuf_hdr *hdr(void *p) {return (void *)((char *)p-8);}
static unsigned length(void *p) {return hdr(p)->len;}
static void consume(struct bpf_ringbuf *rb) {while(rb->consumer_pos!=rb->producer_pos){struct bpf_ringbuf_hdr *h=(void *)(rb->data+(rb->consumer_pos&rb->mask));CHECK(!(h->len&BPF_RINGBUF_BUSY_BIT));rb->consumer_pos+=round_up((h->len&~BPF_RINGBUF_DISCARD_BIT)+8,8);}}
int main(int argc,char **argv) {
 CHECK(argc==2);memfd=memfd_create("ringbuf-test",0);CHECK(memfd>=0);const char *c=argv[1];
 if(!strcmp(c,"attributes")) {
  CHECK(BPF_MAP_TYPE_RINGBUF==27);unsigned sizes[]={4096,8192,32768,65536,1048576};for(unsigned i=0;i<5;i++){struct bpf_ringbuf_map *m=make(sizes[i]);CHECK(m->map.key_size==0&&m->map.value_size==0&&m->map.map_flags==0&&m->map.max_entries==sizes[i]);CHECK(m->map.pages>sizes[i]/PAGE_SIZE);finish(m);}
  unsigned bad[]={0,1,4095,6144,12288};for(unsigned i=0;i<5;i++){union bpf_attr a=attr(bad[i]);CHECK(PTR_ERR(ringbuf_map_alloc(&a))==-EINVAL);}
  for(int field=0;field<4;field++){union bpf_attr a=attr(4096);if(field==0)a.key_size=4;if(field==1)a.value_size=4;if(field==2)a.map_flags=1;if(field==3)a.map_flags=BPF_F_RDONLY_PROG;CHECK(PTR_ERR(ringbuf_map_alloc(&a))==-EINVAL);}
  union bpf_attr a=attr(4096);a.map_flags=BPF_F_NUMA_NODE;a.numa_node=2;struct bpf_map *mp=ringbuf_map_alloc(&a);CHECK(!IS_ERR(mp)&&mp->numa_node==2);ringbuf_map_free(mp);
 } else if(!strcmp(c,"faults")) {
  union bpf_attr a=attr(32768);charge_error=-EPERM;CHECK(PTR_ERR(ringbuf_map_alloc(&a))==-EPERM);CHECK(!alloc_live);charge_error=0;allocations=0;
  struct bpf_ringbuf_map *m=make(32768);int count=allocations;finish(m);for(int i=1;i<=count;i++){allocations=0;fail_alloc=i;struct bpf_map *mp=ringbuf_map_alloc(&a);CHECK(IS_ERR(mp));CHECK(!page_live&&!alloc_live&&!vmap_live);}fail_alloc=0;
  a=attr(1048576);for(int i=0;i<2;i++){allocations=0;fail_alloc=i?262:2;CHECK(IS_ERR(ringbuf_map_alloc(&a)));CHECK(!page_live&&!alloc_live&&!vmap_live);}fail_alloc=0;
 } else if(!strcmp(c,"records")) {
  struct bpf_ringbuf_map *m=make(32768);unsigned sizes[]={32,8,12,0};for(int i=0;i<4;i++){void *p=__bpf_ringbuf_reserve(m->rb,sizes[i]);CHECK(p);memset(p,0x51,sizes[i]);CHECK(length(p)==(sizes[i]|BPF_RINGBUF_BUSY_BIT));bpf_ringbuf_commit(p,0,i==2);CHECK(length(p)==(sizes[i]|(i==2?BPF_RINGBUF_DISCARD_BIT:0)));}consume(m->rb);finish(m);
 } else if(!strcmp(c,"full")) {
  struct bpf_ringbuf_map *m=make(4096);CHECK(!__bpf_ringbuf_reserve(m->rb,UINT64_MAX));CHECK(!__bpf_ringbuf_reserve(m->rb,1ULL<<32));CHECK(!__bpf_ringbuf_reserve(m->rb,4096));void *p=__bpf_ringbuf_reserve(m->rb,4080);CHECK(p);CHECK(!__bpf_ringbuf_reserve(m->rb,0));bpf_ringbuf_commit(p,0,false);consume(m->rb);CHECK(__bpf_ringbuf_reserve(m->rb,32));finish(m);
 } else if(!strcmp(c,"wrap")) {
  struct bpf_ringbuf_map *m=make(4096);void *p=__bpf_ringbuf_reserve(m->rb,4064);CHECK(p);bpf_ringbuf_commit(p,0,false);consume(m->rb);p=__bpf_ringbuf_reserve(m->rb,32);CHECK(p);memset(p,0xa5,32);CHECK(m->rb->data[0]==(char)0xa5&&m->rb->data[15]==(char)0xa5);bpf_ringbuf_commit(p,0,false);consume(m->rb);CHECK(m->rb->consumer_pos==4112);finish(m);
 } else if(!strcmp(c,"pending")) {
  struct bpf_ringbuf_map *m=make(4096);void *first=__bpf_ringbuf_reserve(m->rb,32);CHECK(first);memset(first,0x55,32);m->rb->consumer_pos=m->rb->producer_pos;for(int i=0;i<100;i++){void *p=__bpf_ringbuf_reserve(m->rb,32);CHECK(p);bpf_ringbuf_commit(p,0,true);m->rb->consumer_pos=m->rb->producer_pos;}CHECK(!__bpf_ringbuf_reserve(m->rb,64));CHECK(length(first)==(32|BPF_RINGBUF_BUSY_BIT));CHECK(*(char *)first==0x55);bpf_ringbuf_commit(first,0,false);CHECK(__bpf_ringbuf_reserve(m->rb,64));finish(m);
 } else if(!strcmp(c,"counterwrap")) {
  struct bpf_ringbuf_map *m=make(4096);m->rb->consumer_pos=m->rb->producer_pos=m->rb->pending_pos=ULONG_MAX-15;
  void *p=__bpf_ringbuf_reserve(m->rb,8);CHECK(p);CHECK(m->rb->producer_pos==0);bpf_ringbuf_commit(p,0,false);consume(m->rb);
  p=__bpf_ringbuf_reserve(m->rb,32);CHECK(p);CHECK(m->rb->pending_pos==0);bpf_ringbuf_commit(p,0,false);consume(m->rb);finish(m);
 } else if(!strcmp(c,"ordering")) {
  struct bpf_ringbuf_map *m=make(4096);void *a=__bpf_ringbuf_reserve(m->rb,8),*b=__bpf_ringbuf_reserve(m->rb,12);CHECK(a&&b);bpf_ringbuf_commit(b,0,false);CHECK(length(a)&BPF_RINGBUF_BUSY_BIT);CHECK(!wakeups);bpf_ringbuf_commit(a,0,false);CHECK(queued);consume(m->rb);finish(m);
 } else if(!strcmp(c,"wakeups")) {
  struct bpf_ringbuf_map *m=make(4096);void *p=__bpf_ringbuf_reserve(m->rb,8);bpf_ringbuf_commit(p,BPF_RB_NO_WAKEUP,false);CHECK(!queued);consume(m->rb);p=__bpf_ringbuf_reserve(m->rb,8);bpf_ringbuf_commit(p,BPF_RB_FORCE_WAKEUP,true);CHECK(queued);irq_work_sync(queued);CHECK(wakeups==1);finish(m);
 } else if(!strcmp(c,"nmi")) {
  struct bpf_ringbuf_map *m=make(4096);nmi=true;deny_trylock=true;CHECK(!__bpf_ringbuf_reserve(m->rb,8));CHECK(!m->rb->producer_pos);deny_trylock=false;CHECK(__bpf_ringbuf_reserve(m->rb,8));nmi=false;finish(m);
 } else if(!strcmp(c,"mmap")) {
  struct bpf_ringbuf_map *m=make(4096);struct vm_area_struct v={.vm_flags=VM_WRITE|VM_MAYWRITE,.vm_start=0x10000,.vm_end=0x11000};CHECK(!ringbuf_map_mmap(&m->map,&v));CHECK(mapped_offset==RINGBUF_PGOFF&&remapped_length==PAGE_SIZE);v.vm_pgoff=1;CHECK(ringbuf_map_mmap(&m->map,&v)==-EPERM);v.vm_pgoff=0;v.vm_end+=PAGE_SIZE;CHECK(ringbuf_map_mmap(&m->map,&v)==-EPERM);v.vm_flags=VM_MAYWRITE;v.vm_pgoff=1;v.vm_end=v.vm_start+3*PAGE_SIZE;CHECK(!ringbuf_map_mmap(&m->map,&v));CHECK(!(v.vm_flags&VM_MAYWRITE));v.vm_pgoff=ULONG_MAX;CHECK(ringbuf_map_mmap(&m->map,&v)<0);v.vm_pgoff=4;CHECK(ringbuf_map_mmap(&m->map,&v)<0);v.vm_pgoff=0;remap_error=-ENOMEM;CHECK(ringbuf_map_mmap(&m->map,&v)==-ENOMEM);remap_error=0;finish(m);
 } else if(!strcmp(c,"poll")) {
  struct bpf_ringbuf_map *m=make(4096);CHECK(!ringbuf_map_poll(&m->map,NULL,NULL));void *p=__bpf_ringbuf_reserve(m->rb,8);CHECK(ringbuf_map_poll(&m->map,NULL,NULL)==(POLLIN|POLLRDNORM));CHECK(pollwaits==2);bpf_ringbuf_commit(p,0,true);consume(m->rb);CHECK(!ringbuf_map_poll(&m->map,NULL,NULL));finish(m);
 } else if(!strcmp(c,"destroy")) {
  struct bpf_ringbuf_map *m=make(4096);void *p=__bpf_ringbuf_reserve(m->rb,32);bpf_ringbuf_commit(p,BPF_RB_FORCE_WAKEUP,false);CHECK(queued);finish(m);CHECK(syncs&&rcu_syncs);
 } else if(!strcmp(c,"unsupported")) {
  struct bpf_ringbuf_map *m=make(4096);for(int id=0;id<200;id++) {
#ifdef RINGBUF_PRODUCERS_REGISTERED
   CHECK(check_map_func_compatibility(&m->map,id)==(id==BPF_FUNC_ringbuf_reserve?0:-EINVAL));
#else
   CHECK(check_map_func_compatibility(&m->map,id)==-EINVAL);
#endif
  }
  CHECK(PTR_ERR(ringbuf_map_lookup_elem(&m->map,NULL))==-ENOTSUPP);
  CHECK(ringbuf_map_update_elem(&m->map,NULL,NULL,0)==-ENOTSUPP);
  CHECK(ringbuf_map_delete_elem(&m->map,NULL)==-ENOTSUPP);
  CHECK(ringbuf_map_get_next_key(&m->map,NULL,NULL)==-ENOTSUPP);finish(m);
 } else if(!strcmp(c,"helpers")) {
#ifndef RINGBUF_PRODUCERS_REGISTERED
  CHECK(!"Producer helper integration missing");
#else
  CHECK(BPF_FUNC_ringbuf_reserve==131&&BPF_FUNC_ringbuf_submit==132&&BPF_FUNC_ringbuf_discard==133);
  CHECK(sk_filter_func_proto(131)==&bpf_ringbuf_reserve_proto&&sk_filter_func_proto(132)==&bpf_ringbuf_submit_proto&&sk_filter_func_proto(133)==&bpf_ringbuf_discard_proto);
  CHECK(!sk_filter_func_proto(130)&&!sk_filter_func_proto(134));
  CHECK(bpf_ringbuf_reserve_proto.ret_type==RET_PTR_TO_ALLOC_MEM_OR_NULL);
  CHECK(bpf_ringbuf_reserve_proto.arg2_type==ARG_CONST_ALLOC_SIZE_OR_ZERO);
  CHECK(bpf_ringbuf_submit_proto.releases_reference&&bpf_ringbuf_discard_proto.releases_reference);
  CHECK(bpf_ringbuf_submit_proto.arg1_type==ARG_PTR_TO_ALLOC_MEM&&bpf_ringbuf_discard_proto.arg1_type==ARG_PTR_TO_ALLOC_MEM);
  struct bpf_ringbuf_map *m=make(32768);CHECK(!bpf_ringbuf_reserve(&m->map,8,1));
  unsigned sizes[]={32,8,12};for(int i=0;i<3;i++){void *p=(void *)(uintptr_t)bpf_ringbuf_reserve(&m->map,sizes[i],0);CHECK(p);memset(p,0x31,sizes[i]);CHECK(!(i==2?bpf_ringbuf_discard(p,0):bpf_ringbuf_submit(p,0)));CHECK(length(p)==(sizes[i]|(i==2?BPF_RINGBUF_DISCARD_BIT:0)));}consume(m->rb);
  struct bpf_map other={.map_type=BPF_MAP_TYPE_ARRAY};CHECK(check_map_func_compatibility(&other,BPF_FUNC_ringbuf_reserve)==-EINVAL);other.map_type=BPF_MAP_TYPE_HASH;CHECK(check_map_func_compatibility(&other,BPF_FUNC_ringbuf_reserve)==-EINVAL);
  finish(m);
#endif
 } else if(!strcmp(c,"fd-lifetime")) {
#ifndef RINGBUF_PRODUCERS_REGISTERED
  CHECK(!"Mmap integration missing");
#else
  struct bpf_ringbuf_map *m=make(4096);struct file f={.private_data=&m->map,.f_mode=FMODE_READ|FMODE_WRITE,.refs=1};
  struct vm_area_struct v={.vm_flags=VM_SHARED|VM_WRITE|VM_MAYWRITE|VM_MAYEXEC,.vm_start=0x10000,.vm_end=0x11000,.vm_file=&f};
  CHECK(!bpf_map_mmap(&f,&v));f.refs++;CHECK(m->map.writecnt==1&&v.vm_private_data==&m->map&&v.vm_file==&f&&v.vm_ops);CHECK(!(v.vm_flags&VM_MAYEXEC));
  f.refs--;CHECK(f.refs==1); /* modeled close(fd), VMA keeps file alive */
  struct vm_area_struct clone=v;v.vm_ops->open(&clone);f.refs++;CHECK(m->map.writecnt==2);
  clone.vm_ops->close(&clone);f.refs--;CHECK(m->map.writecnt==1&&f.refs==1);
  v.vm_flags&=~VM_WRITE;v.vm_ops->close(&v);f.refs--;CHECK(!m->map.writecnt&&!f.refs);
  v=(struct vm_area_struct){.vm_flags=VM_SHARED|VM_WRITE|VM_MAYWRITE,.vm_start=0x10000,.vm_end=0x11000,.vm_pgoff=1,.vm_file=&f};
  CHECK(bpf_map_mmap(&f,&v)==-EPERM);CHECK(!m->map.writecnt&&!v.vm_ops&&!v.vm_private_data&&v.vm_file==&f&&(v.vm_flags&VM_WRITE));
  v.vm_pgoff=0;remap_error=-ENOMEM;CHECK(bpf_map_mmap(&f,&v)==-ENOMEM);CHECK(!m->map.writecnt&&!v.vm_ops&&!v.vm_private_data);remap_error=0;
  v.vm_flags=VM_SHARED|VM_MAYWRITE;CHECK(!bpf_map_mmap(&f,&v));CHECK(!(v.vm_flags&VM_MAYWRITE));v.vm_ops->close(&v);CHECK(!m->map.writecnt);
  CHECK(!bpf_map_poll(&f,NULL));finish(m);
#endif
 } else if(!strcmp(c,"foreign-region")) {
  struct bpf_ringbuf_map *one=make(4096),*two=make(4096),*a,*b;
  a=(uintptr_t)one->rb<(uintptr_t)two->rb?one:two;b=a==one?two:one;
  unsigned long offset=((uintptr_t)b->rb-(uintptr_t)a->rb)/PAGE_SIZE-RINGBUF_PGOFF;
  struct file afile={.private_data=&a->map,.f_mode=FMODE_READ,.refs=1};
  struct vm_area_struct v={.vm_flags=VM_SHARED|VM_MAYWRITE,.vm_start=0x10000,.vm_end=0x11000,.vm_pgoff=offset,.vm_file=&afile};
  int ret=bpf_map_mmap(&afile,&v);
  if(ret==0)fprintf(stderr,"foreign mapping succeeded: A map offset reaches B metadata, target_is_B=%d\n",remapped_region==find_vm_area(b->rb));
  bool rejected=ret==-EINVAL&&!remap_calls&&!v.vm_ops&&!v.vm_private_data&&v.vm_file==&afile;ringbuf_map_free(&one->map);ringbuf_map_free(&two->map);CHECK(rejected);
 } else if(!strcmp(c,"mmap-boundary")) {
  struct bpf_ringbuf_map *m=make(4096);struct vm_area_struct v={.vm_flags=0,.vm_start=0x10000};
  unsigned long valid[][2]={{0,4},{1,3},{3,1},{0,1}};
  for(unsigned i=0;i<4;i++){v.vm_pgoff=valid[i][0];v.vm_end=v.vm_start+valid[i][1]*PAGE_SIZE;CHECK(!ringbuf_map_mmap(&m->map,&v));}
  unsigned long invalid[][2]={{4,1},{3,2},{0,5},{ULONG_MAX/PAGE_SIZE,1},{ULONG_MAX,1}};
  for(unsigned i=0;i<5;i++){v.vm_pgoff=invalid[i][0];v.vm_end=v.vm_start+invalid[i][1]*PAGE_SIZE;int calls=remap_calls;CHECK(ringbuf_map_mmap(&m->map,&v)==-EINVAL);CHECK(remap_calls==calls);}
  v.vm_pgoff=0;v.vm_end=v.vm_start;CHECK(ringbuf_map_mmap(&m->map,&v)==-EINVAL);v.vm_end=v.vm_start-1;CHECK(ringbuf_map_mmap(&m->map,&v)==-EINVAL);v.vm_end=v.vm_start+PAGE_SIZE-1;CHECK(ringbuf_map_mmap(&m->map,&v)==-EINVAL);
  v.vm_end=v.vm_start+PAGE_SIZE;v.vm_flags=VM_WRITE|VM_MAYWRITE;CHECK(!ringbuf_map_mmap(&m->map,&v));CHECK((v.vm_flags&(VM_WRITE|VM_MAYWRITE))==(VM_WRITE|VM_MAYWRITE));finish(m);
 } else CHECK(0);
 CHECK(!page_live&&!alloc_live&&!vmap_live&&!queued);close(memfd);puts("PASS");return 0;
}

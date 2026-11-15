/* SPDX-License-Identifier: GPL-2.0 */
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include BPF_UAPI_HEADER
#ifndef BPF_F_MMAPABLE
#define BPF_F_MMAPABLE (1U << 10) /* expected UAPI even for baseline RED */
#endif
#define CHECK(x) do { if (!(x)) {fprintf(stderr,"FAIL %d: %s\n",__LINE__,#x);exit(1);} }while(0)
typedef uint32_t u32;typedef uint64_t u64;
#define PAGE_SIZE 4096UL
#define PAGE_SHIFT 12
#define PAGE_ALIGNED(x) (!((x)&(PAGE_SIZE-1)))
#define PAGE_ALIGN(n) (((n)+PAGE_SIZE-1)&~(PAGE_SIZE-1))
#define round_up(n,a) (((n)+(a)-1)&~((a)-1))
#define round_down(n,a) ((n)&~((a)-1))
#define NUMA_NO_NODE -1
#define CAP_SYS_ADMIN 1
#define CONFIG_MMU 1
#define IS_ENABLED(x) (x)
#define KMALLOC_MAX_SIZE (1UL<<22)
#define U32_MAX UINT32_MAX
#define ERR_PTR(e) ((void*)(intptr_t)(e))
#define IS_ERR(p) ((uintptr_t)(p)>=(uintptr_t)-4095)
#define PTR_ERR(p) ((intptr_t)(p))
#define container_of(p,t,m) ((t*)((char*)(p)-offsetof(t,m)))
typedef unsigned long pgoff_t;
#define ENOTSUPP 524
#define VM_SHARED 1
#define VM_WRITE 2
#define VM_MAYWRITE 4
#define VM_EXEC 8
#define VM_MAYEXEC 16
#define VM_DONTEXPAND 32
#define VM_DONTDUMP 64
#define FMODE_CAN_WRITE 1
#define FMODE_READ 2
#define FMODE_WRITE 4
#define POLLERR 8
#define READ_ONCE(x) (x)
#define WRITE_ONCE(x,v) ((x)=(v))
struct mutex {int locked;};
static void mutex_lock(struct mutex *m){CHECK(!m->locked);m->locked=1;}
static void mutex_unlock(struct mutex *m){CHECK(m->locked);m->locked=0;}
typedef long atomic64_t;
static void atomic64_inc(atomic64_t *p){++*p;}
static void atomic64_dec(atomic64_t *p){CHECK(*p>0);--*p;}
static long atomic64_read(const atomic64_t *p){return *p;}
struct bpf_map;struct file;struct vm_area_struct;struct poll_table_struct {};
struct bpf_map_ops {int (*map_mmap)(struct bpf_map*,struct vm_area_struct*);int (*map_update_elem)(struct bpf_map*,void*,void*,u64);int (*map_delete_elem)(struct bpf_map*,void*);unsigned (*map_poll)(struct bpf_map*,struct file*,struct poll_table_struct*);};
struct bpf_map {const struct bpf_map_ops *ops;bool frozen;struct mutex freeze_mutex;atomic64_t writecnt;unsigned map_type,key_size,value_size,max_entries,map_flags,pages;int numa_node;bool unpriv_array;};
struct bpf_array {struct bpf_map map;u32 elem_size,index_mask;union {char value[0];void *pptrs[0];};};
static int privileged=1,alloc_fail,charge_fail;static void *allocation;static size_t allocation_size;static int allocation_mmap;
static bool capable(int cap){return privileged;}
static int bpf_map_attr_numa_node(union bpf_attr *a){return (a->map_flags&BPF_F_NUMA_NODE)?a->numa_node:NUMA_NO_NODE;}
static unsigned fls_long(unsigned long x){return x?sizeof(x)*8-__builtin_clzl(x):0;}
static int num_possible_cpus(void){return 2;}
static int bpf_map_precharge_memlock(u32 pages){return charge_fail?-EPERM:0;}
static void *bpf_map_area_alloc(size_t size,int node){if(alloc_fail)return NULL;allocation=calloc(1,size);allocation_size=size;allocation_mmap=0;return allocation;}
static void *bpf_map_area_mmapable_alloc(size_t size,int node){if(alloc_fail)return NULL;CHECK(!(size&(PAGE_SIZE-1)));allocation=aligned_alloc(PAGE_SIZE,size);CHECK(allocation);memset(allocation,0,size);allocation_size=size;allocation_mmap=1;return allocation;}
static void bpf_map_area_free(void *p){CHECK(p==allocation);free(p);allocation=NULL;}
static int bpf_array_alloc_percpu(struct bpf_array *a){return 0;}
static void bpf_array_free_percpu(struct bpf_array *a){}
static int rcu_sync;
static void synchronize_rcu(void){rcu_sync++;}
struct file {struct bpf_map *private_data;unsigned f_mode,refs;};
struct vm_operations_struct {void (*open)(struct vm_area_struct*);void (*close)(struct vm_area_struct*);};
struct vm_area_struct {unsigned long vm_start,vm_end,vm_pgoff,vm_flags;struct file *vm_file;const struct vm_operations_struct *vm_ops;void *vm_private_data;};
static struct file *selected_file;static int fdputs,bad_attr;
struct fd {struct file *file;};
static struct fd fdget(int n){return (struct fd){n==7?selected_file:NULL};}
static struct bpf_map *__bpf_map_get(struct fd f){return f.file?f.file->private_data:ERR_PTR(-EBADF);}
static void fdput(struct fd f){CHECK(f.file);fdputs++;}
#define CHECK_ATTR(x) (bad_attr)
static int remap_error,remap_calls;static unsigned long remap_offset;
static int remap_vmalloc_range(struct vm_area_struct *vma,void *base,unsigned long pgoff){
 CHECK(!vma->vm_file->private_data->freeze_mutex.locked);
 CHECK(base==allocation);CHECK(pgoff*PAGE_SIZE>=PAGE_ALIGN(sizeof(struct bpf_array)));
 CHECK(pgoff*PAGE_SIZE+vma->vm_end-vma->vm_start<=allocation_size);
 remap_calls++;remap_offset=pgoff;return remap_error;
}
#define __user
#define u64_to_user_ptr(x) ((void *)(uintptr_t)(x))
#define GFP_USER 0
#define __GFP_NOWARN 0
#define __this_cpu_inc(x) ((x)++)
#define __this_cpu_dec(x) ((x)--)
static int bpf_prog_active,copy_fail,copy_freeze,call_count;
static int map_freeze(const union bpf_attr *attr);
static void *memdup_user(void *p,size_t n){if(copy_fail==1)return ERR_PTR(-EFAULT);void *v=malloc(n);memcpy(v,p,n);return v;}
static void *kmalloc(size_t n,int f){return copy_fail==2?NULL:malloc(n);}
static int copy_from_user(void*d,void*s,size_t n){
 if(copy_freeze){union bpf_attr a={.map_fd=7};CHECK(map_freeze(&a)==-EBUSY);}
 if(copy_fail==3)return 1;memcpy(d,s,n);return 0;
}
static void kfree(void*p){free(p);}
static void preempt_disable(void){}static void preempt_enable(void){}
static void rcu_read_lock(void){}static void rcu_read_unlock(void){}
static void maybe_wait_bpf_programs(struct bpf_map*m){}
static void trace_bpf_map_update_elem(struct bpf_map*m,int fd,void*k,void*v){}
static void trace_bpf_map_delete_elem(struct bpf_map*m,int fd,void*k){}
static int bpf_percpu_hash_update(struct bpf_map*m,void*k,void*v,u64 f){abort();}
static int bpf_percpu_array_update(struct bpf_map*m,void*k,void*v,u64 f){abort();}
static int bpf_fd_array_map_update_elem(struct bpf_map*m,struct file*file,void*k,void*v,u64 f){abort();}
static int bpf_fd_htab_map_update_elem(struct bpf_map*m,struct file*file,void*k,void*v,u64 f){abort();}
static int update_backend(struct bpf_map*m,void*k,void*v,u64 f){call_count++;return copy_fail==4?-EINVAL:0;}
static int delete_backend(struct bpf_map*m,void*k){call_count++;return -EINVAL;}
#include "subject.h"
static struct bpf_map_ops ops;
static struct file file;
static struct bpf_map *make(unsigned flags,unsigned n,unsigned value){
 union bpf_attr attr={.map_type=BPF_MAP_TYPE_ARRAY,.key_size=4,.value_size=value,.max_entries=n,.map_flags=flags};
 struct bpf_map *m=array_map_alloc(&attr);
 if(!IS_ERR(m)){m->ops=&ops;file=(struct file){.private_data=m,.f_mode=FMODE_READ|FMODE_WRITE|FMODE_CAN_WRITE,.refs=1};selected_file=&file;}
 return m;
}
static struct vm_area_struct vma(unsigned flags,unsigned long off,unsigned long len){return (struct vm_area_struct){.vm_start=0x100000,.vm_end=0x100000+len,.vm_pgoff=off,.vm_flags=flags|VM_MAYEXEC,.vm_file=&file};}
static int freeze(void){union bpf_attr a={.map_fd=7};return map_freeze(&a);}
static void mapped(struct vm_area_struct *v){file.refs++;}
static void close_vma(struct vm_area_struct *v){v->vm_ops->close(v);CHECK(file.refs);if(!--file.refs)array_map_free(file.private_data);}
static unsigned poll_backend(struct bpf_map*m,struct file*f,struct poll_table_struct*p){CHECK(f->private_data==m);return 123;}
int main(void){
 ops.map_mmap=array_map_mmap;
 struct bpf_map *m=make(BPF_F_MMAPABLE,1024,8);CHECK(!IS_ERR(m));CHECK(m->map_flags==0x400);CHECK(allocation_mmap);
 struct bpf_array *a=container_of(m,struct bpf_array,map);CHECK(!((uintptr_t)a->value&(PAGE_SIZE-1)));CHECK(allocation_size==PAGE_ALIGN(sizeof(*a))+8192);
 for(size_t i=0;i<8192;i++)CHECK(a->value[i]==0);
 struct vm_area_struct v=vma(VM_SHARED|VM_WRITE|VM_MAYWRITE,1,4096);
 CHECK(!bpf_map_mmap(&file,&v));mapped(&v);CHECK(remap_offset==2);CHECK(m->writecnt==1);CHECK(!(v.vm_flags&VM_MAYEXEC));CHECK(freeze()==-EBUSY);
 /* split/fork: VM owns a new file reference and calls open for extra VMA */
 struct vm_area_struct split=v;file.refs++;split.vm_ops->open(&split);CHECK(m->writecnt==2);
 /* mprotect write->read retains MAYWRITE and must retain accounting */
 split.vm_flags&=~VM_WRITE;close_vma(&split);CHECK(m->writecnt==1);
 close_vma(&v);CHECK(!m->writecnt);CHECK(!freeze());CHECK(freeze()==-EBUSY);
 v=vma(VM_SHARED|VM_WRITE|VM_MAYWRITE,0,4096);CHECK(bpf_map_mmap(&file,&v)==-EPERM);CHECK(!m->writecnt);
 v=vma(VM_SHARED|VM_MAYWRITE,0,4096);CHECK(!bpf_map_mmap(&file,&v));mapped(&v);CHECK(!(v.vm_flags&VM_MAYWRITE));
 /* fd close does not destroy map while VMA file reference exists */
 CHECK(--file.refs==1);CHECK(allocation);close_vma(&v);CHECK(!allocation);CHECK(rcu_sync==1);
 m=make(BPF_F_MMAPABLE,1024,8);CHECK(!IS_ERR(m));
 unsigned long offsets[]={2,ULONG_MAX,ULONG_MAX/PAGE_SIZE+1};
 for(unsigned i=0;i<3;i++){v=vma(VM_SHARED,offsets[i],4096);CHECK(bpf_map_mmap(&file,&v)==-EINVAL);}
 v=vma(VM_SHARED,1,8192);CHECK(bpf_map_mmap(&file,&v)==-EINVAL);
 v=vma(VM_SHARED,0,0);CHECK(bpf_map_mmap(&file,&v)==-EINVAL);
 v=vma(VM_SHARED,0,4095);CHECK(bpf_map_mmap(&file,&v)==-EINVAL);
 v=vma(VM_SHARED|VM_EXEC,0,4096);CHECK(bpf_map_mmap(&file,&v)==-EACCES);
 v=vma(0,0,4096);CHECK(bpf_map_mmap(&file,&v)==-EINVAL);
 m->map_flags|=BPF_F_RDONLY_PROG;v=vma(VM_SHARED|VM_WRITE|VM_MAYWRITE,0,4096);CHECK(bpf_map_mmap(&file,&v)==-EACCES);m->map_flags&=~BPF_F_RDONLY_PROG;
 file.f_mode=FMODE_READ;CHECK(bpf_map_mmap(&file,&v)==-EACCES);file.f_mode=FMODE_READ|FMODE_WRITE|FMODE_CAN_WRITE;
 remap_error=-ENOMEM;CHECK(bpf_map_mmap(&file,&v)==-ENOMEM);CHECK(!m->writecnt);CHECK(!v.vm_ops);remap_error=0;
 CHECK(!map_write_begin(m,(struct fd){&file}));CHECK(freeze()==-EBUSY);bpf_map_write_active_dec(m);CHECK(!freeze());CHECK(map_write_begin(m,(struct fd){&file})==-EPERM);CHECK(!m->writecnt);
 CHECK(bpf_map_poll(&file,NULL)==POLLERR);ops.map_poll=poll_backend;CHECK(bpf_map_poll(&file,NULL)==123);ops.map_poll=NULL;
 array_map_free(m);
 m=make(0,5,3);CHECK(!IS_ERR(m));CHECK(!allocation_mmap);v=vma(VM_SHARED,0,4096);CHECK(bpf_map_mmap(&file,&v)==-EINVAL);array_map_free(m);
 m=make(BPF_F_MMAPABLE,5,3);CHECK(!IS_ERR(m));CHECK(container_of(m,struct bpf_array,map)->elem_size==8);v=vma(VM_SHARED,0,4096);CHECK(!bpf_map_mmap(&file,&v));mapped(&v);close_vma(&v);array_map_free(m);
 /* Speculation padding is allocated but not exposed past visible pages. */
 privileged=0;m=make(BPF_F_MMAPABLE,3,4096);CHECK(!IS_ERR(m));CHECK(allocation_size==PAGE_ALIGN(sizeof(*a))+4*PAGE_SIZE);
 v=vma(VM_SHARED,3,4096);CHECK(bpf_map_mmap(&file,&v)==-EINVAL);v=vma(VM_SHARED,2,4096);CHECK(!bpf_map_mmap(&file,&v));mapped(&v);close_vma(&v);array_map_free(m);privileged=1;
 union bpf_attr attr={.map_type=BPF_MAP_TYPE_PERCPU_ARRAY,.key_size=4,.value_size=8,.max_entries=1024,.map_flags=BPF_F_MMAPABLE};CHECK(PTR_ERR(array_map_alloc(&attr))==-EINVAL);
 attr.map_type=BPF_MAP_TYPE_PROG_ARRAY;CHECK(PTR_ERR(array_map_alloc(&attr))==-EINVAL);
 attr.map_type=BPF_MAP_TYPE_ARRAY;attr.map_flags|=BPF_F_RDONLY_PROG;CHECK(PTR_ERR(array_map_alloc(&attr))==-EINVAL);
 alloc_fail=1;CHECK(PTR_ERR(make(BPF_F_MMAPABLE,1024,8))==-ENOMEM);alloc_fail=0;
 charge_fail=1;CHECK(PTR_ERR(make(BPF_F_MMAPABLE,1024,8))==-EPERM);charge_fail=0;
 CHECK(PTR_ERR(make(BPF_F_MMAPABLE,UINT32_MAX,KMALLOC_MAX_SIZE))==-ENOMEM);
 m=make(BPF_F_MMAPABLE,1024,8);privileged=0;CHECK(freeze()==-EPERM);privileged=1;bad_attr=1;CHECK(freeze()==-EINVAL);bad_attr=0;
 union bpf_attr fa={.map_fd=99};CHECK(map_freeze(&fa)==-EBADF);m->map_type=BPF_MAP_TYPE_HASH;CHECK(freeze()==-EOPNOTSUPP);m->map_type=BPF_MAP_TYPE_ARRAY;array_map_free(m);
 m=make(BPF_F_MMAPABLE,1024,8);ops.map_update_elem=update_backend;ops.map_delete_elem=delete_backend;
 u32 key=0;u64 val=9;union bpf_attr ua={.map_fd=7,.key=(uintptr_t)&key,.value=(uintptr_t)&val};
 copy_freeze=1;CHECK(!map_update_elem(&ua));CHECK(call_count==1);CHECK(!m->writecnt);copy_freeze=0;
 for(int fail=1;fail<=4;fail++){copy_fail=fail;CHECK(map_update_elem(&ua)<0);CHECK(!m->writecnt);}
 copy_fail=1;CHECK(map_delete_elem(&ua)==-EFAULT);CHECK(!m->writecnt);copy_fail=0;CHECK(map_delete_elem(&ua)==-EINVAL);CHECK(!m->writecnt);
 CHECK(!freeze());int calls=call_count;CHECK(map_update_elem(&ua)==-EPERM);CHECK(map_delete_elem(&ua)==-EPERM);CHECK(call_count==calls);CHECK(!m->writecnt);CHECK(!bpf_prog_active);array_map_free(m);
 puts("PASS allocation, offsets, permissions, VMA ownership, freeze, write accounting, poll, failures");return 0;
}

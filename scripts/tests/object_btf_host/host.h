/* SPDX-License-Identifier: GPL-2.0 */
/* Only kernel services are simulated. No BTF parsing/validation here. */
#ifndef OBJECT_BTF_HOST_H
#define OBJECT_BTF_HOST_H
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "linux/types.h"
typedef __u8 u8;
typedef __s8 s8;
typedef __u16 u16;
typedef __s16 s16;
typedef __u32 u32;
typedef __s32 s32;
typedef __u64 u64;
typedef __s64 s64;
#define __user
#define __force
#define __printf(a,b) __attribute__((format(printf,a,b)))
#define CONFIG_BPF_SYSCALL 1
#define CONFIG_PROC_FS 1
#define ENOTSUPP 524
#define GFP_KERNEL 0
#define GFP_ATOMIC 0
#define __GFP_NOWARN 0
#define __GFP_ZERO 1
#define U32_MAX UINT32_MAX
#define S32_MAX INT32_MAX
#define BITS_PER_BYTE 8
#define KSYM_NAME_LEN 128
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#define min(a,b) ({ __auto_type _a=(a); __auto_type _b=(b); _a < _b ? _a : _b; })
#define max(a,b) ({ __auto_type _a=(a); __auto_type _b=(b); _a > _b ? _a : _b; })
#define min_t(t,a,b) min((t)(a),(t)(b))
#define max_t(t,a,b) max((t)(a),(t)(b))
#define container_of(p,t,m) ((t *)((char *)(p) - offsetof(t,m)))
#define ERR_PTR(e) ((void *)(intptr_t)(e))
#define PTR_ERR(p) ((long)(intptr_t)(p))
#define IS_ERR(p) ((uintptr_t)(p) >= (uintptr_t)-4095)
#define WARN_ON_ONCE(x) (!!(x))
#define WARN_ONCE(x,...) ((void)(x))
#define BUG() abort()
static bool is_power_of_2(unsigned long n) { return n && !(n & (n-1)); }
#define CHECK(x) do { if (!(x)) { fprintf(stderr,"%s:%d: CHECK(%s)\n",__FILE__,__LINE__,#x); exit(1); } } while (0)

struct host_allocation { void *p; size_t n; };
static struct host_allocation host_allocs[128];
static unsigned host_alloc_calls, host_fail_alloc, host_frees, host_live, host_alloc_successes;
typedef struct { unsigned refs; } refcount_t;
static refcount_t *host_refcounts[64];
static unsigned host_ref_sets, host_ref_incs, host_ref_decs, host_ref_unpublished;
static void *host_alloc(size_t n, bool zero)
{
	unsigned i;
	host_alloc_calls++;
	if (host_fail_alloc == host_alloc_calls) return NULL;
	void *p = zero ? calloc(1, n ?: 1) : malloc(n ?: 1);
	CHECK(p);
	for (i=0; i<ARRAY_SIZE(host_allocs); i++) if (!host_allocs[i].p) break;
	CHECK(i < ARRAY_SIZE(host_allocs));
	host_allocs[i] = (struct host_allocation){p,n};
	host_live++; host_alloc_successes++;
	return p;
}
static void host_free(const void *p)
{
	if (!p) return;
	unsigned i,j;
	for (i=0; i<ARRAY_SIZE(host_allocs); i++) if (host_allocs[i].p == p) break;
	CHECK(i < ARRAY_SIZE(host_allocs));
	for (j=0; j<ARRAY_SIZE(host_refcounts); j++)
		if ((uintptr_t)host_refcounts[j] >= (uintptr_t)p &&
		    (uintptr_t)host_refcounts[j] < (uintptr_t)p + host_allocs[i].n)
			{ host_ref_unpublished += host_refcounts[j]->refs; host_refcounts[j] = NULL; }
	host_allocs[i].p = NULL;
	host_live--; host_frees++;
	free((void *)p);
}
#define kzalloc(n,f) host_alloc((n),true)
#define kvmalloc(n,f) host_alloc((n),!!((f)&__GFP_ZERO))
static void *kvmalloc_array(size_t n, size_t s, unsigned flags)
{
	if (s && n > SIZE_MAX/s) return NULL;
	return host_alloc(n*s, !!(flags & __GFP_ZERO));
}
#define kvcalloc(n,s,f) kvmalloc_array(n,s,(f)|__GFP_ZERO)
#define kvfree(p) host_free(p)
#define kfree(p) host_free(p)
static void refcount_set(refcount_t *r, unsigned n)
{
	unsigned i;
	for (i=0;i<ARRAY_SIZE(host_refcounts);i++) if (!host_refcounts[i]) break;
	CHECK(i<ARRAY_SIZE(host_refcounts)); host_refcounts[i]=r; r->refs=n; host_ref_sets+=n;
}
static void refcount_inc(refcount_t *r) { CHECK(r->refs && r->refs<UINT_MAX); r->refs++; host_ref_incs++; }
static bool refcount_inc_not_zero(refcount_t *r) { if (!r->refs) return false; refcount_inc(r); return true; }
static bool refcount_dec_and_test(refcount_t *r) { CHECK(r->refs); host_ref_decs++; return !--r->refs; }

struct rcu_head { struct rcu_head *next; void (*fn)(struct rcu_head *); };
static struct rcu_head *host_rcu_queue[64];
static unsigned host_rcu_count, host_rcu_reads, host_graces, host_rcu_calls, host_rcu_frees;
static void rcu_read_lock(void) { host_rcu_reads++; }
static void rcu_read_unlock(void) { CHECK(host_rcu_reads); host_rcu_reads--; }
static void call_rcu(struct rcu_head *r, void (*fn)(struct rcu_head *))
{
	CHECK(host_rcu_count<ARRAY_SIZE(host_rcu_queue));
	for (unsigned i=0;i<host_rcu_count;i++) CHECK(host_rcu_queue[i]!=r);
	host_rcu_calls++; r->fn=fn; host_rcu_queue[host_rcu_count++]=r;
}
static void host_grace(void)
{
	CHECK(!host_rcu_reads); host_graces++;
	while (host_rcu_count) { struct rcu_head *r=host_rcu_queue[--host_rcu_count]; r->fn(r); host_rcu_frees++; }
}
struct idr { void *slots[256]; unsigned next; };
#define DEFINE_IDR(n) struct idr n = {.next=1}
#define DEFINE_SPINLOCK(n) int n
static unsigned host_locks, host_ids, host_id_adds, host_id_removes, host_preloads;
static bool host_fail_idr;
#define spin_lock_bh(p) do { (void)(p); CHECK(!host_locks); host_locks++; } while(0)
#define spin_unlock_bh(p) do { (void)(p); CHECK(host_locks==1); host_locks--; } while(0)
#define spin_lock_irqsave(p,f) do { (f)=0; spin_lock_bh(p); } while(0)
#define spin_unlock_irqrestore(p,f) do { (void)(f); spin_unlock_bh(p); } while(0)
static void idr_preload(unsigned flags) { (void)flags; host_preloads++; }
static void idr_preload_end(void) { CHECK(host_preloads); host_preloads--; }
static int idr_alloc_cyclic(struct idr *idr, void *p, int start, int end, unsigned flags)
{
	(void)flags; CHECK(host_locks && host_preloads); CHECK(start==1 && end==INT_MAX);
	if (host_fail_idr) return -ENOSPC;
	for (unsigned i=0;i<255;i++) {
		unsigned id=idr->next; idr->next=id==255?1:id+1;
		if (!idr->slots[id]) { idr->slots[id]=p; host_ids++; host_id_adds++; return (int)id; }
	}
	return -ENOSPC;
}
static void idr_remove(struct idr *idr, unsigned id)
{
	CHECK(host_locks && id<256 && idr->slots[id]);
	idr->slots[id]=NULL; host_ids--; host_id_removes++;
}
static void *idr_find(struct idr *idr, unsigned id) { CHECK(host_rcu_reads); return id<256?idr->slots[id]:NULL; }

struct inode { int unused; };
struct seq_file { int unused; };
struct file;
struct file_operations {
	int (*release)(struct inode *,struct file *);
	void (*show_fdinfo)(struct seq_file *,struct file *);
};
struct file { const struct file_operations *f_op; void *private_data; unsigned f_count; };
struct fd { struct file *file; };
static struct file host_files[64];
static unsigned host_fds, host_fd_gets, host_fd_puts, host_fd_opens, host_fd_closes;
static bool host_fail_fd;
static int anon_inode_getfd(const char *name, const struct file_operations *ops, void *data, int flags)
{
	CHECK((!strcmp(name,"btf") && flags==(O_RDONLY|O_CLOEXEC)) ||
	      (!strcmp(name,"bpf-map") && (flags&O_CLOEXEC)));
	if (host_fail_fd) return -EMFILE;
	for (unsigned i=4;i<ARRAY_SIZE(host_files);i++) if (!host_files[i].f_count) {
		host_files[i]=(struct file){ops,data,1}; host_fds++; host_fd_opens++; return (int)i;
	}
	return -EMFILE;
}
static struct fd fdget(int fd)
{
	if (fd<0 || (unsigned)fd>=ARRAY_SIZE(host_files) || !host_files[fd].f_count) return (struct fd){0};
	host_files[fd].f_count++; host_fd_gets++; return (struct fd){&host_files[fd]};
}
static void fdput(struct fd f) { CHECK(f.file && f.file->f_count>1); f.file->f_count--; host_fd_puts++; }
static void host_close(int fd)
{
	CHECK(fd>=0 && (unsigned)fd<ARRAY_SIZE(host_files) && host_files[fd].f_count==1);
	host_files[fd].f_count=0; host_fds--; host_fd_closes++;
	CHECK(host_files[fd].f_op->release(NULL,&host_files[fd])==0);
	host_files[fd].private_data=NULL;
}
static long host_input_limit=-1;
static unsigned host_from_calls,host_to_calls,host_fail_to;
static bool host_mutate_input;
static unsigned long copy_from_user(void *to,const void *from,unsigned long n)
{
	host_from_calls++;
	size_t copied=host_input_limit<0?n:min(n,(unsigned long)host_input_limit);
	if (copied) memcpy(to,from,copied);
	if (host_mutate_input && n) ((u8 *)from)[0]^=0xff;
	return n-copied;
}
static unsigned long copy_to_user(void *to,const void *from,unsigned long n)
{
	host_to_calls++;
	if (host_fail_to==host_to_calls) { if (n && to) memcpy(to,from,1); return n?:1; }
	if (n) { CHECK(to); memcpy(to,from,n); }
	return 0;
}
#define put_user(v,p) ({ __typeof__(*(p)) _v=(v); copy_to_user((p),&_v,sizeof(_v)); })
#define u64_to_user_ptr(x) ((void *)(uintptr_t)(x))
static int vscnprintf(char *s,size_t n,const char *fmt,va_list ap)
{
	int r=vsnprintf(s,n,fmt,ap); return r<0?0:((size_t)r>=n?(int)n-1:r);
}
static void sort(void *base,size_t n,size_t size,int (*cmp)(const void *,const void *),void *swap)
{ CHECK(!swap); qsort(base,n,size,cmp); }
/* Seq output remains linked for the untouched ops table, but is not exercised. */
static void seq_printf(struct seq_file *m,const char *fmt,...) { (void)m; (void)fmt; }
static void seq_puts(struct seq_file *m,const char *s) { (void)m; (void)s; }
static void host_balanced(void)
{
	CHECK(!host_fds && !host_ids && !host_locks && !host_preloads && !host_rcu_reads);
	CHECK(host_fd_gets==host_fd_puts && host_fd_opens==host_fd_closes);
	CHECK(host_id_adds==host_id_removes);
	host_grace(); CHECK(!host_live && !host_rcu_count);
	CHECK(host_alloc_successes==host_frees && host_rcu_calls==host_rcu_frees);
	CHECK(host_ref_sets+host_ref_incs==host_ref_decs+host_ref_unpublished);
	for (unsigned i=0;i<ARRAY_SIZE(host_refcounts);i++) CHECK(!host_refcounts[i]);
}
static void host_reset_faults(void)
{ host_fail_alloc=0;host_fail_fd=false;host_fail_idr=false;host_input_limit=-1;host_mutate_input=false;host_fail_to=0; }
#endif

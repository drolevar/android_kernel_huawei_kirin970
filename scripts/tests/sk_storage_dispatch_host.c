/* SPDX-License-Identifier: GPL-2.0 */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#define IS_ERR(p) ((uintptr_t)(p) >= (uintptr_t)-4095L)
#define PTR_ERR(p) ((long)(p))
static int depth, calls, syscalls;
static void rcu_read_lock(void) { depth++; }
static void rcu_read_unlock(void) { assert(depth); depth--; }
struct bpf_map;
struct ops { void *(*map_lookup_elem)(struct bpf_map *, void *); void *(*map_lookup_elem_sys_only)(struct bpf_map *, void *); };
struct bpf_map { struct ops *ops; void *answer; };
static void *lookup(struct bpf_map *m, void *k) { assert(depth); calls++; return m->answer; }
static void *sys_lookup(struct bpf_map *m, void *k) { assert(depth); syscalls++; return m->answer; }
static void *checked_copy(void *d, const void *s, size_t n) { assert(depth); assert(!IS_ERR(s)); return memcpy(d,s,n); }
#define memcpy checked_copy
#include "dispatch.h"
int main(int argc,char **argv) {
    assert(argc==2); int value=123,out=0,err; struct ops ops={lookup,NULL}; struct bpf_map map={&ops,&value};
    if (strstr(argv[1],"null")) map.answer=NULL;
    if (strstr(argv[1],"error")) map.answer=(void *)-EBADF;
    if (strstr(argv[1],"sys_only")) ops.map_lookup_elem_sys_only=sys_lookup;
    err=dispatch(&map,NULL,&out,sizeof(out)); assert(!depth);
    assert(calls+syscalls==1); assert(syscalls==!!ops.map_lookup_elem_sys_only);
    assert(err==(IS_ERR(map.answer)?-EBADF:map.answer?0:-ENOENT));
    if(!err) assert(out==123);
    puts("PASS: single callback, ERR_PTR/NULL/value, RCU copy");
}

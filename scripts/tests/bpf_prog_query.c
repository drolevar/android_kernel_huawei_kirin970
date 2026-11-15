/* SPDX-License-Identifier: GPL-2.0 */
/* Host boundaries for verbatim production functions. No kernel/phone access. */
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include BPF_UAPI_HEADER

typedef uint32_t u32;
typedef unsigned int gfp_t;
#define __rcu
#define __user
#define GFP_USER 1U
#define __GFP_NOWARN 2U
#define CONFIG_CGROUP_BPF 1
#define CAP_NET_ADMIN 12
#define CAP_SYS_ADMIN 21
#define CHECK(x) do { if (!(x)) { \
	fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #x); exit(1); \
} } while (0)
#define READ_ONCE(x) read_prog_once(&(x))
#define WRITE_ONCE(x, v) (*(volatile __typeof__(x) *)&(x) = (v))
#define container_of(p, t, m) ((t *)((char *)(p) - offsetof(t, m)))
#define u64_to_user_ptr(x) ((void *)(uintptr_t)(x))
struct rcu_head { void *next; };
struct bpf_prog_aux { u32 id; };
struct bpf_prog { struct bpf_prog_aux *aux; };
/* A dummy has no aux: production code must skip it before ID access. */
static struct { struct bpf_prog prog; } dummy_bpf_prog;
#include "declarations.h"
struct cgroup { struct cgroup_bpf bpf; };
static int rcu_depth, cgroup_mutex, alloc_calls, copy_calls, fail_copy;
static int refs, fd_gets, fd_puts, fail_fd, has_net_admin = 1, has_sys_admin = 1;
static int sysctl_unprivileged_bpf_disabled, security_error;
static bool fail_alloc, require_mutex;
static size_t allocated_slots;
static struct cgroup target;
static struct bpf_prog_array *release_array;
static struct bpf_prog *release_prog;
static struct bpf_prog_array *delete_array;
static struct bpf_prog **delete_slot;
void bpf_prog_array_delete_safe(struct bpf_prog_array *progs,
				struct bpf_prog *old_prog);
static struct bpf_prog *read_prog_once(struct bpf_prog **slot)
{
	struct bpf_prog *p = *(struct bpf_prog *volatile *)slot;

	if (slot == delete_slot) {
		delete_slot = NULL;
		/* Deterministically interleave the real safe-delete operation. */
		bpf_prog_array_delete_safe(delete_array, p);
	}
	return p;
}

static void rcu_read_lock(void) { CHECK(!rcu_depth); rcu_depth++; }
static void rcu_read_unlock(void)
{
	CHECK(rcu_depth == 1);
	rcu_depth--;
	/* Model immediate reclamation once the read-side section ends. */
	free(release_array);
	release_array = NULL;
	if (release_prog) {
		free(release_prog->aux);
		free(release_prog);
		release_prog = NULL;
	}
}
#define rcu_dereference(x) ({ CHECK(rcu_depth); (x); })
static void *kcalloc(size_t count, size_t size, gfp_t flags)
{
	CHECK(!rcu_depth);
	CHECK(flags & GFP_USER);
	allocated_slots = count;
	alloc_calls++;
	if (fail_alloc || (size && count > SIZE_MAX / size))
		return NULL;
	return calloc(count, size);
}
static void kfree(void *p) { CHECK(!rcu_depth); free(p); }
static unsigned long copy_to_user(void *to, const void *from, size_t length)
{
	CHECK(!rcu_depth);
	CHECK(!require_mutex || cgroup_mutex == 1);
	copy_calls++;
	if (copy_calls == fail_copy)
		return length;
	memcpy(to, from, length);
	return 0;
}
static void mutex_lock(int *m) { CHECK(!*m); *m = 1; }
static void mutex_unlock(int *m) { CHECK(*m == 1); *m = 0; }
static int capable(int cap)
{
	return cap == CAP_NET_ADMIN ? has_net_admin : has_sys_admin;
}
#define IS_ERR(p) ((uintptr_t)(p) >= (uintptr_t)-4095)
#define PTR_ERR(p) ((int)(intptr_t)(p))
static struct cgroup *cgroup_get_from_fd(u32 fd)
{
	fd_gets++;
	if (fail_fd || fd != 42)
		return (void *)(intptr_t)-EBADF;
	refs++;
	return &target;
}
static void cgroup_put(struct cgroup *cgrp)
{
	CHECK(cgrp == &target && refs == 1 && !cgroup_mutex);
	refs--;
	fd_puts++;
}
static void *memchr_inv(const void *p, int value, size_t size)
{
	const unsigned char *s = p;
	for (size_t i = 0; i < size; i++)
		if (s[i] != value)
			return (void *)(s + i);
	return NULL;
}
#define SYSCALL_DEFINE3(name, t1, a1, t2, a2, t3, a3) \
	static int sys_##name(t1 a1, t2 a2, t3 a3)
#define min_t(t, a, b) ((t)(a) < (t)(b) ? (t)(a) : (t)(b))
static int check_uarg_tail_zero(const void *p, size_t known, size_t size)
{
	return size > known && memchr_inv((const char *)p + known, 0, size - known) ? -E2BIG : 0;
}
static int copy_from_user(void *to, const void *from, size_t size)
{
	memcpy(to, from, size);
	return 0;
}
static int security_bpf(int cmd, const union bpf_attr *attr, unsigned int size)
{
	(void)cmd; (void)attr; (void)size;
	return security_error;
}
#define kshield_chk_heap_spray(x) ((void)(x))
/* Unrelated syscall commands are outside this fixture. */
#define map_create(...) (-EOPNOTSUPP)
#define map_lookup_elem(...) (-EOPNOTSUPP)
#define map_update_elem(...) (-EOPNOTSUPP)
#define map_delete_elem(...) (-EOPNOTSUPP)
#define map_get_next_key(...) (-EOPNOTSUPP)
#define bpf_prog_load(...) (-EOPNOTSUPP)
#define bpf_obj_pin(...) (-EOPNOTSUPP)
#define bpf_obj_get(...) (-EOPNOTSUPP)
#define bpf_prog_attach(...) (-EOPNOTSUPP)
#define bpf_prog_detach(...) (-EOPNOTSUPP)
#define bpf_prog_test_run(...) (-EOPNOTSUPP)
#define bpf_obj_get_next_id(...) (-EOPNOTSUPP)
#define bpf_prog_get_fd_by_id(...) (-EOPNOTSUPP)
#define bpf_map_get_fd_by_id(...) (-EOPNOTSUPP)
#define bpf_obj_get_info_by_fd(...) (-EOPNOTSUPP)
/* BTF has its own actual-source fixture; query tests do not invoke it. */
#define bpf_btf_load(...) (-EOPNOTSUPP)
#define bpf_btf_get_fd_by_id(...) (-EOPNOTSUPP)
#include "subject.h"

_Static_assert(BPF_PROG_QUERY == 16, "command ABI");
_Static_assert(offsetof(union bpf_attr, query.prog_ids) == 16, "ID pointer ABI");
_Static_assert(offsetof(union bpf_attr, query.prog_cnt) == 24, "count ABI");

static struct bpf_prog_aux aux[] = { { 11 }, { 22 }, { 33 } };
static struct bpf_prog programs[] = { { &aux[0] }, { &aux[1] }, { &aux[2] } };
#define P(n) (&programs[n])
#define D (&dummy_bpf_prog.prog)
#define CANARY 0xa5a5a5a5U
static struct bpf_prog_array *array(struct bpf_prog **entries, size_t count)
{
	struct bpf_prog_array *a = calloc(1, sizeof(*a) + (count + 1) * sizeof(*entries));
	CHECK(a);
	if (count)
		memcpy(a->progs, entries, count * sizeof(*entries));
	return a;
}
static void init_target(void)
{
	memset(&target, 0, sizeof(target));
	for (unsigned int i = 0; i < MAX_BPF_ATTACH_TYPE; i++) {
		struct list_head *head = &target.bpf.progs[i];
		head->prev = head->next = head;
	}
}
static void add(struct bpf_prog_list *pl, struct bpf_prog *p, unsigned int type)
{
	struct list_head *head = &target.bpf.progs[type];
	pl->prog = p;
	pl->node.next = head;
	pl->node.prev = head->prev;
	head->prev->next = &pl->node;
	head->prev = &pl->node;
}
static union bpf_attr attr_for(u32 *ids, u32 count, bool effective)
{
	union bpf_attr attr = {};
	attr.query.target_fd = 42;
	attr.query.attach_type = BPF_CGROUP_INET_INGRESS;
	attr.query.query_flags = effective ? BPF_F_QUERY_EFFECTIVE : 0;
	attr.query.prog_ids = (uintptr_t)ids;
	attr.query.prog_cnt = count;
	return attr;
}
static int query(union bpf_attr *attr)
{
	require_mutex = true;
	/* Numeric cmd16 must enter the real production syscall dispatch. */
	int ret = sys_bpf(16, attr, sizeof(*attr));
	CHECK(!rcu_depth && !cgroup_mutex && !refs);
	require_mutex = false;
	return ret;
}
static void core_empty(void)
{
	struct bpf_prog_array *a = array(NULL, 0);
	u32 ids[] = { CANARY, CANARY };
	CHECK(bpf_prog_array_length(a) == 0);
	CHECK(bpf_prog_array_copy_to_user(a, ids, 0) == 0);
	CHECK(ids[0] == CANARY && !alloc_calls && !copy_calls);
	CHECK(bpf_prog_array_copy_to_user(a, ids, 1) == 0);
	CHECK(ids[0] == 0 && ids[1] == CANARY);
	free(a);
	a = array((struct bpf_prog *[]){P(0)}, 1);
	CHECK(bpf_prog_array_copy_to_user(a, ids, 0) == 0);
	CHECK(ids[0] == 0 && ids[1] == CANARY);
	CHECK(alloc_calls == 1 && copy_calls == 1);
	free(a);
}
static void core_dummy(bool trailing)
{
	struct bpf_prog *entries[] = { D, P(0), D, P(1), D, D };
	struct bpf_prog_array *a = array(entries, 6);
	u32 ids[] = { CANARY, CANARY, CANARY, CANARY };
	if (trailing) {
		CHECK(bpf_prog_array_copy_to_user(a, ids + 1, 2) == 0);
	} else {
		CHECK(bpf_prog_array_length(a) == 2);
		CHECK(bpf_prog_array_copy_to_user(a, ids + 1, 2) == 0);
	}
	CHECK(ids[0] == CANARY && ids[1] == 11 && ids[2] == 22 && ids[3] == CANARY);
	free(a);
	a = array((struct bpf_prog *[]){D, D}, 2);
	CHECK(bpf_prog_array_length(a) == 0);
	CHECK(bpf_prog_array_copy_to_user(a, ids, 2) == 0);
	CHECK(ids[0] == 0 && ids[1] == 0);
	free(a);
}
static void delete_after_read(void)
{
	struct bpf_prog_array *a = array((struct bpf_prog *[]){P(0)}, 1);
	u32 ids[] = { CANARY, CANARY, CANARY };

	delete_array = a;
	delete_slot = &a->progs[0];
	CHECK(bpf_prog_array_length(a) == 1);
	CHECK(bpf_prog_array_length(a) == 0);
	free(a);
	a = array((struct bpf_prog *[]){P(0)}, 1);
	delete_array = a;
	delete_slot = &a->progs[0];
	CHECK(bpf_prog_array_copy_to_user(a, ids + 1, 1) == 0);
	CHECK(ids[0] == CANARY && ids[1] == 11 && ids[2] == CANARY);
	CHECK(bpf_prog_array_length(a) == 0);
	free(a);
}
static void ancestor_count(void)
{
	struct bpf_prog *entries[70];
	u32 ids[72];

	for (unsigned int i = 0; i < 70; i++)
		entries[i] = P(0);
	for (unsigned int i = 0; i < 72; i++)
		ids[i] = CANARY;
	struct bpf_prog_array *a = array(entries, 70);
	init_target();
	target.bpf.effective[0] = a;
	union bpf_attr attr = attr_for(ids + 1, UINT32_MAX, true);
	CHECK(query(&attr) == 0 && attr.query.prog_cnt == 70);
	CHECK(allocated_slots == 70 && ids[0] == CANARY && ids[71] == CANARY);
	for (unsigned int i = 1; i <= 70; i++)
		CHECK(ids[i] == 11);
	free(a);
}
static void short_query(void)
{
	struct bpf_prog_list pl[3];
	struct bpf_prog *entries[] = { P(0), D, P(1), P(2) };
	struct bpf_prog_array *a = array(entries, 4);
	u32 ids[] = { CANARY, CANARY, CANARY };
	init_target();
	for (int i = 0; i < 3; i++)
		add(&pl[i], P(i), 0);
	target.bpf.effective[0] = a;
	for (int effective = 0; effective < 2; effective++) {
		union bpf_attr attr = attr_for(ids + 1, 1, effective);
		CHECK(query(&attr) == -ENOSPC);
		CHECK(attr.query.prog_cnt == 3 && ids[1] == 11);
		CHECK(ids[0] == CANARY && ids[2] == CANARY);
	}
	free(a);
}
static void snapshot(void)
{
	struct bpf_prog *p = malloc(sizeof(*p));
	CHECK(p);
	p->aux = malloc(sizeof(*p->aux));
	CHECK(p->aux);
	p->aux->id = 99;
	struct bpf_prog_array *a = array((struct bpf_prog *[]){p, D}, 2);
	u32 ids[] = { CANARY, CANARY, CANARY };
	release_array = a;
	release_prog = p;
	CHECK(bpf_prog_array_copy_to_user(a, ids + 1, 1) == 0);
	CHECK(!release_array && !release_prog);
	CHECK(ids[0] == CANARY && ids[1] == 99 && ids[2] == CANARY);
}
static void shrink(void)
{
	struct bpf_prog_array *before = array((struct bpf_prog *[]){P(0), P(1), P(2)}, 3);
	u32 count = bpf_prog_array_length(before);
	CHECK(count == 3);
	for (unsigned int n = 0; n < 2; n++) {
		struct bpf_prog_array *after = array((struct bpf_prog *[]){P(2)}, n);
		u32 ids[] = { CANARY, CANARY, CANARY, CANARY, CANARY };
		CHECK(bpf_prog_array_copy_to_user(after, ids + 1, count) == 0);
		CHECK(ids[0] == CANARY && ids[1] == (n ? 33 : 0));
		CHECK(ids[2] == 0 && ids[3] == 0 && ids[4] == CANARY);
		free(after);
	}
	free(before);
}
static void errors(void)
{
	struct bpf_prog_list direct[2];
	struct bpf_prog_array *a = array((struct bpf_prog *[]){P(0), P(1)}, 2);
	u32 ids[] = { CANARY, CANARY, CANARY };
	fail_alloc = true;
	CHECK(bpf_prog_array_copy_to_user(a, ids + 1, 1) == -ENOMEM);
	CHECK(!copy_calls && ids[1] == CANARY);
	fail_alloc = false;
	fail_copy = 1;
	CHECK(bpf_prog_array_copy_to_user(a, ids + 1, 1) == -EFAULT);
	CHECK(ids[0] == CANARY && ids[1] == CANARY && ids[2] == CANARY);
	init_target();
	target.bpf.effective[0] = a;
	add(&direct[0], P(0), 0);
	add(&direct[1], P(1), 0);
	for (int effective = 0; effective < 2; effective++)
	for (int i = 1; i <= 3; i++) {
		union bpf_attr attr = attr_for(ids + 1, 1, effective);
		copy_calls = 0;
		fail_copy = i; /* flags, count, then IDs; EFAULT wins over ENOSPC */
		CHECK(query(&attr) == -EFAULT);
		CHECK(ids[1] == CANARY);
	}
	fail_copy = 0;
	fail_alloc = true;
	union bpf_attr attr = attr_for(ids + 1, 1, true);
	CHECK(query(&attr) == -ENOMEM);
	CHECK(attr.query.prog_cnt == 2);
	free(a);
}
static void queries(void)
{
	struct bpf_prog_list direct[4];
	/* Effective order represents child followed by two inherited IDs. */
	struct bpf_prog_array *a = array((struct bpf_prog *[]){P(2), P(0), P(1)}, 3);
	init_target();
	for (unsigned int type = 0; type <= BPF_CGROUP_SOCK_OPS; type++) {
		u32 ids[] = { CANARY, CANARY, CANARY, CANARY, CANARY };
		add(&direct[type], P(2), type);
		target.bpf.flags[type] = BPF_F_ALLOW_MULTI;
		target.bpf.effective[type] = a;
		union bpf_attr attr = attr_for(ids + 1, 3, false);
		attr.query.attach_type = type;
		CHECK(query(&attr) == 0);
		CHECK(attr.query.prog_cnt == 1 && attr.query.attach_flags == BPF_F_ALLOW_MULTI);
		CHECK(ids[0] == CANARY && ids[1] == 33 && ids[2] == CANARY);
		attr.query.query_flags = BPF_F_QUERY_EFFECTIVE;
		attr.query.prog_cnt = 3;
		CHECK(query(&attr) == 0);
		CHECK(attr.query.prog_cnt == 3 && attr.query.attach_flags == BPF_F_ALLOW_MULTI);
		CHECK(ids[0] == CANARY && ids[1] == 33 && ids[2] == 11 && ids[3] == 22 && ids[4] == CANARY);
	}
	free(a);
}
static void count_queries(void)
{
	struct bpf_prog_list direct;
	struct bpf_prog_array *a = array((struct bpf_prog *[]){P(0)}, 1);
	u32 ids[] = { CANARY, CANARY, CANARY };
	init_target();
	target.bpf.effective[0] = a;
	add(&direct, P(0), 0);
	for (int effective = 0; effective < 2; effective++) {
		union bpf_attr attr = attr_for((void *)(uintptr_t)1, 0, effective);
		CHECK(query(&attr) == 0 && attr.query.prog_cnt == 1);
		attr = attr_for(NULL, UINT32_MAX, effective);
		CHECK(query(&attr) == 0 && attr.query.prog_cnt == 1);
		CHECK(!alloc_calls);
	}
	for (int effective = 0; effective < 2; effective++) {
		union bpf_attr attr = attr_for(ids + 1, UINT32_MAX, effective);
		CHECK(query(&attr) == 0 && attr.query.prog_cnt == 1);
		CHECK(ids[0] == CANARY && ids[1] == 11 && ids[2] == CANARY);
		CHECK(!effective || allocated_slots == 1);
	}
	free(a);
	init_target();
	a = array(NULL, 0);
	target.bpf.effective[0] = a;
	for (int effective = 0; effective < 2; effective++) {
		union bpf_attr attr = attr_for((void *)(uintptr_t)1, 1, effective);
		CHECK(query(&attr) == 0 && attr.query.prog_cnt == 0);
	}
	free(a);
}
static void validation(void)
{
	init_target();
	union bpf_attr attr = attr_for(NULL, 0, false);
	has_net_admin = 0;
	CHECK(query(&attr) == -EPERM && !fd_gets);
	has_net_admin = 1;
	attr.query.query_flags = 2;
	CHECK(query(&attr) == -EINVAL && !fd_gets);
	attr.query.query_flags = 0;
	const u32 bad_types[] = { BPF_SK_SKB_STREAM_PARSER, BPF_SK_SKB_STREAM_VERDICT,
		MAX_BPF_ATTACH_TYPE, UINT32_MAX };
	for (unsigned int i = 0; i < sizeof(bad_types) / sizeof(*bad_types); i++) {
		attr.query.attach_type = bad_types[i];
		CHECK(query(&attr) == -EINVAL && !fd_gets);
	}
	attr = attr_for(NULL, 0, false);
	((unsigned char *)&attr)[offsetof(union bpf_attr, query.prog_cnt) + sizeof(u32)] = 1;
	CHECK(query(&attr) == -EINVAL && !fd_gets);
	attr = attr_for(NULL, 0, false);
	fail_fd = 1;
	CHECK(query(&attr) == -EBADF && fd_gets == 1 && !fd_puts);
	fail_fd = 0;
	CHECK(query(&attr) == 0 && fd_gets == 2 && fd_puts == 1);
	sysctl_unprivileged_bpf_disabled = 1;
	has_sys_admin = 0;
	CHECK(query(&attr) == -EPERM && fd_gets == 2);
	has_sys_admin = 1;
	security_error = -EACCES;
	CHECK(query(&attr) == -EACCES && fd_gets == 2);
}
int main(int argc, char **argv)
{
	CHECK(argc == 2);
	if (!strcmp(argv[1], "empty")) core_empty();
	else if (!strcmp(argv[1], "dummy")) core_dummy(false);
	else if (!strcmp(argv[1], "trailing")) core_dummy(true);
	else if (!strcmp(argv[1], "delete")) delete_after_read();
	else if (!strcmp(argv[1], "ancestors")) ancestor_count();
	else if (!strcmp(argv[1], "short")) short_query();
	else if (!strcmp(argv[1], "snapshot")) snapshot();
	else if (!strcmp(argv[1], "shrink")) shrink();
	else if (!strcmp(argv[1], "errors")) errors();
	else if (!strcmp(argv[1], "queries")) queries();
	else if (!strcmp(argv[1], "count")) count_queries();
	else if (!strcmp(argv[1], "validation")) validation();
	else CHECK(false);
	CHECK(!rcu_depth && !cgroup_mutex && !refs);
	return 0;
}

// SPDX-License-Identifier: GPL-2.0
/* Host ASan/UBSan harness for extracted kernel/bpf/lpm_trie.c. */
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include BPF_UAPI_HEADER

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef int32_t s32;

#ifndef __rcu
#define __rcu
#endif
#ifndef likely
#define likely(x) __builtin_expect(!!(x), 1)
#endif
#ifndef unlikely
#define unlikely(x) __builtin_expect(!!(x), 0)
#endif
#ifndef BIT
#define BIT(nr) (1UL << (nr))
#endif
#ifndef min
#define min(a, b) ((a) < (b) ? (a) : (b))
#endif
#ifndef round_up
#define round_up(x, y) ((((x) - 1) | ((y) - 1)) + 1)
#endif
#ifndef container_of
#define container_of(ptr, type, member) \
	((type *)((char *)(ptr) - offsetof(type, member)))
#endif
#ifndef READ_ONCE
#define READ_ONCE(x) (*(const volatile typeof(x) *)&(x))
#endif
#ifndef WRITE_ONCE
#define WRITE_ONCE(x, v) (*(volatile typeof(x) *)&(x) = (v))
#endif

#define U32_MAX UINT32_MAX
#define S32_MAX INT32_MAX
#define PAGE_SIZE 4096UL
#define PAGE_SHIFT 12
#define KMALLOC_MAX_SIZE (1UL << 22)
#define NUMA_NO_NODE (-1)
#define CAP_SYS_ADMIN 21
#define GFP_ATOMIC 1U
#define GFP_USER 2U
#define __GFP_NOWARN 4U
#define ENOTSUPP 524

#define ERR_PTR(e) ((void *)(intptr_t)(e))
#define IS_ERR(p) ((uintptr_t)(p) >= (uintptr_t)-4095)
#define PTR_ERR(p) ((int)(intptr_t)(p))
#define IS_ENABLED(cfg) (cfg)
#define CONFIG_IPV6 1

struct rcu_head {
	struct rcu_head *next;
	void *free_base;
};

typedef struct {
	int held;
} raw_spinlock_t;

#define raw_spin_lock_init(l) do { (l)->held = 0; } while (0)
#define raw_spin_lock_irqsave(l, flags) \
	do { (void)(flags); if ((l)->held) abort(); (l)->held = 1; } while (0)
#define raw_spin_unlock_irqrestore(l, flags) \
	do { (void)(flags); if (!(l)->held) abort(); (l)->held = 0; } while (0)
#define lockdep_is_held(l) ((l)->held)

#define RCU_INIT_POINTER(p, v) do { (p) = (v); } while (0)
#define rcu_assign_pointer(p, v) do { (p) = (v); } while (0)
#define rcu_dereference(p) (p)
#define rcu_access_pointer(p) (p)
#define rcu_dereference_protected(p, c) ({ if (!(c)) abort(); (p); })

static struct rcu_head *rcu_queue_head;
static unsigned rcu_pending_count;
static unsigned synchronize_rcu_calls;
static size_t live_allocs;
static int fail_kmalloc_node;
static int fail_kmalloc_node_after;
static int fail_kmalloc_array;
static int host_capable = 1;
static int precharge_fail;

static bool capable(int cap)
{
	(void)cap;
	return host_capable != 0;
}

static void *tracked_alloc(size_t size)
{
	void *p = calloc(1, size ? size : 1);
	if (p)
		live_allocs++;
	return p;
}

static void kfree(const void *ptr)
{
	if (!ptr)
		return;
	if (!live_allocs)
		abort();
	live_allocs--;
	free((void *)ptr);
}

static void *kzalloc(size_t size, unsigned flags)
{
	(void)flags;
	return tracked_alloc(size);
}

static void *kmalloc_node(size_t size, unsigned flags, int node)
{
	(void)flags;
	(void)node;
	if (fail_kmalloc_node)
		return NULL;
	if (fail_kmalloc_node_after > 0) {
		fail_kmalloc_node_after--;
		if (fail_kmalloc_node_after == 0) {
			fail_kmalloc_node = 1;
			return NULL;
		}
	}
	return tracked_alloc(size);
}

static inline void *kmalloc_array(size_t n, size_t size, unsigned flags)
{
	(void)flags;
	if (fail_kmalloc_array)
		return NULL;
	if (n != 0 && size > SIZE_MAX / n)
		return NULL;
	return tracked_alloc(n * size);
}

static inline int fls(unsigned int x)
{
	return x ? (int)(sizeof(int) * 8 - __builtin_clz(x)) : 0;
}

static void synchronize_rcu(void)
{
	synchronize_rcu_calls++;
	while (rcu_queue_head) {
		struct rcu_head *cur = rcu_queue_head;
		rcu_queue_head = cur->next;
		rcu_pending_count--;
		kfree(cur->free_base);
	}
}

#define kfree_rcu(ptr, field) do { \
	typeof(ptr) _p = (ptr); \
	_p->field.free_base = _p; \
	_p->field.next = rcu_queue_head; \
	rcu_queue_head = &_p->field; \
	rcu_pending_count++; \
} while (0)

struct bpf_map;
struct bpf_map_ops {
	struct bpf_map *(*map_alloc)(union bpf_attr *attr);
	void (*map_free)(struct bpf_map *map);
	int (*map_get_next_key)(struct bpf_map *map, void *key, void *next_key);
	void *(*map_lookup_elem)(struct bpf_map *map, void *key);
	int (*map_update_elem)(struct bpf_map *map, void *key, void *value, u64 flags);
	int (*map_delete_elem)(struct bpf_map *map, void *key);
};

struct bpf_map {
	const struct bpf_map_ops *ops;
	u32 map_type;
	u32 key_size;
	u32 value_size;
	u32 max_entries;
	u32 map_flags;
	u32 pages;
	int numa_node;
};

static int bpf_map_attr_numa_node(const union bpf_attr *attr)
{
	return (attr->map_flags & BPF_F_NUMA_NODE) ? (int)attr->numa_node : NUMA_NO_NODE;
}

static int bpf_map_precharge_memlock(u32 pages)
{
	(void)pages;
	return precharge_fail ? -EPERM : 0;
}

#include LPM_TRIE_SUBJECT

#define TEST_CHECK(cond) do { \
	if (!(cond)) { \
		fprintf(stderr, "HOST_TEST_FAIL line=%d cond=%s\n", __LINE__, #cond); \
		return 1; \
	} \
} while (0)

static struct bpf_lpm_trie_key *make_key4(u32 prefixlen, u8 a, u8 b, u8 c, u8 d)
{
	struct bpf_lpm_trie_key *k = calloc(1, sizeof(*k) + 4);
	k->prefixlen = prefixlen;
	k->data[0] = a;
	k->data[1] = b;
	k->data[2] = c;
	k->data[3] = d;
	return k;
}

static bool key4_eq(const struct bpf_lpm_trie_key *k, u32 prefixlen, u8 a, u8 b, u8 c, u8 d)
{
	return k->prefixlen == prefixlen && k->data[0] == a && k->data[1] == b &&
	       k->data[2] == c && k->data[3] == d;
}

static struct bpf_map *alloc_trie4(u32 max_entries)
{
	union bpf_attr attr;
	memset(&attr, 0, sizeof(attr));
	attr.map_type = BPF_MAP_TYPE_LPM_TRIE;
	attr.key_size = sizeof(struct bpf_lpm_trie_key) + 4;
	attr.value_size = sizeof(u32);
	attr.max_entries = max_entries;
	attr.map_flags = BPF_F_NO_PREALLOC;
	return trie_alloc(&attr);
}

static int test_empty_get_next_key(void)
{
	struct bpf_map *map = alloc_trie4(16);
	struct bpf_lpm_trie_key *next = make_key4(0, 0, 0, 0, 0);
	struct bpf_lpm_trie_key *bad = make_key4(33, 0, 0, 0, 0);
	TEST_CHECK(!IS_ERR(map));
	TEST_CHECK(trie_get_next_key(map, NULL, next) == -ENOENT);
	TEST_CHECK(trie_get_next_key(map, bad, next) == -ENOENT);
	free(bad);
	free(next);
	trie_free(map);
	TEST_CHECK(live_allocs == 0);
	return 0;
}

static int test_lookup_prefixlen_bounds(void)
{
	struct bpf_map *map = alloc_trie4(16);
	struct bpf_lpm_trie_key *k = make_key4(16, 192, 168, 0, 0);
	struct bpf_lpm_trie_key *bad = make_key4(33, 192, 168, 0, 0);
	u32 val = 42;
	TEST_CHECK(!IS_ERR(map));
	TEST_CHECK(trie_update_elem(map, k, &val, BPF_ANY) == 0);
	TEST_CHECK(trie_lookup_elem(map, bad) == NULL);
	u32 *got = trie_lookup_elem(map, k);
	TEST_CHECK(got && *got == 42);
	free(bad);
	free(k);
	trie_free(map);
	TEST_CHECK(live_allocs == 0);
	return 0;
}

static int test_update_flags_noexist(void)
{
	struct bpf_map *map = alloc_trie4(16);
	struct lpm_trie *trie = container_of(map, struct lpm_trie, map);
	struct bpf_lpm_trie_key *k0 = make_key4(24, 192, 168, 0, 0);
	struct bpf_lpm_trie_key *k1 = make_key4(24, 192, 168, 1, 0);
	struct bpf_lpm_trie_key *kim = make_key4(23, 192, 168, 0, 0);
	u32 v0 = 10, v1 = 11, vdup = 99, vim = 23;
	TEST_CHECK(!IS_ERR(map));
	TEST_CHECK(trie_update_elem(map, k0, &v0, BPF_NOEXIST) == 0);
	TEST_CHECK(trie->n_entries == 1);
	TEST_CHECK(trie_update_elem(map, k0, &vdup, BPF_NOEXIST) == -EEXIST);
	TEST_CHECK(trie->n_entries == 1);
	u32 *got = trie_lookup_elem(map, k0);
	TEST_CHECK(got && *got == 10);
	TEST_CHECK(trie_update_elem(map, k1, &v1, BPF_NOEXIST) == 0);
	TEST_CHECK(trie->n_entries == 2);
	/* 192.168.0.0/23 is currently an IM node; BPF_NOEXIST must turn it real. */
	TEST_CHECK(trie_lookup_elem(map, kim) == NULL);
	TEST_CHECK(trie_update_elem(map, kim, &vim, BPF_NOEXIST) == 0);
	TEST_CHECK(trie->n_entries == 3);
	got = trie_lookup_elem(map, kim);
	TEST_CHECK(got && *got == 23);
	free(kim);
	free(k1);
	free(k0);
	trie_free(map);
	TEST_CHECK(live_allocs == 0);
	return 0;
}

static int test_update_flags_exist(void)
{
	struct bpf_map *map = alloc_trie4(16);
	struct lpm_trie *trie = container_of(map, struct lpm_trie, map);
	struct bpf_lpm_trie_key *k0 = make_key4(24, 192, 168, 0, 0);
	struct bpf_lpm_trie_key *k1 = make_key4(24, 192, 168, 1, 0);
	struct bpf_lpm_trie_key *kim = make_key4(23, 192, 168, 0, 0);
	struct bpf_lpm_trie_key *k16 = make_key4(16, 192, 168, 0, 0);
	struct bpf_lpm_trie_key *kother = make_key4(16, 192, 169, 0, 0);
	u32 v0 = 10, v1 = 11, vupd = 77;
	TEST_CHECK(!IS_ERR(map));
	/* Empty trie must reject BPF_EXIST with -ENOENT. */
	TEST_CHECK(trie_update_elem(map, k0, &v0, BPF_EXIST) == -ENOENT);
	TEST_CHECK(trie->n_entries == 0);
	TEST_CHECK(trie_update_elem(map, k0, &v0, BPF_ANY) == 0);
	/* Missing ancestor/split paths must reject BPF_EXIST with -ENOENT. */
	TEST_CHECK(trie_update_elem(map, k16, &vupd, BPF_EXIST) == -ENOENT);
	TEST_CHECK(trie_update_elem(map, kother, &vupd, BPF_EXIST) == -ENOENT);
	TEST_CHECK(trie->n_entries == 1);
	TEST_CHECK(trie_update_elem(map, k1, &v1, BPF_ANY) == 0);
	TEST_CHECK(trie->n_entries == 2);
	/* IM node must reject BPF_EXIST with -ENOENT. */
	TEST_CHECK(trie_update_elem(map, kim, &vupd, BPF_EXIST) == -ENOENT);
	TEST_CHECK(trie->n_entries == 2);
	TEST_CHECK(trie_lookup_elem(map, kim) == NULL);
	/* Existing real node must succeed and keep n_entries == 2. */
	TEST_CHECK(trie_update_elem(map, k0, &vupd, BPF_EXIST) == 0);
	TEST_CHECK(trie->n_entries == 2);
	u32 *got = trie_lookup_elem(map, k0);
	TEST_CHECK(got && *got == 77);
	free(kother);
	free(k16);
	free(kim);
	free(k1);
	free(k0);
	trie_free(map);
	TEST_CHECK(live_allocs == 0);
	return 0;
}

static int test_delete_prefixlen_bounds(void)
{
	struct bpf_map *map = alloc_trie4(16);
	struct bpf_lpm_trie_key *bad = make_key4(33, 192, 168, 0, 0);
	TEST_CHECK(!IS_ERR(map));
	TEST_CHECK(trie_delete_elem(map, bad) == -EINVAL);
	free(bad);
	trie_free(map);
	TEST_CHECK(live_allocs == 0);
	return 0;
}

static int test_delete_empty(void)
{
	struct bpf_map *map = alloc_trie4(16);
	struct bpf_lpm_trie_key *k = make_key4(16, 192, 168, 0, 0);
	TEST_CHECK(!IS_ERR(map));
	TEST_CHECK(trie_delete_elem(map, k) == -ENOENT);
	free(k);
	trie_free(map);
	TEST_CHECK(live_allocs == 0);
	return 0;
}

static int test_delete_equal_prefixlen_mismatch(void)
{
	struct bpf_map *map = alloc_trie4(16);
	struct lpm_trie *trie = container_of(map, struct lpm_trie, map);
	struct bpf_lpm_trie_key *k = make_key4(16, 192, 168, 0, 0);
	struct bpf_lpm_trie_key *mismatch = make_key4(16, 192, 169, 0, 0);
	u32 v = 7;
	TEST_CHECK(!IS_ERR(map));
	TEST_CHECK(trie_update_elem(map, k, &v, BPF_ANY) == 0);
	TEST_CHECK(trie_delete_elem(map, mismatch) == -ENOENT);
	TEST_CHECK(trie->n_entries == 1);
	u32 *got = trie_lookup_elem(map, k);
	TEST_CHECK(got && *got == 7);
	free(mismatch);
	free(k);
	trie_free(map);
	TEST_CHECK(live_allocs == 0);
	return 0;
}

static int test_delete_two_children_marks_im(void)
{
	struct bpf_map *map = alloc_trie4(16);
	struct lpm_trie *trie = container_of(map, struct lpm_trie, map);
	struct bpf_lpm_trie_key *r16 = make_key4(16, 192, 168, 0, 0);
	struct bpf_lpm_trie_key *c0 = make_key4(24, 192, 168, 0, 0);
	struct bpf_lpm_trie_key *c128 = make_key4(24, 192, 168, 128, 0);
	struct bpf_lpm_trie_key *q_gap = make_key4(32, 192, 168, 64, 1);
	struct bpf_lpm_trie_key *q_c0 = make_key4(32, 192, 168, 0, 5);
	struct bpf_lpm_trie_key *q_c128 = make_key4(32, 192, 168, 128, 5);
	u32 v1 = 1, v2 = 2, v3 = 3;
	TEST_CHECK(!IS_ERR(map));
	TEST_CHECK(trie_update_elem(map, r16, &v1, BPF_ANY) == 0);
	TEST_CHECK(trie_update_elem(map, c0, &v2, BPF_ANY) == 0);
	TEST_CHECK(trie_update_elem(map, c128, &v3, BPF_ANY) == 0);
	TEST_CHECK(trie->n_entries == 3);
	TEST_CHECK(trie_delete_elem(map, r16) == 0);
	TEST_CHECK(trie->n_entries == 2);
	TEST_CHECK(trie->root && (trie->root->flags & LPM_TREE_NODE_FLAG_IM));
	TEST_CHECK(trie_lookup_elem(map, q_gap) == NULL);
	u32 *g0 = trie_lookup_elem(map, q_c0), *g1 = trie_lookup_elem(map, q_c128);
	TEST_CHECK(g0 && *g0 == 2 && g1 && *g1 == 3);
	TEST_CHECK(trie_delete_elem(map, r16) == -ENOENT);
	free(q_c128);
	free(q_c0);
	free(q_gap);
	free(c128);
	free(c0);
	free(r16);
	trie_free(map);
	TEST_CHECK(live_allocs == 0);
	return 0;
}

static int test_delete_collapse_im_parent(void)
{
	/* Case 1: IM /23 at root. */
	struct bpf_map *map = alloc_trie4(16);
	struct lpm_trie *trie = container_of(map, struct lpm_trie, map);
	struct bpf_lpm_trie_key *k0 = make_key4(24, 192, 168, 0, 0);
	struct bpf_lpm_trie_key *k1 = make_key4(24, 192, 168, 1, 0);
	struct bpf_lpm_trie_key *q0 = make_key4(32, 192, 168, 0, 42);
	struct bpf_lpm_trie_key *q1 = make_key4(32, 192, 168, 1, 42);
	u32 v0 = 2, v1 = 5;
	TEST_CHECK(!IS_ERR(map));
	TEST_CHECK(trie_update_elem(map, k0, &v0, BPF_ANY) == 0);
	TEST_CHECK(trie_update_elem(map, k1, &v1, BPF_ANY) == 0);
	TEST_CHECK(trie->root && (trie->root->flags & LPM_TREE_NODE_FLAG_IM));
	synchronize_rcu();
	TEST_CHECK(trie_delete_elem(map, k0) == 0);
	TEST_CHECK(trie->n_entries == 1);
	TEST_CHECK(rcu_pending_count == 2); /* deleted leaf + collapsed IM parent */
	TEST_CHECK(trie->root && !(trie->root->flags & LPM_TREE_NODE_FLAG_IM));
	TEST_CHECK(trie_lookup_elem(map, q0) == NULL);
	u32 *g1 = trie_lookup_elem(map, q1);
	TEST_CHECK(g1 && *g1 == 5);
	synchronize_rcu();
	TEST_CHECK(rcu_pending_count == 0);
	trie_free(map);
	TEST_CHECK(live_allocs == 0);

	/* Case 2: IM /23 as child of /16. */
	map = alloc_trie4(16);
	trie = container_of(map, struct lpm_trie, map);
	struct bpf_lpm_trie_key *r16 = make_key4(16, 192, 168, 0, 0);
	u32 vr = 1;
	TEST_CHECK(trie_update_elem(map, r16, &vr, BPF_ANY) == 0);
	TEST_CHECK(trie_update_elem(map, k0, &v0, BPF_ANY) == 0);
	TEST_CHECK(trie_update_elem(map, k1, &v1, BPF_ANY) == 0);
	TEST_CHECK(trie->root->child[0]->flags & LPM_TREE_NODE_FLAG_IM);
	TEST_CHECK(trie_delete_elem(map, k0) == 0);
	TEST_CHECK(trie->n_entries == 2);
	TEST_CHECK(!(trie->root->child[0]->flags & LPM_TREE_NODE_FLAG_IM));
	TEST_CHECK(trie->root->child[0]->prefixlen == 24);
	g1 = trie_lookup_elem(map, q1);
	TEST_CHECK(g1 && *g1 == 5);
	free(r16);
	free(q1);
	free(q0);
	free(k1);
	free(k0);
	trie_free(map);
	TEST_CHECK(live_allocs == 0);
	return 0;
}

static int test_delete_single_child_and_leaf(void)
{
	struct bpf_map *map = alloc_trie4(16);
	struct lpm_trie *trie = container_of(map, struct lpm_trie, map);
	struct bpf_lpm_trie_key *r16 = make_key4(16, 192, 168, 0, 0);
	struct bpf_lpm_trie_key *c24 = make_key4(24, 192, 168, 0, 0);
	struct bpf_lpm_trie_key *q24 = make_key4(32, 192, 168, 0, 5);
	struct bpf_lpm_trie_key *next = make_key4(0, 0, 0, 0, 0);
	u32 v1 = 1, v2 = 2;
	TEST_CHECK(!IS_ERR(map));
	TEST_CHECK(trie_update_elem(map, r16, &v1, BPF_ANY) == 0);
	TEST_CHECK(trie_update_elem(map, c24, &v2, BPF_ANY) == 0);
	TEST_CHECK(trie_delete_elem(map, r16) == 0);
	TEST_CHECK(trie->n_entries == 1);
	TEST_CHECK(trie->root && trie->root->prefixlen == 24);
	u32 *g2 = trie_lookup_elem(map, q24);
	TEST_CHECK(g2 && *g2 == 2);
	TEST_CHECK(trie_delete_elem(map, c24) == 0);
	TEST_CHECK(trie->n_entries == 0 && trie->root == NULL);
	TEST_CHECK(trie_get_next_key(map, NULL, next) == -ENOENT);
	free(next);
	free(q24);
	free(c24);
	free(r16);
	trie_free(map);
	TEST_CHECK(live_allocs == 0);
	return 0;
}

static int test_get_next_key_postorder(void)
{
	struct bpf_map *map = alloc_trie4(16);
	struct bpf_lpm_trie_key *k1 = make_key4(16, 192, 168, 0, 0);
	struct bpf_lpm_trie_key *k2 = make_key4(24, 192, 168, 0, 0);
	struct bpf_lpm_trie_key *k3 = make_key4(24, 192, 168, 128, 0);
	struct bpf_lpm_trie_key *k5 = make_key4(24, 192, 168, 1, 0);
	struct bpf_lpm_trie_key *out = make_key4(0, 0, 0, 0, 0);
	struct bpf_lpm_trie_key *cur = make_key4(0, 0, 0, 0, 0);
	u32 v = 1;
	TEST_CHECK(!IS_ERR(map));
	TEST_CHECK(trie_update_elem(map, k1, &v, BPF_ANY) == 0);
	TEST_CHECK(trie_update_elem(map, k2, &v, BPF_ANY) == 0);
	TEST_CHECK(trie_update_elem(map, k3, &v, BPF_ANY) == 0);
	TEST_CHECK(trie_update_elem(map, k5, &v, BPF_ANY) == 0);

	TEST_CHECK(trie_get_next_key(map, NULL, out) == 0 && key4_eq(out, 24, 192, 168, 0, 0));
	memcpy(cur, out, sizeof(*cur) + 4);
	TEST_CHECK(trie_get_next_key(map, cur, out) == 0 && key4_eq(out, 24, 192, 168, 1, 0));
	memcpy(cur, out, sizeof(*cur) + 4);
	TEST_CHECK(trie_get_next_key(map, cur, out) == 0 && key4_eq(out, 24, 192, 168, 128, 0));
	memcpy(cur, out, sizeof(*cur) + 4);
	TEST_CHECK(trie_get_next_key(map, cur, out) == 0 && key4_eq(out, 16, 192, 168, 0, 0));
	memcpy(cur, out, sizeof(*cur) + 4);
	TEST_CHECK(trie_get_next_key(map, cur, out) == -ENOENT);

	/* Also check right-child-only real node fallback (414a7563ccae). */
	struct bpf_lpm_trie_key *r128_hi = make_key4(25, 192, 168, 128, 128);
	TEST_CHECK(trie_delete_elem(map, k5) == 0);
	TEST_CHECK(trie_update_elem(map, r128_hi, &v, BPF_ANY) == 0);
	TEST_CHECK(trie_get_next_key(map, k2, out) == 0 && key4_eq(out, 25, 192, 168, 128, 128));
	memcpy(cur, out, sizeof(*cur) + 4);
	TEST_CHECK(trie_get_next_key(map, cur, out) == 0 && key4_eq(out, 24, 192, 168, 128, 0));

	free(r128_hi);
	free(cur);
	free(out);
	free(k5);
	free(k3);
	free(k2);
	free(k1);
	trie_free(map);
	TEST_CHECK(live_allocs == 0);
	return 0;
}

static int test_get_next_key_full_depth_stack(void)
{
	union bpf_attr attr;
	memset(&attr, 0, sizeof(attr));
	attr.map_type = BPF_MAP_TYPE_LPM_TRIE;
	attr.key_size = sizeof(struct bpf_lpm_trie_key) + 1;
	attr.value_size = sizeof(u32);
	attr.max_entries = 16;
	attr.map_flags = BPF_F_NO_PREALLOC;
	struct bpf_map *map = trie_alloc(&attr);
	TEST_CHECK(!IS_ERR(map));

	struct {
		struct bpf_lpm_trie_key k;
		u8 data[1];
	} key, next;
	memset(&key, 0, sizeof(key));
	memset(&next, 0, sizeof(next));
	for (u32 plen = 0; plen <= 8; plen++) {
		key.k.prefixlen = plen;
		TEST_CHECK(trie_update_elem(map, &key.k, &plen, BPF_ANY) == 0);
	}
	/* Full chain of 9 nodes writes slots [0..8]; ASan catches size-8 overflow. */
	TEST_CHECK(trie_get_next_key(map, NULL, &next.k) == 0 && next.k.prefixlen == 8);
	for (s32 plen = 8; plen >= 1; plen--) {
		key.k.prefixlen = (u32)plen;
		TEST_CHECK(trie_get_next_key(map, &key.k, &next.k) == 0);
		TEST_CHECK(next.k.prefixlen == (u32)(plen - 1));
	}
	key.k.prefixlen = 0;
	TEST_CHECK(trie_get_next_key(map, &key.k, &next.k) == -ENOENT);
	trie_free(map);
	TEST_CHECK(live_allocs == 0);
	return 0;
}

static int test_get_next_key_nonexistent_same_prefixlen(void)
{
	struct bpf_map *map = alloc_trie4(16);
	struct bpf_lpm_trie_key *r16 = make_key4(16, 192, 168, 0, 0);
	struct bpf_lpm_trie_key *c24 = make_key4(24, 192, 168, 128, 0);
	struct bpf_lpm_trie_key *nonexist = make_key4(16, 192, 169, 0, 0);
	struct bpf_lpm_trie_key *out = make_key4(0, 0, 0, 0, 0);
	u32 v = 1;
	TEST_CHECK(!IS_ERR(map));
	TEST_CHECK(trie_update_elem(map, r16, &v, BPF_ANY) == 0);
	TEST_CHECK(trie_update_elem(map, c24, &v, BPF_ANY) == 0);
	TEST_CHECK(trie_get_next_key(map, nonexist, out) == 0);
	TEST_CHECK(key4_eq(out, 24, 192, 168, 128, 0));
	free(out);
	free(nonexist);
	free(c24);
	free(r16);
	trie_free(map);
	TEST_CHECK(live_allocs == 0);
	return 0;
}

static int test_get_next_key_alloc_failure(void)
{
	struct bpf_map *map = alloc_trie4(16);
	struct bpf_lpm_trie_key *k = make_key4(16, 192, 168, 0, 0);
	struct bpf_lpm_trie_key *out = make_key4(0, 0, 0, 0, 0);
	u32 v = 1;
	TEST_CHECK(!IS_ERR(map));
	TEST_CHECK(trie_update_elem(map, k, &v, BPF_ANY) == 0);
	fail_kmalloc_array = 1;
	int err = trie_get_next_key(map, k, out);
	fail_kmalloc_array = 0;
	TEST_CHECK(err == -ENOMEM);
	free(out);
	free(k);
	trie_free(map);
	TEST_CHECK(live_allocs == 0);
	return 0;
}

static int test_clear_loop_simulation(void)
{
	union bpf_attr attr;
	memset(&attr, 0, sizeof(attr));
	attr.map_type = BPF_MAP_TYPE_LPM_TRIE;
	attr.key_size = sizeof(struct bpf_lpm_trie_key) + 24; /* 28-byte LocalNetAccessKey */
	attr.value_size = 1;
	attr.max_entries = 1000;
	attr.map_flags = BPF_F_NO_PREALLOC;
	struct bpf_map *map = trie_alloc(&attr);
	struct lpm_trie *trie = container_of(map, struct lpm_trie, map);
	TEST_CHECK(!IS_ERR(map));

	struct lnp28 {
		struct bpf_lpm_trie_key k;
		u8 data[24];
	};
	struct lnp28 keys[5];
	memset(keys, 0, sizeof(keys));
	keys[0].k.prefixlen = 192; keys[0].data[3] = 1; keys[0].data[19] = 1; keys[0].data[21] = 17; keys[0].data[22] = 0x10;
	keys[1].k.prefixlen = 192; keys[1].data[3] = 1; keys[1].data[19] = 1; keys[1].data[21] = 17; keys[1].data[22] = 0x20;
	keys[2].k.prefixlen = 96;  keys[2].data[3] = 2; keys[2].data[4] = 0xfe; keys[2].data[5] = 0x80;
	keys[3].k.prefixlen = 192; keys[3].data[3] = 2; keys[3].data[4] = 0xfe; keys[3].data[5] = 0x80; keys[3].data[21] = 6;
	keys[4].k.prefixlen = 32;  keys[4].data[3] = 3;
	for (int i = 0; i < 5; i++) {
		u8 v = (u8)i;
		TEST_CHECK(trie_update_elem(map, &keys[i].k, &v, BPF_ANY) == 0);
	}
	TEST_CHECK(trie->n_entries == 5);

	struct lnp28 next;
	int iterations = 0;
	while (trie_get_next_key(map, NULL, &next.k) == 0) {
		TEST_CHECK(trie_delete_elem(map, &next.k) == 0);
		iterations++;
		TEST_CHECK(iterations <= 5);
	}
	TEST_CHECK(iterations == 5);
	TEST_CHECK(trie_get_next_key(map, NULL, &next.k) == -ENOENT);
	TEST_CHECK(trie->n_entries == 0 && trie->root == NULL);
	trie_free(map);
	TEST_CHECK(live_allocs == 0);
	return 0;
}

static int test_rcu_deferred_reclaim(void)
{
	struct bpf_map *map = alloc_trie4(16);
	struct bpf_lpm_trie_key *k0 = make_key4(24, 192, 168, 0, 0);
	struct bpf_lpm_trie_key *k1 = make_key4(24, 192, 168, 128, 0);
	u32 v = 99;
	TEST_CHECK(!IS_ERR(map));
	synchronize_rcu();
	unsigned sync_before = synchronize_rcu_calls;
	TEST_CHECK(trie_update_elem(map, k0, &v, BPF_ANY) == 0);
	TEST_CHECK(trie_update_elem(map, k1, &v, BPF_ANY) == 0);
	TEST_CHECK(trie_delete_elem(map, k0) == 0);
	/* Deleting leaf k0 also collapses its auto-created IM parent -> 2 RCU frees. */
	TEST_CHECK(rcu_pending_count == 2);
	free(k1);
	free(k0);
	trie_free(map);
	TEST_CHECK(synchronize_rcu_calls > sync_before);
	TEST_CHECK(rcu_pending_count == 0);
	TEST_CHECK(live_allocs == 0);
	return 0;
}

static int test_update_alloc_failures(void)
{
	struct bpf_map *map = alloc_trie4(16);
	struct lpm_trie *trie = container_of(map, struct lpm_trie, map);
	struct bpf_lpm_trie_key *k0 = make_key4(24, 192, 168, 0, 0);
	struct bpf_lpm_trie_key *k1 = make_key4(24, 192, 168, 128, 0);
	u32 v = 99;
	TEST_CHECK(!IS_ERR(map));
	TEST_CHECK(trie_update_elem(map, k0, &v, BPF_ANY) == 0);
	/* Fail im_node allocation after new_node succeeds -> must rollback cleanly. */
	fail_kmalloc_node_after = 2;
	TEST_CHECK(trie_update_elem(map, k1, &v, BPF_ANY) == -ENOMEM);
	fail_kmalloc_node = 0;
	fail_kmalloc_node_after = 0;
	TEST_CHECK(trie->n_entries == 1);
	fail_kmalloc_node = 1;
	TEST_CHECK(trie_update_elem(map, k1, &v, BPF_ANY) == -ENOMEM);
	fail_kmalloc_node = 0;
	TEST_CHECK(trie->n_entries == 1);
	free(k1);
	free(k0);
	trie_free(map);
	TEST_CHECK(live_allocs == 0);
	return 0;
}

struct test_case {
	const char *name;
	int (*fn)(void);
};

int main(int argc, char **argv)
{
	static const struct test_case cases[] = {
		{"empty_get_next_key", test_empty_get_next_key},
		{"lookup_prefixlen_bounds", test_lookup_prefixlen_bounds},
		{"update_flags_noexist", test_update_flags_noexist},
		{"update_flags_exist", test_update_flags_exist},
		{"delete_prefixlen_bounds", test_delete_prefixlen_bounds},
		{"delete_empty", test_delete_empty},
		{"delete_equal_prefixlen_mismatch", test_delete_equal_prefixlen_mismatch},
		{"delete_two_children_marks_im", test_delete_two_children_marks_im},
		{"delete_collapse_im_parent", test_delete_collapse_im_parent},
		{"delete_single_child_and_leaf", test_delete_single_child_and_leaf},
		{"get_next_key_postorder", test_get_next_key_postorder},
		{"get_next_key_full_depth_stack", test_get_next_key_full_depth_stack},
		{"get_next_key_nonexistent_same_prefixlen", test_get_next_key_nonexistent_same_prefixlen},
		{"get_next_key_alloc_failure", test_get_next_key_alloc_failure},
		{"clear_loop_simulation", test_clear_loop_simulation},
		{"rcu_deferred_reclaim", test_rcu_deferred_reclaim},
		{"update_alloc_failures", test_update_alloc_failures},
	};
	const char *only = argc > 1 ? argv[1] : NULL;
	unsigned passed = 0, failed = 0;
	for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
		if (only && strcmp(only, cases[i].name))
			continue;
		live_allocs = 0;
		rcu_pending_count = 0;
		rcu_queue_head = NULL;
		fail_kmalloc_node = 0;
		fail_kmalloc_node_after = 0;
		fail_kmalloc_array = 0;
		int r = cases[i].fn();
		printf("CASE %s %s\n", cases[i].name, r ? "FAIL" : "PASS");
		if (r)
			failed++;
		else
			passed++;
	}
	printf("TOTAL passed=%u failed=%u\n", passed, failed);
	return failed ? 1 : 0;
}

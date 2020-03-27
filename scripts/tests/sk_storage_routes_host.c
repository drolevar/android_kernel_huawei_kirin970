/* SPDX-License-Identifier: GPL-2.0 */
#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include BPF_UAPI_HEADER
#define CONFIG_BPF_SYSCALL 1
#define BPF_CALL_1(n,t1,a1) static uint64_t n(t1 a1)
enum {RET_INTEGER,ARG_PTR_TO_CTX};
struct sock {uint64_t cookie;};
static struct sock context={0x123456789abcdef0ULL};
static uint64_t sock_gen_cookie(struct sock *p) {assert(p==&context);return p->cookie;}
struct bpf_func_proto {uint64_t (*func)(struct sock *);bool gpl_only;int ret_type,arg1_type;};
static const struct bpf_func_proto bpf_get_current_uid_gid_proto={0},bpf_sk_storage_get_cg_sock_proto={0};
static const struct bpf_func_proto *bpf_base_func_proto(enum bpf_func_id id) {return NULL;}
#include "subject.h"
int main(void) {
 assert(sock_filter_func_proto(BPF_FUNC_sk_storage_get)==&bpf_sk_storage_get_cg_sock_proto);
 assert(!sock_filter_func_proto(BPF_FUNC_sk_storage_delete));
 const struct bpf_func_proto *p=sock_filter_func_proto(BPF_FUNC_get_socket_cookie);assert(p);assert(p->arg1_type==ARG_PTR_TO_CTX);assert(p->ret_type==RET_INTEGER);assert(p->func(&context)==context.cookie);
 puts("PASS: dedicated sock-context cookie and get-only storage dispatch");return 0;
}

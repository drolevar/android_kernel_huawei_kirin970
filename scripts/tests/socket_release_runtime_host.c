/* SPDX-License-Identifier: GPL-2.0 */
#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include BPF_UAPI_HEADER
typedef uint32_t u32;typedef uint64_t u64;
#define CONFIG_HUAWEI_BASTET 1
#define CONFIG_NETFILTER_XT_MATCH_QTAGUID 1
#define CONFIG_HUAWEI_TRACK_SOCKET 1
#define SOCK_LINGER 1
#define PF_EXITING 4
#define SK_FLAGS_TIMESTAMP 0
#define EXPORT_SYMBOL(x)
#define unlikely(x) (x)
#define likely(x) (x)
#define rcu_dereference(x) (x)
#define READ_ONCE(x) (x)
#define rcu_dereference_check(x,c) (x)
#define RCU_INIT_POINTER(p,v) ((p)=(v))
#define refcount_read(p) (*(p))
#define atomic_read(p) (*(p))
#define pr_debug(...) ((void)0)
#define container_of(p,t,m) ((t*)((char*)(p)-offsetof(t,m)))
struct rcu_head {int dummy;};struct sk_filter {int dummy;};struct sock;
struct proto {void (*close)(struct sock*,long);};
struct bpf_prog {int mode;};struct bpf_prog_array {struct bpf_prog*progs[4];};
struct cgroup {struct {struct bpf_prog_array*effective[40];}bpf;};
struct sock {bool sk_kern_sock,linger,storage;u64 cookie;long sk_lingertime;struct proto*sk_prot,*sk_prot_creator;struct cgroup*sk_cgrp_data;struct rcu_head sk_rcu;void(*sk_destruct)(struct sock*);struct sk_filter*sk_filter;int sk_wmem_alloc,sk_omem_alloc,sk_net_refcnt;struct {void*page;}sk_frag;void*sk_peer_cred,*sk_peer_pid;};
struct socket {struct sock*sk;};
static struct {int flags;}task;
#define current (&task)
#define sock_flag(sk,flag) ((sk)->linger)
#define sock_net(sk) ((void*)sk)
static bool cgroup_bpf_enabled=true,tag=true,deferred;
static int hook_calls,delete_calls,close_calls,destruct_calls,storage_frees,rcu_depth,events[64],event_count;
static long close_timeout;static struct socket*active;
static void event(int v){events[event_count++]=v;}
static struct cgroup*sock_cgroup_ptr(struct cgroup**p){return *p;}
static void rcu_read_lock(void){assert(!rcu_depth);rcu_depth++;}
static void rcu_read_unlock(void){assert(rcu_depth==1);rcu_depth--;}
static u64 sock_gen_cookie(struct sock*s){assert(s->storage&&!close_calls);return s->cookie;}
#define BPF_CALL_1(n,t,a) static u64 n(t a)
/* COOKIE */
static u64 bpf_get_sk_cookie(struct bpf_sock*sk){return bpf_get_socket_cookie_sock((void*)sk);}
static int bpf_cookie_tag_map_delete_elem(const u64*key){assert(*key==99&&rcu_depth==1&&!close_calls);delete_calls++;event(1);if(!tag)return -ENOENT;tag=false;return 0;}
/* CONSUMER */
static u32 run_prog(struct bpf_prog*p,struct sock*sk){assert(rcu_depth==1&&sk->storage&&active->sk==sk&&!close_calls);hook_calls++;event(0);if(p->mode==1)return 0;return netd_release((void*)sk);}
#define BPF_PROG_RUN(p,s) run_prog(p,s)
static void bastet_inet_release(struct sock*s){assert(s->storage);event(2);}
static void qtaguid_untag(struct socket*s,bool close){assert(s->sk->storage);event(3);}
static void release_tcp_socket_tracking(struct sock*s){assert(s->storage);event(4);}
static void ip_mc_drop_socket(struct sock*s){assert(s->storage);event(5);}
static void ipv6_sock_mc_close(struct sock*s){event(10);}
static void ipv6_sock_ac_close(struct sock*s){event(11);}
static void bastet_sock_release(struct sock*s){assert(s->storage);}
static void sk_filter_uncharge(struct sock*s,struct sk_filter*f){assert(s->storage);}
static void bpf_sk_storage_free(struct sock*s){assert(s->storage&&close_calls);s->storage=false;storage_frees++;event(8);}
static void sock_disable_timestamp(struct sock*s,int f){assert(!s->storage);}
static void put_page(void*p){}static void put_cred(void*p){}static void put_pid(void*p){}static void put_net(void*p){}
static void sk_prot_free(struct proto*p,struct sock*s){assert(!s->storage);destruct_calls++;event(9);}
/* SUBJECT */
static void protocol_close(struct sock*s,long t){assert(!active->sk&&s->storage&&!rcu_depth);close_calls++;close_timeout=t;event(7);if(!deferred)__sk_destruct(&s->sk_rcu);}
int main(int argc,char**argv){assert(argc==2);const char*c=argv[1];
 struct bpf_prog p={0},deny={1};struct bpf_prog_array a={.progs={&p,NULL}},empty={0};struct cgroup cg={0};for(int i=0;i<40;i++)cg.bpf.effective[i]=&empty;cg.bpf.effective[34]=&a;
 struct proto prot={.close=protocol_close};struct sock sk={.storage=true,.cookie=99,.sk_prot=&prot,.sk_cgrp_data=&cg};struct socket socket={.sk=&sk};active=&socket;
 if(!strcmp(c,"create-route")){cg.bpf.effective[2]=&a;cg.bpf.effective[34]=&empty;a.progs[0]=&deny;assert(BPF_CGROUP_RUN_PROG_INET_SOCK(&sk)==-EPERM&&hook_calls==1&&!close_calls);assert(!BPF_CGROUP_RUN_PROG_INET_SOCK(NULL)&&hook_calls==1);return 0;}
 bool skip=false,v6=!strcmp(c,"v6");
 if(!strcmp(c,"kernel")){sk.sk_kern_sock=true;skip=true;}
 if(!strcmp(c,"disabled")){cgroup_bpf_enabled=false;skip=true;}
 if(!strcmp(c,"empty")){cg.bpf.effective[34]=&empty;skip=true;}
 if(!strcmp(c,"zero-cookie"))sk.cookie=0;
 if(!strcmp(c,"missing-tag"))tag=false;
 if(!strcmp(c,"verdict-zero"))a.progs[0]=&deny;
 if(!strcmp(c,"multi"))a.progs[1]=&deny;
 if(!strcmp(c,"linger")||!strcmp(c,"exiting")){sk.linger=true;sk.sk_lingertime=123;}
 if(!strcmp(c,"exiting"))task.flags=PF_EXITING;
 if(!strcmp(c,"deferred"))deferred=true;
 if(!strcmp(c,"null-v4")||!strcmp(c,"null-v6")){socket.sk=NULL;assert((!strcmp(c,"null-v4")?inet_release(&socket):inet6_release(&socket))==(!strcmp(c,"null-v4")?0:-EINVAL));assert(!hook_calls&&!close_calls);return 0;}
 assert(!(v6?inet6_release(&socket):inet_release(&socket)));assert(!socket.sk&&close_calls==1&&!rcu_depth);
 assert(hook_calls==(skip?0:!strcmp(c,"multi")?2:1));
 int expected_deletes=skip||!sk.cookie||!strcmp(c,"verdict-zero")?0:1;assert(delete_calls==expected_deletes);
 if(expected_deletes)assert(!tag);assert(close_timeout==(!strcmp(c,"linger")?123:0));
 if(!skip)assert(events[v6?2:0]==0);
 if(v6)assert(events[0]==10&&events[1]==11);
 if(deferred){assert(sk.storage&&!storage_frees&&!destruct_calls);__sk_destruct(&sk.sk_rcu);}
 assert(!sk.storage&&storage_frees==1&&destruct_calls==1);
 if(!strcmp(c,"double-release")){int n=hook_calls;assert(!inet_release(&socket)&&hook_calls==n&&close_calls==1);}
 puts("PASS extracted release/consumer/destructor; modeled services");return 0;
}

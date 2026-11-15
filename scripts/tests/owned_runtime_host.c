/* SPDX-License-Identifier: GPL-2.0 */
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <limits.h>
typedef uint8_t u8;typedef uint32_t u32;typedef int32_t s32;typedef uint64_t u64;
typedef uint32_t __be32;typedef uint16_t __be16;
#define CONFIG_IPV6 1
#define IS_ENABLED(x) (x)
#define S32_MAX INT32_MAX
#define likely(x) (x)
#define unlikely(x) (x)
#define WARN_ONCE(x,...) ((void)(x))
#define SOCK_RCU_FREE 1
struct net {int id;};
struct sock {int state,rcu;struct sock *listener;struct net *net;};
struct net_device {struct net *net;int ifindex;};
struct sk_buff {struct net_device *dev;struct sock *sk;};
struct bpf_sock_tuple {union {struct {__be32 saddr,daddr;__be16 sport,dport;} ipv4;struct {__be32 saddr[4],daddr[4];__be16 sport,dport;} ipv6;};};
static struct net caller={1},other={2};
static struct sock full={0,0,NULL,&caller},listener={0,1,NULL,&caller},request={1,0,&listener,&caller},timewait={2,0,NULL,&caller};
static struct sock *result;
static int calls,release_count,netgets,netrelease_count,which,last_port,last_sdif,last_dif;
static struct net *last_net;
static bool refcounted;
static int tcp_hashinfo,udp_table;
static bool sk_fullsock(struct sock *s){return s->state==0;}
static bool sock_flag(struct sock *s,int f){assert(sk_fullsock(s));return s->rcu;}
static struct sock *sk_to_full_sk(struct sock *s){return s->state==1?s->listener:s;}
static void sock_gen_put(struct sock *s){assert(s==&full||s==&request||s==&timewait);release_count++;}
static struct net *dev_net(struct net_device *d){return d->net;}
static struct net *sock_net(struct sock *s){return s->net;}
static int inet_sdif(struct sk_buff *s){return 3;}
static int inet6_sdif(struct sk_buff *s){return 4;}
static struct net *get_net_ns_by_id(struct net *n,u32 id){assert(n==&caller);netgets++;return id==7?&other:NULL;}
static void put_net(struct net *n){assert(n==&other);netrelease_count++;}
static struct sock *record(struct net*n,int port,int dif,int sdif,int kind){calls++;last_net=n;last_port=port;last_dif=dif;last_sdif=sdif;which=kind;return result;}
static struct sock *__inet_lookup(struct net*n,void*h,void*s,int off,__be32 sa,__be16 sp,__be32 da,__be16 dp,int dif,int sdif,bool*ref){*ref=refcounted;return record(n,dp,dif,sdif,4);}
static struct sock *__udp4_lib_lookup(struct net*n,__be32 sa,__be16 sp,__be32 da,__be16 dp,int dif,int sdif,void*t,void*s){return record(n,dp,dif,sdif,5);}
static struct sock *tcp6(struct net*n,void*h,void*s,int off,const struct in6_addr*sa,__be16 sp,const struct in6_addr*da,uint16_t dp,int dif,int sdif,bool*ref){*ref=refcounted;return record(n,dp,dif,sdif,6);}
static struct sock *udp6(struct net*n,const struct in6_addr*sa,__be16 sp,const struct in6_addr*da,__be16 dp,int dif,int sdif,void*t,void*s){return record(n,dp,dif,sdif,7);}
static const struct {typeof(&tcp6) tcp6_lookup;typeof(&udp6) udp6_lib_lookup;} stub={tcp6,udp6},*ipv6_bpf_stub=&stub;
#define BPF_CALL_5(n,t1,a1,t2,a2,t3,a3,t4,a4,t5,a5) static unsigned long n(t1 a1,t2 a2,t3 a3,t4 a4,t5 a5)
#define BPF_CALL_1(n,t1,a1) static unsigned long n(t1 a1)
#define RET_PTR_TO_SOCKET_OR_NULL 1
#define RET_INTEGER 0
#define ARG_PTR_TO_CTX 1
#define ARG_PTR_TO_MEM 2
#define ARG_CONST_SIZE 3
#define ARG_ANYTHING 4
#define ARG_PTR_TO_SOCK_COMMON 5
struct bpf_func_proto {void *func;bool gpl_only,pkt_access,acquires_reference,releases_reference;int ret_type,arg1_type,arg2_type,arg3_type,arg4_type,arg5_type;};
#include SOURCE
int main(void){
 struct net_device dev={&caller,9};struct sk_buff skb={&dev,&full};
 struct bpf_sock_tuple t={0};t.ipv4.dport=htons(1234);result=&full;refcounted=true;
 assert(sizeof(t.ipv4)==12&&sizeof(t.ipv6)==36);
 for(int len=0;len<40;len++)if(len!=12&&len!=36)assert(!bpf_sk_lookup_tcp(&skb,&t,len,UINT64_MAX,0));assert(!calls);
 assert(!bpf_sk_lookup_tcp(&skb,&t,12,UINT64_MAX,1)&&!calls);
 assert(!bpf_sk_lookup_tcp(&skb,&t,12,1ULL<<32,0)&&!calls);
 assert(bpf_sk_lookup_tcp(&skb,&t,12,UINT64_MAX,0)==(unsigned long)&full);
 assert(which==4&&last_port==htons(1234)&&last_net==&caller&&last_dif==9&&last_sdif==3&&!netgets);
 assert(!bpf_sk_release(&full)&&release_count==1);
 assert(bpf_sk_lookup_tcp(&skb,&t,12,7,0)==(unsigned long)&full&&last_net==&other&&netgets==1&&netrelease_count==1);
 assert(!bpf_sk_lookup_tcp(&skb,&t,12,8,0)&&netgets==2&&netrelease_count==1);
 t.ipv6.dport=htons(4321);
 assert(bpf_sk_lookup_tcp(&skb,&t,36,UINT64_MAX,0)==(unsigned long)&full&&which==6&&last_port==4321&&last_sdif==4);
 result=&listener;refcounted=false;
 assert(bpf_sk_lookup_udp(&skb,&t,36,UINT64_MAX,0)==(unsigned long)&listener&&which==7&&last_port==htons(4321));
 assert(!bpf_sk_release(&listener)&&release_count==1);
 assert(bpf_sk_lookup_udp(&skb,&t,12,UINT64_MAX,0)==(unsigned long)&listener&&which==5);
 ipv6_bpf_stub=NULL;int old=calls;
 assert(!bpf_sk_lookup_tcp(&skb,&t,36,UINT64_MAX,0)&&!bpf_sk_lookup_udp(&skb,&t,36,UINT64_MAX,0)&&calls==old);ipv6_bpf_stub=&stub;
 result=&full;assert(!bpf_sk_lookup_udp(&skb,&t,12,UINT64_MAX,0));
 refcounted=true;result=&request;
 assert(bpf_sk_lookup_tcp(&skb,&t,12,UINT64_MAX,0)==(unsigned long)&listener&&release_count==2);
 result=&timewait;assert(!bpf_sk_lookup_tcp(&skb,&t,12,UINT64_MAX,0)&&release_count==3);
 request.listener=&full;result=&request;assert(!bpf_sk_lookup_tcp(&skb,&t,12,UINT64_MAX,0)&&release_count==4);
 result=NULL;assert(!bpf_sk_lookup_tcp(&skb,&t,12,UINT64_MAX,0)&&release_count==4);
 skb.dev=NULL;result=&full;assert(bpf_sk_lookup_tcp(&skb,&t,12,UINT64_MAX,0)==(unsigned long)&full&&last_dif==0&&last_net==&caller);
 skb.sk=NULL;assert(!bpf_sk_lookup_tcp(&skb,&t,12,UINT64_MAX,0));
 printf("PASS runtime contract mocks (no live networking)\n");return 0;
}

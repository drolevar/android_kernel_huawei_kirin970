/* SPDX-License-Identifier: GPL-2.0 */
#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#undef htons
#define htons(x) __builtin_bswap16((uint16_t)(x))
typedef uint32_t __be32;typedef uint32_t u32;typedef uint64_t u64;typedef uint32_t __u32;typedef uint16_t __be16;
#define function static
struct kver_uint {int n;};
#define KVER_IS_AT_LEAST(k,a,b) ((k).n>=((a)*100+(b)))
#define AID_ROOT 0
#define AID_SHELL 2000
#ifndef IPPROTO_MPTCP
#define IPPROTO_MPTCP 262
#endif
#define BPF_ALLOW 1
#define BPF_DISALLOW 0
static const int BPF_ALLOW_IGNORING_CAP_NET_BIND=3;
static u32 uid=10000,pid=123,netd_pid=123;static bool pid_present=true;
static uint64_t blocked[1024];
static uint64_t bpf_get_current_uid_gid(void){return uid;}
static uint64_t bpf_get_current_pid_tgid(void){return (uint64_t)pid<<32;}
static u32 *bpf_netd_pid_map_lookup_elem(const u32*k){return pid_present?&netd_pid:NULL;}
static uint64_t *bpf_blocked_ports_map_lookup_elem(const int*k){return *k>=0&&*k<1024?&blocked[*k]:NULL;}
struct bpf_sock_addr {u32 user_family,user_ip4,user_ip6[4],user_port,family,type,protocol,msg_src_ip4,msg_src_ip6[4];void*sk;};
/* CONSUMER */
struct sock;struct sockaddr;
struct proto {int (*pre_connect)(struct sock*,struct sockaddr*,int);int (*connect)(struct sock*,struct sockaddr*,int);int (*disconnect)(struct sock*,int);int (*bind)(struct sock*,struct sockaddr*,int);int (*get_port)(struct sock*,unsigned short);};
struct inet_sock {bool freebind,transparent,bind_address_no_port;unsigned short inet_num,inet_sport,inet_dport;u32 inet_rcv_saddr,inet_saddr,inet_daddr;};
struct net {struct {int sysctl_ip_nonlocal_bind;} ipv4;struct {struct {int ip_nonlocal_bind;} sysctl;} ipv6;void*user_ns;};
struct ipv6_pinfo {struct in6_addr saddr;};
struct cgroup;
struct sock {bool sk_ipv6only;struct in6_addr sk_v6_rcv_saddr;struct ipv6_pinfo np;struct proto*sk_prot;int sk_family,sk_protocol,sk_type,sk_bound_dev_if,sk_state,sk_userlocks;struct inet_sock inet;struct net*net;struct cgroup*sk_cgrp_data;};
struct socket {struct sock*sk;int type;};
#define inet_sk(s) (&(s)->inet)
#define sock_net(s) ((s)->net)
#define RT_TABLE_LOCAL 255
#define RTN_LOCAL 2
#define RTN_MULTICAST 5
#define RTN_BROADCAST 3
#define TCP_CLOSE 7
#define SOCK_BINDADDR_LOCK 1
#define SOCK_BINDPORT_LOCK 2
#define CAP_NET_BIND_SERVICE 10
static int lock_count,hook_calls,port_calls,collision,cap_calls;
static bool capable_bind=true,cgroup_bpf_enabled=true;
static void *checked_ns;
static int inet_prot_sock(struct net*n){return 1024;}
static int ns_capable(void*ns,int cap){cap_calls++;checked_ns=ns;return capable_bind;}
static int l3mdev_fib_table_by_index(struct net*n,int i){return 0;}
static int inet_addr_type_table(struct net*n,u32 a,u32 table){return RTN_LOCAL;}
static void lock_sock(struct sock*s){assert(!lock_count);lock_count++;}
static void release_sock(struct sock*s){assert(lock_count==1);lock_count--;}
static void sk_dst_reset(struct sock*s){}
static int get_port(struct sock*s,unsigned short p){port_calls++;if(collision)return 1;s->inet.inet_num=p;return 0;}
#define EXPORT_SYMBOL(x)
#define READ_ONCE(x) (x)
#define rcu_dereference(x) (x)
static int rcu_depth;
static void rcu_read_lock(void){rcu_depth++;}
static void rcu_read_unlock(void){rcu_depth--;}
struct bpf_sock_addr_kern {struct sock*sk;struct sockaddr*uaddr;u64 tmp_reg;void*t_ctx;};
struct bpf_prog {int mode;};struct bpf_prog_array {struct bpf_prog*progs[4];};
struct cgroup {struct {struct bpf_prog_array*effective[23];} bpf;};
static struct cgroup*sock_cgroup_ptr(struct cgroup**p){return *p;}
static int consumer_kver=419;
static u32 run_prog(struct bpf_prog*p,struct bpf_sock_addr_kern*c){
 assert(lock_count==0);hook_calls++;
 if(p->mode==1)return 0;
 struct bpf_sock_addr u={.family=c->sk->sk_family,.type=c->sk->sk_type,.protocol=c->sk->sk_protocol};
 if(c->uaddr->sa_family==AF_INET){struct sockaddr_in*a=(void*)c->uaddr;u.user_family=a->sin_family;u.user_ip4=a->sin_addr.s_addr;u.user_port=a->sin_port;}
 else {struct sockaddr_in6*a=(void*)c->uaddr;u.user_family=a->sin6_family;u.user_port=a->sin6_port;memcpy(u.user_ip6,&a->sin6_addr,16);}
 return netd_inet_bind(&u,(struct kver_uint){consumer_kver});
}
#define BPF_PROG_RUN(p,c) run_prog(p,c)
static int pre_calls,connect_calls,autobind_calls,disconnect_calls;
static int pre_reject(struct sock*s,struct sockaddr*a,int n){pre_calls++;return -EACCES;}
static int connect_ok(struct sock*s,struct sockaddr*a,int n){connect_calls++;return 0;}
static int disconnect_ok(struct sock*s,int f){disconnect_calls++;return 0;}
static int inet_autobind(struct sock*s){autobind_calls++;return 0;}
#define inet6_sk(s) (&(s)->np)
#define SIN6_LEN_RFC2133 24
#define IPV6_ADDR_ANY 0
#define IPV6_ADDR_UNICAST 1
#define IPV6_ADDR_MULTICAST 2
#define IPV6_ADDR_MAPPED 4
#define IPV6_ADDR_LINKLOCAL 8
#define LOOPBACK4_IPV6 htonl(0x7f000001)
static int address_type;static bool device_exists=true,local_address=true;
struct net_device {int dummy;};static struct net_device device;
static int ipv6_addr_type(const struct in6_addr*a){return address_type;}
static int inet_addr_type(struct net*n,u32 a){return RTN_LOCAL;}
static bool __ipv6_addr_needs_scope_id(int t){return t&IPV6_ADDR_LINKLOCAL;}
static struct net_device *dev_get_by_index_rcu(struct net*n,int id){checked_ns=n->user_ns;return device_exists?&device:NULL;}
static bool ipv6_chk_addr(struct net*n,const struct in6_addr*a,struct net_device*d,int x){checked_ns=n->user_ns;return local_address;}
static void inet_reset_saddr(struct sock*s){s->inet.inet_saddr=s->inet.inet_rcv_saddr=0;memset(&s->np.saddr,0,sizeof(s->np.saddr));memset(&s->sk_v6_rcv_saddr,0,sizeof(s->sk_v6_rcv_saddr));}
/* SUBJECT */
int main(int argc,char**argv){assert(argc==2);const char*test=argv[1];
 struct bpf_prog consumer={0},deny={1};struct bpf_prog_array array={.progs={&consumer,NULL}};struct cgroup cg={0};for(int i=0;i<23;i++)cg.bpf.effective[i]=&array;
 struct net net={.user_ns=(void*)123};struct proto prot={.get_port=get_port};struct sock sk={.sk_prot=&prot,.sk_family=AF_INET,.sk_type=SOCK_STREAM,.sk_protocol=IPPROTO_TCP,.sk_state=TCP_CLOSE,.net=&net,.sk_cgrp_data=&cg};struct socket sock={.sk=&sk,.type=SOCK_STREAM};struct sockaddr_in addr={.sin_family=AF_INET,.sin_port=htons(5555)};
 struct sockaddr_in6 addr6={.sin6_family=AF_INET6,.sin6_port=htons(5555)};
 if(!strcmp(test,"blocked6")){sk.sk_family=AF_INET6;unsigned port=addr6.sin6_port;blocked[port>>6]|=1ULL<<(port&63);assert(inet6_bind(&sock,(void*)&addr6,sizeof(addr6))==-EPERM&&hook_calls==1&&!port_calls);}
 else if(!strcmp(test,"cap6")){sk.sk_family=AF_INET6;addr6.sin6_port=htons(80);capable_bind=false;assert(inet6_bind(&sock,(void*)&addr6,sizeof(addr6))==-EACCES&&hook_calls==1&&checked_ns==net.user_ns);}
 else if(!strcmp(test,"short6")){assert(inet6_bind(&sock,(void*)&addr6,23)==-EINVAL&&!hook_calls);}
 else if(!strcmp(test,"mapped-v6only")){sk.sk_family=AF_INET6;sk.sk_ipv6only=true;address_type=IPV6_ADDR_MAPPED;assert(inet6_bind(&sock,(void*)&addr6,sizeof(addr6))==-EINVAL&&hook_calls==1&&!port_calls);}
 else if(!strcmp(test,"scope-missing")){sk.sk_family=AF_INET6;address_type=IPV6_ADDR_LINKLOCAL;assert(inet6_bind(&sock,(void*)&addr6,sizeof(addr6))==-EINVAL&&hook_calls==1&&!port_calls);}
 else if(!strcmp(test,"device-missing")){sk.sk_family=AF_INET6;address_type=IPV6_ADDR_LINKLOCAL;addr6.sin6_scope_id=3;device_exists=false;assert(inet6_bind(&sock,(void*)&addr6,sizeof(addr6))==-ENODEV&&hook_calls==1&&checked_ns==net.user_ns&&!port_calls);}
 else if(!strcmp(test,"nonlocal6")){sk.sk_family=AF_INET6;address_type=IPV6_ADDR_UNICAST;local_address=false;assert(inet6_bind(&sock,(void*)&addr6,sizeof(addr6))==-EADDRNOTAVAIL&&hook_calls==1&&checked_ns==net.user_ns&&!port_calls);}
 else if(!strcmp(test,"collision6")){sk.sk_family=AF_INET6;address_type=IPV6_ADDR_UNICAST;collision=1;assert(inet6_bind(&sock,(void*)&addr6,sizeof(addr6))==-EADDRINUSE&&hook_calls==1&&!sk.sk_ipv6only&&!sk.inet.inet_rcv_saddr);}
 else if(!strcmp(test,"allow6")){sk.sk_family=AF_INET6;assert(!inet6_bind(&sock,(void*)&addr6,sizeof(addr6))&&hook_calls==1&&port_calls==1);}
 else if(!strcmp(test,"blocked")){unsigned port=addr.sin_port;blocked[port>>6]|=1ULL<<(port&63);assert(inet_bind(&sock,(void*)&addr,sizeof(addr))==-EPERM&&!port_calls&&hook_calls==1);}
 else if(!strcmp(test,"privileged-port")){addr.sin_port=htons(80);capable_bind=false;assert(inet_bind(&sock,(void*)&addr,sizeof(addr))==-EACCES&&hook_calls==1&&cap_calls==1);}
 else if(!strcmp(test,"legacy-cap")){consumer_kver=419;addr.sin_port=htons(80);capable_bind=false;assert(inet_bind(&sock,(void*)&addr,sizeof(addr))==-EACCES&&checked_ns==net.user_ns&&hook_calls==1);}
 else if(!strcmp(test,"deny-dominates")){addr.sin_port=htons(80);capable_bind=false;array.progs[1]=&deny;assert(inet_bind(&sock,(void*)&addr,sizeof(addr))==-EPERM&&hook_calls==2&&!port_calls);}
 else if(!strcmp(test,"short")){assert(inet_bind(&sock,(void*)&addr,1)==-EINVAL&&!hook_calls);}
 else if(!strcmp(test,"collision")){collision=1;assert(inet_bind(&sock,(void*)&addr,sizeof(addr))==-EADDRINUSE&&hook_calls==1&&!sk.inet.inet_rcv_saddr&&!sk.inet.inet_saddr);}
 else if(!strcmp(test,"netd-dns")){addr.sin_port=htons(53);uid=0;capable_bind=false;assert(inet_bind(&sock,(void*)&addr,sizeof(addr))==-EACCES&&cap_calls==1&&hook_calls==1);}
 else if(!strcmp(test,"wrong-netd")){addr.sin_port=htons(53);uid=0;netd_pid=124;capable_bind=false;assert(inet_bind(&sock,(void*)&addr,sizeof(addr))==-EACCES&&hook_calls==1);}
 else if(!strcmp(test,"connect-denied")){prot.pre_connect=pre_reject;prot.connect=connect_ok;prot.disconnect=disconnect_ok;assert(inet_dgram_connect(&sock,(void*)&addr,sizeof(addr),0)==-EACCES&&pre_calls==1&&!connect_calls&&!autobind_calls);}
 else if(!strcmp(test,"disconnect")){prot.pre_connect=pre_reject;prot.connect=connect_ok;prot.disconnect=disconnect_ok;addr.sin_family=AF_UNSPEC;assert(!inet_dgram_connect(&sock,(void*)&addr,sizeof(addr),0)&&disconnect_calls==1&&!pre_calls&&!connect_calls&&!autobind_calls);}
 else abort();assert(!lock_count&&!rcu_depth);puts("PASS extracted bind/consumer; modeled services");return 0;
}

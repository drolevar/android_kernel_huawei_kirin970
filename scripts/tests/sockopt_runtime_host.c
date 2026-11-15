/* SPDX-License-Identifier: GPL-2.0 */
#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <stdio.h>
#include <errno.h>
#include <limits.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
typedef uint8_t u8;typedef int32_t s32;typedef uint32_t u32;
#define __user
#define __force
#define PAGE_SIZE 4096
#define GFP_USER 0
#define unlikely(x) (x)
#define max_t(t,a,b) ((t)(a)>(t)(b)?(t)(a):(t)(b))
#define min(a,b) ((a)<(b)?(a):(b))
#define BPF_CGROUP_GETSOCKOPT 21
#define BPF_CGROUP_SETSOCKOPT 22
static int allocations,alloc_fail,copyin_fail,copyout_fail,get_fail,put_fail;
static int locks,lsm_error,protocol_error=-ENOPROTOOPT,protocol_calls,hook_calls,storage_calls,fput_count;
static bool compat,attached=true,cgroup_bpf_enabled=true;
static int mode,fs;static bool storage_missing;
static char *protocol_buffer;static int protocol_length,protocol_level;
static int events[128],nevents;
static void *kzalloc(size_t n,int f){if(alloc_fail)return NULL;void*p=calloc(1,n?n:1);assert(p);allocations++;return p;}
static void kfree(void*p){if(p){allocations--;free(p);}}
static unsigned copy_from_user(void*d,const void*s,size_t n){if(copyin_fail||(!s&&n))return 1;if(n)memcpy(d,s,n);return 0;}
static unsigned copy_to_user(void*d,const void*s,size_t n){if(copyout_fail||(!d&&n))return 1;if(n)memcpy(d,s,n);return 0;}
#define get_user(x,p) (get_fail||!(p)?-EFAULT:((x)=*(p),0))
#define put_user(x,p) (put_fail||!(p)?-EFAULT:(*(p)=(x),0))
typedef int mm_segment_t;
#define KERNEL_DS 1
static int get_fs(void){return fs;}
static void set_fs(int n){fs=n;}
static bool in_compat_syscall(void){return compat;}
enum bpf_attach_type {TEST_ATTACH=0};
static void rcu_read_lock(void){}
static void rcu_read_unlock(void){}
#define rcu_dereference(x) (x)
struct cgroup {struct {void *effective[23];} bpf;};
static struct cgroup cg;
struct sock {int sk_cgrp_data;};static struct sock sk;
struct bpf_sockopt_kern {struct sock *sk;u8 *optval,*optval_end;s32 level,optname,optlen,retval;};
static struct cgroup *sock_cgroup_ptr(int*p){return &cg;}
static int bpf_prog_array_length(void*p){return attached;}
static void lock_sock(struct sock*s){assert(!locks);locks++;}
static void release_sock(struct sock*s){assert(locks==1);locks--;}
struct bpf_sock {u32 bound_dev_if,family,type,protocol,mark,priority;};
struct bpf_sockopt {struct bpf_sock *sk;void *optval,*optval_end;s32 level,optname,optlen,retval;};
struct kver_uint {unsigned value;};struct sdk_level_uint {unsigned value;};
#define function static
#define KVER_IS_AT_LEAST(k,a,b) ((k).value>=((a)*100+(b)))
#define KVER_IS_BETWEEN(a,b,k,c,d) ((k).value>=((a)*100+(b))&&(k).value<((c)*100+(d)))
#define API_IS_AT_LEAST(l,a) false
#define WRITE_ONCE(x,v) ((x)=(v))
/* CONSUMER_API */
#define BPF_ALLOW 1
#define BPF_DISALLOW 0
#define bpf_disallow(v) (0)
static bool is_netd(void){return false;}
typedef struct {uint64_t cookie;u32 gid,uid;uint64_t dropReasons;u8 cache[40];struct {u8 enabled,pad[31];} l4s;u8 loopback[32];} SkStorageValue;
static SkStorageValue storage={.dropReasons=0x8877665544332211ULL};
static SkStorageValue *bpf_sk_storage_get(struct bpf_sock*s,void*v,int flags){storage_calls++;return storage_missing?NULL:&storage;}
/* CONSUMER */
static int run_program(struct bpf_sockopt_kern *ctx,int type){
 assert(locks==1);events[nevents++]=2;hook_calls++;
 struct bpf_sock view={0};struct bpf_sockopt c={&view,ctx->optval,ctx->optval_end,ctx->level,ctx->optname,ctx->optlen,ctx->retval};
 int ret=1;
 switch(mode){
 case 0:ret=type==21?inet_getsockopt(&c,(struct kver_uint){510},(struct sdk_level_uint){0}):inet_setsockopt(&c,(struct kver_uint){510},(struct sdk_level_uint){0});break;
 case 1:ret=0;break;
 case 2:c.optlen=-1;break;
 case 3:c.optlen=4;c.level=123;memcpy(c.optval,"abcd",4);break;
 case 4:c.optlen=PAGE_SIZE+1;break;
 case 5:c.optlen=-2;break;
 case 6:c.retval=-EINVAL;break;
 }
 ctx->level=c.level;ctx->optname=c.optname;ctx->optlen=c.optlen;ctx->retval=c.retval;return ret;
}
#define BPF_PROG_RUN_ARRAY(a,c,f) run_program(c,(c)->retval?21:current_hook)
static int current_hook;
struct socket;
struct proto_ops {int (*setsockopt)(struct socket*,int,int,char*,int);int (*getsockopt)(struct socket*,int,int,char*,int*);};
struct socket {struct sock*sk;void*file;struct proto_ops*ops;};
static int protocol_set(struct socket*s,int l,int o,char*v,int n){events[nevents++]=3;protocol_calls++;protocol_buffer=v;protocol_length=n;protocol_level=l;if(fs==KERNEL_DS)assert(n==4&&!memcmp(v,"abcd",4));return protocol_error;}
static int protocol_get(struct socket*s,int l,int o,char*v,int*n){events[nevents++]=3;protocol_calls++;return protocol_error;}
static struct proto_ops ops={protocol_set,protocol_get};static struct socket socket_={&sk,NULL,&ops};
static struct socket *sockfd_lookup_light(int fd,int*err,int*needed){return &socket_;}
static int security_socket_setsockopt(struct socket*s,int l,int o){events[nevents++]=1;return lsm_error;}
static int security_socket_getsockopt(struct socket*s,int l,int o){events[nevents++]=1;return lsm_error;}
static void fput_light(void*f,int n){fput_count++;}
#define sock_setsockopt protocol_set
#define sock_getsockopt protocol_get
#define SYSCALL_DEFINE5(n,t1,a1,t2,a2,t3,a3,t4,a4,t5,a5) static int sys_##n(t1 a1,t2 a2,t3 a3,t4 a4,t5 a5)
/* SUBJECT */
int main(int argc,char**argv){assert(argc==2);const char*c=argv[1];char buf[8192];memset(buf,0x5a,sizeof(buf));int n=sizeof(buf),ret;current_hook=21;
 if(!strcmp(c,"get-custom")){n=8;ret=sys_getsockopt(1,SOL_SOCKET,SO_ANDROID_DROP_REASON,buf,&n);assert(ret==0&&n==8&&storage.dropReasons==0);uint64_t value;memcpy(&value,buf,8);assert(value==0x8877665544332211ULL);assert(events[0]==1&&events[1]==3&&events[2]==2&&storage_calls==1);}
 else if(!strcmp(c,"get-pass")){protocol_error=0;ret=sys_getsockopt(1,SOL_SOCKET,1,buf,&n);assert(ret==0&&n==8192&&buf[0]==0x5a&&buf[8191]==0x5a&&hook_calls==1);}
 else if(!strcmp(c,"set-pass")){current_hook=22;protocol_error=0;ret=sys_setsockopt(1,SOL_SOCKET,1,buf,n);assert(!ret&&protocol_buffer==buf&&protocol_length==8192&&storage_calls==1&&events[1]==2&&events[2]==3);}
 else if(!strcmp(c,"deny")){mode=1;assert(sys_getsockopt(1,1,1,buf,&n)==-EPERM);current_hook=22;protocol_calls=0;assert(sys_setsockopt(1,1,1,buf,n)==-EPERM&&!protocol_calls);}
 else if(!strcmp(c,"consume")){current_hook=22;mode=2;assert(!sys_setsockopt(1,1,1,buf,n)&&!protocol_calls);}
 else if(!strcmp(c,"replace")){current_hook=22;mode=3;assert(sys_setsockopt(1,1,1,buf,n)==-ENOPROTOOPT&&protocol_length==4&&protocol_level==123&&!fs);}
 else if(!strcmp(c,"lengths")){n=-1;assert(sys_getsockopt(1,1,1,buf,&n)==-EINVAL);assert(sys_setsockopt(1,1,1,buf,-1)==-EINVAL);n=8;mode=4;assert(sys_getsockopt(1,1,1,buf,&n)==-EFAULT);mode=5;assert(sys_getsockopt(1,1,1,buf,&n)==-EFAULT);mode=6;assert(sys_getsockopt(1,1,1,buf,&n)==-EFAULT);}
 else if(!strcmp(c,"copy-faults")){n=8;copyout_fail=1;assert(sys_getsockopt(1,1,SO_ANDROID_DROP_REASON,buf,&n)==-EFAULT&&storage.dropReasons==0);copyout_fail=0;put_fail=1;assert(sys_getsockopt(1,1,SO_ANDROID_DROP_REASON,buf,&n)==-EFAULT);put_fail=0;copyin_fail=1;current_hook=22;assert(sys_setsockopt(1,1,1,buf,8)==-EFAULT);}
 else if(!strcmp(c,"alloc-failure")){alloc_fail=1;assert(sys_getsockopt(1,1,1,buf,&n)==-ENOMEM);current_hook=22;assert(sys_setsockopt(1,1,1,buf,n)==-ENOMEM);}
 else if(!strcmp(c,"disabled")){attached=false;assert(sys_getsockopt(1,1,1,buf,&n)==protocol_error&&!hook_calls&&!allocations);current_hook=22;assert(sys_setsockopt(1,1,1,buf,n)==protocol_error&&!hook_calls);}
 else if(!strcmp(c,"lsm")){lsm_error=-EACCES;assert(sys_getsockopt(1,1,1,buf,&n)==-EACCES&&!protocol_calls&&!hook_calls);assert(sys_setsockopt(1,1,1,buf,n)==-EACCES&&!protocol_calls&&!hook_calls);}
 else if(!strcmp(c,"compat")){compat=true;assert(sys_getsockopt(1,1,SO_ANDROID_DROP_REASON,buf,&n)==protocol_error&&!hook_calls);assert(sys_setsockopt(1,1,1,buf,n)==protocol_error&&!hook_calls);}
 else if(!strcmp(c,"short-buffer")){for(n=0;n<8;n++)assert(sys_getsockopt(1,1,SO_ANDROID_DROP_REASON,buf,&n)==-EPERM&&storage.dropReasons==0x8877665544332211ULL);}
 else if(!strcmp(c,"missing-storage")){storage_missing=true;n=8;assert(sys_getsockopt(1,1,SO_ANDROID_DROP_REASON,buf,&n)==-EPERM&&storage_calls==1);}
 else if(!strcmp(c,"get-copyin")){protocol_error=0;copyin_fail=1;n=8;assert(sys_getsockopt(1,1,1,buf,&n)==-EFAULT&&!hook_calls);}
 else if(!strcmp(c,"get-count-fault")){protocol_error=0;get_fail=1;assert(sys_getsockopt(1,1,1,buf,&n)==-EFAULT&&!hook_calls);}
 else if(!strcmp(c,"set-lengths")){current_hook=22;mode=4;assert(sys_setsockopt(1,1,1,buf,INT_MAX)==-EFAULT&&!protocol_calls);mode=5;assert(sys_setsockopt(1,1,1,buf,8)==-EFAULT&&!protocol_calls);}
 else if(!strcmp(c,"null-count")){protocol_error=-EFAULT;assert(sys_getsockopt(1,1,SO_ANDROID_DROP_REASON,buf,NULL)==-EPERM&&storage.dropReasons==0x8877665544332211ULL);}
 else if(!strcmp(c,"null-value")){n=8;assert(!sys_getsockopt(1,1,SO_ANDROID_DROP_REASON,NULL,&n)&&n==8&&storage.dropReasons==0);current_hook=22;assert(sys_setsockopt(1,1,1,NULL,8)==-EFAULT);}
 else abort();assert(!allocations&&!locks&&!fs);puts("PASS modeled syscall/hook services");return 0;}

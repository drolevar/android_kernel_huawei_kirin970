#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Execute extracted network converters and interpret their emitted instructions.
Sock/skb layout and kernel services are modeled. Both end-pointer/offset layouts
and mask variants are exercised; actual layout compilation is a separate gate.
"""
import argparse,hashlib,json,re,subprocess
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--cc',required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();a.output.mkdir(parents=True,exist_ok=False);root=Path(__file__).resolve().parents[2]
net=(root/'net/core/filter.c').read_text();sock=(root/'include/net/sock.h').read_text()
def fun(s,n):
 m=re.search(r'^(?:static )?(?:inline )?[\w *]+\b'+n+r'\([^;]*?\)\n\{',s,re.M);assert m,n
 b=s.index('{',m.start());i=b+1;d=1
 while d:d+=(s[i]=='{')-(s[i]=='}');i+=1
 return s[m.start():i]
body='\n'.join(fun(net,n) for n in ['sock_filter_convert_ctx_access','bpf_sock_convert_ctx_access','cg_skb_convert_ctx_access'])
addr=(root/'net/core/filter_sockaddr.inc').read_text();body+='\n'+addr[addr.index('/* SOCK_ADDR_LOAD_NESTED_FIELD()'):addr.index('const struct bpf_verifier_ops')]
helper=re.search(r'^BPF_CALL_1\(bpf_sk_fullsock,.*?^\}',net,re.M|re.S)[0]
masks=sock[sock.index('#ifdef __BIG_ENDIAN_BITFIELD\n#define SK_FL_PROTO_SHIFT'):sock.index('\n\tunsigned int\t\tsk_padding')]
source=r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include BPF_UAPI_HEADER
typedef uint32_t u32;typedef uint64_t u64;
enum bpf_access_type {BPF_READ,BPF_WRITE};
struct bpf_prog {int unused;};
struct sock;
struct bpf_sock_addr_kern {struct sock *sk;struct sockaddr *uaddr;u64 tmp_reg;void *t_ctx;};
#define bpf_ctx_range_till(T,F,L) offsetof(T,F) ... (offsetof(T,L)+sizeof(((T*)0)->L)-1)
#define bpf_target_off(T,F,S,Z) (*(Z)=(S),offsetof(T,F))
#define BPF_LDST_BYTES(I) (BPF_SIZE((I)->code)==BPF_DW?8:BPF_SIZE((I)->code)==BPF_W?4:BPF_SIZE((I)->code)==BPF_H?2:1)
#define min(A,B) ((A)<(B)?(A):(B))
static int bytes_to_bpf_size(int n){switch(n){case 1:return BPF_B;case 2:return BPF_H;case 4:return BPF_W;case 8:return BPF_DW;default:abort();}}
struct sock {u32 sk_bound_dev_if,sk_mark,sk_priority;uint16_t sk_family,pad;u32 __sk_flags_offset;int sk_state;};
struct sk_buff {uint64_t padding;struct sock *sk;unsigned char *head;
#ifdef NET_SKBUFF_DATA_USES_OFFSET
 u32 end;
#else
 unsigned char *end;
#endif
};
struct skb_shared_info {uint64_t unused;uint16_t gso_segs;};
#define FIELD_SIZEOF(T,F) sizeof(((T*)0)->F)
#define BPF_FIELD_SIZEOF(T,F) (FIELD_SIZEOF(T,F)==8?BPF_DW:FIELD_SIZEOF(T,F)==4?BPF_W:FIELD_SIZEOF(T,F)==2?BPF_H:BPF_B)
#define BUILD_BUG_ON(x) do { _Static_assert(!(x),#x); } while (0)
#define BPF_REG_AX MAX_BPF_REG
#define BPF_LDX_MEM(S,D,R,O) ((struct bpf_insn){.code=BPF_LDX|BPF_MEM|(S),.dst_reg=D,.src_reg=R,.off=O})
#define BPF_STX_MEM(S,D,R,O) ((struct bpf_insn){.code=BPF_STX|BPF_MEM|(S),.dst_reg=D,.src_reg=R,.off=O})
#define BPF_ALU32_IMM(O,D,I) ((struct bpf_insn){.code=BPF_ALU|(O)|BPF_K,.dst_reg=D,.imm=I})
#define BPF_ALU64_REG(O,D,R) ((struct bpf_insn){.code=BPF_ALU64|(O)|BPF_X,.dst_reg=D,.src_reg=R})
#define TCPF_TIME_WAIT (1<<6)
#define TCPF_NEW_SYN_RECV (1<<12)
#define BPF_CALL_1(N,T,A) static u64 N(T A)
static u32 bpf_convert_ctx_access(enum bpf_access_type t,const struct bpf_insn*s,struct bpf_insn*b,struct bpf_prog*p,u32*z){abort();}
'''+masks+'\n'+fun(sock,'sk_fullsock')+'\n'+helper+'\n'+body+r'''
/* Independent interpreter for the exact load/add/mask/shift subset produced. */
static u64 run(struct bpf_insn *p,int n,u64 base,int dst){u64 r[16]={0};r[1]=base;for(int i=0;i<n;i++){
 struct bpf_insn x=p[i];int cl=BPF_CLASS(x.code),op=BPF_OP(x.code);
 if(cl==BPF_LDX){int size=BPF_SIZE(x.code)==BPF_DW?8:BPF_SIZE(x.code)==BPF_W?4:2;u64 value=0;memcpy(&value,(void*)(uintptr_t)(r[x.src_reg]+x.off),size);r[x.dst_reg]=value;}
 else if(cl==BPF_ALU&&op==BPF_AND)r[x.dst_reg]=(u32)r[x.dst_reg]&(u32)x.imm;
 else if(cl==BPF_ALU&&op==BPF_RSH)r[x.dst_reg]=(u32)r[x.dst_reg]>>x.imm;
 else if(cl==BPF_ALU64&&op==BPF_ADD)r[x.dst_reg]+=r[x.src_reg];else abort();
 }return r[dst];}

static void addr_run(struct bpf_insn*p,int n,u64*r){for(int i=0;i<n;i++){
 struct bpf_insn x=p[i];int cl=BPF_CLASS(x.code),op=BPF_OP(x.code),sz=BPF_LDST_BYTES(&x);
 if(cl==BPF_LDX){u64 v=0;memcpy(&v,(void*)(uintptr_t)(r[x.src_reg]+x.off),sz);r[x.dst_reg]=v;}
 else if(cl==BPF_STX)memcpy((void*)(uintptr_t)(r[x.dst_reg]+x.off),&r[x.src_reg],sz);
 else if(cl==BPF_ALU&&op==BPF_AND)r[x.dst_reg]=(u32)r[x.dst_reg]&(u32)x.imm;
 else if(cl==BPF_ALU&&op==BPF_RSH)r[x.dst_reg]=(u32)r[x.dst_reg]>>x.imm;
 else abort();
}}
static void addr_checks(void){
 struct sock sk={.sk_family=AF_INET6};sk.__sk_flags_offset=(17<<SK_FL_PROTO_SHIFT)|(2<<SK_FL_TYPE_SHIFT);
 struct sockaddr_in6 sa={.sin6_family=AF_INET6,.sin6_port=htons(5353)};
 struct in6_addr source={{0}};struct bpf_sock_addr_kern ctx={.sk=&sk,.uaddr=(void*)&sa,.t_ctx=&source};
 const int offsets[]={0,24,28,32,36,64};u64 expect[]={AF_INET6,htons(5353),AF_INET6,2,17,(u64)(uintptr_t)&sk};
 for(int base=1;base<=9;base++)for(int dst=1;dst<=9;dst++)for(unsigned f=0;f<6;f++){
  u64 regs[16],before[16];for(int i=0;i<16;i++)regs[i]=0xfedcba9876540000ULL+i;regs[base]=(u64)(uintptr_t)&ctx;memcpy(before,regs,sizeof(regs));
  struct bpf_insn in={.code=BPF_LDX|BPF_MEM|(f==5?BPF_DW:BPF_W),.src_reg=base,.dst_reg=dst,.off=offsets[f]},out[16];u32 target=0;
  int n=sock_addr_convert_ctx_access(BPF_READ,&in,out,NULL,&target);assert(n>0&&n<16);addr_run(out,n,regs);assert(regs[dst]==expect[f]);for(int i=0;i<16;i++)if(i!=dst)assert(regs[i]==before[i]);
 }
 const int uoff[]={4,8,12,16,20,24,40,44,48,52,56};
 for(int dst=1;dst<=9;dst++)for(int src=1;src<=9;src++)if(src!=dst)for(unsigned f=0;f<11;f++){
  int size=f==5?2:4;unsigned char*target;
  if(f==0)target=(unsigned char*)&sa+offsetof(struct sockaddr_in,sin_addr);
  else if(f<5)target=(unsigned char*)&sa.sin6_addr+(uoff[f]-8);
  else if(f==5)target=(unsigned char*)&sa.sin6_port;
  else if(f==6)target=(unsigned char*)&source;
  else target=(unsigned char*)&source+(uoff[f]-44);
  u64 regs[16],before[16],value=0x87654321;for(int i=0;i<16;i++)regs[i]=0x12340000+i;regs[dst]=(u64)(uintptr_t)&ctx;regs[src]=value;memcpy(before,regs,sizeof(regs));
  struct bpf_insn in={.code=BPF_STX|BPF_MEM|BPF_W,.src_reg=src,.dst_reg=dst,.off=uoff[f]},out[16];u32 ts=0;int n=sock_addr_convert_ctx_access(BPF_WRITE,&in,out,NULL,&ts);assert(n==4);addr_run(out,n,regs);assert(!memcmp(target,&value,size));assert(!memcmp(regs,before,sizeof(regs)));
 }
 /* Accepted aligned doubleword IPv6 accesses include source offset 48,
  * which is interior to the array at UAPI offset 44. Check actual bytes,
  * untouched neighbors and every scratch-register collision. */
 const int wide_offsets[]={8,16,48};
 for(int base=1;base<=9;base++)for(int reg=1;reg<=9;reg++)for(unsigned f=0;f<3;f++){
  unsigned char *area=f==2?(unsigned char*)&source:(unsigned char*)&sa.sin6_addr;
  int off=f==2?4:wide_offsets[f]-8;
  for(int write=0;write<=1;write++){
   if(write&&base==reg)continue;
   memset(area,0x5a,16);u64 value=0xfedcba9876543210ULL;memcpy(area+off,&value,8);
   u64 regs[16],before[16];for(int i=0;i<16;i++)regs[i]=0xaabb0000+i;
   regs[base]=(u64)(uintptr_t)&ctx;if(write)regs[reg]=value^0xffffffffffffffffULL;
   memcpy(before,regs,sizeof(regs));unsigned char expected[16];memcpy(expected,area,16);
   if(write)memcpy(expected+off,&regs[reg],8);
   struct bpf_insn in={.code=(write?BPF_STX:BPF_LDX)|BPF_MEM|BPF_DW,
    .src_reg=write?reg:base,.dst_reg=write?base:reg,.off=wide_offsets[f]},out[16];u32 ts=0;
   int n=sock_addr_convert_ctx_access(write?BPF_WRITE:BPF_READ,&in,out,NULL,&ts);
   assert(n==(write?4:2));addr_run(out,n,regs);assert(!memcmp(area,expected,16));
   if(!write)assert(regs[reg]==value);
   for(int i=0;i<16;i++)if(write||i!=reg)assert(regs[i]==before[i]);
  }
 }
}
int main(void){addr_checks();struct bpf_insn out[16],in;u32 target=0;struct sock sk={.sk_bound_dev_if=19,.sk_mark=0xfedcba98,.sk_priority=17,.sk_family=10,.sk_state=1};
 sk.__sk_flags_offset=(17<<SK_FL_PROTO_SHIFT)|(3<<SK_FL_TYPE_SHIFT);
 const u32 expected[]={19,10,3,17,0xfedcba98,17};
 for(int dst=1;dst<=2;dst++)for(int i=0;i<6;i++){
  in=(struct bpf_insn){.src_reg=1,.dst_reg=dst,.off=i*4};int n=bpf_sock_convert_ctx_access(BPF_READ,&in,out,NULL,&target);assert(n>0);assert(run(out,n,(u64)(uintptr_t)&sk,dst)==expected[i]);assert(!bpf_sock_convert_ctx_access(BPF_WRITE,&in,out,NULL,&target));
 }
 unsigned char head[256]={0};struct skb_shared_info sh={.gso_segs=1234};memcpy(head+64,&sh,sizeof(sh));struct sk_buff skb={.sk=&sk,.head=head,
#ifdef NET_SKBUFF_DATA_USES_OFFSET
 .end=64
#else
 .end=head+64
#endif
 };
 for(int dst=1;dst<=2;dst++){
  in=(struct bpf_insn){.src_reg=1,.dst_reg=dst,.off=164};int n=cg_skb_convert_ctx_access(BPF_READ,&in,out,NULL,&target);assert(run(out,n,(u64)(uintptr_t)&skb,dst)==1234);
  in.off=168;n=cg_skb_convert_ctx_access(BPF_READ,&in,out,NULL,&target);assert(run(out,n,(u64)(uintptr_t)&skb,dst)==(u64)(uintptr_t)&sk);
 }
 assert(!bpf_sk_fullsock(NULL));assert(bpf_sk_fullsock(&sk)==(u64)(uintptr_t)&sk);sk.sk_state=6;assert(!bpf_sk_fullsock(&sk));sk.sk_state=12;assert(!bpf_sk_fullsock(&sk));sk.sk_state=10;assert(bpf_sk_fullsock(&sk)==(u64)(uintptr_t)&sk);
 puts("PASS: sockaddr scalar/word/doubleword accesses and register preservation; legacy socket/GSO/fullsock translation");return 0;}
'''
f=a.output/'production.c';f.write_text(source);rec={'boundary':__doc__,'source_sha256':hashlib.sha256(source.encode()).hexdigest(),'runs':[]}
for layout,flags in [('offset', ['-DNET_SKBUFF_DATA_USES_OFFSET']),('pointer',[]),('offset-big-masks',['-DNET_SKBUFF_DATA_USES_OFFSET','-D__BIG_ENDIAN_BITFIELD']),('pointer-big-masks',['-D__BIG_ENDIAN_BITFIELD'])]:
 cmd=[a.cc,'-std=gnu11','-g','-O1','-Wall','-Werror','-Wno-unused-function','-fsanitize=address,undefined','-fno-sanitize-recover=all','-DBPF_UAPI_HEADER="'+str(root/'include/uapi/linux/bpf.h')+'"']+flags+[str(f),'-o',str(a.output/layout)]
 r=subprocess.run(cmd,capture_output=True,text=True);entry={'layout':layout,'command':cmd,'compile_exit':r.returncode,'compile_output':r.stdout+r.stderr};print(r.stdout+r.stderr)
 if not r.returncode:
  r=subprocess.run([str(a.output/layout)],capture_output=True,text=True,timeout=20);entry.update(exit_status=r.returncode,output=r.stdout+r.stderr);print(layout,r.returncode,r.stdout+r.stderr)
 rec['runs'].append(entry)
(a.output/'receipt.json').write_text(json.dumps(rec,indent=2)+'\n');raise SystemExit(any(x['compile_exit'] or x.get('exit_status',1) for x in rec['runs']))

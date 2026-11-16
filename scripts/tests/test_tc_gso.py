#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Execute actual TC access checks/converters with modeled skb layouts.
Real ARM64 syscall acceptance is a separate VM gate. Does not test networking.
"""
import argparse,hashlib,json,re,subprocess
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--cc',required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();a.output.mkdir(parents=True,exist_ok=False);root=Path(__file__).resolve().parents[2]
net=(root/'net/core/filter.c').read_text()
def fun(n):
 m=re.search(r'^static [\w *]+\b'+n+r'\([^;]*?\)\n\{',net,re.M);assert m,n
 b=net.index('{',m.start());i=b+1;d=1
 while d:d+=(net[i]=='{')-(net[i]=='}');i+=1
 return net[m.start():i]
names=['bpf_skb_is_valid_access','sk_filter_is_valid_access','cg_skb_is_valid_access','tc_cls_act_is_valid_access']
if 'static struct bpf_insn *bpf_convert_shinfo_access(' in net:names+=['bpf_convert_shinfo_access']
names+=['cg_skb_convert_ctx_access','tc_cls_act_convert_ctx_access']
source=r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include BPF_UAPI_HEADER
typedef uint32_t u32;typedef uint64_t u64;
enum bpf_access_type {BPF_READ,BPF_WRITE};
enum {PTR_TO_PACKET=1,PTR_TO_PACKET_END,PTR_TO_SOCK_COMMON_OR_NULL};
struct bpf_insn_access_aux {int reg_type,ctx_field_size;};
struct bpf_prog {int unused;};
struct net_device {int ifindex;};
struct sock {int unused;};
struct sk_buff {uint64_t padding;struct sock *sk;struct net_device *dev;unsigned char *head;
#ifdef NET_SKBUFF_DATA_USES_OFFSET
 u32 end;
#else
 unsigned char *end;
#endif
};
struct skb_shared_info {uint64_t unused;uint16_t gso_size,gso_segs;};
#define FIELD_SIZEOF(T,F) sizeof(((T*)0)->F)
#define BPF_FIELD_SIZEOF(T,F) (FIELD_SIZEOF(T,F)==8?BPF_DW:FIELD_SIZEOF(T,F)==4?BPF_W:BPF_H)
#define BPF_REG_AX MAX_BPF_REG
#define BPF_LDX_MEM(S,D,R,O) ((struct bpf_insn){.code=BPF_LDX|BPF_MEM|(S),.dst_reg=D,.src_reg=R,.off=O})
#define BPF_ALU64_REG(O,D,R) ((struct bpf_insn){.code=BPF_ALU64|(O)|BPF_X,.dst_reg=D,.src_reg=R})
#define offsetofend(T,F) (offsetof(T,F)+sizeof(((T*)0)->F))
#define bpf_ctx_range(T,F) offsetof(T,F) ... offsetofend(T,F)-1
#define bpf_ctx_range_till(T,F,L) offsetof(T,F) ... offsetofend(T,L)-1
#define bpf_ctx_record_field_size(I,S) ((I)->ctx_field_size=(S))
#define bpf_ctx_narrow_access_ok(O,S,D) ((S)==(D))
#define bpf_target_off(T,F,S,P) (*(P)=sizeof(((T*)0)->F),offsetof(T,F))
static u32 bpf_convert_ctx_access(enum bpf_access_type t,const struct bpf_insn*s,struct bpf_insn*b,struct bpf_prog*p,u32*z){return 0;}
'''+ '\n'.join(fun(n) for n in names)+r'''
static u64 run(struct bpf_insn *p,int n,u64 base,int dst){u64 r[16]={0};r[1]=base;assert(n>0&&n<=4);for(int i=0;i<n;i++){
 struct bpf_insn x=p[i];int cl=BPF_CLASS(x.code),op=BPF_OP(x.code);
 if(cl==BPF_LDX){int size=BPF_SIZE(x.code)==BPF_DW?8:BPF_SIZE(x.code)==BPF_W?4:2;u64 value=0;memcpy(&value,(void*)(uintptr_t)(r[x.src_reg]+x.off),size);r[x.dst_reg]=value;}
 else if(cl==BPF_ALU64&&op==BPF_ADD)r[x.dst_reg]+=r[x.src_reg];else abort();
 }return r[dst];}
int main(void){struct bpf_insn out[16],in;u32 target=0;struct bpf_insn_access_aux info={0};
 for(int off=140;off<188;off++)for(int size=1;size<=8;size*=2)for(int write=0;write<2;write++){
  bool want=!write&&size==4&&(off==164||off==176);
  assert(tc_cls_act_is_valid_access(off,size,write?BPF_WRITE:BPF_READ,&info)==want);
  assert(!sk_filter_is_valid_access(off,size,write?BPF_WRITE:BPF_READ,&info));
  if(off==176)assert(!cg_skb_is_valid_access(off,size,write?BPF_WRITE:BPF_READ,&info));
 }
 assert(tc_cls_act_is_valid_access(offsetof(struct __sk_buff,mark),4,BPF_WRITE,&info));
 struct net_device dev={.ifindex=19};unsigned char head[256]={0};struct skb_shared_info sh={.gso_size=0xf234,.gso_segs=0xabcd};memcpy(head+64,&sh,sizeof(sh));struct sk_buff skb={.head=head,.dev=&dev,
#ifdef NET_SKBUFF_DATA_USES_OFFSET
 .end=64
#else
 .end=head+64
#endif
 };
 for(int dst=1;dst<=2;dst++)for(int field=0;field<2;field++){
  in=(struct bpf_insn){.src_reg=1,.dst_reg=dst,.off=field?176:164};int n=tc_cls_act_convert_ctx_access(BPF_READ,&in,out,NULL,&target);assert(run(out,n,(u64)(uintptr_t)&skb,dst)==(field?0xf234:0xabcd));
 }
 in=(struct bpf_insn){.src_reg=1,.dst_reg=2,.off=offsetof(struct __sk_buff,ifindex)};int n=tc_cls_act_convert_ctx_access(BPF_READ,&in,out,NULL,&target);assert(run(out,n,(u64)(uintptr_t)&skb,2)==19);
 in.off=164;n=cg_skb_convert_ctx_access(BPF_READ,&in,out,NULL,&target);assert(run(out,n,(u64)(uintptr_t)&skb,2)==0xabcd);
 puts("PASS TC GSO access bounds, read-only/scope, both aliases, ushort values, TC ifindex and cgroup regression");}
'''
f=a.output/'production.c';f.write_text(source);rec={'boundary':__doc__,'extracted_functions':names,'source_sha256':hashlib.sha256(source.encode()).hexdigest(),'runs':[]}
for layout,flags in [('offset',['-DNET_SKBUFF_DATA_USES_OFFSET']),('pointer',[])]:
 cmd=[a.cc,'-std=gnu11','-g','-O1','-Wall','-Werror','-Wno-unused-function','-fsanitize=address,undefined','-fno-sanitize-recover=all','-DBPF_UAPI_HEADER="'+str(root/'include/uapi/linux/bpf.h')+'"']+flags+[str(f),'-o',str(a.output/layout)]
 r=subprocess.run(cmd,capture_output=True,text=True);entry={'layout':layout,'command':cmd,'compile_exit':r.returncode,'compile_output':r.stdout+r.stderr};print(r.stdout+r.stderr)
 if not r.returncode:
  r=subprocess.run([str(a.output/layout)],capture_output=True,text=True,timeout=20);entry.update(exit_status=r.returncode,output=r.stdout+r.stderr);print(layout,r.returncode,r.stdout+r.stderr)
 rec['runs'].append(entry)
(a.output/'receipt.json').write_text(json.dumps(rec,indent=2)+'\n');raise SystemExit(any(x['compile_exit'] or x.get('exit_status',1) for x in rec['runs']))

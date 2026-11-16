#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Production UDP hook blocks/runner with modeled surrounding transport services.
Not a complete UDP syscall execution: routing and payload copying are modeled; error cleanup
statements and labels are extracted from production. Real source configuration compilation is a separate gate.
"""
import argparse,json,re,subprocess,hashlib
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--cc',required=True);p.add_argument('--foundation',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();r=Path(__file__).resolve().parents[2];a.output.mkdir(parents=True,exist_ok=False)
def block(s,needle):
 if needle not in s:return ''
 start=s.index(needle);b=s.index('{',start);i=b+1;d=1
 while d:d+=(s[i]=='{')-(s[i]=='}');i+=1
 return s[start:i]
s=(a.foundation/'production.c').read_text();s=s[:s.index('int main(int argc,')];old=block(s,'static u32 run_prog(')
s=s.replace(old,'''static int mode;
static u32 run_prog(struct bpf_prog*p,struct bpf_sock_addr_kern*c){
 assert(lock_count==1);hook_calls++;
 if(mode==1)return 0;
 if(mode==2||mode==3||mode==4){
  if(c->uaddr->sa_family==AF_INET){struct sockaddr_in*x=(void*)c->uaddr;x->sin_port=mode==3?0:htons(4321);x->sin_addr.s_addr=htonl(0x7f000002);if(c->t_ctx)*(u32*)c->t_ctx=htonl(0x7f000003);}
  else if(c->uaddr->sa_family==AF_INET6){struct sockaddr_in6*x=(void*)c->uaddr;x->sin6_port=mode==3?0:htons(4321);x->sin6_addr.s6_addr[15]=2;if(mode==4){x->sin6_addr.s6_addr[10]=255;x->sin6_addr.s6_addr[11]=255;}if(c->t_ctx)((struct in6_addr*)c->t_ctx)->s6_addr[15]=3;}
 }
 return 1;
}''')
s+='''
#define ENOTSUPP 524
static bool ipv6_addr_v4mapped(const struct in6_addr*a){return a->s6_addr[10]==255&&a->s6_addr[11]==255;}
static u32 final_addr,source_addr;static unsigned short final_port;static struct in6_addr final6,source6;
static int cleanup_calls,flow_releases,dst_releases;
static void kfree(void*p){assert(p==(void*)1);cleanup_calls++;}
static void fl6_sock_release(void*p){assert(p==(void*)2);flow_releases++;}
static void txopt_put(void*p){assert(p==(void*)1);cleanup_calls++;}
static void dst_release(void*p){dst_releases++;}

'''
for fam in (4,6):
 text=(r/f'net/ipv{fam}/udp.c').read_text();b=block(text,'if (cgroup_bpf_enabled && !connected)')
 if fam==4:
  tail=text[text.index('out_free:',text.index('int udp_sendmsg(')):];tail=tail[:tail.index('\tif (!err)')]
  s+='static int send4(struct sock*sk,struct sockaddr_in*usin,int connected){int err=0;struct {u32 addr;void*opt;}ipc={.opt=(void*)1};int free=1;u32 daddr=0;unsigned short dport=0;\n'+b+'\nfinal_addr=daddr;source_addr=ipc.addr;final_port=dport;return 0;'+tail+'return err;}\n'
 else:
  tail=text[text.index('out:\n\tdst_release(dst);',text.index('int udpv6_sendmsg(')):];tail=tail[:tail.index('\tif (!err)')]
  s+='static int send6(struct sock*sk,struct sockaddr_in6*sin6,int connected){int err=0;void*dst=(void*)99,*flowlabel=(void*)2,*opt_to_free=(void*)1;struct {struct in6_addr saddr,daddr;unsigned short fl6_dport;}fl6={0};\n'+b+'\nfinal6=fl6.daddr;source6=fl6.saddr;final_port=fl6.fl6_dport;return 0;'+tail+'return err;}\n'
 m=re.search(r'if \(cgroup_bpf_enabled\)\s+BPF_CGROUP_RUN_PROG_UDP'+str(fam)+r'_RECVMSG_LOCK\(sk,\s*\(struct sockaddr \*\)sin6?\);',text)
 b=m[0] if m else ''
 s+=f'static int recv{fam}(struct sock*sk,struct sockaddr_in'+('6' if fam==6 else '')+'*'+('sin6' if fam==6 else 'sin')+') {if('+('sin6' if fam==6 else 'sin')+'){'+b+'}return 7;}\n'
s+='''
int main(int argc,char**argv){assert(argc==2);const char*c=argv[1];struct bpf_prog p={0};struct bpf_prog_array array={.progs={&p,NULL}};struct cgroup cg={0};for(int i=0;i<23;i++)cg.bpf.effective[i]=&array;struct sock sk={.sk_cgrp_data=&cg,.sk_family=AF_INET};struct sockaddr_in a={.sin_family=AF_INET,.sin_port=htons(1234)};struct sockaddr_in6 b={.sin6_family=AF_INET6,.sin6_port=htons(1234)};
 if(!strcmp(c,"send4-deny")){mode=1;assert(send4(&sk,&a,0)==-EPERM&&cleanup_calls==1);}
 else if(!strcmp(c,"send6-deny")){mode=1;sk.sk_family=AF_INET6;assert(send6(&sk,&b,0)==-EPERM&&cleanup_calls==1);}
 else if(!strcmp(c,"send4-rewrite")){mode=2;assert(!send4(&sk,&a,0)&&final_port==htons(4321)&&final_addr==htonl(0x7f000002)&&source_addr==htonl(0x7f000003));}
 else if(!strcmp(c,"send6-rewrite")){mode=2;sk.sk_family=AF_INET6;assert(!send6(&sk,&b,0)&&final_port==htons(4321)&&final6.s6_addr[15]==2&&source6.s6_addr[15]==3);}
 else if(!strcmp(c,"send4-zero")){mode=3;assert(send4(&sk,&a,0)==-EINVAL&&cleanup_calls==1);}
 else if(!strcmp(c,"send6-zero")){mode=3;sk.sk_family=AF_INET6;assert(send6(&sk,&b,0)==-EINVAL&&cleanup_calls==1);}
 else if(!strcmp(c,"send6-mapped")){mode=4;sk.sk_family=AF_INET6;assert(send6(&sk,&b,0)==-ENOTSUPP&&cleanup_calls==1);}
 else if(!strcmp(c,"connected")){mode=1;assert(!send4(&sk,&a,1)&&!send6(&sk,&b,1)&&!hook_calls);}
 else if(!strcmp(c,"recv4")){mode=2;assert(recv4(&sk,&a)==7&&hook_calls==1&&a.sin_port==htons(4321));}
 else if(!strcmp(c,"recv6")){mode=2;sk.sk_family=AF_INET6;assert(recv6(&sk,&b)==7&&hook_calls==1&&b.sin6_port==htons(4321));}
 else if(!strcmp(c,"recv-null")){assert(recv4(&sk,NULL)==7&&recv6(&sk,NULL)==7&&!hook_calls);}
 else if(!strcmp(c,"send-null")){assert(!send4(&sk,NULL,0)&&hook_calls==1);sk.sk_family=AF_INET6;assert(!send6(&sk,NULL,0)&&hook_calls==2);}
 else abort();assert(!lock_count&&!rcu_depth&&!dst_releases);if(cleanup_calls&&sk.sk_family==AF_INET6)assert(flow_releases==1);return 0;
}
'''
f=a.output/'production.c';f.write_text(s);cmd=[a.cc,'-std=gnu11','-O1','-g','-fsanitize=address,undefined','-fno-sanitize-recover=all',str(f),'-o',str(a.output/'test')];x=subprocess.run(cmd,capture_output=True,text=True);d={'boundary':__doc__,'command':cmd,'compile_exit':x.returncode,'compile_output':x.stdout+x.stderr,'source_sha256':hashlib.sha256(s.encode()).hexdigest(),'cases':{}}
if not x.returncode:
 for case in ['send4-deny','send6-deny','send4-rewrite','send6-rewrite','send4-zero','send6-zero','send6-mapped','connected','recv4','recv6','recv-null','send-null']:
  x=subprocess.run([str(a.output/'test'),case],capture_output=True,text=True);d['cases'][case]={'exit':x.returncode,'output':x.stdout+x.stderr};print(case,x.returncode)
else:print(x.stderr)
(a.output/'receipt.json').write_text(json.dumps(d,indent=2)+'\n');raise SystemExit(bool(d['compile_exit'] or any(x['exit'] for x in d['cases'].values())))

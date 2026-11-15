#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Execute extracted production SK_STORAGE and syscall dispatch with modeled services."""
import argparse, hashlib, json, re, subprocess, struct
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--cc', required=True)
p.add_argument('--output', required=True, type=Path)
p.add_argument('--dispatcher-only', action='store_true')
p.add_argument('--mutation',choices=['precharge','cache','minimum-buckets','clone','allocation-uncharge','double-callback'])
a=p.parse_args(); k=Path(__file__).resolve().parents[2]
a.output.mkdir(parents=True,exist_ok=False)
s=(k/'kernel/bpf/syscall.c').read_text()
start=s.index('\t\trcu_read_lock();',s.index('static int map_lookup_elem('))
end=s.index('\n\t}\n', start)
dispatch='static int dispatch(struct bpf_map *map, void *key, void *value, size_t value_size) { void *ptr; int err;\n'+s[start:end]+'\nreturn err; }\n'
if a.mutation=='double-callback':
    dispatch=dispatch.replace('\t\tif (IS_ERR(ptr))','\t\tptr = map->ops->map_lookup_elem(map, key);\n\t\tif (IS_ERR(ptr))')
(a.output/'dispatch.h').write_text(dispatch)
source='sk_storage_dispatch_host.c'
if not a.dispatcher_only:
    path=k/'net/core/bpf_sk_storage.c'
    if not path.exists():
        (a.output/'receipt.json').write_text(json.dumps({'failure':'SK_STORAGE production implementation absent'},indent=2)+'\n')
        raise SystemExit('FAIL: SK_STORAGE production implementation absent')
    subject=re.sub(r'^#include.*$', '', path.read_text(), flags=re.M)
    sock=(k/'net/core/sock.c').read_text()
    clone=sock[sock.index('\t\tsock_copy(newsk, sk);'):sock.index('\t\tnewsk->sk_prot_creator = sk->sk_prot;')]
    subject+='\nstatic void test_clone_init(struct sock *newsk, const struct sock *sk) {\n'+clone+'\n}\n'
    mutations={
      'precharge':('if (err) {\n\t\tkfree(smap);\n\t\treturn ERR_PTR(err);','if (err) {\n\t\treturn ERR_PTR(err);'),
      'cache':('RCU_INIT_POINTER(sk_storage->cache[smap->cache_idx], NULL);','(void)0;'),
      'minimum-buckets':('max_t(u32, 2, num_possible_cpus())','num_possible_cpus()'),
      'clone':('RCU_INIT_POINTER(newsk->sk_bpf_storage, NULL);','(void)0;'),
      'allocation-uncharge':('if (charge_omem)\n\t\tatomic_sub(smap->elem_size, &sk->sk_omem_alloc);','if (charge_omem)\n\t\t(void)0;'),
    }
    if a.mutation in mutations:
        old,new=mutations[a.mutation];assert old in subject,a.mutation;subject=subject.replace(old,new,1)
    start=s.index('static int map_check_btf(');end=s.index('\n}',start)+2
    subject+='\n'+s[start:end]+'\n'
    (a.output/'subject.h').write_text(subject)
    fixture=k/'scripts/tests/btf-fixtures/data/libbpf/netd.o/no-global-func.btf'
    raw=fixture.read_bytes();index=json.loads((k/'scripts/tests/btf-fixtures/data/parser-fixtures.json').read_text())
    expected=next(x for x in index['fixtures'] if x['path']=='libbpf/netd.o/no-global-func.btf')['sha256']
    assert hashlib.sha256(raw).hexdigest()==expected
    _,_,_,hl,to,tl,so,sl=struct.unpack_from('<HBBIIIII',raw)
    offset=hl+to;end=offset+tl;offsets=[]
    while offset<end:
        offsets.append(offset);name,info,size=struct.unpack_from('<III',raw,offset);kind=(info>>24)&31;n=info&65535
        tail={1:4,2:0,3:12,4:n*12,5:n*12,6:n*8,7:0,8:0,9:0,10:0,11:0,12:0,13:n*8,14:4,15:n*12}[kind]
        offset+=12+tail
    assert offset==end and len(offsets)<2048
    (a.output/'fixture.h').write_text('static const unsigned char corpus[] __attribute__((aligned(8)))={'+','.join(str(x) for x in raw)+'};\nstatic unsigned offsets[]={0,'+','.join(map(str,offsets))+'};\nstatic const char *corpus_strings=(const char *)corpus+'+str(hl+so)+';\n')
    source='sk_storage_host.c'
cmd=[a.cc,'-std=gnu11','-O1','-g','-Wall','-Wextra','-Werror','-Wno-unused-function','-Wno-unused-parameter','-Wno-sign-compare','-fsanitize=address,undefined','-fno-sanitize-recover=all','-fno-omit-frame-pointer','-I'+str(a.output),'-DBPF_UAPI_HEADER="'+str(k/'include/uapi/linux/bpf.h')+'"','-DBTF_UAPI_HEADER="'+str(k/'include/uapi/linux/btf.h')+'"',str(k/'scripts/tests'/source),'-o',str(a.output/'test')]
r=subprocess.run(cmd,capture_output=True,text=True)
receipt={'mutation':a.mutation,'source_root':str(k),'command':cmd,'compile_exit':r.returncode,'compile_output':r.stdout+r.stderr,'compiler_version':subprocess.check_output([a.cc,'--version'],text=True),'dispatch_sha256':hashlib.sha256(dispatch.encode()).hexdigest(),'cases':{}}
print(r.stdout+r.stderr,end='')
if not r.returncode:
    cases=['valid','null','error','sys_only'] if a.dispatcher_only else ['attributes','alloc','fd','replace','cache','socket_first','map_first','multi','helper','precharge','optmem','interleave','btf','clone','cache_collision','publish_race','delete_race','empty_race','destroy_race','corpus_btf','map_btf']
    for case in cases:
        r=subprocess.run([str(a.output/'test'),case],capture_output=True,text=True,timeout=10)
        receipt['cases'][case]={'exit':r.returncode,'output':r.stdout+r.stderr}
        print(case,r.returncode,r.stdout+r.stderr)
(a.output/'receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
raise SystemExit(bool(receipt['compile_exit'] or any(v['exit'] for v in receipt['cases'].values())))

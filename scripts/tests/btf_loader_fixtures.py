#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Reproduce selected Android loader BTF inputs offline, never load BPF.

prepare extracts production source verbatim and prepares an isolated build.
generate audits actual ELF/BTF and emits load-boundary snapshots and an index.
All data readers are bounded; this reader is not a candidate kernel validator.
"""
import argparse
from collections import Counter
import hashlib
import json
import os
import shlex
from pathlib import Path
import re
import shutil
import struct
import subprocess

CONNECTIVITY = '7c04d866538e6f689823b769fb5c1e614ca0e295'
LIBBPF = '9723b4de6459ab48b361aed3bae5df3c1bd20cb8'
IMAGE = 'sha256:13c02403ad20d9ff81af455ed762d0c30eb1336d3990b16db3d33ebf44b0cbd8'
FILES = ['offload.o', 'test.o', 'clatd.o', 'dscpPolicy.o', 'netd.o', 'bpfRingbufProg.bpf']
KINDS = ['VOID', 'INT', 'PTR', 'ARRAY', 'STRUCT', 'UNION', 'ENUM', 'FWD', 'TYPEDEF',
         'VOLATILE', 'CONST', 'RESTRICT', 'FUNC', 'FUNC_PROTO', 'VAR', 'DATASEC',
         'FLOAT', 'DECL_TAG', 'TYPE_TAG', 'ENUM64']


def sha(data): return hashlib.sha256(data).hexdigest()
def write_json(path, obj): path.write_text(json.dumps(obj, indent=2, sort_keys=True) + '\n')
def region(data, off, size):
    if off < 0 or size < 0 or off > len(data) or size > len(data) - off:
        raise ValueError('range outside bounded input')
    return data[off:off + size]
def string(data, off):
    if off < 0 or off >= len(data): raise ValueError('string offset')
    end = data.find(b'\0', off)
    if end < 0: raise ValueError('unterminated string')
    return data[off:end].decode('utf-8', errors='strict')


class Elf:
    def __init__(self, data):
        if len(data) < 64 or len(data) > 16*1024*1024 or data[:7] != b'\x7fELF\x02\x01\x01':
            raise ValueError('bounded ELF64 little-endian required')
        self.data = data
        h = struct.unpack_from('<16sHHIQQQIHHHHHH', data)
        if h[1:4] != (1, 247, 1) or h[11] != 64: raise ValueError('ELF layout')
        table = region(data, h[6], h[12]*64)
        entries = [struct.unpack_from('<IIQQQQIIQQ', table, i*64) for i in range(h[12])]
        if h[13] >= len(entries): raise ValueError('section names index')
        names_hdr = entries[h[13]]
        names = region(data, names_hdr[4], names_hdr[5])
        self.sections = []
        for i, s in enumerate(entries):
            self.sections.append(dict(index=i, name=string(names, s[0]), type=s[1], flags=s[2],
                                      offset=s[4], size=s[5], link=s[6], entsize=s[9]))
        self.by_name = {s['name']: s for s in self.sections}
        self.symbols = []
        for s in self.sections:
            if s['type'] != 2: continue
            raw = region(data, s['offset'], s['size'])
            if len(raw) % 24 or s['link'] >= len(self.sections): raise ValueError('symtab layout')
            ns = self.sections[s['link']]
            syms = region(data, ns['offset'], ns['size'])
            for i in range(0, len(raw), 24):
                name, info, other, sec, value, size = struct.unpack_from('<IBBHQQ', raw, i)
                self.symbols.append(dict(name=string(syms, name), info=info, visibility=other&3,
                                         section=sec, value=value, size=size))

    def section(self, name):
        s = self.by_name[name]
        return region(self.data, s['offset'], s['size'])


class Btf:
    def __init__(self, data):
        if len(data) < 24 or len(data) > 16*1024*1024: raise ValueError('BTF size')
        magic, version, flags, hdr, toff, tlen, soff, slen = struct.unpack_from('<HBBIIIII', data)
        if (magic, version, flags) != (0xeb9f, 1, 0) or hdr < 24: raise ValueError('BTF header')
        types = region(data, hdr + toff, tlen)
        self.strings = region(data, hdr + soff, slen)
        if not self.strings or self.strings[0] or self.strings[-1]: raise ValueError('BTF strings')
        self.types = {}; off = 0
        while off < len(types):
            name, info, size = struct.unpack('<III', region(types, off, 12))
            kind, vlen = (info >> 24)&31, info&0xffff
            if not 1 <= kind < len(KINDS): raise ValueError('unknown BTF kind')
            extra = {1:4, 3:12, 4:12*vlen, 5:12*vlen, 6:8*vlen, 13:8*vlen,
                     14:4, 15:12*vlen, 17:4, 19:12*vlen}.get(kind, 0)
            payload = region(types, off+12, extra)
            t = dict(name=string(self.strings, name), kind=kind, info=info, size_type=size,
                     offset=hdr+toff+off, vlen=vlen)
            if kind == 15: t['entries'] = [struct.unpack_from('<III',payload,j) for j in range(0,extra,12)]
            if kind == 14: t['linkage'] = struct.unpack('<I',payload)[0]
            self.types[len(self.types)+1] = t
            off += 12 + extra

    def summary(self):
        return dict(type_count=len(self.types), kinds=dict(sorted(Counter(KINDS[t['kind']] for t in self.types.values()).items())),
                    datasecs=[dict(id=i, name=t['name'], size=t['size_type'], entries=t['entries'])
                              for i,t in self.types.items() if t['kind']==15],
                    typed_externs=[dict(id=i, name=t['name'], kind=KINDS[t['kind']]) for i,t in self.types.items()
                                   if (t['kind']==14 and t['linkage']==2) or (t['kind']==12 and t['vlen']==2)])

    def ext(self, data):
        if len(data) < 24: raise ValueError('BTF.ext header')
        magic, version, flags, hdr = struct.unpack_from('<HBBI',data)
        if (magic,version,flags)!=(0xeb9f,1,0) or hdr < 24: raise ValueError('BTF.ext layout')
        result = {}
        for name, pos in [('func_info',8),('line_info',16),('core_relo',24)]:
            if pos+8 > hdr:
                result[name] = dict(bytes=0, records=0, sections=[]); continue
            off, n = struct.unpack_from('<II', data, pos)
            raw = region(data, hdr+off,n)
            recs=[]; total=0
            if raw:
                recsize = struct.unpack('<I',region(raw,0,4))[0]
                minimum = {'func_info':8,'line_info':16,'core_relo':16}[name]
                if recsize < minimum: raise ValueError('BTF.ext record size')
                cursor=4
                while cursor < len(raw):
                    sec, count = struct.unpack('<II',region(raw,cursor,8)); cursor+=8
                    region(raw,cursor,count*recsize); cursor+=count*recsize
                    recs.append(dict(section=string(self.strings,sec), records=count)); total+=count
            result[name] = dict(bytes=n,records=total,sections=recs)
        return result


def function(text, name):
    match = re.search(r'^[^\n]*\b'+re.escape(name)+r'\([^;{]*\{.*?^\}',text,re.M | re.S)
    if not match: raise ValueError('cannot extract '+name)
    return match.group(0)


def fresh_output(path):
    if path.exists() or path.is_symlink():
        raise ValueError('output already exists; choose a fresh directory: '+str(path))
    path.mkdir(parents=True, exist_ok=False)


def prepare(args):
    root=args.workspace.resolve(); out=args.output.resolve()
    fresh_output(out)
    build=out/'build'; build.mkdir()
    conn=root/'src/lineage-24.0/packages/modules/Connectivity'; lib=root/'src/lineage-24.0/external/libbpf'
    provenance={}
    for p,want in [(conn,CONNECTIVITY),(lib,LIBBPF)]:
        head=subprocess.check_output(['git','-C',str(p),'rev-parse','HEAD'],text=True).strip()
        dirty=subprocess.check_output(['git','-C',str(p),'status','--porcelain'],text=True)
        if head != want or dirty: raise ValueError('selected source pin or cleanliness differs: '+str(p))
        provenance[str(p.relative_to(root))]=head
    src=conn/'bpf/loader/NetBpfLoad.cpp'; text=src.read_text()
    exact=text[text.index('static int setBtfDatasecSize('):text.index('static bool isBtfSupported(')]
    (build/'netbpf_exact.inc').write_text(text[:text.index('#define LOG_TAG')]+exact)
    methods=[]
    for name in ['getSectionByIdx','getStr','readSectionByName','getSymOffsetByName']:
        start=re.search(r'^    (?:template[^\n]*\n    )?[^\n]*\b'+name+r'\([^;{]*\{.*?^    \}',text,re.M | re.S)
        if not start: raise ValueError('ELF method extraction '+name)
        methods.append(start.group(0))
    (build/'elf_methods.inc').write_text('\n'.join(methods)+'\n')
    mh=conn/'bpf/progs/include/bpf_map_def.h'; mt=mh.read_text()
    macro=re.search(r'^#define BPF_DEF_CHAR_ARRAY_SIZE.*$',mt,re.M).group(0)
    map_def=mt[mt.index('struct bpf_map_def {'):mt.index('\n};',mt.index('struct bpf_map_def {'))+3]
    (build/'android_map_def.inc').write_text(macro+'\n'+map_def+'\nstatic_assert(sizeof(bpf_map_def)==192);\n')
    lc=lib/'src/libbpf.c'; lt=lc.read_text()
    # Only the feature answers are replaced: profiles are assumptions, not probes.
    sanitizer=lt[:lt.index('#include')]+'''// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Exact extracted sanitizer. Feature answers below are explicit assumptions.
#include <stdbool.h>
#include <string.h>
#define kernel_supports fixture_kernel_supports
#include "libbpf_internal.h"
static int profile;
bool fixture_kernel_supports(const struct bpf_object *obj, enum kern_feature_id id) {
    (void)obj;
    if (profile == 0) return true;
    if (profile == 1) return id != FEAT_BTF_GLOBAL_FUNC;
    return id != FEAT_BTF_FUNC && id != FEAT_BTF_DATASEC && id != FEAT_BTF_GLOBAL_FUNC;
}
'''+function(lt,'starts_with_qmark')+'\n'+function(lt,'bpf_object__sanitize_btf')+'''
int fixture_libbpf_sanitize(struct btf *b, int selected_profile) {
    if (selected_profile < 0 || selected_profile > 2) return -EINVAL;
    profile = selected_profile;
    return bpf_object__sanitize_btf(NULL, b);
}
'''
    (build/'libbpf_sanitize_exact.c').write_text(sanitizer)
    for file in ['btf_loader_host.cpp','btf_loader_fixtures.py','btf_loader_test.py']:
        shutil.copyfile(Path(__file__).with_name(file),build/file)
    for p in [src,mh,lc,lib/'src/btf.c',lib/'src/libbpf_internal.h']:
        provenance[str(p.relative_to(root))]=dict(sha256=sha(p.read_bytes()))
    provenance['extracts']={p.name:sha(p.read_bytes()) for p in build.glob('*.inc')}
    provenance['extracts']['libbpf_sanitize_exact.c']=sha(sanitizer.encode())
    provenance['image']=IMAGE
    provenance['source_spans']={}
    for name in ['setBtfDatasecSize','setBtfVarOffset','sanitizeBtf','loadBtf','getKeyValueTids']:
        f=function(text,name); start=text.index(f)
        provenance['source_spans'][name]=dict(path=str(src.relative_to(root)),
            first_line=text[:start].count('\n')+1,lines=f.count('\n')+1,sha256=sha(f.encode()))
    f=function(lt,'bpf_object__sanitize_btf'); start=lt.index(f)
    provenance['source_spans']['bpf_object__sanitize_btf']=dict(path=str(lc.relative_to(root)),
        first_line=lt[:start].count('\n')+1,lines=f.count('\n')+1,sha256=sha(f.encode()))
    write_json(out/'source-provenance.json',provenance)
    # Shell script lives only in isolated logs; runner receives immutable image id.
    import shlex
    q=shlex.quote
    script=f'''#!/usr/bin/env bash
set -euo pipefail
build={q(str(build))}
lib={q(str(lib))}
clang={q(str(root/'src/lineage-24.0/prebuilts/clang/host/linux-x86/clang-r596125/bin'))}
"$clang/clang" --version
make -C "$lib/src" OBJDIR="$build/libbpf" BUILD_STATIC_ONLY=1 CC="$clang/clang" AR="$clang/llvm-ar" -j2 "$build/libbpf/libbpf.a"
"$clang/clang" -std=gnu11 -O2 -g -I"$lib/src" -I"$lib/include" -I"$lib/include/uapi" -c "$build/libbpf_sanitize_exact.c" -o "$build/sanitize.o"
"$clang/clang++" -std=c++20 -O2 -g -I"$build" -I"$lib/src" -I"$lib/include" -I"$lib/include/uapi" "$build/btf_loader_host.cpp" "$build/sanitize.o" "$build/libbpf/libbpf.a" -lelf -lz -o "$build/btf_loader_host"
'''
    (build/'build.sh').write_text(script)
    print(json.dumps(dict(build_script=str(build/'build.sh'), image=IMAGE)))


def build(args):
    """Execute the checked-in runner's exact plan, relocating only receipt paths."""
    root=args.workspace.resolve(); out=args.output.resolve()
    if any((out/name).exists() for name in
           ('build-started.json', 'build-receipt.json', 'build.cid', 'build.log', 'runner-dry-run.txt')):
        raise ValueError('build already attempted; prepare a fresh output directory')
    if not (out/'build/build.sh').is_file() or not (out/'source-provenance.json').is_file():
        raise ValueError('prepare must complete before build')
    with (out/'build-started.json').open('x') as stream:
        json.dump(dict(image=IMAGE, scope='one build attempt; never reuse receipts'), stream)
    command=['bash',str(root/'scripts/container.sh'),'--dry-run','lineage-24.0',
             'bash',str(out/'build/build.sh')]
    r=subprocess.run(command,env=dict(os.environ,HUAWEI_BUILD_IMAGE=IMAGE),
                     capture_output=True,text=True,check=True)
    (out/'runner-dry-run.txt').write_text(r.stdout)
    argv=shlex.split(r.stdout.splitlines()[-1])
    argv[argv.index('--cidfile')+1]=str(out/'build.cid')
    for i,a in enumerate(argv):
        if a.startswith('HUAWEI_CONTAINER_LOG_DIR='):
            argv[i]='HUAWEI_CONTAINER_LOG_DIR='+str(out)
    with (out/'build.log').open('w') as stream:
        result=subprocess.run(argv,stdout=stream,stderr=subprocess.STDOUT)
    record=dict(runner_plan_command=command,argv=argv,image=IMAGE,exit_status=result.returncode,
                change='only cidfile and log env relocated into owned loader-fixtures directory')
    if (out/'build.cid').exists(): record['container_id']=(out/'build.cid').read_text().strip()
    if result.returncode == 0:
        record['build_hashes']={str(p.relative_to(out)):sha(p.read_bytes()) for p in
                               [out/'build/btf_loader_host',out/'build/libbpf/libbpf.a',out/'build/sanitize.o']}
    write_json(out/'build-receipt.json',record)
    print(json.dumps(record))
    if result.returncode: raise ValueError('build failed; see build.log')


def generate(args):
    out=args.output.resolve()
    if args.parser_dir:
        dest=args.parser_dir.resolve()
        if dest.exists() or dest == out or dest in out.parents or out in dest.parents:
            raise ValueError('parser destination must be fresh and disjoint from output')
    fresh_output(out)
    calls=[]; corpus=[]; index=[]
    def call(argv):
        r=subprocess.run([str(args.helper.resolve()),*map(str,argv)],capture_output=True,text=True,timeout=30)
        calls.append(dict(argv=r.args,returncode=r.returncode,stdout=r.stdout,stderr=r.stderr))
        if r.returncode: raise ValueError('helper failed: '+r.stderr)
        return json.loads(r.stdout)
    def add(path, family, source, role):
        b=Btf(path.read_bytes()); rel=str(path.relative_to(out))
        entry=dict(path=rel,family=family,source=source,role=role,bytes=path.stat().st_size,
                   sha256=sha(path.read_bytes()),summary=b.summary())
        index.append(entry)
        return entry
    for name in FILES:
        source=args.input.resolve()/name; elf=Elf(source.read_bytes()); raw=elf.section('.BTF'); btf=Btf(raw)
        item=dict(name=name,elf_sha256=sha(source.read_bytes()),raw_btf_sha256=sha(raw),
                  raw_btf_is_load_fixture=False,sections=elf.sections,btf=btf.summary(),
                  undefined_symbols=[s for s in elf.symbols if not s['section'] and s['name']],
                  ext=btf.ext(elf.section('.BTF.ext')) if '.BTF.ext' in elf.by_name else None)
        if name=='offload.o':
            for branch,version in [('manual','new'),('manual-pre510','old')]:
                p=out/branch; p.mkdir(exist_ok=True)
                report=call(['manual',source,p/'attempt',version,'22,0'])
                item[branch]=report
                for attempt in (1,2): add(p/f'attempt{attempt}.btf',branch,name,f'load attempt {attempt}; first simulated EINVAL')
            # A lone successful attempt must be exactly the first EINVAL snapshot.
            p=out/'manual-success'; p.mkdir(exist_ok=True)
            item['manual-success']=call(['manual',source,p/'attempt','new','0'])
            add(p/'attempt1.btf','manual-success',name,'first load succeeds')
        p=out/'libbpf'/name; p.mkdir(parents=True,exist_ok=True)
        report=call(['open',source,p/'open'])
        item['libbpf_open']=report
        if not report['open_errno']:
            add(p/'open.btf','libbpf-open',name,'actual public open_file fixups, before load/probes')
            for profile,number in [('all-supported',0),('no-global-func',1),('no-func-datasec',2)]:
                target=p/(profile+'.btf')
                call(['sanitize',p/'open.btf',target,number])
                add(target,'libbpf-assumed-'+profile,name,'exact sanitizer under explicit assumed feature answers; no probe evidence')
            for mp in report['maps']:
                mp['freeze_on_initialization']=bool(mp['internal'] and ('.rodata' in mp['name'] or '.kconfig' in mp['name']))
        corpus.append(item)
    comparisons = {}
    for label, left, right in [
        ('manual_attempt1_equals_libbpf_open','manual/attempt1.btf','libbpf/offload.o/open.btf'),
        ('manual_retry_equals_assumed_no_global_func','manual/attempt2.btf','libbpf/offload.o/no-global-func.btf'),
        ('manual_pre510_equals_assumed_no_func_datasec','manual-pre510/attempt1.btf','libbpf/offload.o/no-func-datasec.btf')]:
        comparisons[label] = (out/left).read_bytes() == (out/right).read_bytes()
    write_json(out/'path-comparisons.json', comparisons)
    write_json(out/'corpus-audit.json',corpus)
    write_json(out/'helper-commands.json',calls)
    write_json(out/'parser-fixtures.json',dict(format='raw little-endian BTF, magic 9feb; no ELF wrapper',
               candidate_kernel_parser_executed=False,fixtures=index))
    # Source-owned parser corpus contains exact offload boundary and bounded synthetic cases.
    if args.parser_dir:
        dest=args.parser_dir.resolve(); fresh_output(dest)
        selected=[]
        for item in index:
            if item['source']=='offload.o' and item['family'] in ('manual','manual-pre510'):
                target=dest/(item['family']+'-'+Path(item['path']).name)
                shutil.copyfile(out/item['path'],target)
                selected.append(dict(path=target.name,sha256=item['sha256'],origin=item['path']))
        # Import only the independent synthetic builder from our test file.
        import importlib.util
        spec=importlib.util.spec_from_file_location('btf_loader_test',Path(__file__).with_name('btf_loader_test.py'))
        module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        p=out/'bounded'; p.mkdir(exist_ok=True)
        for name,kwargs in [('normalized-unsorted',{}),('offset-overrun',dict(sym=1000)),
                            ('size-overrun',dict(var_size=32)),('zero-sized-var',dict(var_size=0))]:
            elf=p/(name+'.o'); elf.write_bytes(module.synthetic(**kwargs))
            report=call(['manual',elf,p/(name+'-'),'new','0'])
            if report['ret']: raise ValueError('unexpected bounded normalization error')
            path=p/(name+'-1.btf'); target=dest/(name+'.btf'); shutil.copyfile(path,target)
            selected.append(dict(path=target.name,sha256=sha(target.read_bytes()),origin=str(path.relative_to(out)),
                                 expectation='candidate parser must decide; manual loader does not validate VAR interval bounds'))
        write_json(dest/'index.json',dict(candidate_parser_executed=False,fixtures=selected))
        write_json(out/'helper-commands.json',calls)
    write_json(out/'generation-provenance.json', dict(
        helper_sha256=sha(args.helper.resolve().read_bytes()),
        generator_sha256=sha(Path(__file__).read_bytes()),
        synthetic_builder_sha256=sha(Path(__file__).with_name('btf_loader_test.py').read_bytes()),
        source_pins=dict(connectivity=CONNECTIVITY, libbpf=LIBBPF),
        scope='offline host helper; no kernel execution or feature probes'))
    hashes={str(p.relative_to(out)):sha(p.read_bytes()) for p in sorted(out.rglob('*.btf'))}
    write_json(out/'btf-sha256.json',hashes)
    print(json.dumps(dict(objects=len(corpus),load_and_open_fixtures=len(index),btf_files=len(hashes),
                          manifest_sha256=sha((out/'btf-sha256.json').read_bytes()))))


def main():
    p=argparse.ArgumentParser(description=__doc__); sub=p.add_subparsers(dest='command',required=True)
    prep=sub.add_parser('prepare'); prep.add_argument('--workspace',type=Path,required=True); prep.add_argument('--output',type=Path,required=True)
    builder=sub.add_parser('build'); builder.add_argument('--workspace',type=Path,required=True); builder.add_argument('--output',type=Path,required=True)
    gen=sub.add_parser('generate'); gen.add_argument('--input',type=Path,required=True); gen.add_argument('--output',type=Path,required=True)
    gen.add_argument('--helper',type=Path,required=True); gen.add_argument('--parser-dir',type=Path)
    args=p.parse_args()
    try: {'prepare':prepare,'build':build,'generate':generate}[args.command](args)
    except (ValueError,KeyError,struct.error,OSError) as e: p.exit(2,'fixture: '+str(e)+'\n')
if __name__=='__main__': main()

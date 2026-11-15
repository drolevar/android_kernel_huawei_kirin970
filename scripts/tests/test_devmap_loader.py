#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Execute selected loader map policy with synthetic map-info/version replies.

No BPF syscall, kernel or device access. Source functions are extracted verbatim.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--connectivity', type=Path, required=True)
p.add_argument('--cxx', required=True)
p.add_argument('--output', type=Path, required=True)
a = p.parse_args()
pin = '7c04d866538e6f689823b769fb5c1e614ca0e295'
assert subprocess.check_output(['git', '-C', str(a.connectivity), 'rev-parse', 'HEAD'], text=True).strip() == pin
relative = 'bpf/loader/NetBpfLoad.cpp'
data = (a.connectivity / relative).read_bytes()
assert data == subprocess.check_output(['git', '-C', str(a.connectivity), 'show', pin + ':' + relative])
source = data.decode()
parts = []
for name in ('sanitizeMapFlags', 'mapMatchesExpectations', 'isBtfSupported', 'sanitizeMapType'):
    matches = re.findall(r'^static [^\n]*\b' + name + r'\(.*?^\}', source, re.M | re.S)
    assert len(matches) == 1, name
    parts.append(matches[0])
a.output.mkdir(parents=True, exist_ok=False)
text = r'''
#include <linux/bpf.h>
#include <cassert>
#include <cerrno>
#include <cstdio>
using unique_fd = int;
static int version;
static bool isAtLeastKernelVersion(int major, int minor) { return version >= major*100+minor; }
static unsigned int page_size=4096;
struct bpf_map_def { unsigned int key_size,value_size,max_entries,map_flags; const char* name() const { return "tether_dev_map"; } };
struct Reply { int type,key,value,capacity,flags; } reply;
static int bpfGetFdMapType(int) { return reply.type; }
static int bpfGetFdKeySize(int) { return reply.key; }
static int bpfGetFdValueSize(int) { return reply.value; }
static int bpfGetFdMaxEntries(int) { return reply.capacity; }
static int bpfGetFdMapFlags(int) { return reply.flags; }
#define ALOGE(...) ((void)0)
'''
text += '\n'.join(parts)
text += r'''
int main() {
 static_assert(BPF_MAP_TYPE_DEVMAP_HASH==25 && BPF_F_RDONLY_PROG==128, "ABI");
 static_assert(BPF_F_RDONLY_PROG!=BPF_F_RDONLY, "program and syscall flags differ");
 int fd=7; bpf_map_def md{4,4,64,0}; unsigned int checks=0;
 for (int v : {414,503,504,510}) {
  version=v; auto type=sanitizeMapType(BPF_MAP_TYPE_DEVMAP_HASH);
  assert(type==(v<504?BPF_MAP_TYPE_HASH:BPF_MAP_TYPE_DEVMAP_HASH)); checks++;
  assert(isBtfSupported(type)==(v<504)); checks++;
  reply={type,4,4,64,v<504?0:128}; assert(mapMatchesExpectations(fd,md,type)); checks++;
  for (int field=0;field<5;field++) {
   Reply good=reply;
   switch(field) { case 0:reply.type++;break;case 1:reply.key++;break;case 2:reply.value++;break;case 3:reply.capacity++;break;case 4:reply.flags^=128;break; }
   assert(!mapMatchesExpectations(fd,md,type)); checks++; reply=good;
  }
 }
 version=510; reply={25,4,4,64,BPF_F_RDONLY};assert(!mapMatchesExpectations(fd,md,BPF_MAP_TYPE_DEVMAP_HASH));checks++;
 printf("%u loader policy checks passed; map-info/version replies simulated\n",checks);
}
'''
text = '#include <initializer_list>\n' + text
subject=a.output/'loader.cpp';subject.write_text(text)
command=[a.cxx,'-std=c++17','-O1','-g','-fsanitize=address,undefined','-fno-sanitize-recover=all',str(subject),'-o',str(a.output/'loader')]
r=subprocess.run(command,capture_output=True,text=True)
receipt={'connectivity':pin,'source_sha256':hashlib.sha256(data).hexdigest(),'extracted_sha256':hashlib.sha256('\n'.join(parts).encode()).hexdigest(),'command':command,'compile_exit':r.returncode,'compiler_output':r.stdout+r.stderr,'scope':'Actual loader policy; synthetic map-info and effective-version replies, host Linux UAPI; no kernel execution'}
if r.returncode==0:
 r=subprocess.run([str(a.output/'loader')],capture_output=True,text=True);receipt.update(run_exit=r.returncode,output=r.stdout+r.stderr)
(a.output/'receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
print(receipt.get('output',receipt['compiler_output']))
raise SystemExit(r.returncode)

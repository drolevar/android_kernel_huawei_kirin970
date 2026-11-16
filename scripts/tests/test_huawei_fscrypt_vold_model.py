#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Connect selected vold functions to the existing sequential ownership model.
No real ioctls, keyrings, mounts, worker threads or device operations.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys

CASES = ('clean', 'busy-retry', 'readd', 'admission', 'publication', 'errors',
         'inheritance', 'duplicate-add', 'scope', 'dirty-only', 'busy-only')


def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--android',type=Path,required=True)
    p.add_argument('--cc',type=Path,required=True)
    p.add_argument('--keep-output',type=Path,required=True)
    p.add_argument('--mutation',choices=('tombstone','generation','busy-flag',
                   'owner-release','readd-status','admission','master-retirement',
                   'dirty-owner','busy-owner'))
    a=p.parse_args(); out=a.keep_output.resolve(); out.mkdir(parents=True,exist_ok=False)
    here=Path(__file__).resolve().parent
    commands=[]
    def run(command,log):
        commands.append(command)
        r=subprocess.run(command,text=True,capture_output=True,timeout=180)
        (out/log).write_text(r.stdout+r.stderr)
        if r.returncode: raise RuntimeError(f'{log}: exit {r.returncode}')
        return r
    run([sys.executable,'-B',str(here/'test_huawei_fscrypt_vold.py'),
         '--android',str(a.android.resolve()),'--cc',str(a.cc.resolve()),
         '--keep-output',str(out/'consumer')], 'consumer.log')
    run([sys.executable,'-B',str(here/'test_huawei_fscrypt_contract.py'),
         '--cc',str(a.cc.resolve().with_name('clang')),'--suite','model',
         '--keep-output',str(out/'historical')], 'historical.log')
    model=(here/'huawei_fscrypt_model.h').read_text()
    bridge=(here/'huawei_fscrypt_vold_model.c').read_text()
    mutations={
        'tombstone':('model','if (key->present || key->managed)','if (key->present)'),
        'generation':('model','inode->master_generation != inode->owner->generation','false'),
        'busy-flag':('bridge','return fs_remove(&state.fs);',
                     'int result = fs_remove(&state.fs); return result > 0 ? 0 : result;'),
        'owner-release':('bridge','inode_detach(&owners[i]);','/* lost owner release */'),
        'readd-status':('bridge','case PRESENT: return 2;',
                        'case PRESENT: return state.fs.enrolled ? 3 : 2;'),
        'admission':('model','if (key->readers) return -EAGAIN;','if (false) return -EAGAIN;'),
        'master-retirement':('model','!inode->owner->present','false'),
        'dirty-owner':('bridge','owners[i].busy || owners[i].dirty','owners[i].busy'),
        'busy-owner':('bridge','owners[i].busy || owners[i].dirty','owners[i].dirty'),
    }
    if a.mutation:
        target,before,after=mutations[a.mutation]
        text=model if target=='model' else bridge
        if text.count(before)!=1: raise ValueError('Ambiguous mutation: '+a.mutation)
        text=text.replace(before,after)
        if target=='model': model=text
        else: bridge=text
    (out/'model-subject.h').write_text(model)
    (out/'bridge.c').write_text(bridge)
    cc=str(a.cc.resolve().with_name('clang'))
    ccmd=[cc,'-std=gnu11','-O1','-g','-Wall','-Wextra','-Werror',
          '-Wno-unused-parameter','-Wno-unused-function','-Wno-pointer-sign',
          '-fsanitize=address,undefined','-fno-sanitize-recover=all',
          '-fno-omit-frame-pointer','-I'+str(out),'-I'+str(out/'historical'),
          '-I'+str(here),'-c',str(out/'bridge.c'),
          '-o',str(out/'model.o')]
    run(ccmd,'model-compile.log')
    consumer=json.loads((out/'consumer/receipt.json').read_text())
    binary=out/'vold-model'
    link=consumer['command'][:-2]+['-DVOLD_MANAGED_MODEL','-I'+str(here),str(out/'model.o'),'-o',str(binary)]
    run(link,'link.log')
    results=[]
    for case in CASES:
        name='managed-'+case
        r=subprocess.run([str(binary),name],text=True,capture_output=True,timeout=10)
        (out/(name+'.log')).write_text(r.stdout+r.stderr)
        results.append({'case':name,'exit_status':r.returncode})
        print(name,'PASS' if not r.returncode else 'FAIL',flush=True)
    sources=[here/n for n in ('huawei_fscrypt_vold_host.cpp','huawei_fscrypt_vold_model.h',
             'huawei_fscrypt_vold_model.c','huawei_fscrypt_vold_model_cases.inc',
             'test_huawei_fscrypt_vold.py','test_huawei_fscrypt_vold_model.py',
             'huawei_fscrypt_model.h','huawei_fscrypt_host.h')]
    receipt={'scope':'Extracted selected vold consumer against unchanged existing sequential ownership model plus narrow host bridge, not a kernel registry',
             'commands':commands,'results':results,'binary_sha256':sha(binary),
             'mutation':a.mutation,
             'compiled_input_sha256':{p.name:sha(p) for p in (out/'bridge.c',out/'model-subject.h')},
             'source_sha256':{p.name:sha(p) for p in sources},
             'consumer_receipt_sha256':sha(out/'consumer/receipt.json'),
             'historical_receipt_sha256':sha(out/'historical/receipt.json'),
             'source_head':subprocess.check_output(['git','-C',str(here.parents[1]),'rev-parse','HEAD'],text=True).strip(),
             'source_status':subprocess.check_output(['git','-C',str(here.parents[1]),'status','--porcelain'],text=True),
             'limits':['Sequential synthetic schedules; no kernel locks/RCU/transactions or real inode I/O',
                       'One synthetic descriptor with64-byte raw keys; no real keyring/credential/quota semantics',
                       'Model removal with active readers returns EAGAIN; production semaphore wait remains unimplemented',
                       'Cached file access and wrapping permission are model checks, not cached production-transform retirement']}
    (out/'receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
    return int(any(r['exit_status'] for r in results))


if __name__=='__main__':
    raise SystemExit(main())

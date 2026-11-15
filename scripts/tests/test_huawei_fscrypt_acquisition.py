#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Extract current production acquisition/consumers; simulate only kernel services.

The historical contract runner supplies declarations and unchanged GCM functions
from its pinned source. No device, keyctl, mounts or kernel syscalls are used.
"""
import argparse, hashlib, json, subprocess
from pathlib import Path
from test_huawei_fscrypt_contract import function, extract

p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--cc',required=True)
p.add_argument('--keep-output',type=Path,required=True)
p.add_argument('--historical-output',type=Path,required=True)
p.add_argument('--mutation',choices=('payload-write','double-unlock','skip-validation','fallback','capacity','class','size','wipe'))
a=p.parse_args()
k=Path(__file__).resolve().parents[2]; here=k/'scripts/tests'; out=a.keep_output.resolve(); out.mkdir(parents=True,exist_ok=False)
inputs={name:(k/name).read_text() for name in ('fs/crypto/keyinfo.c','fs/crypto/policy.c','fs/f2fs/keyinfo.c','include/linux/fscrypt_supp.h')}
(out/'declarations.h').write_text((a.historical_output/'declarations.h').read_text())
(out/'crypto-subject.h').write_text('\n'.join(function(inputs['fs/crypto/keyinfo.c'],n) for n in ('derive_crypt_complete','fscrypt_set_gcm_key','fscrypt_derive_gcm_key')))
(out/'lease.h').write_text(extract(r'^struct fscrypt_ce_key \{.*?^\};',inputs['include/linux/fscrypt_supp.h']))
subject='\n'.join(function(inputs[path],n) for path,names in (
 ('fs/crypto/keyinfo.c',('fscrypt_acquire_ce_key','fscrypt_release_ce_key')),
 ('fs/crypto/policy.c',('create_encryption_context_from_policy',)),
 ('fs/crypto/keyinfo.c',('find_and_derive_key',)),
 ('fs/f2fs/keyinfo.c',('f2fs_do_get_keyring_payload','f2fs_do_get_fek'))) for n in names)
mutations={
 'payload-write':('memcpy(&lease->material, payload, sizeof(*payload));','((struct fscrypt_key *)payload)->size = 32; memcpy(&lease->material, payload, sizeof(*payload));'),
 'double-unlock':('if (lease->key) {','if (lease->key) { up_read(&lease->key->sem);'),
 'skip-validation':('err = key_validate(key);','err = 0;'),
 'fallback':('key == ERR_PTR(-ENOKEY) && alternate','IS_ERR(key) && alternate'),
 'capacity':('if (private_size > capacity || public_size > capacity - private_size)','if (false)'),
 'class':('if (mst_sdp->sdpclass != expected_class)','if (false)'),
 'size':('if (payload->size != FS_AES_256_GCM_KEY_SIZE &&','if (false && payload->size != FS_AES_256_GCM_KEY_SIZE &&'),
 'wipe':('memzero_explicit(lease, sizeof(*lease));\n}', '/* missing wipe */\n}')}
if a.mutation:
 before,after=mutations[a.mutation]; assert subject.count(before)==1,(a.mutation,subject.count(before));subject=subject.replace(before,after)
(out/'subject.h').write_text(subject)
version=subprocess.check_output([a.cc,'--version'],text=True);assert 'clang version 22.' in version
results=[];commands=[]
for variant in ('baseline','v3'):
 binary=out/variant
 cmd=[a.cc,'-std=gnu11','-O1','-g','-Wall','-Wextra','-Werror','-Wno-pointer-sign','-Wno-unused-function','-Wno-unused-parameter','-Wno-sign-compare','-fsanitize=address,undefined','-fno-sanitize-recover=all','-fno-omit-frame-pointer','-I'+str(out),'-I'+str(here),str(here/'huawei_fscrypt_acquisition.c'),'-lcrypto','-o',str(binary)]
 if variant=='v3':cmd+=['-DCONFIG_SCSI_UFS_ENHANCED_INLINE_CRYPTO_V3']
 commands.append(cmd);subprocess.run(cmd,check=True,timeout=60)
 for case in ('immutable','tails','revocation','prefix','lookup-errors','sizes','errors','policy-errors','f2fs-ce','f2fs-errors','sdp-bounds'):
  r=subprocess.run([str(binary),case],capture_output=True,text=True,timeout=10)
  (out/(variant+'-'+case+'.log')).write_text(r.stdout+r.stderr)
  results.append({'variant':variant,'case':case,'exit':r.returncode})
  print(variant,case,'PASS' if r.returncode==0 else 'FAIL',flush=True)
receipt={'source_commit':subprocess.check_output(['git','-C',str(k),'rev-parse','HEAD'],text=True).strip(),'dirty':bool(subprocess.check_output(['git','-C',str(k),'status','--porcelain'],text=True)), 'compiler':version,'mutation':a.mutation,'commands':commands,'results':results,'production_sha256':{p:hashlib.sha256(t.encode()).hexdigest() for p,t in inputs.items()},'test_sha256':{p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in here.glob('*fscrypt_acquisition*')},'execution':'current extracted production functions; modeled key lookup/read locks/revocation and allocation; OpenSSL AES-GCM behind kernel crypto API; no actual keyrings/concurrency/kernel/device'}
(out/'receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
raise SystemExit(int(any(r['exit'] for r in results)))

#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Execute production registry/core and VFS release helper with synthetic services."""
import argparse, hashlib, json, re, subprocess
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--cc',required=True);p.add_argument('--output',required=True,type=Path)
p.add_argument('--red-stub',action='store_true')
p.add_argument('--mutation', choices=['namespace','missing-error','tombstone','lookup-ref','payload-ref','root','size','module-pin','sb-key-put','sb-module-put','link-error','duplicate','keep','init-error','exit-unregister','ring-user-search','entry-user-search','unpossessed-lookup'])
a=p.parse_args();root=Path(__file__).resolve().parents[2];out=a.output.resolve();out.mkdir(parents=True,exist_ok=False)
def strip(s):return re.sub(r'^#include[^\n]*\n','',s,flags=re.M)
files=['include/linux/fscrypt_owner.h','fs/crypto/master_key.h','fs/crypto/master_key.c']
core=strip('\n'.join((root/f).read_text() for f in files))
# Reuse the accepted core's exact test-only POSIX/OpenSSL service definitions.
shim=(root/'scripts/tests/huawei_fscrypt_master.c').read_text().split('#include "subject.h"')[0]
(out/'core-shim.h').write_text(shim)
(out/'core.h').write_text(core)
kc=(root/'security/keys/keyctl.c').read_text()
start=kc.index('long keyctl_invalidate_key(');end=kc.index('\n}\n',start)+3
(out/'invalidate.h').write_text(kc[start:end])
for filename, source, name in [
 ('permission.h','security/keys/permission.c','int key_task_permission('),
 ('key-invalidate.h','security/keys/key.c','void key_invalidate('),
]:
 text=(root/source).read_text();start=text.index(name);end=text.index('\n}\n',start)+3
 (out/filename).write_text(text[start:end])
if a.red_stub:
 subject='''
static int fscrypt_registry_init(void) { return 0; }
static void fscrypt_registry_exit(void) {}
static int fscrypt_registry_add(struct super_block *sb,const u8 *d,const u8 *raw,size_t size) { return -EOPNOTSUPP; }
static struct fscrypt_master_key *fscrypt_registry_lookup(struct super_block *sb,const u8 *d) { return ERR_PTR(-ENOENT); }
static void fscrypt_registry_sb_free(struct super_block *sb) {}
'''
else:
 files+=['fs/crypto/registry.h','fs/crypto/keyring.c','include/linux/fscrypt_registry.h']
 subject=strip('\n'.join((root/f).read_text() for f in files[3:]))
if not a.red_stub:
 crypto=(root/'fs/crypto/crypto.c').read_text()
 for name in ('static int __init fscrypt_init(', 'static void __exit fscrypt_exit('):
  start=crypto.index(name);end=crypto.index('\n}\n',start)+3
  subject+='\n'+crypto[start:end]
 files+=['fs/crypto/crypto.c']
else:
 subject+='\nstatic int fscrypt_init(void) { return 0; }\nstatic void fscrypt_exit(void) {}\n'
if a.mutation:
 mutations={
 'namespace':('keyring = smp_load_acquire(&sb->s_fscrypt_keys);','keyring = test_first_ring;'),
 'missing-error':('PTR_ERR(keyref) == -EAGAIN','PTR_ERR(keyref) != 0'),
 'tombstone':('fscrypt_mk_get(mk);\n\t}', 'fscrypt_mk_get(mk);\n\t\tif (!mk->present) { fscrypt_mk_put(mk); mk = ERR_PTR(-ENOENT); }\n\t}'),
 'lookup-ref':('fscrypt_mk_get(mk);\n\t}', '/* missing lookup reference */\n\t}'),
 'payload-ref':('fscrypt_mk_get(mk);\n\tkey->payload', '/* missing payload reference */\n\tkey->payload'),
 'root':('if (!capable(CAP_SYS_ADMIN))','if (false)'),
 'size':('size != FSCRYPT_MK_RAW_SIZE','size > FSCRYPT_MK_RAW_SIZE'),
 'module-pin':('if (!try_module_get(THIS_MODULE))','if (false)'),
 'sb-key-put':('key_put(sb->s_fscrypt_keys);','/* missing key put */'),
 'sb-module-put':('module_put(sb->s_fscrypt_keys_owner);','/* missing module put */'),
 'link-error':('return err;\n}\n\nint fscrypt_registry_add','(void)err; return 0;\n}\n\nint fscrypt_registry_add'),
 'duplicate':('err = fscrypt_mk_add(mk, raw, size);','err = 0;'),
 'keep':('set_bit(KEY_FLAG_KEEP, &keyring->flags);','/* missing keep */'),
 'init-error':('fail:\n\treturn err;', 'fail:\n\treturn -ENOMEM;'),
 'exit-unregister':('\tfscrypt_registry_exit();', '\t/* missing unregister */'),
 'ring-user-search':('current_cred(), KEY_POS_SEARCH |', 'current_cred(), KEY_POS_SEARCH | KEY_USR_SEARCH |'),
 'entry-user-search':('KEY_POS_SEARCH | KEY_USR_VIEW,', 'KEY_POS_SEARCH | KEY_USR_SEARCH | KEY_USR_VIEW,'),
 'unpossessed-lookup':('make_key_ref(keyring, true /* possessed */)', 'make_key_ref(keyring, false /* incorrect */)'),
 }
 old,new=mutations[a.mutation];assert subject.count(old)==1,(a.mutation,subject.count(old));subject=subject.replace(old,new)
(out/'subject.h').write_text(subject)
version=subprocess.check_output([a.cc,'--version'],text=True);assert 'clang version 22.' in version
cmd=[a.cc,'-std=gnu11','-O1','-g','-Wall','-Wextra','-Werror','-Wno-unused-function','-Wno-unused-parameter','-Wno-unused-variable','-fsanitize=address,undefined','-fno-sanitize-recover=all','-fno-omit-frame-pointer','-pthread','-I'+str(out),str(root/'scripts/tests/huawei_fscrypt_registry.c'),'-lcrypto','-o',str(out/'test')]
c=subprocess.run(cmd,capture_output=True,text=True,timeout=60);(out/'compile.log').write_text(c.stdout+c.stderr)
results=[]
cases=['namespace','concurrent-first','duplicate','root','format','missing','errors','tombstone','readd','stable-ref','failures','module','register-failure','payload-null','description','keep','init-unwind','publication-ring','publication-entry','permissions']
if c.returncode==0:
 for case in cases:
  try:
   r=subprocess.run([str(out/'test'),case],capture_output=True,text=True,timeout=20);log=r.stdout+r.stderr;status=r.returncode
  except subprocess.TimeoutExpired:log='Timed out\n';status=124
  (out/(case+'.log')).write_text(log);results.append({'case':case,'exit':status});print(case,'PASS' if not status else 'FAIL',flush=True)
else:print(c.stderr)
receipt={'command':cmd,'compiler':version,'compile_exit':c.returncode,'results':results,'red_stub':a.red_stub,'mutation':a.mutation,'source_commit':subprocess.check_output(['git','-C',str(root),'rev-parse','HEAD'],text=True).strip(),'sha256':{f:hashlib.sha256((root/f).read_bytes()).hexdigest() for f in files+['scripts/tests/huawei_fscrypt_registry.c','scripts/tests/test_huawei_fscrypt_registry.py','scripts/tests/huawei_fscrypt_master.c','security/keys/keyctl.c','security/keys/key.c','security/keys/permission.c']},'limits':'Actual registry/core/release helper, permission/invalidate functions; synthetic key allocation/publication/search/process-possession, credentials, LSM, module refs and deferred GC; deterministic publication interleavings and pthread scheduling. No kernel key-service/RCU/LSM/module runtime proof.'}
(out/'receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
raise SystemExit(bool(c.returncode or any(r['exit'] for r in results)))

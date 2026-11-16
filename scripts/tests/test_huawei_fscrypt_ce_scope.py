#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Execute extracted legacy CE scope and inheritance call sites with host services."""
import argparse
import hashlib
import json
import os
import re
import subprocess
from pathlib import Path

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--cc', required=True)
p.add_argument('--output', required=True, type=Path)
p.add_argument('--mutation', choices=(
    'purpose', 'scope-sb', 'scope-descriptor', 'scope-wipe',
    'material-wipe', 'lock-release', 'owner-ref', 'slot',
    'preload-public', 'cached-acquire', 'f2fs-purpose', 'hmfs-purpose',
    'tfm-descriptor', 'hw-enc-guard'))
a = p.parse_args()
root = Path(__file__).resolve().parents[2]
here = root / 'scripts/tests'
out = a.output.resolve()
out.mkdir(parents=True, exist_ok=False)

paths = ('fs/crypto/keyinfo.c', 'fs/crypto/policy.c', 'fs/f2fs/keyinfo.c',
         'fs/hmfs/keyinfo.c', 'include/linux/fscrypt_common.h',
         'include/linux/fscrypt_supp.h', 'fs/crypto/fscrypt_private.h',
         'include/linux/fscrypt.h', 'include/uapi/linux/fs.h')
inputs = {name: (root / name).read_text() for name in paths}

def extract(pattern, text):
    match = re.search(pattern, text, re.M | re.S)
    if not match:
        raise ValueError('source extraction failed: ' + pattern)
    return match.group(0)

def body(text, signature):
    hit = text.index(signature)
    start = text.rfind('\n', 0, hit) + 1
    brace = text.index('{', start)
    depth = 0
    for pos in range(brace, len(text)):
        if text[pos] == '{':
            depth += 1
        elif text[pos] == '}':
            depth -= 1
            if depth == 0:
                return text[start:pos + 1]
    raise ValueError('unterminated function: ' + signature)

decls = []
for path, names in {
    'include/linux/fscrypt_common.h': ('FS_KEY_DERIVATION_NONCE_SIZE',
        'FS_KEY_DERIVATION_IV_SIZE', 'FS_KEY_DERIVATION_TAG_SIZE',
        'FS_KEY_DERIVATION_CIPHER_SIZE'),
    'fs/crypto/fscrypt_private.h': ('FS_AES_256_GCM_KEY_SIZE',
        'FS_ENCRYPTION_CONTEXT_FORMAT_V2'),
    'include/linux/fscrypt.h': ('FSCRYPT_SET_CONTEXT_MAX_SIZE',),
    'include/uapi/linux/fs.h': ('FS_KEY_DESCRIPTOR_SIZE', 'FS_MAX_KEY_SIZE',
        'FS_KEY_DESC_PREFIX', 'FS_KEY_DESC_PREFIX_SIZE', 'FS_POLICY_FLAGS_VALID',
        'FS_ENCRYPTION_MODE_AES_256_XTS', 'FS_ENCRYPTION_MODE_AES_256_CTS',
        'FS_ENCRYPTION_MODE_AES_128_CBC'),
}.items():
    for name in names:
        decls.append(extract(r'^#define ' + name + r'\b[^\n]*', inputs[path]))
for path, names in {
    'include/linux/fscrypt_common.h': ('fscrypt_context',),
    'include/uapi/linux/fs.h': ('fscrypt_key', 'fscrypt_policy'),
}.items():
    for name in names:
        decls.append(extract(r'^struct ' + name + r' \{.*?^\}[^;]*;', inputs[path]))
(out / 'declarations.h').write_text('\n\n'.join(decls) + '\n')

keyinfo = inputs['fs/crypto/keyinfo.c']
implemented = 'int fscrypt_ce_scope_open(' in keyinfo
crypto_names = ('derive_crypt_complete', 'fscrypt_set_gcm_key',
                'fscrypt_derive_gcm_key')
(out / 'crypto-subject.h').write_text('\n'.join(body(keyinfo, n + '(')
    for n in crypto_names) + '\n')

if implemented:
    supp = inputs['include/linux/fscrypt_supp.h']
    common = inputs['include/linux/fscrypt_common.h']
    subject = extract(r'^enum fscrypt_ce_purpose \{.*?^\};', supp) + '\n'
    subject += extract(r'^struct fscrypt_ce_key \{.*?^\};', supp) + '\n'
    subject += extract(r'^struct fscrypt_ce_tfm \{.*?^\};', keyinfo) + '\n'
    subject += extract(r'^struct fscrypt_ce_scope \{.*?^\};', keyinfo) + '\n'
    for name in ('fscrypt_acquire_ce_key', 'fscrypt_release_ce_key',
                 'fscrypt_ce_tfm_get', 'fscrypt_ce_tfm_put',
                 'fscrypt_ce_scope_open', 'fscrypt_ce_scope_open_cached',
                 'fscrypt_ce_scope_matches', 'fscrypt_ce_scope_crypt',
                 'fscrypt_ce_scope_legacy_slot',
                 'fscrypt_ce_scope_attach_legacy_tfm', 'fscrypt_ce_scope_put'):
        subject += body(keyinfo, name + '(') + '\n'
    for name in ('find_and_derive_key_with_scope', 'find_and_derive_key',
                 'put_crypt_info', 'fscrypt_get_encryption_info_internal',
                 'fscrypt_get_encryption_info_with_scope',
                 'fscrypt_get_encryption_info',
                 'fscrypt_put_encryption_info'):
        subject += body(keyinfo, name + '(') + '\n'
    subject += body(inputs['fs/crypto/policy.c'],
                    'static int create_encryption_context_from_policy(') + '\n'
    subject += body(inputs['fs/crypto/policy.c'],
                    'int fscrypt_inherit_context(') + '\n'
    subject += body(inputs['fs/f2fs/keyinfo.c'],
                    'static int f2fs_do_get_ce_fek(') + '\n'
    subject += body(inputs['fs/hmfs/keyinfo.c'],
                    'static int hmfs_do_get_ce_fek(') + '\n'
else:
    subject = r'''
enum fscrypt_ce_purpose { POLICY_WRAP, FILE_UNWRAP, SDP_CE_SOURCE, CHILD_WRAP };
struct fscrypt_ce_tfm { int unused; };
struct fscrypt_ce_scope { int unused; };
static void fscrypt_ce_tfm_put(struct fscrypt_ce_tfm *owner) {}
static int fscrypt_ce_scope_open(struct inode *inode, const u8 *d,
 enum fscrypt_ce_purpose p, struct fscrypt_ce_scope **out) { *out=NULL; return -EOPNOTSUPP; }
static int fscrypt_ce_scope_open_cached(struct inode *inode,
 enum fscrypt_ce_purpose p, struct fscrypt_ce_scope **out) { *out=NULL; return -EOPNOTSUPP; }
static bool fscrypt_ce_scope_matches(const struct fscrypt_ce_scope *s,
 const struct inode *i, const u8 *d, enum fscrypt_ce_purpose p) { return false; }
static int fscrypt_ce_scope_crypt(struct fscrypt_ce_scope *s,const u8 *a,u8 *b,const u8 *iv,bool e){return -EOPNOTSUPP;}
static int fscrypt_ce_scope_legacy_slot(const struct fscrypt_ce_scope *s,u8 *v){return -EOPNOTSUPP;}
static int fscrypt_ce_scope_attach_legacy_tfm(struct fscrypt_ce_scope *s,struct fscrypt_info *ci){return -EOPNOTSUPP;}
static void fscrypt_ce_scope_put(struct fscrypt_ce_scope *s) {}
static int create_encryption_context_from_policy(struct inode *i,const struct fscrypt_policy *p){return -EOPNOTSUPP;}
static int fscrypt_inherit_context(struct inode *p,struct inode *c,void *d,bool preload){return -EOPNOTSUPP;}
static int f2fs_do_get_ce_fek(struct inode *i,u8 *d,u8 *n,u8 *f,u8 *iv,int e){return -EOPNOTSUPP;}
static int hmfs_do_get_ce_fek(struct inode *i,u8 *d,u8 *n,u8 *f,u8 *iv,int e){return -EOPNOTSUPP;}
'''

mutations = {
    'purpose': ('scope->purpose == purpose', 'true'),
    'scope-sb': ('scope->sb == inode->i_sb', 'true'),
    'scope-descriptor': ('memcmp(scope->descriptor, descriptor,', 'false && memcmp(scope->descriptor, descriptor,'),
    'scope-wipe': ('fscrypt_ce_tfm_put(scope->owner);\n\tmemzero_explicit(scope, sizeof(*scope));',
                   'fscrypt_ce_tfm_put(scope->owner);\n\t/* missing scope wipe */'),
    'material-wipe': ('memzero_explicit(&material, sizeof(material));',
                      '/* missing stack material wipe */'),
    'lock-release': ('memcpy(&material, &lease.material, sizeof(material));\n\tfscrypt_release_ce_key(&lease);',
                     'memcpy(&material, &lease.material, sizeof(material));\n\t/* retained legacy semaphore/reference */'),
    'owner-ref': ('refcount_inc(&owner->refs);', '/* missing transform owner reference */'),
    'slot': ('*slot = scope->owner->legacy_slot;', '*slot = 0;'),
    'preload-public': ('fscrypt_get_encryption_info_with_scope(child, &ctx,\n'
                       '\t\t\t\t\t\t      scope)',
                       'fscrypt_get_encryption_info(child)'),
    'cached-acquire': ('fscrypt_ce_scope_open_cached(parent, CHILD_WRAP, &scope)',
                       'fscrypt_ce_scope_open(parent, ci->ci_master_key, CHILD_WRAP, &scope)'),
    'f2fs-purpose': ('SDP_CE_SOURCE, &scope); /* F2FS */', 'FILE_UNWRAP, &scope); /* F2FS */'),
    'hmfs-purpose': ('SDP_CE_SOURCE, &scope); /* HMFS */', 'FILE_UNWRAP, &scope); /* HMFS */'),
    'tfm-descriptor': ('memcpy(owner->descriptor, descriptor, sizeof(owner->descriptor));',
                       'memset(owner->descriptor, 0, sizeof(owner->descriptor));'),
    'hw-enc-guard': ('ci->ci_hw_enc_flag || !ci->ci_gtfm_owner',
                     'false || !ci->ci_gtfm_owner'),
}
if a.mutation:
    old, new = mutations[a.mutation]
    if subject.count(old) != 1:
        raise ValueError(f'mutation {a.mutation}: expected one target, got {subject.count(old)}')
    subject = subject.replace(old, new)
(out / 'subject.h').write_text(subject)

version = subprocess.check_output([a.cc, '--version'], text=True)
if 'clang version 22.' not in version:
    raise ValueError('fixture requires selected Clang 22')
cmd = [a.cc, '-std=gnu11', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
       '-Wno-unused-function', '-Wno-unused-parameter', '-Wno-pointer-sign',
       '-fsanitize=address,undefined', '-fno-sanitize-recover=all',
       '-fno-omit-frame-pointer', '-I' + str(out), '-I' + str(here),
       str(here / 'huawei_fscrypt_ce_scope.c'), '-lcrypto', '-o', str(out / 'test')]
c = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
(out / 'compile.log').write_text(c.stdout + c.stderr)
cases = ('scope', 'purpose', 'failures', 'policy-boundary', 'cached',
         'preload', 'child-lifetime', 'f2fs-ce', 'hmfs-ce')
results = []
if c.returncode == 0:
    run_env = dict(os.environ)
    run_env['ASAN_OPTIONS'] = 'detect_leaks=0'
    for case in cases:
        r = subprocess.run([str(out / 'test'), case], capture_output=True,
                           text=True, timeout=15, env=run_env)
        (out / (case + '.log')).write_text(r.stdout + r.stderr)
        results.append({'case': case, 'exit': r.returncode})
        print(case, 'PASS' if r.returncode == 0 else 'FAIL', flush=True)
else:
    print(c.stderr)
receipt = {
    'source_commit': subprocess.check_output(
        ['git', '-C', str(root), 'rev-parse', 'HEAD'], text=True).strip(),
    'production_implemented': implemented,
    'mutation': a.mutation,
    'compiler': version,
    'command': cmd,
    'compile_exit': c.returncode,
    'results': results,
    'source_sha256': {name: hashlib.sha256(text.encode()).hexdigest()
                      for name, text in inputs.items()},
    'test_sha256': {name.name: hashlib.sha256(name.read_bytes()).hexdigest()
                    for name in (Path(__file__), here / 'huawei_fscrypt_ce_scope.c',
                                 here / 'huawei_fscrypt_ce_scope_host.h')},
    'limits': 'Extracted CE scope, real generic construction/teardown, policy/inheritance and CE-only F2FS/HMFS helpers with synthetic keyring, locks, inode lifetime and filesystem callback; OpenSSL AES-GCM. No kernel VFS/SMP/filesystem/hardware/device execution.'
}
(out / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
raise SystemExit(bool(c.returncode or any(r['exit'] for r in results)))

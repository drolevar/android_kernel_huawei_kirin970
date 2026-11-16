#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Compile the internal master-key C core with bounded host-service shims."""
import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--cc', required=True)
p.add_argument('--output', required=True, type=Path)
p.add_argument('--red-stub', action='store_true')
p.add_argument('--mutation', choices=('remove-wipe', 'final-wipe', 'generation',
    'identity', 'owner-ref', 'owner-count', 'admission', 'overflow', 'remove-lock', 'error-state'))
a = p.parse_args()
root = Path(__file__).resolve().parents[2]
out = a.output.resolve()
out.mkdir(parents=True, exist_ok=False)
header = root / 'fs/crypto/master_key.h'
source = root / 'fs/crypto/master_key.c'
owner = root / 'include/linux/fscrypt_owner.h'
if a.red_stub:
    subject = '''
#define RED_STUB
struct fscrypt_master_key { int unused; };
struct fscrypt_mk_lease { struct fscrypt_master_key *key; u64 generation; };
struct fscrypt_mk_owner { struct fscrypt_master_key *key; u64 generation; };
enum fscrypt_mk_state { FSCRYPT_MK_ABSENT, FSCRYPT_MK_PRESENT, FSCRYPT_MK_BUSY };
static struct fscrypt_master_key *fscrypt_mk_alloc(const u8 *raw, size_t size) { return ERR_PTR(-EOPNOTSUPP); }
static void fscrypt_mk_get(struct fscrypt_master_key *k) {}
static void fscrypt_mk_put(struct fscrypt_master_key *k) {}
static int fscrypt_mk_add(struct fscrypt_master_key *k, const u8 *r, size_t s) { return -EOPNOTSUPP; }
static int fscrypt_mk_acquire(struct fscrypt_master_key *k, u64 g, struct fscrypt_mk_lease *l) { return -EOPNOTSUPP; }
static const u8 *fscrypt_mk_secret(const struct fscrypt_mk_lease *l) { return NULL; }
static void fscrypt_mk_release(struct fscrypt_mk_lease *l) {}
static int fscrypt_mk_enroll(const struct fscrypt_mk_lease *l, struct fscrypt_mk_owner *o) { return -EOPNOTSUPP; }
static void fscrypt_mk_drop_owner(struct fscrypt_mk_owner *o) {}
static enum fscrypt_mk_state fscrypt_mk_status(struct fscrypt_master_key *k) { return FSCRYPT_MK_ABSENT; }
static bool fscrypt_mk_remove(struct fscrypt_master_key *k) { return false; }
'''
else:
    subject = re.sub(r'^#include[^\n]*\n', '', owner.read_text() + '\n' + header.read_text() + '\n' + source.read_text(), flags=re.M)
if a.mutation:
    mutations = {
        'remove-wipe': ('memzero_explicit(key->raw, sizeof(key->raw));\n\tkey->present = false;', 'key->present = false;'),
        'final-wipe': ('memzero_explicit(key->fingerprint, sizeof(key->fingerprint));', '/* omitted fingerprint wipe */'),
        'generation': ('key->generation++;', '/* omitted generation advance */'),
        'identity': ('(key->present || atomic_read(&key->owners)) &&', 'key->present &&'),
        'owner-ref': ('fscrypt_mk_get(key);\n\towner->key = key;', 'owner->key = key;'),
        'owner-count': ('atomic_dec(&key->owners);', '/* omitted owner retirement */'),
        'admission': ('!key->present || (generation && generation != key->generation)', '!key->present'),
        'overflow': ('if (key->generation == U64_MAX)', 'if (false)'),
        'remove-lock': ('down_write(&key->secret_sem);\n\tmemzero_explicit(key->raw', '/* omitted guard */\n\tmemzero_explicit(key->raw'),
        'error-state': ('if (err)\n\t\tgoto out;', 'if (err) { key->fingerprint[0] ^= 1; goto out; }'),
    }
    old, new = mutations[a.mutation]
    assert subject.count(old) == 1, a.mutation
    subject = subject.replace(old, new)
    if a.mutation == 'remove-lock':
        old = 'up_write(&key->secret_sem);\n\treturn busy;'
        assert subject.count(old) == 1
        subject = subject.replace(old, 'return busy;')
(out / 'subject.h').write_text(subject)
version = subprocess.check_output([a.cc, '--version'], text=True)
assert 'clang version 22.' in version
cmd = [a.cc, '-std=gnu11', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
       '-Wno-unused-function', '-Wno-unused-parameter', '-fsanitize=address,undefined',
       '-fno-sanitize-recover=all', '-fno-omit-frame-pointer', '-pthread',
       '-I' + str(out), str(root / 'scripts/tests/huawei_fscrypt_master.c'),
       '-lcrypto', '-o', str(out / 'test')]
subprocess.run(cmd, check=True, timeout=60)
cases = ('basic', 'remove', 'owners', 'readd', 'identity', 'generation',
         'failures', 'tokens', 'lifetime', 'admission-race', 'overflow', 'immutable', 'backend-failure-preserves')
results = []
for case in cases:
    try:
        r = subprocess.run([str(out / 'test'), case], capture_output=True, text=True, timeout=15)
        log, status = r.stdout + r.stderr, r.returncode
    except subprocess.TimeoutExpired:
        log, status = 'Case exceeded the 15-second execution bound.\n', 124
    (out / (case + '.log')).write_text(log)
    results.append({'case': case, 'exit': status})
    print(case, 'PASS' if status == 0 else 'FAIL', flush=True)
receipt = {'command': cmd, 'compiler': version, 'results': results,
           'red_stub': a.red_stub,
           'mutation': a.mutation,
           'source_commit': subprocess.check_output(['git', '-C', str(root), 'rev-parse', 'HEAD'], text=True).strip(),
           'source_sha256': {str(f.relative_to(root)): hashlib.sha256(f.read_bytes()).hexdigest()
                             for f in (owner, header, source) if f.exists()},
           'test_sha256': {f.name: hashlib.sha256(f.read_bytes()).hexdigest()
                          for f in (Path(__file__), root / 'scripts/tests/huawei_fscrypt_master.c')},
           'execution': 'production core with POSIX rwlocks/C atomics and OpenSSL SHA256; simulated allocation/crypto failures; no kernel keyring/inodes/syscalls/phone'}
(out / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
raise SystemExit(int(any(r['exit'] for r in results)))

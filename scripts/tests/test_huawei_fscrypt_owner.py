#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Execute extracted ci initialization/release and the actual owner core."""
import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--cc', required=True)
p.add_argument('--output', required=True, type=Path)
p.add_argument('--mutation', choices=[f'init-{n}' for n in range(6)] +
               [f'drop-{n}' for n in range(3)] + ['owner-ref', 'owner-count', 'generation-init'])
a = p.parse_args()
root = Path(__file__).resolve().parents[2]
out = a.output.resolve()
out.mkdir(parents=True, exist_ok=False)
files = {}
regions = []

def read(path):
    text = (root / path).read_text()
    files[path] = hashlib.sha256(text.encode()).hexdigest()
    return text

def strip(text):
    return re.sub(r'^#include[^\n]*\n', '', text, flags=re.M)

def region(path, start, end, offset=0):
    text = read(path)
    first = text.index(start, offset)
    last = text.index(end, first) + len(end)
    regions.append({'path': path, 'first_line': text.count('\n', 0, first) + 1,
                    'last_line': text.count('\n', 0, last) + 1,
                    'sha256': hashlib.sha256(text[first:last].encode()).hexdigest()})
    return text[first:last]

def function(path, name):
    return region(path, name, '\n}\n')

owner_path = 'include/linux/fscrypt_owner.h'
baseline = not (root / owner_path).exists()
owner = '' if baseline else strip(read(owner_path))
core = strip(read('fs/crypto/master_key.h') + '\n' + read('fs/crypto/master_key.c'))
if a.mutation in ('owner-ref', 'owner-count'):
    old, new = {
        'owner-ref': ('fscrypt_mk_get(key);\n\towner->key = key;', 'owner->key = key;'),
        'owner-count': ('atomic_dec(&key->owners);', '/* missing owner retirement */'),
    }[a.mutation]
    assert core.count(old) == 1
    core = core.replace(old, new)
if a.mutation == 'generation-init':
    assert owner.count('owner->generation = 0;') == 1
    owner = owner.replace('owner->generation = 0;', '/* missing generation init */')
(out / 'core.h').write_text(owner + '\n' + core)
shim = read('scripts/tests/huawei_fscrypt_master.c').split('#include "subject.h"')[0]
(out / 'core-shim.h').write_text(shim)
layout = region('include/linux/fscrypt_common.h', 'struct fscrypt_info {', '\n};')
if baseline:
    # API/layout scaffold only: unchanged baseline init/release bodies must fail.
    # No constructor/drop implementation is supplied by this scaffold.
    layout = layout.replace('\n};', '\n\tstruct fscrypt_mk_owner ci_owner;\n};')
(out / 'layout.h').write_text(layout)
paths = ['fs/crypto/keyinfo.c', 'fs/f2fs/keyinfo.c', 'fs/hmfs/keyinfo.c']
destructors = []
for n, path in enumerate(paths):
    name = 'put_crypt_info' if n == 0 else 'f2fs_put_crypt_info'
    body = function(path, 'static void ' + name + '(')
    if a.mutation == f'drop-{n}':
        assert body.count('fscrypt_mk_drop_owner(&ci->ci_owner);') == 1
        body = body.replace('fscrypt_mk_drop_owner(&ci->ci_owner);', '/* missing drop */')
    destructors.append(body.replace(name, ['put_crypt_info', 'f2fs_put_crypt_info', 'hmfs_put_crypt_info'][n]))
(out / 'release.h').write_text('\n'.join(destructors) + '\n' +
    function(paths[0], 'void fscrypt_put_encryption_info('))

# Generic and SDP constructors have extensive unrelated filesystem dependencies.
# Execute only their unmodified allocation/init blocks; HWDPS executes whole.
constructors = []
for n, (path, occurrence) in enumerate([(paths[0], 0), (paths[0], 1),
                                      (paths[1], 0), (paths[1], 1),
                                      (paths[2], 0), (paths[2], 1)]):
    if n == 1:
        body = function(path, 'static struct fscrypt_info *hwdps_get_fscrypt_info(')
    else:
        text = read(path)
        starts = [m.start() for m in re.finditer(r'crypt_info = kmem_cache_alloc\(', text)]
        first = starts[occurrence]
        body = region(path, 'crypt_info = kmem_cache_alloc(', 'sizeof(crypt_info->ci_master_key));', first)
        body = ('static int ctor_' + str(n) + '(struct fscrypt_info **result)\n{\n'
                'struct fscrypt_info *crypt_info;\n'
                'struct fscrypt_context ctx = {0}, sdp_ctx = {0};\n' + body +
                '\n*result = crypt_info;\nreturn 0;\n}\n')
    if a.mutation == f'init-{n}':
        old = 'fscrypt_mk_init_owner(&' + ('ci' if n == 1 else 'crypt_info') + '->ci_owner);'
        assert body.count(old) == 1
        body = body.replace(old, '/* missing init */')
    constructors.append(body)
(out / 'construct.h').write_text('\n'.join(constructors))
# Exact generic production publication/out path: attachment is intentionally
# done by the harness before it, never spliced into production source.
publication = region(paths[0],
    '\t} else if (cmpxchg(&inode->i_crypt_info, NULL, crypt_info) == NULL)',
    '\n\treturn res;')
publication = publication.replace('\t} else if', '\tif', 1)
(out / 'publish.h').write_text(publication)
version = subprocess.check_output([a.cc, '--version'], text=True)
assert 'clang version 22.' in version
cmd = [a.cc, '-std=gnu11', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
       '-Wno-unused-function', '-Wno-unused-parameter', '-Wno-unused-variable',
       '-fsanitize=address,undefined', '-fno-sanitize-recover=all',
       '-fno-omit-frame-pointer', '-pthread', '-I' + str(out),
       str(root / 'scripts/tests/huawei_fscrypt_owner.c'), '-lcrypto', '-o', str(out / 'test')]
c = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
(out / 'compile.log').write_text(c.stdout + c.stderr)
cases = [f'ctor-{n}' for n in range(6)] + [f'alloc-failure-{n}' for n in range(6)] + [
    'hwdps-copy-failure', 'hwdps-cipher-failure', 'empty-drop',
    'drop-0', 'drop-1', 'drop-2', 'attach-errors', 'private-failure',
    'publication-loser', 'final-eviction', 'last-reference', 'parent-child']
results = []
if c.returncode == 0:
    for case in cases:
        r = subprocess.run([str(out / 'test'), case], capture_output=True, text=True, timeout=15)
        (out / (case + '.log')).write_text(r.stdout + r.stderr)
        results.append({'case': case, 'exit': r.returncode})
        print(case, 'PASS' if r.returncode == 0 else 'FAIL', flush=True)
else:
    print(c.stderr)
for name in ('scripts/tests/test_huawei_fscrypt_owner.py', 'scripts/tests/huawei_fscrypt_owner.c'):
    read(name)
receipt = {'baseline_layout_scaffold': baseline, 'mutation': a.mutation,
           'command': cmd, 'compiler': version, 'compile_exit': c.returncode,
           'results': results, 'source_sha256': files, 'extracted_regions': regions,
           'source_commit': subprocess.check_output(['git', '-C', str(root), 'rev-parse', 'HEAD'], text=True).strip(),
           'limits': 'Exact core, ci layout, six initialization regions (one whole HWDPS constructor), three whole destructors, generic publication/out and fscrypt_put_encryption_info. Synthetic allocator/crypto/slab/CAS/inode; attachment and failure schedules driven by fixture. No full generic/SDP constructors, kernel VFS eviction, SMP, filesystem locks, registry consumer, ioctl, hardware slot or durability proof.'}
(out / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
raise SystemExit(bool(c.returncode or any(r['exit'] for r in results)))

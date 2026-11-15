#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Replay pinned vold functions with synthetic fd/ioctl/thread/sleep boundaries.
No real device, ioctl, keyring, thread worker, sleep or filesystem encryption.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess

VOLD = '11d8982f824d52e8122c7aa732207ba66b8f23c8'
EXTRAS = '378b92d7f4511cb3f23a34fecc694b9704530374'
CASES = ('options', 'add-shapes', 'remove-clean', 'busy-cleanup', 'busy-retry',
         'readd-present', 'already-absent', 'readd-during-wait', 'status-error',
         'retry-remove-error', 'initial-remove-error', 'other-users',
         'worker-other-users', 'exhaustion', 'invalid-spec', 'open-errors', 'add-error')


def git(repo, *args):
    return subprocess.check_output(['git', '-C', str(repo), *args], text=True, timeout=30)


def function(text, name):
    # These pinned functions all end with a column-zero brace. Fail closed on count.
    pattern = (r'^(?:static )?(?:bool|void|std::string) ' + re.escape(name)
               + r'\(.*?^\}')
    matches = re.findall(pattern, text, re.M | re.S)
    if len(matches) != 1:
        raise ValueError(f'{name}: expected exactly one function, got {len(matches)}')
    return matches[0]


def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--android', type=Path, required=True)
    ap.add_argument('--cc', type=Path, required=True)
    ap.add_argument('--keep-output', type=Path, required=True)
    ap.add_argument('--mutation', choices=('ignore-readd', 'remove-error', 'skip-worker',
                                         'no-backoff', 'wrapped-flag', 'default-v2',
                                         'specifier-tail'))
    args = ap.parse_args()
    root = args.android.resolve()
    here = Path(__file__).resolve().parent
    out = args.keep_output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    vold = git(root/'system/vold', 'show', VOLD+':KeyUtil.cpp')
    options = git(root/'system/extras', 'show', EXTRAS+':libfscrypt/fscrypt.cpp')
    header = git(root/'system/extras', 'show', EXTRAS+':libfscrypt/include/fscrypt/fscrypt.h')
    inputs = {'vold/KeyUtil.cpp': vold, 'libfscrypt/fscrypt.cpp': options,
              'libfscrypt/include/fscrypt/fscrypt.h': header}
    names = ('generateKeyRef', 'buildKeySpecifier', 'installKey', 'waitForBusyFiles', 'evictKey')
    subjects = {name: function(vold, name) for name in names}
    keyutil = '\n\n'.join(subjects.values())+'\n'
    # Preserve Apache notice with the generated, uncommitted source extraction.
    notice = vold[:vold.index('*/')+2]+'\n'
    mode_tables = re.search(r'^struct ModeLookupEntry \{.*?^};\n\nstatic const auto contents_modes.*?^};\n\nstatic const auto filenames_modes.*?^};', options, re.M | re.S)
    if not mode_tables:
        raise ValueError('mode table extraction failed')
    option_subject = mode_tables[0]+'\n'+function(options, 'LookupModeByName')+'\n'+function(options, 'ParseOptionsForApiLevel')+'\n'
    mutations = {
        'ignore-readd': ('keyutil', 'if (get_arg.status != FSCRYPT_KEY_STATUS_INCOMPLETELY_REMOVED)', 'if (false)'),
        'remove-error': ('keyutil', 'PLOG(ERROR) << "Failed to evict fscrypt key with ref " << ref << " from " << mountpoint;\n        return false;', 'PLOG(ERROR) << "Failed to evict fscrypt key with ref " << ref << " from " << mountpoint;\n        return true;'),
        'skip-worker': ('keyutil', 'busyFilesThread.detach();', '(void)busyFilesThread;'),
        'no-backoff': ('keyutil', 'wait_time *= 2;', 'wait_time *= 1;'),
        'wrapped-flag': ('keyutil', 'arg->__flags |= __FSCRYPT_ADD_KEY_FLAG_HW_WRAPPED;', 'arg->flags |= __FSCRYPT_ADD_KEY_FLAG_HW_WRAPPED;'),
        'default-v2': ('options', 'options->version = first_api_level > __ANDROID_API_Q__ ? 2 : 1;', '(void)first_api_level; options->version = 2;'),
        'specifier-tail': ('keyutil', 'spec->type = FSCRYPT_KEY_SPEC_TYPE_DESCRIPTOR;', 'spec->u.__reserved[31] = 0xa5; spec->type = FSCRYPT_KEY_SPEC_TYPE_DESCRIPTOR;'),
    }
    if args.mutation:
        target, before, after = mutations[args.mutation]
        text = keyutil if target == 'keyutil' else option_subject
        assert text.count(before) == 1, args.mutation
        text = text.replace(before, after)
        if target == 'keyutil': keyutil = text
        else: option_subject = text
    refs = []
    for name, length in [('full', 64), ('half', 32)]:
        digest = hashlib.sha512(hashlib.sha512(bytes(range(length))).digest()).digest()[:8]
        refs.append('static const std::array<unsigned char,8> expected_'+name+'_ref = {'+','.join(str(x) for x in digest)+'};\n')
    (out/'selected-keyutil.h').write_text(notice+keyutil)
    (out/'selected-options.h').write_text(notice+option_subject+''.join(refs))
    (out/'fscrypt').mkdir()
    (out/'fscrypt/fscrypt.h').write_text(header)
    bionic = root/'bionic'
    uapi_path = 'libc/kernel/uapi/linux/fscrypt.h'
    assert not git(bionic, 'status', '--porcelain', '--', uapi_path)
    uapi = (bionic/uapi_path).read_text()
    (out/'selected-fscrypt-uapi.h').write_text(uapi)
    inputs['bionic/'+uapi_path] = uapi
    version = subprocess.check_output([str(args.cc), '--version'], text=True, timeout=10)
    if 'clang version 22.' not in version:
        raise ValueError('Use the selected Android Clang22 toolchain')
    toolroot = args.cc.resolve().parents[1]
    runtime = toolroot/'lib/x86_64-unknown-linux-gnu'
    if not (runtime/'libc++.so').is_file():
        raise ValueError('Selected toolchain lacks the GNU x86-64 libc++ runtime')
    binary = out/'vold-contract'
    command = [str(args.cc), '-std=c++20', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
               '-Wno-deprecated-declarations', '-Wno-unused-function',
               '-fsanitize=address,undefined', '-fno-sanitize-recover=all',
               '-fno-omit-frame-pointer', '-stdlib=libc++', '-nostdinc++',
               '-isystem', str(toolroot/'include/c++/v1'), '-L'+str(runtime),
               '-Wl,-rpath,'+str(runtime), '-I'+str(out),
               str(here/'huawei_fscrypt_vold_host.cpp'), '-lcrypto', '-pthread', '-o', str(binary)]
    compiled = subprocess.run(command, text=True, capture_output=True, timeout=90)
    (out/'compile.log').write_text(compiled.stdout+compiled.stderr)
    receipt = {'scope': 'Host consumer replay, extracted production functions with synthetic services; no kernel filesystem/key-service/concurrency result',
               'vold_revision': VOLD, 'extras_revision': EXTRAS,
               'bionic_revision': git(bionic, 'rev-parse', 'HEAD').strip(),
               'kernel_fixture_head': git(here.parents[1], 'rev-parse', 'HEAD').strip(),
               'fixture_status': git(here.parents[1], 'status', '--porcelain'),
               'source_hashes': {k: hashlib.sha256(v.encode()).hexdigest() for k,v in inputs.items()},
               'function_hashes': {k: hashlib.sha256(v.encode()).hexdigest() for k,v in subjects.items()},
               'boundary_remapping': 'open/ioctl/std macro mapping only while including exact function text; std redirects thread/sleep and aliases other used types',
               'compiler': version, 'compiler_sha256': sha(args.cc), 'command': command,
               'compile_exit_status': compiled.returncode, 'mutation': args.mutation,
               'results': []}
    if compiled.returncode:
        print(compiled.stderr[-5000:])
    else:
        for case in CASES:
            p = subprocess.run([str(binary), case], text=True, capture_output=True, timeout=10)
            (out/(case+'.log')).write_text(p.stdout+p.stderr)
            receipt['results'].append({'case': case, 'exit_status': p.returncode})
            print(case, 'PASS' if not p.returncode else 'FAIL')
        receipt['binary_sha256'] = sha(binary)
    receipt['fixture_sha256'] = {p.name: sha(p) for p in [here/'test_huawei_fscrypt_vold.py', here/'huawei_fscrypt_vold_host.cpp']}
    (out/'receipt.json').write_text(json.dumps(receipt, indent=2)+'\n')
    return int(bool(compiled.returncode or any(x['exit_status'] for x in receipt['results'])))


if __name__ == '__main__':
    raise SystemExit(main())

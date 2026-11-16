#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Compile extracted fscrypt setattr/key helpers with the actual inode field guard.

Only surrounding inode/dentry types and key-loading outcomes are simulated.
Uses the selected tree's IS_ENABLED macros; no configured kernel build is needed.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess


def extract_function(source, name):
    match = re.search(r'^static inline int ' + name + r'\(.*?^\}', source, re.M | re.S)
    if match is None:
        raise ValueError('Missing production function: ' + name)
    return match.group()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cc', required=True)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    kernel = Path(__file__).resolve().parents[2]
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    paths = ('include/linux/fscrypt.h', 'include/linux/fs.h', 'include/linux/kconfig.h')
    inputs = {name: (kernel / name).read_text() for name in paths}
    fscrypt, fs, kconfig = (inputs[name] for name in paths)
    functions = '\n'.join(extract_function(fscrypt, name) for name in
                          ('fscrypt_require_key', 'fscrypt_prepare_setattr'))
    inode_field = re.search(
        r'^#if IS_ENABLED\(CONFIG_FS_ENCRYPTION\)\n'
        r'\s*struct fscrypt_info\s+\*i_crypt_info;\n#endif', fs, re.M).group()
    # Keep production macro semantics, including undefined and _MODULE options.
    macros = kconfig[kconfig.index('#define __ARG_PLACEHOLDER_1'):
                     kconfig.index('/* Make sure we always have all types')]
    flag = re.search(r'^#define F2FS_XATTR_SDP_SECE_ENABLE_FLAG.*$', fscrypt, re.M).group()
    prefix = r'''
#include <assert.h>
#include <errno.h>
#include <stddef.h>
#define ATTR_SIZE 8
struct fscrypt_info { unsigned char ci_hw_enc_flag; };
struct inode {
    int encrypted;
INODE_FIELD
};
struct dentry { struct inode *inode; };
struct iattr { unsigned int ia_valid; };
#define d_inode(dentry) ((dentry)->inode)
#define IS_ENCRYPTED(inode) ((inode)->encrypted)
static int info_calls, key_calls, info_error, key_present;
static int fscrypt_get_encryption_info(struct inode *inode)
{
    (void)inode;
    ++info_calls;
    return __FS_HAS_ENCRYPTION ? info_error : -EOPNOTSUPP;
}
static int fscrypt_has_encryption_key(struct inode *inode)
{
    (void)inode;
    ++key_calls;
    return __FS_HAS_ENCRYPTION && key_present;
}
'''.replace('INODE_FIELD', inode_field)
    checks = r'''
static void check(struct dentry *dentry, unsigned int valid, int error, int key,
                  int expected, int info_count, int key_count)
{
    struct iattr attr = { .ia_valid = valid };
    info_calls = key_calls = 0;
    info_error = error;
    key_present = key;
    assert(fscrypt_prepare_setattr(dentry, &attr) == expected);
    assert(info_calls == info_count);
    assert(key_calls == key_count);
}
int main(void)
{
    struct inode inode = { .encrypted = 0 };
    struct dentry dentry = { .inode = &inode };
#if IS_ENABLED(CONFIG_FS_ENCRYPTION)
    struct fscrypt_info ci = { .ci_hw_enc_flag = 2 }; /* non-SECE bit */
    inode.i_crypt_info = &ci;
#endif
    /* A non-size attribute must not even dereference the supplied dentry. */
    check(NULL, 1, -EIO, 0, 0, 0, 0);
    check(&dentry, ATTR_SIZE, -EIO, 0, 0, 0, 0); /* unencrypted */
    inode.encrypted = 1;
    check(&dentry, ATTR_SIZE, 0, 1,
          __FS_HAS_ENCRYPTION ? 0 : -EOPNOTSUPP, 1, __FS_HAS_ENCRYPTION);
    check(&dentry, ATTR_SIZE, 0, 0,
          __FS_HAS_ENCRYPTION ? -ENOKEY : -EOPNOTSUPP, 1, __FS_HAS_ENCRYPTION);
    check(&dentry, ATTR_SIZE, -EIO, 1,
          __FS_HAS_ENCRYPTION ? -EIO : -EOPNOTSUPP, 1, 0);
#if IS_ENABLED(CONFIG_FS_ENCRYPTION)
    inode.i_crypt_info = NULL;
#endif
    check(&dentry, ATTR_SIZE, 0, 0,
          __FS_HAS_ENCRYPTION ? -ENOKEY : -EOPNOTSUPP, 1, __FS_HAS_ENCRYPTION);
#if IS_ENABLED(CONFIG_FS_ENCRYPTION)
    inode.i_crypt_info = &ci;
    ci.ci_hw_enc_flag = 4; /* independent oracle for retained Huawei SECE bit */
    check(&dentry, ATTR_SIZE, -EIO, 0, 0, 0, 0);
    ci.ci_hw_enc_flag = 6; /* additional bits must not disable SECE handling */
    check(&dentry, ATTR_SIZE, -EIO, 0, 0, 0, 0);
#endif
    return 0;
}
'''
    results = []
    modes = [('disabled', '', 0), ('builtin', '#define CONFIG_FS_ENCRYPTION 1\n', 1),
             ('builtin-notsupp', '#define CONFIG_FS_ENCRYPTION 1\n', 0),
             ('module', '#define CONFIG_FS_ENCRYPTION_MODULE 1\n', 1),
             ('module-notsupp', '#define CONFIG_FS_ENCRYPTION_MODULE 1\n', 0)]
    for name, config, filesystem_support in modes:
        source = output / (name + '.c')
        source.write_text(config + f'#define __FS_HAS_ENCRYPTION {filesystem_support}\n' +
                          macros + '\n' + flag + '\n' + prefix + functions + checks)
        binary = output / name
        command = [args.cc, '-std=gnu11', '-O0', '-Wall', '-Wextra', '-Werror',
                   '-fsanitize=address,undefined', '-fno-sanitize-recover=all',
                   str(source), '-o', str(binary)]
        build = subprocess.run(command, text=True, capture_output=True, timeout=30)
        run = (subprocess.run([str(binary)], text=True, capture_output=True, timeout=10)
               if build.returncode == 0 else None)
        (output / (name + '.log')).write_text(
            build.stdout + build.stderr + (run.stdout + run.stderr if run else ''))
        passed = build.returncode == 0 and run is not None and run.returncode == 0
        results.append({'case': name, 'command': command, 'compile_exit': build.returncode,
                        'run_exit': run.returncode if run else None, 'passed': passed})
        print(name, 'PASS' if passed else 'FAIL', flush=True)
    receipt = {'source_sha256': {p: hashlib.sha256(s.encode()).hexdigest()
                                 for p, s in inputs.items()},
               'compiler': subprocess.check_output([args.cc, '--version'], text=True),
               'results': results,
               'limits': 'Extracted production functions/macros/field guard; surrounding types and key outcomes simulated. Not full header, kernel, filesystem or device execution.'}
    (output / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    return int(not all(result['passed'] for result in results))


if __name__ == '__main__':
    raise SystemExit(main())

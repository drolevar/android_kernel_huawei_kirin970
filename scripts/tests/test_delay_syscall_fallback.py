#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Link actual sys_ni.c against extracted Huawei delay implementations.

Exercise missing-provider ENOSYS and strong-provider precedence in both link
orders. Kernel syscall declaration macros are reduced to host C signatures;
only __hrudelay is simulated. No kernel build or hardware delay is performed.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cc', required=True)
    parser.add_argument('--nm', default='nm')
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    kernel = Path(__file__).resolve().parents[2]
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    paths = ('kernel/sys_ni.c', 'kernel/sched/core.c', 'include/linux/linkage.h',
             'include/linux/export.h', 'include/uapi/asm-generic/errno.h',
             'include/uapi/asm-generic/unistd.h', 'arch/arm64/include/asm/unistd32.h',
             'arch/arm64/include/asm/linkage.h')
    src = {p: (kernel / p).read_text() for p in paths}
    linkage = src['include/linux/linkage.h']
    macro = linkage[linkage.index('#ifndef cond_syscall'):linkage.index('#ifndef SYSCALL_ALIAS')]
    export = src['include/linux/export.h']
    symbols = export[export.index('#ifdef CONFIG_HAVE_UNDERSCORE_SYMBOL_PREFIX'):
                     export.index('#ifndef __ASSEMBLY__')]
    assert 'cond_syscall' not in src['arch/arm64/include/asm/linkage.h']
    core = src['kernel/sched/core.c']
    start = core.rfind('#ifdef CONFIG_ARCH_HISI', 0, core.index('SYSCALL_DEFINE1(delay,'))
    end = core.index('#ifdef __ARCH_WANT_SYS_NICE', start)
    assert start >= 0
    strong = core[start:end]
    shim = output / 'include'
    for directory in ('linux', 'asm'):
        (shim / directory).mkdir(parents=True)
    (shim / 'linux/linkage.h').write_text('#define asmlinkage\n' + symbols + macro)
    enosys = re.search(r'^#define\s+ENOSYS\s+.*$', src['include/uapi/asm-generic/errno.h'], re.M).group()
    (shim / 'linux/errno.h').write_text(enosys + '\n')
    # sys_ni.c needs no ARM64 unistd definitions for these generic aliases.
    (shim / 'asm/unistd.h').write_text('/* Host shim: no arch-specific aliases. */\n')
    native = re.search(r'^#define __NR_delay .*\n__SC_COMP\(__NR_delay,.*$',
                       src['include/uapi/asm-generic/unistd.h'], re.M).group()
    compat = re.search(r'^#define __NR_delay .*\n__SYSCALL\(__NR_delay,.*$',
                       src['arch/arm64/include/asm/unistd32.h'], re.M).group()
    provider = output / 'provider.c'
    provider.write_text('''unsigned long observed_us;
unsigned int delay_calls;
static void __attribute__((unused)) __hrudelay(unsigned long us)
{ observed_us = us; ++delay_calls; }
#define SYSCALL_DEFINE1(name, type, arg) long sys_##name(type arg)
#define COMPAT_SYSCALL_DEFINE1(name, type, arg) long compat_sys_##name(type arg)
''' + strong)
    caller = output / 'caller.c'
    caller.write_text('''#include <assert.h>
#include <errno.h>
extern unsigned long observed_us;
extern unsigned int delay_calls;
extern long sys_delay(unsigned long);
extern long compat_sys_delay(unsigned long);
typedef long (*syscall_fn)(unsigned long);
#define __SC_COMP(nr, native, compat) [nr] = native,
static syscall_fn native_table[] = {
''' + native + '''
};
#undef __NR_delay
#define __SYSCALL(nr, fn) [nr] = fn,
static syscall_fn compat_table[] = {
''' + compat + '''
};
int main(void)
{
    assert(native_table[295](1234567UL) == (EXPECT_NATIVE ? 0 : -ENOSYS));
    assert(delay_calls == EXPECT_NATIVE);
    assert(observed_us == (EXPECT_NATIVE ? 1234UL : 0UL));
    observed_us = 0;
    assert(compat_table[400](9876543UL) == (EXPECT_COMPAT ? 0 : -ENOSYS));
    assert(delay_calls == EXPECT_NATIVE + EXPECT_COMPAT);
    assert(observed_us == (EXPECT_COMPAT ? 9876UL : 0UL));
    return 0;
}
''')
    results = []
    for arch, compat_enabled in ((False, False), (False, True), (True, False), (True, True)):
        case = output / ('hisi%d-compat%d' % (arch, compat_enabled))
        case.mkdir()
        commands = []

        def run(command):
            proc = subprocess.run([str(x) for x in command], capture_output=True,
                                  text=True, timeout=30)
            commands.append({'command': [str(x) for x in command], 'exit': proc.returncode,
                             'stdout': proc.stdout, 'stderr': proc.stderr})
            return proc

        flags = [args.cc, '-std=gnu11', '-O0', '-Wall', '-Wextra', '-Werror', '-I', shim]
        if arch:
            flags += ['-DCONFIG_ARCH_HISI=1']
        if compat_enabled:
            flags += ['-DCONFIG_COMPAT=1']
        flags += ['-DEXPECT_NATIVE=%d' % arch,
                  '-DEXPECT_COMPAT=%d' % (arch and compat_enabled)]
        for name, source in (('ni', kernel / 'kernel/sys_ni.c'),
                             ('provider', provider), ('caller', caller)):
            proc = run(flags + ['-c', source, '-o', case / (name + '.o')])
            if proc.returncode:
                raise RuntimeError(proc.stderr)
        for order in (('ni', 'provider'), ('provider', 'ni')):
            name = case.name + '-' + '-'.join(order)
            executable = case / ('-'.join(order))
            link = run([args.cc, case / 'caller.o'] +
                       [case / (x + '.o') for x in order] + ['-o', executable])
            passed = False
            if link.returncode == 0:
                execute = run([executable])
                nm = run([args.nm, executable])
                bindings = {parts[2]: parts[1] for line in nm.stdout.splitlines()
                            if len(parts := line.split()) == 3}
                passed = (execute.returncode == 0 and nm.returncode == 0 and
                          bindings.get('sys_delay') == ('T' if arch else 'W') and
                          bindings.get('compat_sys_delay') ==
                          ('T' if arch and compat_enabled else 'W'))
            results.append({'case': name, 'passed': passed, 'link_exit': link.returncode})
            print(name, 'PASS' if passed else 'FAIL', flush=True)
        (case / 'commands.json').write_text(json.dumps(commands, indent=2) + '\n')
    receipt = {'inputs': {p: hashlib.sha256((kernel / p).read_bytes()).hexdigest() for p in paths},
               'compiler': subprocess.check_output([args.cc, '--version'], text=True),
               'results': results,
               'limits': 'Host ELF linking/runtime, production alias macro and sys_ni.c, extracted guarded delay bodies/table rows. Syscall declaration shims and simulated __hrudelay; no ARM64 ABI or full kernel validation.'}
    (output / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    return int(not all(result['passed'] for result in results))


if __name__ == '__main__':
    raise SystemExit(main())

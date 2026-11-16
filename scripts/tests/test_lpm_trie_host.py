#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Compile and run extracted-production ASan/UBSan tests for kernel/bpf/lpm_trie.c."""
import argparse
import hashlib
import json
import subprocess
from pathlib import Path

CASES = [
    'empty_get_next_key',
    'lookup_prefixlen_bounds',
    'update_flags_noexist',
    'update_flags_exist',
    'delete_prefixlen_bounds',
    'delete_empty',
    'delete_equal_prefixlen_mismatch',
    'delete_two_children_marks_im',
    'delete_collapse_im_parent',
    'delete_single_child_and_leaf',
    'get_next_key_postorder',
    'get_next_key_full_depth_stack',
    'get_next_key_nonexistent_same_prefixlen',
    'get_next_key_alloc_failure',
    'clear_loop_simulation',
    'rcu_deferred_reclaim',
    'update_alloc_failures',
]

MUTATIONS = {
    'stack-size': (
        'kmalloc_array(trie->max_prefixlen + 1,',
        'kmalloc_array(trie->max_prefixlen,',
    ),
    'delete-mismatch': (
        'node->prefixlen != matchlen ||\n\t    (node->flags & LPM_TREE_NODE_FLAG_IM)',
        '(node->flags & LPM_TREE_NODE_FLAG_IM)',
    ),
    'next-key-exact': (
        'if (!node || node->prefixlen != matchlen ||',
        'if (!node || node->prefixlen != key->prefixlen ||',
    ),
    'noexist-check': (
        'if (flags == BPF_NOEXIST) {',
        'if (0 && flags == BPF_NOEXIST) {',
    ),
    'exist-check': (
        'if (flags == BPF_EXIST) {\n\t\t\tret = -ENOENT;\n\t\t\tgoto out;\n\t\t}',
        'if (0 && flags == BPF_EXIST) {\n\t\t\tret = -ENOENT;\n\t\t\tgoto out;\n\t\t}',
    ),
    'im-parent-collapse': (
        'if (parent && (parent->flags & LPM_TREE_NODE_FLAG_IM) &&',
        'if (0 && parent && (parent->flags & LPM_TREE_NODE_FLAG_IM) &&',
    ),
    'lookup-prefixlen': (
        'if (key->prefixlen > trie->max_prefixlen)\n\t\treturn NULL;',
        'if (0 && key->prefixlen > trie->max_prefixlen)\n\t\treturn NULL;',
    ),
}


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cc', default='/usr/bin/clang')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--mutation', choices=sorted(MUTATIONS))
    parser.add_argument('--subject', type=Path)
    parser.add_argument('--allow-baseline-stubs', action='store_true')
    args = parser.parse_args()

    kroot = Path(__file__).resolve().parents[2]
    lpm_src = args.subject.resolve() if args.subject else (kroot / 'kernel/bpf/lpm_trie.c')
    host_c = kroot / 'scripts/tests/lpm_trie_host.c'
    uapi_h = kroot / 'include/uapi/linux/bpf.h'

    args.output.mkdir(parents=True, exist_ok=False)
    shim = args.output / 'shim'
    for sub in ('linux/bpf.h', 'linux/err.h', 'linux/slab.h',
                'linux/spinlock.h', 'linux/vmalloc.h', 'net/ipv6.h'):
        p = shim / sub
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text('/* host test shim */\n')

    subject_path = lpm_src
    if args.mutation:
        old, new = MUTATIONS[args.mutation]
        src_text = lpm_src.read_text()
        assert old in src_text, f'mutation target missing: {args.mutation}'
        subject_path = args.output / 'mutated_lpm_trie.c'
        subject_path.write_text(src_text.replace(old, new, 1))

    cmd = [
        args.cc,
        '-std=gnu11',
        '-O2',
        '-g',
        '-fsanitize=address,undefined',
        '-fno-omit-frame-pointer',
        '-fno-sanitize-recover=all',
        '-Wall',
        '-Wextra',
        '-Werror',
    ]
    if args.allow_baseline_stubs:
        cmd.extend(['-Wno-unused-parameter', '-Wno-unused-function'])
    cmd.extend([
        '-I' + str(shim),
        f'-DBPF_UAPI_HEADER="{uapi_h}"',
        f'-DLPM_TRIE_SUBJECT="{subject_path}"',
        str(host_c),
        '-o',
        str(args.output / 'test'),
    ])

    comp = subprocess.run(cmd, capture_output=True, text=True)
    receipt = {
        'mutation': args.mutation,
        'source_commit': subprocess.check_output(
            ['git', '-C', str(kroot), 'rev-parse', 'HEAD'], text=True
        ).strip(),
        'source_dirty': bool(
            subprocess.check_output(
                ['git', '-C', str(kroot), 'status', '--porcelain'], text=True
            ).strip()
        ),
        'input_hashes': {
            'kernel/bpf/lpm_trie.c': sha256(lpm_src),
            'include/uapi/linux/bpf.h': sha256(uapi_h),
            'scripts/tests/lpm_trie_host.c': sha256(host_c),
            'scripts/tests/test_lpm_trie_host.py': sha256(Path(__file__)),
        },
        'subject_sha256': sha256(subject_path),
        'command': cmd,
        'compile_exit': comp.returncode,
        'compile_output': comp.stdout + comp.stderr,
        'cases': {},
        'failed_cases': [],
    }
    if comp.stdout or comp.stderr:
        print(comp.stdout + comp.stderr, end='')

    if comp.returncode == 0:
        for case in CASES:
            res = subprocess.run(
                [str(args.output / 'test'), case],
                capture_output=True,
                text=True,
                timeout=30,
            )
            receipt['cases'][case] = {
                'exit': res.returncode,
                'output': res.stdout + res.stderr,
            }
            if res.returncode != 0:
                receipt['failed_cases'].append(case)
            print(f'{case}: exit={res.returncode}')

    receipt['passed_count'] = sum(1 for v in receipt['cases'].values() if v['exit'] == 0)
    receipt['failed_count'] = len(receipt['failed_cases'])
    receipt['success'] = comp.returncode == 0 and receipt['failed_count'] == 0
    (args.output / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    return 0 if receipt['success'] else 1


if __name__ == '__main__':
    raise SystemExit(main())

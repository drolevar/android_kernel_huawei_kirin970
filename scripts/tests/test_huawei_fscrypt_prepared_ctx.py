#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Extract and exercise the fscrypt prepared-context production lifecycle."""

import argparse
import hashlib
import json
import os
import re
import subprocess
from pathlib import Path


CASES = (
    "policy-owned-order",
    "legacy-set-context-fallback",
    "inherit-borrowed-private-preload",
    "ext4-owned-root-inline-stop-retry-credit",
    "ext4-borrowed-handle-flags-preload",
    "ext4-deferred-iput-array",
    "ext4-deferred-iput-direct",
    "f2fs-four-task-order",
    "f2fs-inline-regular-one-scope",
    "f2fs-dummy-unencrypted-dir",
    "f2fs-tmpfile-order",
    "hmfs-four-task-order",
    "hmfs-inline-regular-one-scope",
    "hmfs-dummy-unencrypted-dir",
    "hmfs-tmpfile-order",
)

MUTATIONS = {
    "policy-missing-nonce-wipe": (
        ("fs/crypto/policy.c", "create_encryption_context_from_policy"),
        "memzero_explicit(nonce, sizeof(nonce));",
        "memset(nonce, 0, sizeof(nonce));", 1),
    "policy-no-retry": (
        ("fs/crypto/policy.c", "create_encryption_context_from_policy"),
        "} while (retry);", "} while (false);", 1),
    "policy-skip-legacy-fallback": (
        ("fs/crypto/policy.c", "create_encryption_context_from_policy"),
        "!cops->finish_context)", "false)", 1),
    "inherit-second-parent-load": (
        ("fs/crypto/policy.c", "fscrypt_inherit_context_prepared"),
        "if (!scope) {", "if (true) {", 1),
    "inherit-public-preload": (
        ("fs/crypto/policy.c", "fscrypt_inherit_context_prepared"),
        "fscrypt_get_encryption_info_with_scope(\n"
        "\t\t\t\t\t\tchild, &ctx, scope)",
        "(false ? fscrypt_get_encryption_info_with_scope(child, &ctx, scope) : "
        "fscrypt_get_encryption_info(child))", 2),
    "ext4-skip-inline-conversion": (
        ("fs/ext4/super.c", "ext4_prepare_context"),
        "res = ext4_convert_inline_data(inode);",
        "res = false ? ext4_convert_inline_data(inode) : 0;", 1),
    "ext4-stop-overwrites-error": (
        ("fs/ext4/super.c", "ext4_finish_context"),
        "if (!res)\n\t\t\tres = res2;", "res = res2;", 1),
    "ext4-disable-enospc-retry": (
        ("fs/ext4/super.c", "ext4_finish_context"),
        "res == -ENOSPC &&", "false &&", 1),
    "ext4-stop-borrowed-handle": (
        ("fs/ext4/super.c", "ext4_finish_context"),
        "if (op->origin == FSCRYPT_CTX_OWNED_POLICY) {", "if (true) {", 1),
    "ext4-immediate-deferred-iput": (
        ("fs/ext4/xattr.c", "ext4_xattr_defer_iput"),
        "if (!deferred) {", "if (true) {", 1),
    "ext4-disable-iput-overflow-guard": (
        ("fs/ext4/xattr.c", "ext4_xattr_defer_iput"),
        "if (WARN_ON_ONCE(deferred->count >=\n"
        "\t\t\t EXT4_XATTR_MAX_DEFERRED_IPUTS))",
        "if (false && WARN_ON_ONCE(deferred->count >=\n"
        "\t\t\t EXT4_XATTR_MAX_DEFERRED_IPUTS))", 1),
    "f2fs-owned-without-cp-lock": (
        ("fs/f2fs/super.c", "f2fs_prepare_context"),
        "f2fs_lock_op(sbi);", "if (false) f2fs_lock_op(sbi);", 1),
    "f2fs-reopen-fallback-scope": (
        ("fs/f2fs/dir.c", "f2fs_add_dentry"),
        "\t\t\t\tscope);", "\t\t\t\tNULL);", 2),
    "f2fs-skip-parent-info": (
        ("fs/f2fs/dir.c", "f2fs_add_dentry"),
        "err = fscrypt_get_encryption_info(dir);", "err = 0;", 1),
    "hmfs-borrowed-takes-cp-lock": (
        ("fs/hmfs/super.c", "hmfs_prepare_context"),
        "if (origin == FSCRYPT_CTX_OWNED_POLICY) {", "if (true) {", 1),
    "hmfs-reopen-fallback-scope": (
        ("fs/hmfs/dir.c", "hmfs_add_dentry"),
        "\t\t\t\tscope);", "\t\t\t\tNULL);", 2),
    "hmfs-skip-parent-info": (
        ("fs/hmfs/dir.c", "hmfs_add_dentry"),
        "err = fscrypt_get_encryption_info(dir);", "err = 0;", 1),
}

REQUIRED = (
    ("fs/crypto/policy.c", "create_encryption_context_from_policy"),
    ("fs/crypto/policy.c", "fscrypt_inherit_context_prepared"),
    ("fs/ext4/super.c", "ext4_prepare_context"),
    ("fs/ext4/super.c", "ext4_context_op"),
    ("fs/ext4/super.c", "ext4_set_context_prepared"),
    ("fs/ext4/super.c", "ext4_finish_context"),
    ("fs/ext4/ialloc.c", "ext4_inherit_context"),
    ("fs/ext4/xattr.c", "ext4_xattr_set_handle_prepared"),
    ("fs/ext4/xattr.c", "ext4_xattr_ensure_credits"),
    ("fs/ext4/xattr.c", "ext4_xattr_inode_dec_ref_all"),
    ("fs/ext4/xattr.c", "ext4_xattr_set_entry"),
    ("fs/ext4/xattr.c", "ext4_xattr_block_set"),
    ("fs/ext4/xattr.c", "ext4_xattr_defer_iput"),
    ("fs/ext4/xattr.c", "ext4_xattr_drain_deferred_iputs"),
    ("fs/f2fs/super.c", "f2fs_prepare_context"),
    ("fs/f2fs/super.c", "f2fs_set_context_prepared"),
    ("fs/f2fs/super.c", "f2fs_finish_context"),
    ("fs/f2fs/dir.c", "f2fs_add_dentry"),
    ("fs/f2fs/dir.c", "f2fs_do_tmpfile"),
    ("fs/f2fs/inline.c", "f2fs_add_inline_entry"),
    ("fs/f2fs/namei.c", "__f2fs_tmpfile"),
    ("fs/hmfs/super.c", "hmfs_prepare_context"),
    ("fs/hmfs/super.c", "hmfs_set_context_prepared"),
    ("fs/hmfs/super.c", "hmfs_finish_context"),
    ("fs/hmfs/dir.c", "hmfs_add_dentry"),
    ("fs/hmfs/dir.c", "hmfs_do_tmpfile"),
    ("fs/hmfs/inline.c", "hmfs_add_inline_entry"),
    ("fs/hmfs/namei.c", "__f2fs_tmpfile"),
)


def find_function(text, name):
    needle = name + "("
    search = 0
    while True:
        pos = text.find(needle, search)
        if pos < 0:
            raise ValueError("missing function " + name)
        start = text.rfind("\n", 0, pos) + 1
        prefix = text[start:pos].lstrip()
        brace = text.find("{", pos)
        semicolon = text.find(";", pos)
        if (prefix.startswith(("*", "/*", "//")) or brace < 0 or
                (semicolon >= 0 and semicolon < brace)):
            search = pos + len(needle)
            continue
        previous_start = text.rfind("\n", 0, max(0, start - 1)) + 1
        previous = text[previous_start:start].strip()
        if not prefix and re.fullmatch(
                r"(?:static\s+)?(?:inline\s+)?[A-Za-z_][\w\s*]*",
                previous):
            start = previous_start
        break
    depth = 0
    for end in range(brace, len(text)):
        if text[end] == "{":
            depth += 1
        elif text[end] == "}":
            depth -= 1
            if depth == 0:
                return start, end + 1, text[start : end + 1]
    raise ValueError("unterminated body for " + name)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cc", required=True)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--source-root", type=Path)
    parser.add_argument("--mutation", choices=tuple(MUTATIONS))
    args = parser.parse_args()

    test_root = Path(__file__).resolve().parents[2]
    root = args.source_root.resolve() if args.source_root else test_root
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    compiler = subprocess.check_output([args.cc, "--version"], text=True)
    if "clang version 22." not in compiler:
        raise SystemExit("host compiler is not Clang 22")

    command = [
        args.cc,
        "-std=gnu11",
        "-O1",
        "-g",
        "-Wall",
        "-Wextra",
        "-Werror",
        "-Wno-unused-function",
        "-Wno-unused-variable",
        "-fsanitize=address,undefined",
        "-fno-sanitize-recover=all",
        "-pthread",
        str(test_root / "scripts/tests/huawei_fscrypt_prepared_ctx.c"),
        "-o",
        str(output / "test"),
    ]
    run_env = os.environ.copy()
    run_env["ASAN_OPTIONS"] = "detect_leaks=0"
    compiled = subprocess.run(command, text=True, capture_output=True,
                              timeout=60)
    (output / "compile.log").write_text(compiled.stdout + compiled.stderr)

    regions = []
    missing = []
    bodies = {}
    for relative, name in REQUIRED:
        path = root / relative
        text = path.read_text()
        try:
            first, last, body = find_function(text, name)
        except ValueError as error:
            missing.append({"path": relative, "symbol": name,
                            "error": str(error)})
            continue
        regions.append({
            "path": relative,
            "symbol": name,
            "first_line": text.count("\n", 0, first) + 1,
            "last_line": text.count("\n", 0, last) + 1,
            "file_sha256": hashlib.sha256(text.encode()).hexdigest(),
            "extracted_sha256": hashlib.sha256(body.encode()).hexdigest(),
        })
        bodies[(relative, name)] = body

    mutation_applied = None
    if args.mutation:
        symbol, old, new, expected = MUTATIONS[args.mutation]
        if symbol not in bodies:
            raise SystemExit("mutation subject is missing: " + str(symbol))
        actual = bodies[symbol].count(old)
        if actual != expected:
            raise SystemExit(
                "%s target count: expected %d, got %d" %
                (args.mutation, expected, actual)
            )
        bodies[symbol] = bodies[symbol].replace(old, new)
        mutation_applied = {
            "symbol": symbol,
            "target_count": actual,
            "replacement_sha256": hashlib.sha256(
                bodies[symbol].encode()
            ).hexdigest(),
        }

    source_checks = []

    def require_order(label, subject, needles):
        positions = [subject.find(needle) for needle in needles]
        passed = all(position >= 0 for position in positions) and all(
            left < right for left, right in zip(positions, positions[1:])
        )
        source_checks.append({"check": label, "passed": passed,
                              "positions": positions})

    for label, namei_path, dir_path, inline_path, prefix in (
        ("f2fs", "fs/f2fs/namei.c", "fs/f2fs/dir.c",
         "fs/f2fs/inline.c", "f2fs"),
        ("hmfs", "fs/hmfs/namei.c", "fs/hmfs/dir.c",
         "fs/hmfs/inline.c", "hmfs"),
    ):
        tmpfile = bodies.get((namei_path, "__f2fs_tmpfile"), "")
        do_tmpfile = bodies.get((dir_path, prefix + "_do_tmpfile"), "")
        inline = bodies.get((inline_path, prefix + "_add_inline_entry"), "")
        require_order(
            label + "-tmpfile-scope-before-child-lock",
            tmpfile,
            ("f2fs_lock_op(sbi);", "fscrypt_ce_scope_open_cached",
             prefix + "_do_tmpfile(inode, dentry, dir, scope)"),
        )
        require_order(
            label + "-tmpfile-scope-threaded",
            do_tmpfile,
            ("down_write(&F2FS_I(inode)->i_sem);",
             prefix + "_init_inode_metadata", "scope);"),
        )
        require_order(
            label + "-inline-page-before-child-lock",
            inline,
            (prefix + "_get_node_page", "down_write(&F2FS_I(inode)->i_sem);",
             prefix + "_init_inode_metadata"),
        )
        puts = tmpfile.count("fscrypt_ce_scope_put(scope);")
        source_checks.append({
            "check": label + "-tmpfile-balanced-scope-put",
            "passed": puts == 2,
            "count": puts,
        })

    set_entry = bodies.get(("fs/ext4/xattr.c", "ext4_xattr_set_entry"), "")
    block_set = bodies.get(("fs/ext4/xattr.c", "ext4_xattr_block_set"), "")
    dec_all = bodies.get(
        ("fs/ext4/xattr.c", "ext4_xattr_inode_dec_ref_all"), ""
    )
    source_checks.extend((
        {
            "check": "ext4-absolute-zero-name-capacity-bound",
            "passed": "EXT4_XATTR_LEN(0)" in
                      (root / "fs/ext4/xattr.h").read_text(),
        },
        {
            "check": "ext4-direct-iputs-deferred",
            "passed": "ext4_xattr_defer_iput(deferred, old_ea_inode);" in set_entry
                      and "ext4_xattr_defer_iput(deferred, new_ea_inode);" in set_entry
                      and not re.search(r"(?<!defer_)\biput\(", set_entry),
        },
        {
            "check": "ext4-block-replacement-iputs-deferred",
            "passed": "ext4_xattr_defer_iput(deferred, tmp_inode);" in block_set
                      and "ext4_xattr_defer_iput(deferred, ea_inode);" in block_set
                      and not re.search(r"(?<!defer_)\biput\(", block_set),
        },
        {
            "check": "ext4-ea-array-bypassed-for-prepared",
            "passed": "if (deferred)" in dec_all
                      and "ext4_xattr_defer_iput(deferred, ea_inode);" in dec_all
                      and "ext4_expand_inode_array" in dec_all,
        },
    ))

    policy_compile_exit = None
    policy_results = []
    policy_symbols = (
        ("fs/crypto/policy.c", "create_encryption_context_from_policy"),
        ("fs/crypto/policy.c", "fscrypt_inherit_context_prepared"),
    )
    if all(symbol in bodies for symbol in policy_symbols):
        (output / "subject_policy.h").write_text(
            "\n\n".join(bodies[symbol] for symbol in policy_symbols) + "\n"
        )
        policy_command = command[:-3] + [
            "-I" + str(output),
            str(test_root / "scripts/tests/huawei_fscrypt_prepared_policy.c"),
            "-o",
            str(output / "test-policy"),
        ]
        policy_compiled = subprocess.run(policy_command, text=True,
                                         capture_output=True, timeout=60)
        policy_compile_exit = policy_compiled.returncode
        (output / "compile-policy.log").write_text(
            policy_compiled.stdout + policy_compiled.stderr
        )
        if policy_compiled.returncode == 0:
            for case in CASES[:3]:
                run = subprocess.run([str(output / "test-policy"), case],
                                     text=True, capture_output=True, timeout=10,
                                     env=run_env)
                (output / (case + "-policy.log")).write_text(
                    run.stdout + run.stderr
                )
                policy_results.append({"case": case, "exit": run.returncode,
                                       "passed": run.returncode == 0})

    ext4_compile_exit = None
    ext4_results = []
    ext4_symbols = (
        ("fs/ext4/super.c", "ext4_prepare_context"),
        ("fs/ext4/super.c", "ext4_set_context_prepared"),
        ("fs/ext4/super.c", "ext4_finish_context"),
        ("fs/ext4/ialloc.c", "ext4_inherit_context"),
        ("fs/ext4/xattr.c", "ext4_xattr_ensure_credits"),
        ("fs/ext4/xattr.c", "ext4_xattr_defer_iput"),
        ("fs/ext4/xattr.c", "ext4_xattr_drain_deferred_iputs"),
    )
    if all(symbol in bodies for symbol in ext4_symbols):
        (output / "subject_ext4.h").write_text(
            "\n\n".join(bodies[symbol] for symbol in ext4_symbols) + "\n"
        )
        ext4_command = command[:-3] + [
            "-I" + str(output),
            str(test_root / "scripts/tests/huawei_fscrypt_prepared_ext4.c"),
            "-o",
            str(output / "test-ext4"),
        ]
        ext4_compiled = subprocess.run(ext4_command, text=True,
                                       capture_output=True, timeout=60)
        ext4_compile_exit = ext4_compiled.returncode
        (output / "compile-ext4.log").write_text(
            ext4_compiled.stdout + ext4_compiled.stderr
        )
        if ext4_compiled.returncode == 0:
            for case in CASES[3:7]:
                run = subprocess.run([str(output / "test-ext4"), case],
                                     text=True, capture_output=True, timeout=10,
                                     env=run_env)
                (output / (case + "-ext4.log")).write_text(
                    run.stdout + run.stderr
                )
                ext4_results.append({"case": case, "exit": run.returncode,
                                     "passed": run.returncode == 0})

    fs_compile_exits = {}
    fs_results = []
    fs_specs = (
        ("f2fs", "fs/f2fs/super.c", "fs/f2fs/dir.c",
         "fs/f2fs/namei.c", "f2fs", CASES[7:11]),
        ("hmfs", "fs/hmfs/super.c", "fs/hmfs/dir.c",
         "fs/hmfs/namei.c", "hmfs", CASES[11:15]),
    )
    for (label, super_path, dir_path, namei_path, prefix,
         selected_cases) in fs_specs:
        symbols = (
            (super_path, prefix + "_prepare_context"),
            (super_path, prefix + "_set_context_prepared"),
            (super_path, prefix + "_finish_context"),
            (dir_path, prefix + "_add_dentry"),
            (namei_path, "__f2fs_tmpfile"),
        )
        if not all(symbol in bodies for symbol in symbols):
            continue
        (output / ("subject_" + label + ".h")).write_text(
            "\n\n".join(bodies[symbol] for symbol in symbols) + "\n"
        )
        fs_command = command[:-3] + [
            "-I" + str(output),
            "-DTEST_" + label.upper(),
            str(test_root / "scripts/tests/huawei_fscrypt_prepared_f2fs.c"),
            "-o",
            str(output / ("test-" + label)),
        ]
        fs_compiled = subprocess.run(fs_command, text=True,
                                     capture_output=True, timeout=60)
        fs_compile_exits[label] = fs_compiled.returncode
        (output / ("compile-" + label + ".log")).write_text(
            fs_compiled.stdout + fs_compiled.stderr
        )
        if fs_compiled.returncode == 0:
            for case in selected_cases:
                run = subprocess.run([str(output / ("test-" + label)), case],
                                     text=True, capture_output=True, timeout=10,
                                     env=run_env)
                (output / (case + "-" + label + ".log")).write_text(
                    run.stdout + run.stderr
                )
                fs_results.append({"filesystem": label, "case": case,
                                   "exit": run.returncode,
                                   "passed": run.returncode == 0})

    results = []
    if compiled.returncode == 0:
        for case in CASES:
            run = subprocess.run([str(output / "test"), case], text=True,
                                 capture_output=True, timeout=10, env=run_env)
            (output / (case + ".log")).write_text(run.stdout + run.stderr)
            results.append({"case": case, "exit": run.returncode,
                            "passed": run.returncode == 0 and not missing})

    receipt = {
        "commit": subprocess.check_output(
            ["git", "-C", str(test_root), "rev-parse", "HEAD"], text=True
        ).strip(),
        "source_root": str(root),
        "mutation": args.mutation,
        "mutation_applied": mutation_applied,
        "compiler": compiler,
        "command": command,
        "compile_exit": compiled.returncode,
        "policy_compile_exit": policy_compile_exit,
        "ext4_compile_exit": ext4_compile_exit,
        "filesystem_compile_exits": fs_compile_exits,
        "missing": missing,
        "source_checks": source_checks,
        "regions": regions,
        "results": results,
        "policy_results": policy_results,
        "ext4_results": ext4_results,
        "filesystem_results": fs_results,
        "test_hashes": {
            "runner": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            "harness": hashlib.sha256(
                (test_root / "scripts/tests/huawei_fscrypt_prepared_ctx.c").read_bytes()
            ).hexdigest(),
        },
        "limits": "Extracted production functions run with modeled kernel "
                  "services under ASan/UBSan; this is not a kernel mount or "
                  "full Kbuild test.",
    }
    (output / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")

    if compiled.returncode:
        raise SystemExit(compiled.returncode)
    if missing:
        for item in missing:
            print("RED", item["path"], item["symbol"], item["error"])
        raise SystemExit(1)
    if not all(item["passed"] for item in source_checks):
        for item in source_checks:
            if not item["passed"]:
                print("source check failed", item["check"])
        raise SystemExit(1)
    if policy_compile_exit or not all(item["passed"] for item in policy_results):
        raise SystemExit(1)
    if ext4_compile_exit or not all(item["passed"] for item in ext4_results):
        raise SystemExit(1)
    if any(fs_compile_exits.values()) or not all(
            item["passed"] for item in fs_results):
        raise SystemExit(1)
    if not all(item["passed"] for item in results):
        raise SystemExit(1)


if __name__ == "__main__":
    main()

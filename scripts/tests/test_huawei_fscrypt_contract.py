#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Synthetic contract model + unchanged extracted Huawei error-path probes.

No kernel configuration, keys, mounts, keyctl, ioctls or devices are used.
Requires host Clang22, ASan/UBSan and OpenSSL development headers/library.
"""
import argparse
import hashlib
import json
import platform
from pathlib import Path
import re
import subprocess


def extract(pattern, text):
    match = re.search(pattern, text, re.M | re.S)
    if not match:
        raise ValueError("source extraction failed: " + pattern)
    return match.group(0)


def function(text, name):
    return extract(r"^(?:static )?(?:struct key \*\n?|int\s+|void\s+)"
                   + re.escape(name) + r"\(.*?^\}", text)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cc", required=True)
    parser.add_argument("--keep-output", type=Path, required=True)
    parser.add_argument("--suite", choices=("all", "model", "actual"), default="all")
    parser.add_argument("--mutation", choices=("fallback", "publication", "sdp-release",
                                             "cached", "metadata", "payload-write"))
    args = parser.parse_args()
    kernel = Path(__file__).resolve().parents[2]
    here = kernel / "scripts/tests"
    out = args.keep_output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    inputs = {p: (kernel / p).read_text() for p in (
        "fs/crypto/policy.c", "fs/crypto/keyinfo.c", "fs/f2fs/keyinfo.c",
        "fs/crypto/fscrypt_private.h", "include/linux/fscrypt_common.h",
        "include/uapi/linux/fs.h", "fs/f2fs/sdp_internal.h", "crypto/gcm.c")}
    # Copy declarations and numeric constants; do not silently repair function text.
    decls = []
    for path, names in {
        "include/linux/fscrypt_common.h": ["FS_KEY_DERIVATION_NONCE_SIZE",
            "FS_KEY_DERIVATION_IV_SIZE", "FS_KEY_DERIVATION_TAG_SIZE",
            "FS_KEY_DERIVATION_CIPHER_SIZE"],
        "fs/crypto/fscrypt_private.h": ["FS_AES_256_GCM_KEY_SIZE",
            "FS_ENCRYPTION_CONTEXT_FORMAT_V2"],
        "include/uapi/linux/fs.h": ["FS_KEY_DESCRIPTOR_SIZE", "FS_MAX_KEY_SIZE",
            "FS_KEY_DESC_PREFIX", "FS_KEY_DESC_PREFIX_SIZE", "FS_POLICY_FLAGS_VALID",
            "FS_ENCRYPTION_MODE_AES_256_XTS", "FS_ENCRYPTION_MODE_AES_256_CTS",
            "FS_ENCRYPTION_MODE_AES_128_CBC", "FS_ENCRYPTION_MODE_AES_128_CTS"],
        "fs/f2fs/sdp_internal.h": ["FSCRYPT_SDP_ECE_CLASS", "FSCRYPT_SDP_SECE_CLASS",
            "FS_SDP_ECC_PRIV_KEY_SIZE", "FS_SDP_ECC_PUB_KEY_SIZE"],
    }.items():
        for name in names:
            decls.append(extract(r"^#define " + name + r"\b[^\n]*", inputs[path]))
    for path, names in {
        "include/linux/fscrypt_common.h": ["fscrypt_context"],
        "include/uapi/linux/fs.h": ["fscrypt_key", "fscrypt_policy"],
        "fs/f2fs/sdp_internal.h": ["fscrypt_sdp_key"],
    }.items():
        for name in names:
            decls.append(extract(r"^struct " + name + r" \{.*?^\}[^;]*;", inputs[path]))
    # This boundary is tied to this source's algorithm, not the misleading IV comment.
    assert "inst->alg.ivsize = 12;" in inputs["crypto/gcm.c"]
    (out / "declarations.h").write_text("\n\n".join(decls) + "\n")
    crypto = inputs["fs/crypto/keyinfo.c"]
    (out / "crypto-subject.h").write_text("\n\n".join(function(crypto, name) for name in
        ("derive_crypt_complete", "fscrypt_set_gcm_key", "fscrypt_derive_gcm_key")) + "\n")
    actual = [function(inputs["fs/crypto/policy.c"], "create_encryption_context_from_policy")]
    actual += [function(crypto, name) for name in
               ("find_and_lock_process_key", "find_and_derive_key")]
    actual += [function(inputs["fs/f2fs/keyinfo.c"], name) for name in
               ("f2fs_do_get_keyring_payload", "f2fs_do_get_fek")]
    (out / "actual-subject.h").write_text("\n\n".join(actual) + "\n")
    model = (here / "huawei_fscrypt_model.h").read_text()
    mutations = {
        "fallback": ("if (key->present || key->managed)", "if (key->present)"),
        "publication": ("if (!t->key->present || t->generation != t->key->generation)",
                        "if (false)"),
        "sdp-release": ("if (!err && fail_step == 1)",
                        "inode_detach(inode); if (!err && fail_step == 1)"),
        "cached": ("if (inode->kind != CE && !authorized)", "if (false)"),
        "metadata": ("key->format == LEGACY_PAYLOAD && key->source == LOGON",
                     "true"),
        "payload-write": ("/* immutable input: never normalize the payload in place */",
                          "key->raw_size = 32;"),
    }
    if args.mutation:
        before, after = mutations[args.mutation]
        assert model.count(before) == 1, (args.mutation, model.count(before))
        model = model.replace(before, after)
    (out / "model-subject.h").write_text(model)
    compiler = subprocess.run([args.cc, "--version"], check=True, text=True,
                              capture_output=True).stdout
    if not re.search(r"clang version 22\.", compiler):
        raise ValueError("fixture requires selected Clang 22")
    commands = []
    results = []
    for suite in ("model", "actual") if args.suite == "all" else (args.suite,):
        binary = out / suite
        command = [args.cc, "-std=gnu11", "-O1", "-g", "-Wall", "-Wextra", "-Werror",
                   "-Wno-pointer-sign", "-Wno-unused-function", "-Wno-unused-parameter", "-Wno-sign-compare",
                   "-fsanitize=address,undefined", "-fno-sanitize-recover=all",
                   "-fno-omit-frame-pointer", "-I" + str(out), "-I" + str(here),
                   str(here / ("huawei_fscrypt_" + suite + ".c")), "-lcrypto", "-o", str(binary)]
        commands.append(command)
        subprocess.run(command, check=True, timeout=60)
        # Each case runs separately, so expected original-source null dereference
        # is a narrow sanitizer subprocess probe, never swallowed in a large run.
        cases = {
            "actual": ("gcm-vector", "payload-writes", "policy-null", "unwrap-revoked",
                       "double-unlock", "errors", "f2fs"),
            "model": ("formats", "immutable", "consumers", "errors", "fallback",
                      "remove", "publication", "sdp", "sdp-preflight", "owners", "cached"),
        }[suite]
        for case in cases:
            result = subprocess.run([str(binary), case], text=True, capture_output=True, timeout=10)
            log = result.stdout + result.stderr
            (out / (suite + "-" + case + ".log")).write_text(log)
            expected_fault = suite == "actual" and case == "policy-null"
            passed = (result.returncode != 0 and
                      "member access within null pointer" in log) if expected_fault else result.returncode == 0
            print(f"{suite}/{case}: {'PASS' if passed else 'FAIL'}" +
                  (" (original-source null payload reproduced)" if expected_fault and passed else ""), flush=True)
            if not passed:
                print(log, flush=True)
            results.append({"suite": suite, "case": case, "exit": result.returncode,
                            "passed": passed, "expected_original_fault": expected_fault})
    # Verify the consumer cannot write through the public const secret view.
    if args.suite != "actual":
        negative = out / "const-negative.c"
        negative.write_text('#include "huawei_fscrypt_host.h"\n#include "crypto-subject.h"\n'
                            '#include "model-subject.h"\nvoid bad(struct lease *t) '
                            '{ lease_view(t).bytes[0] = 1; }\n')
        result = subprocess.run([args.cc, "-std=gnu11", "-fsyntax-only", "-I" + str(out),
                                 "-I" + str(here), str(negative)], text=True, capture_output=True, timeout=10)
        (out / "const-negative.log").write_text(result.stderr)
        ok = result.returncode != 0 and "read-only" in result.stderr
        results.append({"case": "const-negative", "passed": ok})
        print("model/const-negative:", "PASS" if ok else "FAIL", flush=True)
    receipt = {"compiler": compiler, "host": platform.platform(),
               "execution": "host synthetic fixture; no build container or kernel execution",
               "source_commit": subprocess.check_output(["git", "-C", str(kernel), "rev-parse", "HEAD"], text=True).strip(),
               "fixture_sha256": {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                                  for p in here.glob("*huawei_fscrypt*") if p.is_file()},
               "commands": commands, "results": results, "mutation": args.mutation,
               "inputs_sha256": {p: hashlib.sha256(t.encode()).hexdigest() for p, t in inputs.items()},
               "artifacts_sha256": {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                                    for p in out.iterdir() if p.is_file()}}
    (out / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    return int(not all(r["passed"] for r in results))


if __name__ == "__main__":
    raise SystemExit(main())

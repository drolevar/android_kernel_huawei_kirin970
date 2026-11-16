#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Exercise extracted Stage 1A managed-admission production paths."""

import argparse
import hashlib
import json
import os
import re
import subprocess
from pathlib import Path


MUTATIONS = (
    "registry-present-absence", "registry-error-collapse", "sdp-fallback",
    "managed-fallback", "managed-enroll", "managed-release", "owner-transfer",
    "owner-drop", "legacy-size", "cached-generation", "cached-enroll",
    "managed-marker", "secret-wipe", "inline-negative",
    "hwdps-keyindex-key-validation", "f2fs-keyindex-key-validation",
    "hmfs-keyindex-key-validation", "f2fs-sdp-managed-guard",
    "hmfs-sdp-managed-guard", "f2fs-publish-sdp-flag",
    "hmfs-publish-sdp-flag", "inherit-preload",
    "publication-owner-drop",
    "f2fs-publish-dir-fastpath", "hmfs-publish-dir-fastpath",
    "f2fs-publish-hwdps-flag", "hmfs-publish-hwdps-flag",
    "f2fs-ece-cold-ce-guard", "f2fs-ece-cold-sdp-guard",
    "f2fs-sece-cold-ce-guard", "f2fs-sece-cold-sdp-guard",
    "hmfs-ece-cold-ce-guard", "hmfs-ece-cold-sdp-guard",
    "hmfs-sece-cold-ce-guard", "hmfs-sece-cold-sdp-guard",
    "f2fs-warm-descriptor-guard", "hmfs-warm-descriptor-guard",
    "f2fs-warm-key-validation", "hmfs-warm-key-validation",
    "f2fs-payload-descriptor-guard", "hmfs-payload-descriptor-guard",
    "hmfs-payload-key-validation", "f2fs-warm-managed-guard",
    "hmfs-warm-managed-guard", "f2fs-policy-ce-guard",
    "f2fs-policy-sdp-guard", "hmfs-policy-ce-guard",
    "hmfs-policy-sdp-guard",
    "hwdps-do-context-descriptor", "hwdps-update-managed",
    "hwdps-cached-managed", "hwdps-context-error-map",
    "hwdps-tombstone-preserve", "f2fs-dps-warm-managed",
    "hmfs-dps-warm-managed", "f2fs-dps-context-descriptor",
    "hmfs-dps-context-descriptor", "f2fs-dps-null-ci",
    "hmfs-dps-null-ci", "hwdps-inherit-managed",
    "hwdps-inherit-descriptor", "hwdps-logon-key-validation",
)
CASES = (
    "descriptor-admission", "managed-policy", "managed-file-owner",
    "publication-loser", "tombstone-legacy", "cached-retirement",
    "managed-inheritance", "inline-keyindex", "hwdps-keyindex", "sdp-keyindex",
    "sdp-guards-publication", "publish-dir-lock-order",
    "sdp-cold-and-warm-guards",
    "hwdps-admission-guards",
)


def extract(pattern, text):
    match = re.search(pattern, text, re.M | re.S)
    if not match:
        raise ValueError("source extraction failed: " + pattern)
    return match.group(0)


def function(text, name):
    pattern = re.compile(r"^(?:static\s+)?[^\n]*\b" + re.escape(name) +
                         r"\s*\(", re.M)
    match = None
    brace = None
    for candidate in pattern.finditer(text):
        paren = text.find("(", candidate.start())
        depth = 0
        close = None
        for pos in range(paren, len(text)):
            if text[pos] == "(":
                depth += 1
            elif text[pos] == ")":
                depth -= 1
                if depth == 0:
                    close = pos
                    break
        if close is None:
            continue
        body = close + 1
        while body < len(text) and text[body].isspace():
            body += 1
        if body < len(text) and text[body] == "{":
            match = candidate
            brace = body
            break
    if match is None:
        raise ValueError("function not found: " + name)
    start = match.start()
    previous_start = text.rfind("\n", 0, max(0, start - 1)) + 1
    previous = text[previous_start:start].strip()
    if previous in ("static int", "int", "static void", "void",
                    "static bool", "bool"):
        start = previous_start
    depth = 0
    for pos in range(brace, len(text)):
        if text[pos] == "{":
            depth += 1
        elif text[pos] == "}":
            depth -= 1
            if depth == 0:
                return text[start:pos + 1]
    raise ValueError("unterminated function: " + name)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cc", required=True)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--mutation", choices=MUTATIONS)
    parser.add_argument("--case", choices=CASES)
    parser.add_argument("--v2", action="store_true")
    parser.add_argument("--source-commit")
    args = parser.parse_args()

    root = Path(__file__).resolve().parents[2]
    here = root / "scripts/tests"
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    paths = (
        "fs/crypto/keyinfo.c", "fs/crypto/policy.c",
        "include/linux/fscrypt_common.h",
        "include/linux/fscrypt_supp.h", "fs/crypto/fscrypt_private.h",
        "include/linux/fscrypt.h", "include/uapi/linux/fs.h",
        "include/huawei_platform/hwdps/hwdps_defines.h",
        "fs/f2fs/keyinfo.c", "fs/hmfs/keyinfo.c",
        "fs/f2fs/policy.c", "fs/hmfs/policy.c",
        "security/hwdps/hwdps_fs_hooks.c",
        "drivers/huawei_platform/hwdps/src/tee/hwdps_keyinfo.c",
    )
    if args.source_commit:
        inputs = {
            name: subprocess.check_output(
                ["git", "-C", str(root), "show",
                 args.source_commit + ":" + name], text=True)
            for name in paths
        }
    else:
        inputs = {name: (root / name).read_text() for name in paths}

    declarations = []
    for path, names in {
        "include/linux/fscrypt_common.h": (
            "FS_KEY_DERIVATION_NONCE_SIZE", "FS_KEY_DERIVATION_IV_SIZE",
            "FS_KEY_DERIVATION_TAG_SIZE", "FS_KEY_DERIVATION_CIPHER_SIZE",
        ),
        "fs/crypto/fscrypt_private.h": (
            "FS_AES_256_GCM_KEY_SIZE", "FS_ENCRYPTION_CONTEXT_FORMAT_V2",
        ),
        "include/linux/fscrypt.h": ("FSCRYPT_SET_CONTEXT_MAX_SIZE",),
        "include/uapi/linux/fs.h": (
            "FS_KEY_DESCRIPTOR_SIZE", "FS_MAX_KEY_SIZE", "FS_KEY_DESC_PREFIX",
            "FS_KEY_DESC_PREFIX_SIZE", "FS_POLICY_FLAGS_VALID",
            "FS_ENCRYPTION_MODE_AES_256_XTS", "FS_ENCRYPTION_MODE_AES_256_CTS",
            "FS_ENCRYPTION_MODE_AES_128_CBC",
        ),
    }.items():
        for name in names:
            declarations.append(extract(r"^#define " + name + r"\b[^\n]*",
                                        inputs[path]))
    for path, names in {
        "include/linux/fscrypt_common.h": ("fscrypt_context",),
        "include/uapi/linux/fs.h": ("fscrypt_key", "fscrypt_policy"),
    }.items():
        for name in names:
            declarations.append(extract(r"^struct " + name +
                                        r" \{.*?^\}[^;]*;", inputs[path]))
    declarations.append(extract(
        r"^typedef struct \{.*?^\} fek_efek_t;",
        inputs["include/huawei_platform/hwdps/hwdps_defines.h"]))
    (output / "declarations.h").write_text("\n\n".join(declarations) + "\n")

    keyinfo = inputs["fs/crypto/keyinfo.c"]
    crypto_names = ("derive_crypt_complete", "fscrypt_set_gcm_key",
                    "fscrypt_derive_gcm_key")
    (output / "crypto-subject.h").write_text(
        "\n".join(function(keyinfo, name) for name in crypto_names) + "\n")

    admission_implemented = "fscrypt_check_unmanaged_descriptor" in keyinfo
    implemented = (admission_implemented and
                   "bool has_legacy_slot;" in keyinfo and
                   "struct fscrypt_mk_owner mk_owner;" in keyinfo)
    if implemented:
        subject = function(inputs["include/linux/fscrypt_common.h"],
                           "fscrypt_ci_is_managed") + "\n"
        subject += extract(r"^enum fscrypt_ce_purpose \{.*?^\};",
                          inputs["include/linux/fscrypt_supp.h"]) + "\n"
        subject += extract(r"^struct fscrypt_ce_key \{.*?^\};",
                           inputs["include/linux/fscrypt_supp.h"]) + "\n"
        subject += extract(r"^struct fscrypt_ce_tfm \{.*?^\};", keyinfo) + "\n"
        subject += extract(r"^struct fscrypt_ce_scope \{.*?^\};", keyinfo) + "\n"
        for name in (
            "fscrypt_check_unmanaged_descriptor", "fscrypt_acquire_ce_key",
            "fscrypt_release_ce_key", "fscrypt_ce_tfm_get",
            "fscrypt_ce_tfm_put", "fscrypt_ce_scope_open",
            "fscrypt_ce_scope_open_cached", "fscrypt_ce_scope_matches",
            "fscrypt_ce_scope_crypt", "fscrypt_ce_scope_legacy_slot",
            "fscrypt_ce_scope_attach_legacy_tfm", "fscrypt_ce_scope_put",
            "find_and_derive_key_with_scope", "put_crypt_info",
            "fscrypt_get_encryption_info_internal",
            "fscrypt_get_encryption_info_with_scope",
            "fscrypt_get_encryption_info", "fscrypt_put_encryption_info",
        ):
            subject += function(keyinfo, name) + "\n"
        subject += function(inputs["fs/crypto/policy.c"],
                            "fscrypt_inherit_context_prepared") + "\n"
        if args.v2:
            subject += "#define FS_KEY_INDEX_OFFSET 63\n"
            subject += function(keyinfo, "hwdps_get_key_index") + "\n"
            f2fs_keyindex = function(inputs["fs/f2fs/keyinfo.c"],
                                     "f2fs_do_get_keyindex")
            if "struct super_block *sb" not in f2fs_keyindex:
                f2fs_keyindex = f2fs_keyindex.replace(
                    "f2fs_do_get_keyindex(u8 *descriptor",
                    "f2fs_do_get_keyindex(struct super_block *sb, u8 *descriptor",
                    1)
            hmfs_keyindex = function(inputs["fs/hmfs/keyinfo.c"],
                                     "f2fs_do_get_keyindex")
            hmfs_keyindex = hmfs_keyindex.replace("f2fs_do_get_keyindex(",
                                                  "hmfs_do_get_keyindex(", 1)
            if "struct super_block *sb" not in hmfs_keyindex:
                hmfs_keyindex = hmfs_keyindex.replace(
                    "hmfs_do_get_keyindex(u8 *descriptor",
                    "hmfs_do_get_keyindex(struct super_block *sb, u8 *descriptor",
                    1)
            subject += f2fs_keyindex + "\n" + hmfs_keyindex + "\n"
        f2fs_create = function(inputs["fs/f2fs/policy.c"],
                               "f2fs_create_sdp_encryption_context_from_policy")
        hmfs_create = function(inputs["fs/hmfs/policy.c"],
                               "f2fs_create_sdp_encryption_context_from_policy")
        hmfs_create = hmfs_create.replace(
            "f2fs_create_sdp_encryption_context_from_policy(",
            "hmfs_create_sdp_encryption_context_from_policy(", 1)

        f2fs_check = function(inputs["fs/f2fs/policy.c"],
                              "f2fs_inode_check_sdp_keyring")
        if "struct super_block *sb" not in f2fs_check:
            f2fs_check = f2fs_check.replace(
                "f2fs_inode_check_sdp_keyring(u8 *descriptor",
                "f2fs_inode_check_sdp_keyring(struct super_block *sb, "
                "u8 *descriptor", 1)
            f2fs_create = f2fs_create.replace(
                "f2fs_inode_check_sdp_keyring(master_key_descriptor_tmp, 0)",
                "f2fs_inode_check_sdp_keyring(inode->i_sb, "
                "master_key_descriptor_tmp, 0)")
        f2fs_check = f2fs_check.replace(
            "{\n", "{\n\tf2fs_sdp_keyring_checks++;\n", 1)
        hmfs_check = function(inputs["fs/hmfs/policy.c"],
                              "hmfs_inode_check_sdp_keyring")
        if "struct super_block *sb" not in hmfs_check:
            hmfs_check = hmfs_check.replace(
                "hmfs_inode_check_sdp_keyring(u8 *descriptor",
                "hmfs_inode_check_sdp_keyring(struct super_block *sb, "
                "u8 *descriptor", 1)
        hmfs_check = hmfs_check.replace(
            "{\n", "{\n\thmfs_sdp_keyring_checks++;\n", 1)
        hmfs_policy_check = function(inputs["fs/hmfs/policy.c"],
                                     "hmfs_check_keyring_by_policy")
        if "hmfs_inode_check_sdp_keyring(inode->i_sb" not in hmfs_policy_check:
            hmfs_policy_check = hmfs_policy_check.replace(
                "hmfs_inode_check_sdp_keyring(master_key_descriptor_tmp, 0, ver)",
                "hmfs_inode_check_sdp_keyring(inode->i_sb, "
                "master_key_descriptor_tmp, 0, ver)")

        f2fs_payload = function(inputs["fs/f2fs/keyinfo.c"],
                                "f2fs_do_get_keyring_payload")
        if "struct super_block *sb" not in f2fs_payload:
            f2fs_payload = f2fs_payload.replace(
                "f2fs_do_get_keyring_payload(u8 *descriptor",
                "f2fs_do_get_keyring_payload(struct super_block *sb, "
                "u8 *descriptor", 1)
        hmfs_payload = function(inputs["fs/hmfs/keyinfo.c"],
                                "f2fs_do_get_keyring_payload")
        hmfs_payload = hmfs_payload.replace(
            "f2fs_do_get_keyring_payload(",
            "hmfs_do_get_keyring_payload(", 1)
        if "struct super_block *sb" not in hmfs_payload:
            hmfs_payload = hmfs_payload.replace(
                "hmfs_do_get_keyring_payload(u8 *descriptor",
                "hmfs_do_get_keyring_payload(struct super_block *sb, "
                "u8 *descriptor", 1)

        f2fs_cold_ece = function(inputs["fs/f2fs/keyinfo.c"],
                                 "f2fs_get_sdp_ece_crypt_info")
        f2fs_cold_sece = function(inputs["fs/f2fs/keyinfo.c"],
                                  "f2fs_get_sdp_sece_crypt_info")
        hmfs_cold_ece = function(inputs["fs/hmfs/keyinfo.c"],
                                 "f2fs_get_sdp_ece_crypt_info").replace(
            "f2fs_get_sdp_ece_crypt_info(",
            "hmfs_get_sdp_ece_crypt_info(", 1)
        hmfs_cold_sece = function(inputs["fs/hmfs/keyinfo.c"],
                                  "f2fs_get_sdp_sece_crypt_info").replace(
            "f2fs_get_sdp_sece_crypt_info(",
            "hmfs_get_sdp_sece_crypt_info(", 1)
        f2fs_get_sdp = function(inputs["fs/f2fs/keyinfo.c"],
                                "f2fs_get_sdp_crypt_info")
        if "f2fs_inode_check_sdp_keyring(inode->i_sb" not in f2fs_get_sdp:
            f2fs_get_sdp = f2fs_get_sdp.replace(
                "f2fs_inode_check_sdp_keyring(ci_info->ci_master_key, 1)",
                "f2fs_inode_check_sdp_keyring(inode->i_sb, "
                "ci_info->ci_master_key, 1)")
        hmfs_get_sdp = function(inputs["fs/hmfs/keyinfo.c"],
                                "f2fs_get_sdp_crypt_info")
        hmfs_get_sdp = hmfs_get_sdp.replace(
            "f2fs_get_sdp_crypt_info(", "hmfs_get_sdp_crypt_info(", 1)
        hmfs_get_sdp = hmfs_get_sdp.replace(
            "f2fs_get_sdp_ece_crypt_info(",
            "hmfs_get_sdp_ece_crypt_info(")
        hmfs_get_sdp = hmfs_get_sdp.replace(
            "f2fs_get_sdp_sece_crypt_info(",
            "hmfs_get_sdp_sece_crypt_info(")
        if "hmfs_inode_check_sdp_keyring(inode->i_sb" not in hmfs_get_sdp:
            hmfs_get_sdp = hmfs_get_sdp.replace(
                "hmfs_inode_check_sdp_keyring(\n\t\t\tci_info->ci_master_key",
                "hmfs_inode_check_sdp_keyring(\n\t\t\tinode->i_sb, "
                "ci_info->ci_master_key")

        subject += f2fs_check + "\n" + hmfs_check + "\n"
        subject += hmfs_policy_check + "\n"
        subject += f2fs_payload + "\n" + hmfs_payload + "\n"
        subject += function(inputs["fs/f2fs/keyinfo.c"],
                            "f2fs_put_crypt_info") + "\n"
        subject += f2fs_cold_ece + "\n" + f2fs_cold_sece + "\n"
        subject += hmfs_cold_ece + "\n" + hmfs_cold_sece + "\n"
        subject += f2fs_get_sdp + "\n" + hmfs_get_sdp + "\n"
        subject += f2fs_create + "\n" + hmfs_create + "\n"

        hooks = inputs["security/hwdps/hwdps_fs_hooks.c"]
        subject += function(hooks, "hwdps_check_support") + "\n"
        for name in ("hwdps_dir_inherit_flags", "hwdps_get_parent_dps_flag",
                     "check_params", "set_inode_attr",
                     "hwdps_inherit_context"):
            subject += function(hooks, name) + "\n"

        subject += function(keyinfo, "hwdps_do_get_context") + "\n"
        subject += function(keyinfo, "hwdps_update_context") + "\n"
        subject += function(keyinfo, "hwdps_get_context") + "\n"
        subject += function(
            inputs["drivers/huawei_platform/hwdps/src/tee/hwdps_keyinfo.c"],
            "hwdps_get_key") + "\n"

        f2fs_check_flag = function(inputs["fs/f2fs/policy.c"],
                                   "check_inode_flag")
        f2fs_set_dps = function(inputs["fs/f2fs/policy.c"],
                                "set_dps_attr_and_flag")
        f2fs_set_policy = function(inputs["fs/f2fs/policy.c"],
                                   "set_dps_policy_inner")
        hmfs_check_flag = function(inputs["fs/hmfs/policy.c"],
                                   "check_inode_flag").replace(
            "check_inode_flag(", "hmfs_check_inode_flag(", 1)
        hmfs_set_dps = function(inputs["fs/hmfs/policy.c"],
                                "set_dps_attr_and_flag").replace(
            "set_dps_attr_and_flag(", "hmfs_set_dps_attr_and_flag(", 1)
        hmfs_set_policy = function(inputs["fs/hmfs/policy.c"],
                                   "set_dps_policy_inner")
        hmfs_set_policy = hmfs_set_policy.replace(
            "set_dps_policy_inner(", "hmfs_set_dps_policy_inner(", 1)
        hmfs_set_policy = hmfs_set_policy.replace(
            "check_inode_flag(inode)", "hmfs_check_inode_flag(inode)")
        hmfs_set_policy = hmfs_set_policy.replace(
            "set_dps_attr_and_flag(inode)",
            "hmfs_set_dps_attr_and_flag(inode)")
        subject += f2fs_check_flag + "\n" + f2fs_set_dps + "\n"
        subject += f2fs_set_policy + "\n" + hmfs_check_flag + "\n"
        subject += hmfs_set_dps + "\n" + hmfs_set_policy + "\n"

        subject += function(inputs["fs/f2fs/keyinfo.c"],
                            "f2fs_get_crypt_keyinfo") + "\n"
        hmfs_get_keyinfo = function(inputs["fs/hmfs/keyinfo.c"],
                                    "hmfs_get_crypt_keyinfo")
        hmfs_get_keyinfo = hmfs_get_keyinfo.replace(
            "f2fs_get_sdp_crypt_info(inode, fs_data)",
            "hmfs_get_sdp_crypt_info(inode, fs_data)")
        subject += hmfs_get_keyinfo + "\n"
        for path, names in (
            ("fs/f2fs/keyinfo.c", ("f2fs_change_to_sdp_crypto",
                                    "f2fs_publish_crypt_info")),
            ("fs/hmfs/keyinfo.c", ("hmfs_change_to_sdp_crypto",
                                    "hmfs_publish_crypt_info")),
            ("fs/f2fs/policy.c", ("f2fs_sdp_crypt_inherit",)),
            ("fs/hmfs/policy.c", ("hmfs_sdp_crypt_inherit",)),
        ):
            for name in names:
                piece = function(inputs[path], name)
                if name == "f2fs_sdp_crypt_inherit" and \
                        "f2fs_inode_check_sdp_keyring(parent->i_sb" not in piece:
                    piece = piece.replace(
                        "f2fs_inode_check_sdp_keyring(sdp_mkey_desc, 0)",
                        "f2fs_inode_check_sdp_keyring(parent->i_sb, "
                        "sdp_mkey_desc, 0)")
                if name == "hmfs_sdp_crypt_inherit" and \
                        "hmfs_inode_check_sdp_keyring(parent->i_sb" not in piece:
                    piece = piece.replace(
                        "hmfs_inode_check_sdp_keyring(sdp_mkey_desc, 0,",
                        "hmfs_inode_check_sdp_keyring(parent->i_sb, "
                        "sdp_mkey_desc, 0,")
                subject += piece + "\n"
    else:
        if admission_implemented:
            admission = function(keyinfo, "fscrypt_check_unmanaged_descriptor")
        else:
            admission = r'''static int fscrypt_check_unmanaged_descriptor(
 struct super_block *sb, const u8 *descriptor) { return 0; }
'''
        subject = admission + r'''
enum fscrypt_ce_purpose { POLICY_WRAP, FILE_UNWRAP, SDP_CE_SOURCE, CHILD_WRAP };
struct fscrypt_ce_tfm {
 refcount_t refs; struct crypto_aead *tfm; u8 descriptor[FS_KEY_DESCRIPTOR_SIZE];
 u8 legacy_slot; bool managed; bool has_legacy_slot;
};
struct fscrypt_ce_scope {
 struct super_block *sb; u8 descriptor[FS_KEY_DESCRIPTOR_SIZE];
 enum fscrypt_ce_purpose purpose; struct fscrypt_ce_tfm *owner;
 struct fscrypt_mk_owner mk_owner;
};
static int fscrypt_ce_scope_open(struct inode *inode, const u8 *descriptor,
 enum fscrypt_ce_purpose purpose, struct fscrypt_ce_scope **out)
{ *out = NULL; return -EOPNOTSUPP; }
static int fscrypt_ce_scope_open_cached(struct inode *inode,
 enum fscrypt_ce_purpose purpose, struct fscrypt_ce_scope **out)
{ *out = NULL; return -EOPNOTSUPP; }
static int fscrypt_ce_scope_legacy_slot(const struct fscrypt_ce_scope *scope,
 u8 *slot) { return -EOPNOTSUPP; }
static int fscrypt_ce_scope_attach_legacy_tfm(struct fscrypt_ce_scope *scope,
 struct fscrypt_info *ci) { return -EOPNOTSUPP; }
static void fscrypt_ce_scope_put(struct fscrypt_ce_scope *scope) { }
static void put_crypt_info(struct fscrypt_info *ci)
{ if (ci) { fscrypt_mk_drop_owner(&ci->ci_owner); kmem_cache_free(fscrypt_info_cachep, ci); } }
static int fscrypt_get_encryption_info(struct inode *inode)
{ return -EOPNOTSUPP; }
static void fscrypt_put_encryption_info(struct inode *inode)
{ put_crypt_info(inode->i_crypt_info); inode->i_crypt_info = NULL; }
static int fscrypt_inherit_context_prepared(struct inode *parent,
 struct inode *child, void *fs_data, struct fscrypt_ce_scope *borrowed_scope,
 bool preload) { return -EOPNOTSUPP; }
#ifdef CONFIG_SCSI_UFS_ENHANCED_INLINE_CRYPTO_V2
static int hwdps_get_key_index(struct super_block *sb, u8 *descriptor)
{ return fscrypt_check_unmanaged_descriptor(sb, descriptor); }
static int f2fs_do_get_keyindex(struct super_block *sb, u8 *descriptor,
 int *slot) { return fscrypt_check_unmanaged_descriptor(sb, descriptor); }
static int hmfs_do_get_keyindex(struct super_block *sb, u8 *descriptor,
 int *slot, unsigned char ver)
{ return fscrypt_check_unmanaged_descriptor(sb, descriptor); }
#endif
static int f2fs_create_sdp_encryption_context_from_policy(struct inode *inode,
 const struct fscrypt_sdp_policy *policy) { return 0; }
static int hmfs_create_sdp_encryption_context_from_policy(struct inode *inode,
 const struct fscrypt_sdp_policy *policy) { return 0; }
int f2fs_change_to_sdp_crypto(struct inode *inode, void *fs_data)
{ return 0; }
int hmfs_change_to_sdp_crypto(struct inode *inode, void *fs_data)
{ return 0; }
static int f2fs_sdp_crypt_inherit(struct inode *parent, struct inode *child,
 void *dpage, void *fs_data) { return 0; }
static int hmfs_sdp_crypt_inherit(struct inode *parent, struct inode *child,
 void *dpage, void *fs_data) { return 0; }
static int f2fs_publish_crypt_info(struct inode *inode, struct fscrypt_info *ci)
{ return 0; }
static int hmfs_publish_crypt_info(struct inode *inode, struct fscrypt_info *ci)
{ return 0; }
static int f2fs_get_sdp_ece_crypt_info(struct inode *inode, void *fs_data)
{ return 0; }
static int f2fs_get_sdp_sece_crypt_info(struct inode *inode, void *fs_data)
{ return 0; }
static int hmfs_get_sdp_ece_crypt_info(struct inode *inode, void *fs_data)
{ return 0; }
static int hmfs_get_sdp_sece_crypt_info(struct inode *inode, void *fs_data)
{ return 0; }
static int f2fs_get_sdp_crypt_info(struct inode *inode, void *fs_data)
{ return 0; }
static int hmfs_get_sdp_crypt_info(struct inode *inode, void *fs_data)
{ return 0; }
static int f2fs_inode_check_sdp_keyring(struct super_block *sb,
 u8 *descriptor, int enforce) { return 0; }
static int hmfs_inode_check_sdp_keyring(struct super_block *sb,
 u8 *descriptor, int enforce, unsigned char ver) { return 0; }
static int f2fs_do_get_keyring_payload(struct super_block *sb, u8 *descriptor,
 u8 *raw, size_t capacity, int *size, bool filepubkey, u32 expected_class)
{ return 0; }
static int hmfs_do_get_keyring_payload(struct super_block *sb, u8 *descriptor,
 u8 *raw, int *size, bool filepubkey, unsigned char ver) { return 0; }
static int set_dps_policy_inner(struct file *filp, struct inode *inode)
{ return 0; }
static int hmfs_set_dps_policy_inner(struct file *filp, struct inode *inode)
{ return 0; }
static int f2fs_get_crypt_keyinfo(struct inode *inode, void *fs_data, int *flag)
{ *flag = 0; return 0; }
static int hmfs_get_crypt_keyinfo(struct inode *inode, void *fs_data, int *flag)
{ *flag = 0; return 0; }
static int hwdps_do_get_context(struct inode *inode, struct fscrypt_context *ctx)
{ return 0; }
static int hwdps_get_context(struct inode *inode) { return 0; }
static int hwdps_update_context(struct inode *inode, uid_t new_uid) { return 0; }
s32 hwdps_check_support(struct inode *inode, uint32_t *flags)
{ return 0; }
static s32 hwdps_inherit_context(struct inode *parent, struct inode *inode,
 const struct dentry *dentry, void *fs_data, struct page *page) { return 0; }
static s32 hwdps_get_key(const u8 *descriptor, buffer_t *aes_key, uid_t uid)
{ return 0; }
'''

    replacements = {
        "registry-present-absence": (
            "fscrypt_mk_put(mk);\n\t\treturn -EOPNOTSUPP;",
            "fscrypt_mk_put(mk);\n\t\treturn 0;", 1),
        "registry-error-collapse": (
            "if (err == -ENOENT)\n\t\treturn 0;\n\treturn err;",
            "(void)err;\n\treturn 0;", 1),
        "sdp-fallback": (
            "if (purpose == SDP_CE_SOURCE)", "if (false)", 1),
        "managed-fallback": (
            "err = fscrypt_mk_acquire(mk, 0, &mk_lease);\n"
            "\t\tfscrypt_mk_put(mk);\n\t\tif (err)",
            "err = fscrypt_mk_acquire(mk, 0, &mk_lease);\n"
            "\t\tfscrypt_mk_put(mk);\n\t\tif (err == -EINVAL)", 1),
        "managed-enroll": (
            "if (purpose == FILE_UNWRAP) {\n"
            "\t\t\terr = fscrypt_mk_enroll(&mk_lease, &scope->mk_owner);",
            "if (purpose == FILE_UNWRAP) {\n\t\t\terr = 0;", 1),
        "managed-release": (
            "memcpy(secret, fscrypt_mk_secret(&mk_lease), sizeof(secret));\n"
            "\t\tfscrypt_mk_release(&mk_lease);",
            "memcpy(secret, fscrypt_mk_secret(&mk_lease), sizeof(secret));\n"
            "\t\t/* retained lease */", 1),
        "owner-transfer": (
            "ci->ci_owner = scope->mk_owner;",
            "/* missing owner transfer */", 1),
        "owner-drop": (
            "fscrypt_mk_drop_owner(&scope->mk_owner);\n"
            "\tfscrypt_ce_tfm_put(scope->owner);",
            "/* missing owner drop */\n\tfscrypt_ce_tfm_put(scope->owner);", 1),
        "legacy-size": (
            "material.size == FS_AES_256_GCM_KEY_SIZE", "true", 1),
        "cached-generation": (
            "ci->ci_owner.generation, &mk_lease", "0, &mk_lease", 1),
        "cached-enroll": (
            "err = fscrypt_mk_acquire(ci->ci_owner.key,\n"
            "\t\t\t\t\tci->ci_owner.generation, &mk_lease);\n"
            "\t\tif (err)\n\t\t\tgoto out;\n"
            "\t\terr = fscrypt_mk_enroll(&mk_lease, &scope->mk_owner);",
            "err = fscrypt_mk_acquire(ci->ci_owner.key,\n"
            "\t\t\t\t\tci->ci_owner.generation, &mk_lease);\n"
            "\t\tif (err)\n\t\t\tgoto out;\n\t\terr = 0;", 1),
        "managed-marker": (
            "owner->managed = true;", "owner->managed = false;", 1),
        "secret-wipe": (
            "memzero_explicit(secret, sizeof(secret));",
            "/* missing secret wipe */", 1),
        "inline-negative": (
            "if (crypt_info->ci_key_index < 0)",
            "if (crypt_info->ci_key_index < -1)", 1),
        "key-validation": (
            "down_read(&keyring_key->sem);\n"
            "\tres = key_validate(keyring_key);\n"
            "\tif (res)\n\t\tgoto out;\n"
            "\tif (keyring_key->type != &key_type_logon)",
            "down_read(&keyring_key->sem);\n\tres = 0;\n"
            "\tif (keyring_key->type != &key_type_logon)", 3),
        "sdp-managed-guard": (
            "if (fscrypt_ci_is_managed(READ_ONCE(inode->i_crypt_info)))\n"
            "\t\treturn -EOPNOTSUPP;",
            "if (false)\n\t\treturn -EOPNOTSUPP;", 2),
        "publish-sdp-flag": (
            "if (F2FS_INODE_IS_SDP_ENCRYPTED(sdpflag))",
            "if (false)", 2),
        "inherit-preload": (
            "} else {\n\t\tres = cops->set_context(child, &ctx, "
            "sizeof(ctx), fs_data);\n\t\tif (!res && preload)",
            "} else {\n\t\tres = cops->set_context(child, &ctx, "
            "sizeof(ctx), fs_data);\n\t\tif (false)", 1),
        "publication-owner-drop": (
            "\tfscrypt_mk_drop_owner(&ci->ci_owner);\n"
            "\tkmem_cache_free(fscrypt_info_cachep, ci);",
            "\t/* missing candidate owner drop */\n"
            "\tkmem_cache_free(fscrypt_info_cachep, ci);", 1),
    }
    if args.mutation:
        if args.mutation in (
                "f2fs-publish-dir-fastpath", "hmfs-publish-dir-fastpath",
                "f2fs-publish-hwdps-flag", "hmfs-publish-hwdps-flag"):
            name = args.mutation.split("-publish-", 1)[0] + \
                "_publish_crypt_info"
            original = function(subject, name)
            if args.mutation.endswith("dir-fastpath"):
                old = ("if (!S_ISREG(inode->i_mode) || "
                       "!fscrypt_ci_is_managed(ci))\n\t\treturn ")
                new = "if (false)\n\t\treturn "
            else:
                old = "if (sdpflag & HWDPS_ENABLE_FLAG)"
                new = "if (false)"
            if original.count(old) != 1:
                raise ValueError(f"mutation {args.mutation}: target count "
                                 f"{original.count(old)}")
            subject = subject.replace(
                original, original.replace(old, new, 1), 1)
        elif args.mutation in (
                "f2fs-ece-cold-ce-guard", "f2fs-ece-cold-sdp-guard",
                "f2fs-sece-cold-ce-guard", "f2fs-sece-cold-sdp-guard",
                "hmfs-ece-cold-ce-guard", "hmfs-ece-cold-sdp-guard",
                "hmfs-sece-cold-ce-guard", "hmfs-sece-cold-sdp-guard",
                "f2fs-warm-descriptor-guard", "hmfs-warm-descriptor-guard",
                "f2fs-warm-key-validation", "hmfs-warm-key-validation",
                "f2fs-payload-descriptor-guard",
                "hmfs-payload-descriptor-guard",
                "hmfs-payload-key-validation", "f2fs-warm-managed-guard",
                "hmfs-warm-managed-guard", "f2fs-policy-ce-guard",
                "f2fs-policy-sdp-guard", "hmfs-policy-ce-guard",
                "hmfs-policy-sdp-guard"):
            mutation_specs = {
                "f2fs-ece-cold-ce-guard": ("f2fs_get_sdp_ece_crypt_info",
                    "ctx.master_key_descriptor"),
                "f2fs-ece-cold-sdp-guard": ("f2fs_get_sdp_ece_crypt_info",
                    "sdp_ctx.master_key_descriptor"),
                "f2fs-sece-cold-ce-guard": ("f2fs_get_sdp_sece_crypt_info",
                    "ctx.master_key_descriptor"),
                "f2fs-sece-cold-sdp-guard": ("f2fs_get_sdp_sece_crypt_info",
                    "sdp_ctx.master_key_descriptor"),
                "hmfs-ece-cold-ce-guard": ("hmfs_get_sdp_ece_crypt_info",
                    "ctx.master_key_descriptor"),
                "hmfs-ece-cold-sdp-guard": ("hmfs_get_sdp_ece_crypt_info",
                    "sdp_ctx.master_key_descriptor"),
                "hmfs-sece-cold-ce-guard": ("hmfs_get_sdp_sece_crypt_info",
                    "ctx.master_key_descriptor"),
                "hmfs-sece-cold-sdp-guard": ("hmfs_get_sdp_sece_crypt_info",
                    "sdp_ctx.master_key_descriptor"),
            }
            if args.mutation in mutation_specs:
                name, descriptor = mutation_specs[args.mutation]
                original = function(subject, name)
                old = ("res = fscrypt_check_unmanaged_descriptor(inode->i_sb,\n"
                       f"\t\t{descriptor});\n\tif (res)\n\t\treturn res;")
                new = "res = 0;"
            elif args.mutation.endswith("warm-descriptor-guard"):
                name = args.mutation.split("-warm-", 1)[0] + \
                    "_inode_check_sdp_keyring"
                original = function(subject, name)
                old = ("res = fscrypt_check_unmanaged_descriptor(sb, descriptor);\n"
                       "\tif (res)\n\t\treturn res;")
                new = "res = 0;"
            elif args.mutation.endswith("warm-key-validation"):
                name = args.mutation.split("-warm-", 1)[0] + \
                    "_inode_check_sdp_keyring"
                original = function(subject, name)
                old = ("res = key_validate(keyring_key);\n\tif (res)\n"
                       "\t\tgoto out;")
                new = "res = 0;"
            elif args.mutation == "hmfs-payload-key-validation":
                original = function(subject, "hmfs_do_get_keyring_payload")
                old = ("res = key_validate(keyring_key);\n\tif (res)\n"
                       "\t\tgoto out;")
                new = "res = 0;"
            elif args.mutation.endswith("payload-descriptor-guard"):
                name = ("f2fs_do_get_keyring_payload" if
                        args.mutation.startswith("f2fs-") else
                        "hmfs_do_get_keyring_payload")
                original = function(subject, name)
                old = ("res = fscrypt_check_unmanaged_descriptor(sb, "
                       "descriptor);\n\tif (res)\n\t\treturn res;")
                new = "res = 0;"
            elif args.mutation.endswith("warm-managed-guard"):
                name = ("f2fs_get_sdp_crypt_info" if
                        args.mutation.startswith("f2fs-") else
                        "hmfs_get_sdp_crypt_info")
                original = function(subject, name)
                old = ("if (fscrypt_ci_is_managed(ci_info))\n"
                       "\t\t\treturn -EOPNOTSUPP;")
                new = "if (false)\n\t\t\treturn -EOPNOTSUPP;"
            else:
                name = ("f2fs_create_sdp_encryption_context_from_policy" if
                        args.mutation.startswith("f2fs-") else
                        "hmfs_create_sdp_encryption_context_from_policy")
                original = function(subject, name)
                descriptor = ("ce_ctx.master_key_descriptor" if "-ce-" in
                              args.mutation else
                              "policy->master_key_descriptor")
                old = ("res = fscrypt_check_unmanaged_descriptor(inode->i_sb,\n"
                       f"\t\t{descriptor});\n\tif (res)\n\t\treturn res;")
                new = "res = 0;"
            if original.count(old) != 1:
                raise ValueError(f"mutation {args.mutation}: target count "
                                 f"{original.count(old)}")
            subject = subject.replace(
                original, original.replace(old, new, 1), 1)
        elif args.mutation in (
                "hwdps-keyindex-key-validation",
                "f2fs-keyindex-key-validation",
                "hmfs-keyindex-key-validation", "f2fs-sdp-managed-guard",
                "hmfs-sdp-managed-guard", "f2fs-publish-sdp-flag",
                "hmfs-publish-sdp-flag", "hwdps-do-context-descriptor",
                "hwdps-update-managed", "hwdps-cached-managed",
                "hwdps-context-error-map", "hwdps-tombstone-preserve",
                "f2fs-dps-warm-managed", "hmfs-dps-warm-managed",
                "f2fs-dps-context-descriptor",
                "hmfs-dps-context-descriptor", "f2fs-dps-null-ci",
                "hmfs-dps-null-ci", "hwdps-inherit-managed",
                "hwdps-inherit-descriptor",
                "hwdps-logon-key-validation"):
            if args.mutation.endswith("keyindex-key-validation"):
                name = {
                    "hwdps-keyindex-key-validation": "hwdps_get_key_index",
                    "f2fs-keyindex-key-validation": "f2fs_do_get_keyindex",
                    "hmfs-keyindex-key-validation": "hmfs_do_get_keyindex",
                }[args.mutation]
                old = ("res = key_validate(keyring_key);\n\tif (res)\n"
                       "\t\tgoto out;")
                new = "res = 0;"
            elif args.mutation.endswith("sdp-managed-guard"):
                name = ("f2fs_change_to_sdp_crypto" if
                        args.mutation.startswith("f2fs-") else
                        "hmfs_change_to_sdp_crypto")
                old = ("if (fscrypt_ci_is_managed(ci_info))\n"
                       "\t\treturn -EOPNOTSUPP;")
                new = "if (false)\n\t\treturn -EOPNOTSUPP;"
            elif args.mutation.endswith("publish-sdp-flag"):
                name = args.mutation.split("-publish-", 1)[0] + \
                    "_publish_crypt_info"
                old = "if (F2FS_INODE_IS_SDP_ENCRYPTED(sdpflag))"
                new = "if (false)"
            elif args.mutation == "hwdps-do-context-descriptor":
                name = "hwdps_do_get_context"
                old = ("err = fscrypt_check_unmanaged_descriptor(inode->i_sb,\n"
                       "\t\tctx->master_key_descriptor);\n\tif (err != 0)\n"
                       "\t\treturn err;")
                new = "err = 0;"
            elif args.mutation == "hwdps-update-managed":
                name = "hwdps_update_context"
                old = ("if (fscrypt_ci_is_managed(READ_ONCE("
                       "inode->i_crypt_info)))\n\t\treturn -EOPNOTSUPP;")
                new = "if (false)\n\t\treturn -EOPNOTSUPP;"
            elif args.mutation in ("hwdps-cached-managed",
                                   "hwdps-context-error-map",
                                   "hwdps-tombstone-preserve"):
                name = "hwdps_get_context"
                if args.mutation == "hwdps-cached-managed":
                    old = "if (fscrypt_ci_is_managed(ci_existing))"
                    new = "if (false)"
                elif args.mutation == "hwdps-context-error-map":
                    old = "if (err == -EOPNOTSUPP)\n\t\t\terr = -EKEYREJECTED;"
                    new = "if (false)\n\t\t\terr = -EKEYREJECTED;"
                else:
                    old = ("if (err != 0) {\n\t\tif (err == -EOPNOTSUPP)\n"
                           "\t\t\terr = -EKEYREJECTED;\n"
                           "\t\tgoto free_encoded_wfek;\n\t}")
                    new = old.replace("goto free_encoded_wfek;",
                                      "goto free_fek;")
            elif args.mutation.startswith(("f2fs-dps-", "hmfs-dps-")):
                name = ("set_dps_policy_inner" if
                        args.mutation.startswith("f2fs-") else
                        "hmfs_set_dps_policy_inner")
                if args.mutation.endswith("warm-managed"):
                    old = ("if (fscrypt_ci_is_managed(ci)) {\n"
                           "\t\tret = -EOPNOTSUPP;\n\t\tgoto err;\n\t}")
                    new = "if (false) {\n\t\tret = -EOPNOTSUPP;\n\t\tgoto err;\n\t}"
                elif args.mutation.endswith("context-descriptor"):
                    old = ("ret = fscrypt_check_unmanaged_descriptor("
                           "inode->i_sb,\n\t\t\t\t\t\t "
                           "ce_ctx.master_key_descriptor);\n"
                           "\t\tif (ret != 0)\n\t\t\tgoto err;")
                    new = "ret = 0;"
                else:
                    old = ("if (S_ISREG(inode->i_mode) && !ci) {\n"
                           "\t\tret = -ENOKEY;\n\t\tgoto err;\n\t}")
                    new = "if (false) {\n\t\tret = -ENOKEY;\n\t\tgoto err;\n\t}"
            elif args.mutation.startswith("hwdps-inherit-"):
                name = "hwdps_inherit_context"
                if args.mutation.endswith("managed"):
                    old = "if (fscrypt_ci_is_managed(parent_ci))"
                    new = "if (false)"
                else:
                    old = ("err = fscrypt_check_unmanaged_descriptor("
                           "parent->i_sb,\n\t\t\t\t\t\t "
                           "parent_ci->ci_master_key);\n"
                           "\tif (err != 0)")
                    new = "err = 0;\n\tif (false)"
            else:
                name = "hwdps_get_key"
                old = ("res = key_validate(keyring_key);\n\tif (res != 0)\n"
                       "\t\tgoto out;")
                new = "res = 0;"
            original = function(subject, name)
            if original.count(old) != 1:
                raise ValueError(f"mutation {args.mutation}: target count "
                                 f"{original.count(old)}")
            subject = subject.replace(
                original, original.replace(old, new, 1), 1)
        elif args.mutation == "publication-owner-drop":
            original = function(subject, "put_crypt_info")
            old, new, expected = replacements[args.mutation]
            count = original.count(old)
            if count != expected:
                raise ValueError(f"mutation {args.mutation}: expected {expected} "
                                 f"targets, got {count}")
            subject = subject.replace(
                original, original.replace(old, new, 1), 1)
        else:
            old, new, expected = replacements[args.mutation]
            count = subject.count(old)
            if count != expected:
                raise ValueError(f"mutation {args.mutation}: expected {expected} "
                                 f"targets, got {count}")
            subject = subject.replace(old, new, 1)
    (output / "subject.h").write_text(subject)

    version = subprocess.check_output([args.cc, "--version"], text=True)
    if "clang version 22." not in version:
        raise ValueError("fixture requires selected Clang 22")
    command = [
        args.cc, "-std=gnu11", "-O1", "-g", "-Wall", "-Wextra", "-Werror",
        "-Wno-unused-function", "-Wno-unused-parameter", "-Wno-pointer-sign",
        "-fsanitize=address,undefined", "-fno-sanitize-recover=all",
        "-fno-omit-frame-pointer", "-I" + str(output), "-I" + str(here),
        str(here / "huawei_fscrypt_managed_admission.c"), "-lcrypto",
        "-pthread", "-o", str(output / "test"),
    ]
    command.insert(-2, "-DCONFIG_HWDPS")
    if args.v2:
        command.insert(-2, "-DCONFIG_SCSI_UFS_ENHANCED_INLINE_CRYPTO_V2")
    compiled = subprocess.run(command, capture_output=True, text=True, timeout=60)
    (output / "compile.log").write_text(compiled.stdout + compiled.stderr)
    results = []
    if compiled.returncode == 0:
        environment = dict(os.environ)
        # LeakSanitizer cannot enumerate threads under the managed ptrace
        # harness.  The C fixture asserts allocation/ref/lock balance itself.
        environment["ASAN_OPTIONS"] = "detect_leaks=0"
        for case in ((args.case,) if args.case else CASES):
            run = subprocess.run([str(output / "test"), case], capture_output=True,
                                 text=True, timeout=15, env=environment)
            (output / (case + ".log")).write_text(run.stdout + run.stderr)
            results.append({"case": case, "exit": run.returncode})
            print(case, "PASS" if run.returncode == 0 else "FAIL", flush=True)
    else:
        print(compiled.stderr)

    receipt = {
        "source_commit": subprocess.check_output(
            ["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip(),
        "source_override": args.source_commit,
        "dirty": bool(subprocess.check_output(
            ["git", "-C", str(root), "status", "--porcelain"], text=True)),
        "production_implemented": implemented,
        "admission_implemented": admission_implemented,
        "mutation": args.mutation,
        "v2": args.v2,
        "compiler": version,
        "command": command,
        "compile_exit": compiled.returncode,
        "results": results,
        "source_sha256": {name: hashlib.sha256(text.encode()).hexdigest()
                          for name, text in inputs.items()},
        "test_sha256": {
            path.name: hashlib.sha256(path.read_bytes()).hexdigest()
            for path in (Path(__file__),
                         here / "huawei_fscrypt_managed_admission.c",
                         here / "huawei_fscrypt_ce_scope_host.h")
        },
        "limits": ("Extracted CE admission/scope/owner teardown with modeled "
                   "registry, master lease, kernel keyring, locks and allocation; "
                   "real OpenSSL AES-GCM; no kernel VFS/SMP/device execution."),
    }
    (output / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    return int(compiled.returncode != 0 or
               any(result["exit"] != 0 for result in results))


if __name__ == "__main__":
    raise SystemExit(main())

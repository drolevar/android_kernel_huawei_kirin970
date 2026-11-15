#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Actual object-BTF parser with simulated host services; no BPF syscalls."""
import argparse
import hashlib
import json
import os
import re
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

KERNEL = Path(__file__).resolve().parents[2]
DEFAULT_CC = shutil.which("clang-22") or "clang"
OPTIONS = argparse.Namespace(cc=os.environ.get("CC", DEFAULT_CC), keep_output=None,
                             fixtures=KERNEL / "scripts/tests/btf-fixtures/data")
_STORAGE = None


class ObjectBtfHostTest(unittest.TestCase):
    """Each case targets parser acceptance, rejection, or resource ownership."""
    binary = None

    def run_case(self, case):
        for path in ("kernel/bpf/btf.c", "include/linux/btf.h", "include/uapi/linux/btf.h"):
            self.assertTrue((KERNEL / path).is_file(), "missing actual object-BTF implementation: " + path)
        if self.__class__.binary is None:
            self.__class__.binary = build(OPTIONS)
        p = subprocess.run([str(self.binary), case], capture_output=True, text=True, timeout=30)
        if OPTIONS.keep_output:
            (Path(self.binary).parent / (case + ".result.json")).write_text(json.dumps({
                "command": [str(self.binary), case], "returncode": p.returncode,
                "stdout": p.stdout, "stderr": p.stderr}, indent=2) + "\n")
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)

    def test_valid_int_typedef_struct_array_hash_sizes(self): self.run_case("types")
    def test_func_global_linkage_rejected_then_vlen_cleared(self): self.run_case("func")
    def test_var_datasec_resolver_mode_reset(self): self.run_case("datasec")
    def test_malformed_headers_sections_and_strings(self): self.run_case("headers")
    def test_payload_references_cycles_members_and_overflow(self): self.run_case("malformed")
    def test_allocation_failure_at_every_allocation(self): self.run_case("alloc")
    def test_type_capacity_failure_is_not_silently_ignored(self): self.run_case("capacity")
    def test_info_copy_truncation_query_and_faults(self): self.run_case("info")
    def test_partial_input_copy_and_snapshot(self): self.run_case("copy")
    def test_anon_fd_idr_failure_unwinds(self): self.run_case("publish")
    def test_source_fd_close_held_reference_stale_ids_rcu(self): self.run_case("lifetime")
    def test_log_full_multipart_and_diagnostics(self): self.run_case("log")
    def test_log_copy_fault_prevents_publication(self): self.run_case("log-fault")
    def test_datasec_u32_addition_does_not_wrap(self): self.run_case("datasec-overflow")
    def test_actual_parser_typed_map_creation_and_cleanup(self): self.run_case("maps")
    def test_btf_syscall_gateways_attributes_permissions_and_info(self): self.run_case("gateway")

    def test_producer_normalized_fixtures(self):
        if not OPTIONS.fixtures:
            self.skipTest("pass --fixtures PATH to consume existing producer fixtures")
        self.run_case("types")
        base = OPTIONS.fixtures.resolve()
        index = json.loads((base / "parser-fixtures.json").read_text())
        cases = {
            "manual/attempt1.btf": -22,
            "manual/attempt2.btf": 0,
            "manual-pre510/attempt1.btf": 0,
            "manual-pre510/attempt2.btf": 0,
            "manual-success/attempt1.btf": -22,
        }
        for source in ("offload.o", "test.o", "clatd.o", "dscpPolicy.o", "netd.o", "bpfRingbufProg.bpf"):
            for stage in ("open", "all-supported", "no-global-func", "no-func-datasec"):
                cases[f"libbpf/{source}/{stage}.btf"] = 0 if source == "test.o" or stage in ("no-global-func", "no-func-datasec") else -22
        records = []
        entries = {f["path"]: f for f in index["fixtures"]}
        for path, want in cases.items():
            with self.subTest(path=path):
                fixture = base / path
                digest = hashlib.sha256(fixture.read_bytes()).hexdigest()
                self.assertEqual(digest, entries[path]["sha256"])
                p = subprocess.run([str(self.binary), "--file", str(fixture)], capture_output=True, text=True, timeout=30)
                result = json.loads(p.stdout)
                records.append({"command": [str(self.binary), "--file", str(fixture)], "sha256": digest,
                    "returncode": p.returncode, "stdout": result, "stderr": p.stderr, "expected": want})
                self.assertEqual(p.returncode, 0 if want == 0 else 1, p.stderr)
                self.assertEqual(result["result"], want, p.stderr)
                if want == 0:
                    self.assertEqual(len(result["types"]), entries[path]["summary"]["type_count"])
                    by_id = {t["id"]: t for t in result["types"]}
                    for section in entries[path]["summary"]["datasecs"]:
                        # no-func-datasec sanitization replaces section kinds with STRUCT.
                        if "no-func-datasec" not in path:
                            self.assertEqual(by_id[section["id"]]["size"], section["size"])
                else:
                    self.assertIn("vlen != 0", p.stderr)
        (Path(self.binary).parent / "fixture-results.json").write_text(json.dumps(records, indent=2) + "\n")

    def test_manual_normalized_btf_to_ordinary_maps(self):
        if not OPTIONS.fixtures:
            self.skipTest("pass --fixtures PATH for exact loader fixtures")
        self.run_case("types")
        base = OPTIONS.fixtures.resolve()
        audit_path = base / "corpus-audit.json"
        if not audit_path.exists():
            self.skipTest("producer corpus-audit.json required for exact map requests")
        audit = json.loads(audit_path.read_text())
        offload = next(x for x in audit if x["name"] == "offload.o")
        results = []
        unsupported = []
        for m in offload["manual"]["maps"]:
            self.assertEqual(m["kv_ret"], 0)
            if m["type"] not in (1, 2):
                self.assertEqual((m["name"], m["type"]), ("tether_dev_map", 25))
                unsupported.append({"name": m["name"], "type": m["type"],
                    "status": "unsupported DEVMAP_HASH; not executed by ordinary map harness"})
                continue
            self.assertEqual(m["flags"], 0, "ordinary storage contract covers zero flags")
            command = [str(self.binary), "--map", str(base / "manual/attempt2.btf"),
                       *(str(m[key]) for key in ("type", "key_type_id", "value_type_id", "key_size", "value_size"))]
            p = subprocess.run(command, capture_output=True, text=True, timeout=30)
            self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
            self.assertEqual(json.loads(p.stdout)["result"], 0)
            results.append({"name": m["name"], "command": command, "returncode": p.returncode})
        self.assertEqual(len(results), 8)
        self.assertEqual(len(unsupported), 1)
        (Path(self.binary).parent / "manual-map-results.json").write_text(json.dumps({"ordinary_maps": results, "unsupported": unsupported}, indent=2) + "\n")


def build(options):
    """Only remove include lines; retain all executable parser/logger source."""
    global _STORAGE
    if options.keep_output:
        output = options.keep_output.resolve()
        output.mkdir(parents=True, exist_ok=False)
    else:
        _STORAGE = tempfile.TemporaryDirectory(prefix="object-btf-host-")
        output = Path(_STORAGE.name)
    inputs = {}

    def read(path):
        data = (KERNEL / path).read_bytes()
        if len(data) > 1024 * 1024:
            raise AssertionError("bounded source helper: oversized " + path)
        inputs[path] = hashlib.sha256(data).hexdigest()
        return data.decode()

    def strip_includes(path, target):
        source = read(path)
        lines = source.splitlines(keepends=True)
        removed = []
        for i, line in enumerate(lines):
            if re.match(r"^[ \t]*#\s*include\s+[<\"]", line):
                if line.rstrip().endswith("\\"):
                    raise AssertionError("multiline include unsupported: " + path)
                removed.append({"line": i + 1, "text": line.rstrip()})
                lines[i] = "\n"
        (output / target).write_text("".join(lines))
        return removed

    transforms = {}
    for path, target in (("kernel/bpf/btf.c", "subject.c"),
                         ("kernel/bpf/btf_log.c", "logger.c"),
                         ("include/uapi/linux/btf.h", "btf_uapi.h"),
                         ("include/linux/btf.h", "btf_api.h")):
        transforms[path] = strip_includes(path, target)
    verifier = read("include/linux/bpf_verifier.h")
    start = verifier.index("#define BPF_VERIFIER_TMP_LOG_SIZE")
    end = verifier.index("\n/* Maximum variable offset", start)
    (output / "log_api.h").write_text(verifier[start:end])
    bpf = read("include/uapi/linux/bpf.h")
    temporary = not re.search(r"__u32\s+btf_size\s*;", bpf)
    if temporary:
        # TEMPORARY parser-only stand-in while main imports UAPI plumbing.
        # Never used as ABI evidence; replaced automatically when actual fields exist.
        (output / "bpf_uapi.h").write_text("""
/* TEMPORARY PARSER-ONLY UAPI STUB: NOT ABI EVIDENCE. */
union bpf_attr {
 struct { __aligned_u64 btf; __aligned_u64 btf_log_buf;
          __u32 btf_size; __u32 btf_log_size; __u32 btf_log_level; };
 struct { __u32 bpf_fd; __u32 info_len; __aligned_u64 info; } info;
};
struct bpf_btf_info { __aligned_u64 btf; __u32 btf_size; __u32 id; };
""")
        print("TEMPORARY parser-only bpf_attr stub; no ABI claim", flush=True)
    else:
        (output / "bpf_uapi.h").write_text('#include "' + str(KERNEL / "include/uapi/linux/bpf.h") + '"\n')
    (output / "subject.h").write_text('\n'.join('#include "' + h + '"' for h in
        ("bpf_uapi.h", "btf_uapi.h", "btf_api.h", "log_api.h")) + '\n')
    # Execute production metadata/creation/cleanup code; only map storage and
    # unchanged kernel services are host doubles. Keep callback registration real.
    def function(text, name):
        match = re.search(r"^(?:static )?[^\n;{}]+\b" + name + r"\(.*?^\}", text, re.S | re.M)
        if not match:
            raise AssertionError("missing production map path: " + name)
        return match.group()
    syscall = read("kernel/bpf/syscall.c")
    array = read("kernel/bpf/arraymap.c")
    header = read("include/linux/bpf.h")
    declarations = []
    for name in ("bpf_map_ops", "bpf_map"):
        declarations.append(re.search(r"^struct " + name + r" \{.*?^\};", header, re.S | re.M).group())
    (output / "map_structures.h").write_text("\n".join(declarations))
    table = re.search(r"^const struct bpf_map_ops array_map_ops = \{.*?^\};", array, re.S | re.M).group()
    names = re.findall(r"\.(\w+)\s*=\s*(\w+)", table)
    stub = ["#define " + name + (" storage_alloc" if field == "map_alloc" else
            " storage_free" if field == "map_free" else " NULL")
            for field, name in names if field != "map_check_btf"]
    (output / "array_registration.h").write_text("\n".join(stub) + "\n" + table)
    parts = [re.search(r"#define CHECK_ATTR\(CMD\).*?(?=\n\n)", syscall, re.S).group()]
    parts += [re.search(r"#define BPF_MAP_CREATE_LAST_FIELD[^\n]*", syscall).group()]
    parts += [function(syscall, n) for n in ("bpf_map_free_deferred", "bpf_map_put_uref",
              "__bpf_map_put", "bpf_map_put", "bpf_map_put_with_uref", "bpf_map_release",
              "bpf_get_file_flag", "bpf_map_new_fd", "bpf_obj_name_cpy", "map_check_btf", "map_create")]
    (output / "map_subject.c").write_text("\n\n".join(parts))
    (output / "array_subject.c").write_text(function(array, "array_map_check_btf"))
    gates = [function(syscall, "check_uarg_tail_zero")]
    gates += [function(syscall, "bpf_map_get_info_by_fd")]
    for name in ("BPF_BTF_LOAD_LAST_FIELD", "BPF_BTF_GET_FD_BY_ID_LAST_FIELD", "BPF_OBJ_GET_INFO_BY_FD_LAST_FIELD"):
        gates.append(re.search(r"#define " + name + r"[^\n]*", syscall).group())
    gates += [function(syscall, n) for n in ("bpf_btf_load", "bpf_btf_get_fd_by_id", "bpf_obj_get_info_by_fd")]
    (output / "gateway_subject.c").write_text("\n\n".join(gates))
    harness = KERNEL / "scripts/tests/object_btf_host"
    for p in sorted(harness.rglob("*")):
        if p.is_file():
            inputs[str(p.relative_to(KERNEL))] = hashlib.sha256(p.read_bytes()).hexdigest()
    inputs["scripts/tests/test_object_btf.py"] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    binary = output / "object-btf-host"
    command = [options.cc, "-std=gnu11", "-O1", "-g", "-Wall", "-Wextra", "-Werror",
               "-Wno-unused-parameter", "-Wno-sign-compare", "-Wno-unused-function",
               "-Wno-missing-field-initializers", "-fsanitize=address,undefined",
               "-fno-sanitize-recover=all", "-fno-omit-frame-pointer",
               "-I" + str(harness), "-I" + str(output), "-I" + str(KERNEL / "include/uapi"),
               str(harness / "cases.c"), "-o", str(binary)]
    version = subprocess.run([options.cc, "--version"], capture_output=True, text=True, check=True).stdout
    if not re.search(r"clang version 22[.]", version):
        raise AssertionError("Clang 22 required, got " + version)
    p = subprocess.run(command, capture_output=True, text=True, timeout=60)
    (output / "compile.log").write_text(p.stdout + p.stderr)
    receipt = {"command": command, "compiler": version, "returncode": p.returncode,
               "inputs_sha256": inputs, "removed_includes": transforms,
               "temporary_bpf_attr_stub": temporary,
               "scope": "host simulation only: no real BPF syscalls, FDs, kernel RCU or hardware"}
    receipt["generated_sha256"] = {str(p.relative_to(output)): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in sorted(output.iterdir()) if p.is_file() and p.suffix in (".h", ".c")}
    if p.returncode == 0:
        receipt["binary_sha256"] = hashlib.sha256(binary.read_bytes()).hexdigest()
    (output / "build-receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    if p.returncode:
        raise AssertionError(p.stdout + p.stderr)
    return binary


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cc", default=OPTIONS.cc)
    parser.add_argument("--keep-output", type=Path)
    parser.add_argument("--fixtures", type=Path, default=OPTIONS.fixtures,
                        help="existing loader-fixtures directory; defaults to bundled data")
    OPTIONS, rest = parser.parse_known_args()
    unittest.main(argv=[__file__, *rest], verbosity=2)

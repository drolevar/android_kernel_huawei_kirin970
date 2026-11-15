#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Offline contracts: exact production boundary; no kernel loading."""
import importlib.util
import json
import os
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('btf_loader_fixtures', HERE / 'btf_loader_fixtures.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def synthetic(*, sym=12, linkage=1, datasec_size=0, var_id=3, var_size=4,
              section_name='.data', omit_symbol=False, map_sizes=None):
    """Hand-built ELF64/BTF; literal independent normalization expectations below."""
    names = b'\0.shstrtab\0.symtab\0.data\0.BTF\0a\0b\0.android_maps\0'
    def no(s): return names.index(s.encode() + b'\0')
    strings = b'\0int\0a\0b\0.data\0f\0____btf_map_t\0'
    def bo(s): return strings.index(s.encode() + b'\0')
    def typ(name, kind, size, vlen=0):
        return struct.pack('<III', bo(name) if name else 0, kind << 24 | vlen, size)
    types = typ('int', 1, 4) + struct.pack('<I', 32)
    types += typ('a', 14, 1) + struct.pack('<I', 0)
    types += typ('b', 14, 1) + struct.pack('<I', linkage)
    types += typ('.data', 15, datasec_size, 2) + struct.pack('<IIIIII', var_id, 0, var_size, 2, 8, 4)
    types += typ('', 13, 1) + typ('f', 12, 5, 1)
    if map_sizes:
        types += typ('____btf_map_t', 4, 8, 2) + struct.pack('<IIIIII', bo('a'), 1, 0, bo('b'), 1, 32)
    btf = struct.pack('<HBBIIIII', 0xeb9f, 1, 0, 24, 0, len(types), len(types), len(strings)) + types + strings
    symbols = bytes(24)
    if not omit_symbol:
        symbols += struct.pack('<IBBHQQ', no('b'), 0x11, 0, 3, sym, 4)
    parts = [b'', names, symbols, bytes(16), btf]
    if map_sizes:
        parts.append(struct.pack('<12I', 2, *map_sizes, 1, 0, 0, 0, 0, 0, 0, 0, 0) + bytes(70) + b't\0' + bytes(68) + bytes(4))
    blob = bytearray(64)
    headers = []
    for i, part in enumerate(parts):
        blob += bytes((-len(blob)) % 8)
        off = len(blob)
        blob += part
        name = ['', '.shstrtab', '.symtab', section_name, '.BTF', '.android_maps'][i]
        name_off = no(name) if name in ('', '.shstrtab', '.symtab', '.data', '.BTF', '.android_maps') else no('a')
        headers.append(struct.pack('<IIQQQQIIQQ', name_off, [0, 3, 2, 1, 1, 1][i], 0, 0,
                                   off, len(part), 1 if i == 2 else 0, 1 if i == 2 else 0,
                                   8, 24 if i == 2 else 0))
    shoff = len(blob)
    blob += b''.join(headers)
    blob[:64] = struct.pack('<16sHHIQQQIHHHHHH', b'\x7fELF\x02\x01\x01' + bytes(9),
                           1, 247, 1, 0, 0, shoff, 0, 64, 0, 0, 64, len(parts), 1)
    return bytes(blob)


class ExactLoaderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.helper = Path(os.environ['BTF_LOADER_HELPER'])

    def run_loader(self, data=None, *, errors='22,0', old=False, **kwargs):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)
            (p / 'input.o').write_bytes(synthetic(**kwargs) if data is None else data)
            cmd = [str(self.helper), 'manual', str(p / 'input.o'), str(p / 'attempt'),
                   'old' if old else 'new', errors]
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            outputs = [x.read_bytes() for x in sorted(p.glob('attempt*.btf'))]
            return r, outputs

    def test_verbatim_normalization_and_einval_retry(self):
        r, raw = self.run_loader(datasec_size=64)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(json.loads(r.stdout)['attempts'], 2)
        first, retry = map(m.Btf, raw)
        self.assertEqual(first.types[4]['size_type'], 16)
        self.assertEqual(first.types[4]['entries'], [(3, 12, 4), (2, 8, 4)])
        self.assertEqual(first.types[6]['info'], 0x0c000001)
        self.assertEqual(retry.types[6]['info'], 0x0c000000)
        expected = bytearray(raw[0])
        struct.pack_into('<I', expected, first.types[6]['offset'] + 4, 0x0c000000)
        self.assertEqual(raw[1], expected)

    def test_only_einval_retries_and_second_failure_propagates(self):
        for errors, ret, attempts in [('0', 0, 1), ('1', -1, 1), ('22,1', -1, 2), ('22,22', -22, 2)]:
            with self.subTest(errors=errors):
                r, raw = self.run_loader(errors=errors)
                report = json.loads(r.stdout)
                self.assertEqual((report['ret'], len(raw)), (ret, attempts))

    def test_missing_symbol_section_and_non_var_fail_before_capture(self):
        for kwargs, ret in [({'omit_symbol': True}, -1), ({'section_name': 'a'}, -2), ({'var_id': 1}, -1)]:
            with self.subTest(kwargs=kwargs):
                r, raw = self.run_loader(**kwargs)
                self.assertEqual(json.loads(r.stdout)['ret'], ret)
                self.assertEqual(raw, [])

    def test_actual_get_key_value_type_ids_enforces_expected_sizes(self):
        for sizes, result in [((4, 4), 0), ((4, 8), -1), ((8, 4), -1)]:
            with self.subTest(sizes=sizes):
                r, raw = self.run_loader(errors='0', map_sizes=sizes)
                self.assertEqual(r.returncode, 0, r.stderr)
                row = json.loads(r.stdout)['maps'][0]
                self.assertEqual(row['kv_ret'], result)
                if result == 0:
                    self.assertEqual((row['key_type_id'], row['value_type_id'],
                                      row['resolved_key_size'], row['resolved_value_size']), (1, 1, 4, 4))

    def test_static_versus_extern_lookup_and_int_truncation(self):
        for kwargs, ret, offset in [({'linkage': 0, 'omit_symbol': True}, 0, 0),
                                    ({'linkage': 2, 'omit_symbol': True}, -1, None),
                                    ({'sym': (1 << 32) + 12}, 0, 12),
                                    ({'sym': 0xffffffff}, -1, None)]:
            with self.subTest(kwargs=kwargs):
                r, raw = self.run_loader(errors='0', **kwargs)
                self.assertEqual(json.loads(r.stdout)['ret'], ret)
                if raw:
                    self.assertEqual(m.Btf(raw[0]).types[4]['entries'][0][1], offset)

    def test_size_offset_overrun_is_not_silently_fixed(self):
        r, raw = self.run_loader(errors='0', sym=1000, var_size=32)
        self.assertEqual(json.loads(r.stdout)['ret'], 0)
        self.assertEqual(m.Btf(raw[0]).types[4]['entries'][0], (3, 1000, 32))

    def test_exact_libbpf_sanitizer_assumptions(self):
        r, raw = self.run_loader(errors='0')
        self.assertEqual(r.returncode, 0, r.stderr)
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)
            (p/'input.btf').write_bytes(raw[0])
            for profile, kinds in [(0, [14, 15, 13, 12]), (1, [14, 15, 13, 12]), (2, [1, 4, 6, 8])]:
                r = subprocess.run([str(self.helper), 'sanitize', str(p/'input.btf'),
                                    str(p/'out.btf'), str(profile)], capture_output=True, text=True, timeout=5)
                self.assertEqual(r.returncode, 0, r.stderr)
                data = (p/'out.btf').read_bytes()
                b = m.Btf(data)
                self.assertEqual([b.types[i]['kind'] for i in [2, 4, 5, 6]], kinds)
                if profile == 0: self.assertEqual(data, raw[0])
                if profile == 1: self.assertEqual(b.types[6]['vlen'], 0)

    def test_pre510_sanitizes_before_capture_and_no_func_retry_change(self):
        r, raw = self.run_loader(old=True)
        self.assertEqual(json.loads(r.stdout)['ret'], 0)
        b = m.Btf(raw[0])
        self.assertEqual([b.types[i]['kind'] for i in [2, 3, 4, 5, 6]], [1, 1, 4, 6, 8])
        self.assertEqual(b.types[4]['name'], '_data')
        self.assertEqual(raw[0], raw[1])

    def test_bounded_malformed_elf_headers_and_strings(self):
        valid = synthetic()
        cases = [b'', valid[:63], b'NOPE' + valid[4:]]
        for offset, fmt, value in [(40, '<Q', (1 << 64) - 64), (58, '<H', 63),
                                   (62, '<H', 99), (40, '<Q', 65)]:
            bad = bytearray(valid)
            struct.pack_into(fmt, bad, offset, value)
            cases.append(bytes(bad))
        for data in cases:
            with self.subTest(size=len(data)):
                r, raw = self.run_loader(data=data)
                self.assertEqual(r.returncode, 2, r.stderr)
                self.assertFalse(raw)

    def test_section_payload_overrun_and_unterminated_names(self):
        valid = synthetic()
        shoff = struct.unpack_from('<Q', valid, 40)[0]
        bad = bytearray(valid)
        struct.pack_into('<Q', bad, shoff + 3*64 + 24, len(valid)+1)
        r, raw = self.run_loader(data=bytes(bad), errors='0')
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(json.loads(r.stdout)['ret'], -1)
        self.assertEqual(raw, [])
        bad = bytearray(valid)
        str_start, str_len = struct.unpack_from('<QQ', bad, shoff+64+24)
        bad[str_start+str_len-1] = 65
        r, raw = self.run_loader(data=bytes(bad))
        self.assertEqual(r.returncode, 2)
        self.assertEqual(raw, [])

    def test_ext_core_records_are_distinct_from_func_line_info(self):
        elf = m.Elf(synthetic())
        b = m.Btf(elf.section('.BTF'))
        # .data string offset is 9; one section, two 16-byte CO-RE records.
        payload = struct.pack('<III', 16, 9, 2) + bytes(32)
        ext = struct.pack('<HBBIIIIIII', 0xeb9f, 1, 0, 32, 0, 0, 0, 0, 0, len(payload)) + payload
        report = b.ext(ext)
        self.assertEqual(report['func_info']['records'], 0)
        self.assertEqual(report['line_info']['records'], 0)
        self.assertEqual(report['core_relo']['records'], 2)
        self.assertEqual(report['core_relo']['sections'], [dict(section='.data', records=2)])
        with self.assertRaises(ValueError):
            b.ext(ext[:-1])

    def test_elf_reader_rejects_truncated_table(self):
        with self.assertRaises(ValueError):
            m.Elf(synthetic()[:-1])

    def test_truncated_btf_and_unknown_kind_rejected(self):
        for raw in [b'', bytes(24), struct.pack('<HBBIIIII', 0xeb9f, 1, 0, 24, 0, 12, 12, 1)
                    + struct.pack('<III', 0, 31 << 24, 0) + b'\0']:
            with self.assertRaises(ValueError):
                m.Btf(raw)


class BundledCorpusTests(unittest.TestCase):
    def test_hashes_snapshots_and_explicit_profile_boundaries(self):
        base = HERE/'btf-fixtures/data'
        index = json.loads((base/'parser-fixtures.json').read_text())
        self.assertEqual(len(index['fixtures']), 29)
        for entry in index['fixtures']:
            self.assertEqual(m.sha((base/entry['path']).read_bytes()), entry['sha256'])
        first = (base/'manual/attempt1.btf').read_bytes()
        retry = (base/'manual/attempt2.btf').read_bytes()
        self.assertEqual(first, (base/'manual-success/attempt1.btf').read_bytes())
        expected = bytearray(first)
        changed = 0
        for t in m.Btf(first).types.values():
            if t['kind'] == 12 and t['vlen']:
                struct.pack_into('<I', expected, t['offset']+4, t['info'] & ~0xffff)
                changed += 1
        self.assertGreater(changed, 0)
        self.assertEqual(retry, expected)
        self.assertEqual((base/'manual-pre510/attempt1.btf').read_bytes(),
                         (base/'manual-pre510/attempt2.btf').read_bytes())
        # Coincidence for these bytes does not make assumed libbpf probes real.
        for left, right in [('manual/attempt1.btf', 'open'),
                            ('manual/attempt2.btf', 'no-global-func'),
                            ('manual-pre510/attempt1.btf', 'no-func-datasec')]:
            self.assertEqual((base/left).read_bytes(),
                             (base/'libbpf/offload.o'/f'{right}.btf').read_bytes())
        for entry in json.loads((HERE/'btf-fixtures/index.json').read_text())['fixtures']:
            self.assertEqual(m.sha((HERE/'btf-fixtures'/entry['path']).read_bytes()), entry['sha256'])

    def test_corpus_excludes_core_externs_and_internal_maps(self):
        audit = json.loads((HERE/'btf-fixtures/data/corpus-audit.json').read_text())
        self.assertEqual({x['name'] for x in audit}, set(m.FILES))
        for obj in audit:
            self.assertFalse(obj['btf']['typed_externs'])
            if obj['ext'] is not None:
                self.assertEqual(obj['ext']['core_relo']['records'], 0)
            self.assertEqual(obj['libbpf_open']['open_errno'], 0)
            for section in obj['sections']:
                self.assertFalse(section['name'].startswith(('.rodata', '.kconfig')))
            for map_ in obj['libbpf_open']['maps']:
                self.assertFalse(map_['internal'])
                self.assertFalse(map_['freeze_on_initialization'])


class OutputOwnershipTests(unittest.TestCase):
    def test_existing_destinations_are_rejected_before_work(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            marker = out / 'build-receipt.json'
            marker.write_text('original receipt')
            args = SimpleNamespace(output=out, workspace=out, parser_dir=None)
            for action in (m.prepare, m.generate, m.build):
                with self.subTest(action=action.__name__), patch.object(m.subprocess, 'run') as run:
                    with self.assertRaises((ValueError, FileExistsError)):
                        action(args)
                    run.assert_not_called()
                    self.assertEqual(marker.read_text(), 'original receipt')

    def test_existing_parser_destination_is_rejected_before_generation(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            args = SimpleNamespace(output=base/'new', parser_dir=base)
            with self.assertRaises(ValueError):
                m.generate(args)
            self.assertFalse(args.output.exists())


if __name__ == '__main__':
    unittest.main()

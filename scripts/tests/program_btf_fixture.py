# SPDX-License-Identifier: GPL-2.0
"""Decode pinned clatd ELF metadata. No execution or loader feature overrides."""
import base64
import hashlib
import struct

OBJECT_SHA = '966ea4779ca9a4c1a294cb25f7685a6edd9f7a41f8d519c8a0f9791b062c725d'
SECTIONS = [('schedcls/ingress6_clat_ether$4_14', 383, 106),
            ('schedcls/ingress6_clat_rawip$4_14', 302, 97),
            ('schedcls/egress4_clat_rawip$4_9', 247, 100)]


def extract(blob):
    assert hashlib.sha256(blob).hexdigest() == OBJECT_SHA
    assert blob[:6] == b'\x7fELF\x02\x01'
    shoff = struct.unpack_from('<Q', blob, 40)[0]
    size, count, si = struct.unpack_from('<HHH', blob, 58)
    headers = [struct.unpack_from('<IIQQQQIIQQ', blob, shoff+i*size) for i in range(count)]
    def content(h): return blob[h[4]:h[4]+h[5]]
    def string(data, pos): return data[pos:data.index(0, pos)].decode()
    names = content(headers[si])
    sections = {string(names, h[0]): content(h) for h in headers}
    btf = sections['.BTF']
    _, _, _, hl, to, tl, so, sl = struct.unpack_from('<HBBIIIII', btf)
    strings = btf[hl+so:hl+so+sl]
    types, pos = [], hl+to
    while pos < hl+to+tl:
        name, info, val = struct.unpack_from('<III', btf, pos)
        kind, vlen = (info >> 24) & 31, info & 65535
        types.append([name, info, val])
        pos += 12 + {1:4, 3:12, 4:12*vlen, 5:12*vlen, 6:8*vlen,
                     13:8*vlen, 14:4, 15:12*vlen, 17:4, 19:12*vlen}.get(kind, 0)
    assert pos == hl+to+tl
    ext = sections['.BTF.ext']
    _, _, _, eh, fo, fl, lo, ll = struct.unpack_from('<HBBIIIII', ext)
    groups = {}
    for key, offset, length in [('func', fo, fl), ('line', lo, ll)]:
        pos = eh+offset
        rs = struct.unpack_from('<I', ext, pos)[0]
        assert rs == (8 if key == 'func' else 16)
        pos += 4
        records = {}
        while pos < eh+offset+length:
            no, count = struct.unpack_from('<II', ext, pos)
            pos += 8
            raw = [list(struct.unpack_from('<'+'I'*(rs//4), ext, pos+i*rs)) for i in range(count)]
            pos += count*rs
            records[string(strings, no)] = raw
        assert pos == eh+offset+length
        groups[key] = records
    programs = []
    for name, slots, lines in SECTIONS:
        code = sections[name]
        funcs, linfo = groups['func'][name], groups['line'][name]
        assert len(code) == slots*8 and len(funcs) == 1 and len(linfo) == lines
        assert funcs[0][0] == 0 and all(r[0] % 8 == 0 for r in linfo)
        assert not any(code[i] == 0x85 and code[i+1] >> 4 == 1 for i in range(0,len(code),8))
        programs.append(dict(section=name, slots=slots, code=base64.b64encode(code).decode(),
                             raw_func=funcs, raw_line=linfo,
                             func=[[r[0]//8]+r[1:] for r in funcs],
                             line=[[r[0]//8]+r[1:] for r in linfo]))
    return dict(object_sha256=OBJECT_SHA, btf_sha256=hashlib.sha256(btf).hexdigest(),
                btf_ext_sha256=hashlib.sha256(ext).hexdigest(),
                strings=base64.b64encode(strings).decode(), raw_type_headers=types,
                note='Raw ELF records retained; offsets divided by8 as libbpf. Test BTF service uses existing libbpf FUNC global-to-static sanitation only; it does not test BTF parsing.',
                programs=programs)


def c_fixture(f):
    def values(data): return ','.join(str(x) for x in data)
    def records(data): return ',\n'.join('{'+values(x)+'}' for x in data)
    out = ['static char fixture_strings[] = {'+values(base64.b64decode(f['strings']))+'};']
    types = [[0,0,0]] + [r.copy() for r in f['raw_type_headers']]
    for r in types:
        if (r[1] >> 24) & 31 == 12:
            r[1] &= ~0xffff  # existing libbpf sanitation for old-kernel FUNC linkage
    out.append('static struct btf_type fixture_types[] = {'+',\n'.join('{.name_off=%d,.info=%d,.type=%d}' % tuple(r) for r in types)+'};')
    for i, p in enumerate(f['programs']):
        out += ['static unsigned char code%d[] = {%s};' % (i, values(base64.b64decode(p['code']))),
                'static struct bpf_func_info func%d[] = {%s};' % (i, records(p['func'])),
                'static struct bpf_line_info line%d[] = {%s};' % (i, records(p['line']))]
    out.append('static struct { unsigned char *code; size_t size; struct bpf_func_info *func; struct bpf_line_info *line; unsigned lines; } fixtures[] = {')
    out += ['{code%d,sizeof(code%d),func%d,line%d,%d},' % (i,i,i,i,len(p['line'])) for i,p in enumerate(f['programs'])]
    out.append('};')
    return '\n'.join(out)

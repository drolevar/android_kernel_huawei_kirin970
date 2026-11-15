// SPDX-License-Identifier: Apache-2.0
// Offline adapter only. Normalization is included verbatim from selected source.
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <cerrno>
#include <cinttypes>
#include <elf.h>
#include <fstream>
#include <iostream>
#include <span>
#include <stdexcept>
#include <string>
#include <vector>
#include </usr/include/linux/filter.h>
#include <linux/seccomp.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include "btf.h"
#include "libbpf.h"
using std::span;
using std::vector;

// A successful helper exit proves that neither this code nor linked libbpf
// executed bpf(2). No feature-probe or object-load public API is called.
static void denyBpf() {
    sock_filter f[] = {BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_bpf, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)};
    sock_fprog p = {4, f};
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) || prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &p))
        throw std::runtime_error("cannot install bpf syscall guard");
}
static void check(bool ok, const char* why) { if (!ok) throw std::runtime_error(why); }
class ElfObject {
    vector<char> storage;
    size_t size = 0;
    span<const char> bytes, strtab;
    vector<Elf64_Shdr> headerStorage;
    vector<Elf64_Sym> symbolStorage;
    span<const Elf64_Shdr> sh;
    span<const Elf64_Sym> symtab;
public:
    explicit ElfObject(const char* file) {
        std::ifstream in(file, std::ios::binary | std::ios::ate);
        check(bool(in), "open ELF");
        auto n = in.tellg();
        check(n >= 64 && n <= 16 * 1024 * 1024, "bounded ELF size");
        size = size_t(n); storage.resize(size); in.seekg(0); in.read(storage.data(), n);
        check(bool(in), "read ELF"); bytes = storage;
        const auto* eh = reinterpret_cast<const Elf64_Ehdr*>(bytes.data());
        check(!memcmp(eh->e_ident, "\177ELF\2\1\1", 7), "ELF64 little-endian required");
        check(eh->e_machine == EM_BPF && eh->e_type == ET_REL, "relocatable BPF ELF required");
        check(eh->e_shentsize == sizeof(Elf64_Shdr), "section entry size");
        check(eh->e_shoff <= bytes.size() && eh->e_shnum <= (bytes.size()-eh->e_shoff)/sizeof(Elf64_Shdr), "section table bounds");
        headerStorage.resize(eh->e_shnum);
        memcpy(headerStorage.data(),bytes.data()+eh->e_shoff,headerStorage.size()*sizeof(Elf64_Shdr));
        sh = headerStorage;
        check(eh->e_shstrndx < sh.size(), "section string index");
        strtab = getSectionByIdx(eh->e_shstrndx);
        check(!strtab.empty() && strtab.back() == 0, "terminated section strings");
        for (const auto& s : sh) check(s.sh_name < strtab.size(), "section name bounds");
        bool found = false;
        for (const auto& s : sh) if (s.sh_type == SHT_SYMTAB) {
            check(s.sh_size % sizeof(Elf64_Sym) == 0, "symbol entry size");
            check(s.sh_offset <= bytes.size() && s.sh_size <= bytes.size()-s.sh_offset, "symbol table bounds");
            symbolStorage.resize(s.sh_size/sizeof(Elf64_Sym));
            memcpy(symbolStorage.data(),bytes.data()+s.sh_offset,s.sh_size);
            symtab = symbolStorage;
            found = true; break;
        }
        check(found, "missing symbol table");
        // Production uses shstrtab for symbol names too. Keep that choice exactly;
        // getStr rejects offsets outside that table, and its last byte is NUL.
    }
#include "elf_methods.inc"
};

static bool oldKernel;
static bool isAtLeastKernelVersion(int, int) { return !oldKernel; }
static std::string prefix;
static vector<int> outcomes;
static size_t attempts;
static void saveBtf(const btf* b, const std::string& path) {
    __u32 n; const void* p = btf__raw_data(b, &n);
    check(p != nullptr, "serialize BTF");
    std::ofstream out(path, std::ios::binary); out.write(static_cast<const char*>(p), n);
    check(bool(out), "write BTF");
}
static int captureLoad(btf* b) {
    saveBtf(b, prefix + std::to_string(++attempts) + ".btf");
    check(attempts <= outcomes.size(), "unexpected extra load attempt");
    errno = outcomes[attempts-1];
    return -errno;
}
#define ALOGE(...) do { fprintf(stderr, __VA_ARGS__); fputc('\n', stderr); } while (0)
#define btf__load_into_kernel captureLoad
#include "netbpf_exact.inc"
#undef btf__load_into_kernel
#include "android_map_def.inc"
extern "C" int fixture_libbpf_sanitize(struct btf*, int);

static void jsonString(const char* s) {
    std::cout << '"';
    for (const unsigned char* p = reinterpret_cast<const unsigned char*>(s); *p; ++p) {
        if (*p == '"' || *p == '\\') std::cout << '\\' << char(*p);
        else if (*p < 32) { char b[7]; snprintf(b, sizeof(b), "\\u%04x", *p); std::cout << b; }
        else std::cout << char(*p);
    }
    std::cout << '"';
}
static void manualMaps(const ElfObject& elf, btf* b) {
    span<const bpf_map_def> maps;
    std::cout << ",\"maps\":[";
    if (!elf.readSectionByName(".android_maps", maps)) {
        bool first = true;
        for (const auto& m : maps) {
            check(m.name_idx < sizeof(m.pin_location) && memchr(m.pin_location, 0, sizeof(m.pin_location)), "bounded map name");
            if (!first) std::cout << ','; first = false;
            uint32_t k = 0, v = 0;
            int ret = getKeyValueTids(b, m.name(), m.key_size, m.value_size, &k, &v);
            std::cout << "{\"name\":"; jsonString(m.name());
            std::cout << ",\"type\":" << m.type << ",\"key_size\":" << m.key_size
                      << ",\"value_size\":" << m.value_size << ",\"flags\":" << m.map_flags
                      << ",\"kv_ret\":" << ret << ",\"key_type_id\":" << k << ",\"value_type_id\":" << v;
            if (!ret) std::cout << ",\"resolved_key_size\":" << btf__resolve_size(b,k)
                               << ",\"resolved_value_size\":" << btf__resolve_size(b,v);
            std::cout << '}';
        }
    }
    std::cout << ']';
}
int main(int argc, char** argv) {
    try {
        denyBpf();
        check(argc >= 4, "usage: manual ELF PREFIX new|old ERRNOS | open ELF PREFIX | sanitize BTF OUTPUT PROFILE");
        std::string mode = argv[1];
        if (mode == "manual") {
            check(argc == 6, "manual arguments");
            ElfObject elf(argv[2]); span<const char> data;
            check(!elf.readSectionByName(".BTF", data), "missing BTF");
            btf* b = btf__new(data.data(), data.size()); check(b != nullptr, "parse BTF");
            prefix = argv[3]; oldKernel = std::string(argv[4]) == "old";
            std::string seq = argv[5]; size_t pos = 0;
            do { outcomes.push_back(std::stoi(seq.substr(pos))); pos = seq.find(',',pos); if (pos != std::string::npos) ++pos; } while (pos != std::string::npos);
            int ret = loadBtf(elf, b);
            std::cout << "{\"ret\":" << ret << ",\"attempts\":" << attempts;
            if (!ret) manualMaps(elf,b);
            std::cout << "}\n"; btf__free(b);
        } else if (mode == "open") {
            bpf_object_open_opts opts = {}; opts.sz = sizeof(opts); opts.bpf_token_path = "";
            bpf_object* obj = bpf_object__open_file(argv[2], &opts);
            if (!obj) { std::cout << "{\"open_errno\":" << errno << "}\n"; return 0; }
            btf* b = bpf_object__btf(obj); check(b != nullptr, "open object BTF");
            saveBtf(b, std::string(argv[3])+".btf");
            std::cout << "{\"open_errno\":0,\"maps\":[";
            bpf_map* map = nullptr; bool first = true;
            while ((map = bpf_object__next_map(obj, map))) {
                if (!first) std::cout << ','; first = false;
                std::cout << "{\"name\":"; jsonString(bpf_map__name(map));
                std::cout << ",\"internal\":" << (bpf_map__is_internal(map)?"true":"false")
                          << ",\"type\":" << bpf_map__type(map) << ",\"key_size\":" << bpf_map__key_size(map)
                          << ",\"value_size\":" << bpf_map__value_size(map) << ",\"max_entries\":" << bpf_map__max_entries(map)
                          << ",\"flags\":" << bpf_map__map_flags(map)
                          << ",\"key_type_id\":" << bpf_map__btf_key_type_id(map)
                          << ",\"value_type_id\":" << bpf_map__btf_value_type_id(map);
                if (bpf_map__btf_key_type_id(map))
                    std::cout << ",\"resolved_key_size\":" << btf__resolve_size(b,bpf_map__btf_key_type_id(map));
                if (bpf_map__btf_value_type_id(map))
                    std::cout << ",\"resolved_value_size\":" << btf__resolve_size(b,bpf_map__btf_value_type_id(map));
                std::cout << '}';
            }
            std::cout << "]}\n"; bpf_object__close(obj);
        } else if (mode == "sanitize") {
            check(argc == 5, "sanitize arguments");
            btf* b = btf__parse(argv[2], nullptr); check(b != nullptr, "parse serialized BTF");
            check(!fixture_libbpf_sanitize(b, std::stoi(argv[4])), "libbpf sanitizer");
            saveBtf(b, argv[3]); btf__free(b); std::cout << "{\"ret\":0}\n";
        } else throw std::runtime_error("unknown mode");
        return 0;
    } catch (const std::exception& e) { std::cerr << "fixture: " << e.what() << '\n'; return 2; }
}

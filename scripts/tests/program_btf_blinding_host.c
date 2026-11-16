/* SPDX-License-Identifier: GPL-2.0 */
/* Exercises production blinding/patch/clone ownership with modeled allocation,
 * random-number, capability and deferred-free services. */
/* MODEL */
#define BUILD_BUG_ON(x) _Static_assert(!(x), "build assertion")
#define BPF_REG_AX MAX_BPF_REG
#define MAX_BPF_JIT_REG (BPF_REG_AX + 1)
#define BPF_ALU64_IMM(OP, DST, IMM) ((struct bpf_insn){.code=BPF_ALU64|BPF_OP(OP)|BPF_K,.dst_reg=DST,.imm=IMM})
#define BPF_ALU32_IMM(OP, DST, IMM) ((struct bpf_insn){.code=BPF_ALU|BPF_OP(OP)|BPF_K,.dst_reg=DST,.imm=IMM})
#define BPF_ALU64_REG(OP, DST, SRC) ((struct bpf_insn){.code=BPF_ALU64|BPF_OP(OP)|BPF_X,.dst_reg=DST,.src_reg=SRC})
#define BPF_ALU32_REG(OP, DST, SRC) ((struct bpf_insn){.code=BPF_ALU|BPF_OP(OP)|BPF_X,.dst_reg=DST,.src_reg=SRC})
#define BPF_JMP_REG(OP, DST, SRC, OFF) ((struct bpf_insn){.code=BPF_JMP|BPF_OP(OP)|BPF_X,.dst_reg=DST,.src_reg=SRC,.off=OFF})
#define BPF_LD_IND(CODE, SRC, IMM) ((struct bpf_insn){.code=(CODE),.src_reg=SRC,.imm=IMM})
#define BPF_STX_MEM(SIZE, DST, SRC, OFF) ((struct bpf_insn){.code=BPF_STX|BPF_MEM|(SIZE),.dst_reg=DST,.src_reg=SRC,.off=OFF})
static unsigned get_random_int(void) { return 0x9e3779b9U; }
static bool bpf_jit_blinding_enabled(void) { return true; }
/* SUBJECT */
static struct user_struct owner = {.uid = 1000};

static struct bpf_prog *make_blind_prog(unsigned n, bool with_linfo)
{
    struct bpf_prog *p = bpf_prog_alloc(bpf_prog_size(n), 0);
    assert(p);
    p->len = n;
    p->aux->user = &owner;
    charges += p->pages;
    for (unsigned i = 0; i < n; i++)
        p->insnsi[i] = BPF_ALU64_IMM(BPF_MOV, BPF_REG_0, i + 1);
    if (with_linfo) {
        p->aux->linfo = allocate(2 * sizeof(struct bpf_line_info));
        p->aux->nr_linfo = 2;
        p->aux->linfo[0].insn_off = 0;
        p->aux->linfo[1].insn_off = n - 1;
    }
    return p;
}

static void destroy_prog(struct bpf_prog *p)
{
    bpf_prog_uncharge_memlock(p);
    __bpf_prog_free(p);
    assert(!live && !charges);
}

static void allocation_failures_restore_original(void)
{
    bool saw_error_after_rewrite = false;
    for (int fail = 1; fail <= 5; fail++) {
        struct bpf_prog *p = make_blind_prog(700, true);
        int before = alloc_calls;
        alloc_fail = before + fail;
        struct bpf_prog *q = bpf_jit_blind_constants(p);
        alloc_fail = 0;
        fprintf(stderr, "blinding allocation case %d: result=%s live=%d charges=%d\n",
                fail, IS_ERR(q) ? "error" : "success", live, charges);
        if (IS_ERR(q)) {
            assert(p->aux->prog == p);
            assert(p->aux->linfo[1].insn_off == 699);
            if (fail >= 2)
                saw_error_after_rewrite = true;
            destroy_prog(p);
        } else {
            bpf_jit_prog_release_other(q, p);
            destroy_prog(q);
        }
    }
    assert(saw_error_after_rewrite);
}

static void jit_failure_restores_original(void)
{
    struct bpf_prog *p = make_blind_prog(4, true);
    struct bpf_prog *q = bpf_jit_blind_constants(p);
    assert(!IS_ERR(q) && q != p && p->aux->linfo[1].insn_off > 3);
    bpf_jit_prog_release_other(p, q); /* architecture kept interpreter image */
    assert(p->aux->prog == p && p->aux->linfo[1].insn_off == 3);
    destroy_prog(p);
}

static void jit_success_commits_adjusted_lines(void)
{
    struct bpf_prog *p = make_blind_prog(4, true);
    struct bpf_prog *q = bpf_jit_blind_constants(p);
    assert(!IS_ERR(q) && q != p);
    unsigned adjusted = q->aux->linfo[1].insn_off;
    assert(adjusted > 3);
    bpf_jit_prog_release_other(q, p); /* architecture kept blinded image */
    assert(q->aux->prog == q && q->aux->linfo[1].insn_off == adjusted);
    destroy_prog(q);
}

static void metadata_absent_is_unchanged(void)
{
    struct bpf_prog *p = make_blind_prog(4, false);
    struct bpf_prog *q = bpf_jit_blind_constants(p);
    assert(!IS_ERR(q) && q != p && !q->aux->linfo && !q->aux->nr_linfo);
    bpf_jit_prog_release_other(q, p);
    destroy_prog(q);
}

static void metadata_absent_jit_failure_releases_growth(void)
{
    struct bpf_prog *p = make_blind_prog(700, false);
    unsigned original_pages = p->pages;
    struct bpf_prog *q = bpf_jit_blind_constants(p);
    assert(!IS_ERR(q) && q != p && q->pages > original_pages);
    bpf_jit_prog_release_other(p, q);
    assert(p->pages == original_pages && charges == (int)original_pages);
    destroy_prog(p);
}

int main(int argc, char **argv)
{
    assert(argc == 2);
    switch (strtoul(argv[1], NULL, 10)) {
    case 0: allocation_failures_restore_original(); break;
    case 1: jit_failure_restores_original(); break;
    case 2: jit_success_commits_adjusted_lines(); break;
    case 3: metadata_absent_is_unchanged(); break;
    case 4: metadata_absent_jit_failure_releases_growth(); break;
    default: assert(0);
    }
    puts("PASS blinding transaction");
    return 0;
}

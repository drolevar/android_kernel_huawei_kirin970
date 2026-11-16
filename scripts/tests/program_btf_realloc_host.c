/* SPDX-License-Identifier: GPL-2.0 */
/* Uses production allocation, patching, verifier-aux adjustment and cleanup.
 * Allocator, charges and BTF references are host models, not kernel execution. */
/* MODEL */
#define vzalloc(n) allocate(n)
#define array_size(a, b) ((size_t)(a) * (b))
/* SUBJECT */
static struct user_struct owner = {.uid = 1000};
static struct btf metadata_btf;
static void run_case(unsigned which)
{
    const unsigned page_insns = (PAGE_SIZE - sizeof(struct bpf_prog)) /
                               sizeof(struct bpf_insn);
    unsigned n = which == 3 ? 8 : page_insns;
    struct bpf_prog *p = bpf_prog_alloc(bpf_prog_size(n), 0);
    assert(p);
    p->len = n;
    p->aux->user = &owner;
    charges += p->pages;
    for (unsigned i = 0; i < n; i++) p->insnsi[i].code = 0xb7;
    metadata_btf.refcnt = 1;
    if (which != 4) {
        p->aux->btf = &metadata_btf;
        metadata_btf.refcnt++;
        p->aux->func_info = allocate(sizeof(struct bpf_func_info));
        p->aux->func_info_cnt = 1;
        p->aux->linfo = allocate(2 * sizeof(struct bpf_line_info));
        p->aux->nr_linfo = 2;
        p->aux->linfo[1].insn_off = n - 1;
    }
    struct bpf_verifier_env env = {.prog = p};
    env.insn_aux_data = allocate(n * sizeof(*env.insn_aux_data));
    env.insn_aux_data[n - 1].tag = 73;
    struct bpf_insn_aux_data *original_data = env.insn_aux_data;
    struct bpf_prog_aux *aux = p->aux;
    struct bpf_insn patch[3] = {{.code=0xb7}, {.code=0xb7}, {.code=0xb7}};
    unsigned count = which == 5 ? 1 : 3;
    /* Moving allocation first, then auxiliary-array allocation. */
    if (which == 0 || which == 3 || which == 4)
        alloc_fail = alloc_calls + 1; /* verifier aux preallocation */
    if (which == 1)
        alloc_fail = alloc_calls + 2; /* program reallocation */
    struct bpf_prog *result = bpf_patch_insn_data(&env, 0, patch, count);
    alloc_fail = 0;
    if (which == 2 || which == 5) {
        assert(result);
        env.prog = result; /* production callers install a successful patch */
        assert(env.prog->len == n + count - 1);
        assert(env.insn_aux_data[n + count - 2].tag == 73);
        if (count > 1) {
            assert(env.insn_aux_data[0].seen && env.insn_aux_data[1].seen);
            assert(env.insn_aux_data != original_data);
        } else assert(env.insn_aux_data == original_data);
    } else {
        assert(!result && env.insn_aux_data == original_data);
        /* Failure must precede instruction mutation and program ownership
         * transfer, so the verifier retains the original live image. */
        assert(env.prog == aux->prog);
        assert(env.prog->len == n);
    }
    assert(env.prog->aux == aux && aux->prog == env.prog);
    if (which != 4) {
        assert(aux->btf == &metadata_btf && metadata_btf.refcnt == 2);
        assert(aux->linfo[1].insn_off == n - 1 +
               ((which == 2) ? 2 : 0));
    }
    release(env.insn_aux_data);
    bpf_prog_uncharge_memlock(env.prog);
    __bpf_prog_free(env.prog);
    assert(metadata_btf.refcnt == 1 && !live && !charges);
}
int main(int argc, char **argv)
{
    assert(argc == 2);
    unsigned which = strtoul(argv[1], NULL, 10);
    assert(which < 6);
    run_case(which);
    printf("PASS realloc cleanup case%u\n", which);
    return 0;
}

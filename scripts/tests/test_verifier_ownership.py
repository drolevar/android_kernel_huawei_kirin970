#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Execute extracted production ownership/bounds/state logic with host allocation.
Not a kernel program loader, JIT, helper implementation or concurrency test.
"""
import argparse, hashlib, json, re, subprocess, shutil
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--mutation',choices=['bounds','aliases','prune','base','null','call','copy']);p.add_argument('--cc',required=True);p.add_argument('--keep-output',required=True,type=Path)
a=p.parse_args(); root=Path(__file__).resolve().parents[2]

def decl(text,name,kind='function'):
    if kind=='function':
        m=re.search(r'^static [\w *]+\b'+name+r'\([^;]*?\)\n\{',text,re.M)
    else:
        m=re.search(r'^(?:struct|enum) '+name+r' \{',text,re.M)
    assert m, 'missing production '+kind+': '+name
    start=m.start(); b=text.index('{',m.start());depth=1;i=b+1
    while depth:
        depth+=(text[i]=='{')-(text[i]=='}');i+=1
    return text[start:i]+(';' if kind!='function' else '')

v=(root/'kernel/bpf/verifier.c').read_text(); h=(root/'include/linux/bpf_verifier.h').read_text(); b=(root/'include/linux/bpf.h').read_text()
# No alternate implementation substitutes for missing production code.
assert 'ref_obj_id' in h, 'production ownership absent: acquired resource aliases are not tracked'
inc=(root/'kernel/bpf/verifier_refs.inc').read_text()
host=(root/'scripts/tests/verifier_ownership_host.c').read_text()
enums='\n'.join(decl(b,n,'enum') for n in ['bpf_reg_type','bpf_arg_type','bpf_return_type','bpf_access_type'])
structs='\n'.join(decl(h,n,'struct') for n in ['bpf_reg_liveness','bpf_reg_state','bpf_stack_slot_type','bpf_stack_state','bpf_reference_state','bpf_verifier_state'])
funcnames=['__mark_reg_unbounded','__mark_reg_unknown','__mark_reg_not_init','mark_reg_not_init','__mark_reg_known','__mark_reg_known_zero','copy_stack_state','realloc_verifier_state','free_verifier_state','copy_verifier_state','mark_map_reg','mark_map_regs','is_spillable_regtype','range_within','check_ids','regsafe','stacksafe','states_equal','mark_reg_unknown','mark_reg_known_zero','__is_pointer_value','is_pointer_value','coerce_reg_to_size','check_stack_write','mark_stack_slot_read','check_stack_read','check_mem_access','register_is_null','check_helper_mem_access','check_func_arg','check_raw_mode','clear_all_pkt_pointers','check_map_func_compatibility','check_call','check_cond_jmp_op']
functions='\n'.join(decl(v,n) for n in funcnames)
source=host.replace('/* TYPES */',enums+'\n'+decl(v,'bpf_call_arg_meta','struct')+'\n'+decl(b,'bpf_func_proto','struct')+'\n'+structs).replace('/* CORE */',inc+'\n'+functions)
mutations={
 'bounds':('(s64)reg->umax_value + off + size > reg->mem_size','false'),
 'aliases':('state->regs[i].ref_obj_id == id','false'),
 'prune':('if (!refsafe(old, cur))','if (false)'),
 'base':('reg->type != PTR_TO_MEM || reg->off ||','reg->type != PTR_TO_MEM ||'),
 'null':('is_null && id && regs[regno].ref_obj_id == id','is_null && id'),
 'call':('if (fn->releases_reference) {','if (false) {'),
 'copy':('memcpy(refs, src->refs, src->acquired_refs * sizeof(*refs));','memset(refs, 0, src->acquired_refs * sizeof(*refs));'),
}
if a.mutation:
 old,new=mutations[a.mutation];assert old in source;source=source.replace(old,new,1)
 if a.mutation=='null': source=source.replace('release_reference_state(state, id));','release_reference_state(state, regs[regno].ref_obj_id));',1)
a.keep_output.mkdir(parents=True,exist_ok=False)
f=a.keep_output/'production.c';f.write_text(source)
cmd=[a.cc,'-DBPF_UAPI_HEADER="'+str(root/'include/uapi/linux/bpf.h')+'"','-std=gnu11','-g','-O1','-Wall','-Wextra','-Wno-sign-compare','-Wno-unused-variable','-Werror','-Wno-unused-function','-Wno-unused-parameter','-fsanitize=address,undefined','-fno-omit-frame-pointer',str(f),'-o',str(a.keep_output/'test')]
compiler=Path(shutil.which(a.cc) or a.cc).resolve()
receipt={'source_commit':subprocess.check_output(['git','-C',str(root),'rev-parse','HEAD'],text=True).strip(),'source_dirty':bool(subprocess.check_output(['git','-C',str(root),'status','--porcelain'],text=True)),'compiler':{'path':str(compiler),'sha256':hashlib.sha256(compiler.read_bytes()).hexdigest(),'version':subprocess.check_output([a.cc,'--version'],text=True)},'mutation':a.mutation,'command':cmd,'production_sources':{},'cases':[]}
for n in ['kernel/bpf/verifier.c','kernel/bpf/verifier_refs.inc','include/linux/bpf_verifier.h','include/linux/bpf.h','include/uapi/linux/bpf.h','scripts/tests/test_verifier_ownership.py','scripts/tests/verifier_ownership_host.c']:
 receipt['production_sources'][n]=hashlib.sha256((root/n).read_bytes()).hexdigest()
r=subprocess.run(cmd,capture_output=True,text=True,timeout=60);(a.keep_output/'compile.log').write_text(r.stdout+r.stderr);receipt['compile_exit']=r.returncode
if r.returncode: print(r.stderr)
else:
 for case in ['leak','release','spill','borrowed','double','null','cast_null','copy','copy_fail','acquire_fail','bounds','release_offsets','sizes','prune','stale','overflow','multi','nullable_access','arithmetic','prototype','prune_alias','prune_bounds','zero_access','null_spill_release','calls','bad_call','access_handler','helper_bounds','pointer_write','release_call_offset','tailcall_leak','unknown_helper','default_proto','branch_eq','branch_ne','spill_fill','spill_partial']:
  r=subprocess.run([str(a.keep_output/'test'),case],capture_output=True,text=True,timeout=10)
  receipt['cases'].append({'case':case,'exit_status':r.returncode,'output':r.stdout+r.stderr}); print(case,r.returncode,r.stdout+r.stderr)
(a.keep_output/'receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
assert receipt['compile_exit']==0 and all(c['exit_status']==0 for c in receipt['cases'])

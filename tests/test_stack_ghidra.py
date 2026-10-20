"""O0–O3 stack recovery on independent two-translation-unit binaries.

Source sizes are fixture truth, never analyzer input. Recovery can infer a different
extent: each result records that discrepancy instead of treating inferred types as
ground truth. Exact rule behavior is independently asserted in test_stack_bounds.
"""
import os
import re
import subprocess

import pytest

from redesign.pipeline.bounds import analyze
from redesign.pipeline.context_worker import extract
from redesign.pipeline.inventory import ROOT, encode, read_json
from redesign.pipeline.pcode import lift


GHIDRA=os.environ.get('GHIDRA_HOME')
CASES=('safe_copy','overflow_copy','padding_byte','safe_stores','optimized_stores','ambiguous','infeasible',
       'anchored_safe','anchored_overflow')


@pytest.mark.skipif(not GHIDRA,reason='Set GHIDRA_HOME for independent stack recovery fixtures')
@pytest.mark.parametrize('optimization',('O0','O1','O2','O3'))
@pytest.mark.parametrize('case',CASES)
def test_stack_recovery_across_optimizations(tmp_path,case,optimization):
    helper='void helper(char *p) { memcpy(p,"123456789",10); }'
    if case=='overflow_copy':helper='void helper(char *p) { memcpy(p,"1234567890",11); }'
    if case=='anchored_overflow':helper='void helper(char *p) { memcpy(p,"1234567890",11); }'
    if case=='padding_byte':helper='void helper(char *p) { p[10]=0; }'
    if case in ('safe_stores','optimized_stores'):
        helper='void helper(char *p) { *(unsigned long long *)p=0x3132333435363738ULL; *(unsigned short *)(p+8)=0x3900;'
        helper+=('p[10]=0;' if case=='optimized_stores' else '')+'}'
    if case=='infeasible':helper='void helper(char *p) { if(0) memcpy(p,"1234567890",11); }'
    caller='char buffer[10]; helper(buffer); return 0;'
    if case in ('anchored_safe','anchored_overflow'):
        caller='struct { char buffer[10]; volatile unsigned short marker; } local; local.marker=7; helper(local.buffer); return local.marker;'
    if case=='ambiguous':caller='char first[10],second[10]; helper(argc>1?first:second); return 0;'
    sources=[tmp_path/'caller.c',tmp_path/'helper.c']
    sources[0].write_text('extern void helper(char *); int main(int argc,char **argv) { '+caller+' }\n')
    sources[1].write_text('#include <string.h>\n'+helper+'\n')
    objects=[]
    for source in sources:
        obj=source.with_suffix('.o');objects.append(str(obj))
        subprocess.run(['gcc-15','-'+optimization,'-fno-pie','-fno-stack-protector',
                        '-U_FORTIFY_SOURCE','-D_FORTIFY_SOURCE=0','-c',str(source),'-o',str(obj)],
                       check=True,capture_output=True)
    binary=tmp_path/'input.elf'
    subprocess.run(['gcc-15','-no-pie',*objects,'-o',str(binary)],check=True,capture_output=True)
    symbols=subprocess.check_output(['nm','-S',str(binary)],text=True)
    entry=hex(int(re.search(r'^(\w+) \w+ T main$',symbols,re.M)[1],16))
    bundle,trace=extract(binary,entry,read_json(ROOT/'context_policy.json'),tmp_path/'context')
    assert bundle['status']=='available',trace
    binary.rename(tmp_path/'excluded.elf')
    for index,source in enumerate(sources):source.rename(tmp_path/f'excluded-source-{index}')
    policy=read_json(ROOT/'baseline_policy.json');ir=lift(bundle,policy,tmp_path/'lift')
    result=analyze(bundle,ir,policy)
    truth=('vulnerable_CWE-121' if case in ('overflow_copy','padding_byte','optimized_stores','anchored_overflow') else
           'not_vulnerable')
    report={'case':case,'optimization':optimization,'source_capacity':10,'expected_binary_behavior':truth,
            'prediction':result,'recovered_stack_variables':{f['entry']:f['stack_variables'] for f in ir['functions']}}
    (tmp_path/'stack-fixture-result.json').write_text(encode(report))
    # O0 retains parameter spills with no recovered local extent. They remain an
    # explicit support limit, even for a subsequent infeasible helper write.
    if optimization=='O0':
        assert result['decision']=='uncertain',encode(report)
        assert 'missing_stack_array_extent' in result['reason_codes'],encode(report)
    elif case=='infeasible':assert result['decision']=='not_vulnerable',encode(report)
    elif case=='ambiguous':assert result['decision']=='uncertain',encode(report)
    else:
        # Known heuristic mistake: without a neighboring recovered scalar, Ghidra
        # includes padding in an 18-byte array. Preserve these false negatives.
        expected='vulnerable_CWE-121' if case=='anchored_overflow' else 'not_vulnerable'
        assert result['decision']==expected,encode(report)
        assert 'inferred_stack_object_extent' in result['reason_codes'],encode(report)
        assert any(c['bound_basis']=='inferred_stack_object_extent' for c in result['write_checks'])
        if case in ('overflow_copy','padding_byte','optimized_stores'):
            assert any(c['capacity']==18 for c in result['write_checks']),encode(report)

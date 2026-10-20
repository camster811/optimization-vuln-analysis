"""Real GCC/Ghidra fixtures; these are development data, not research corpus modifications."""
from copy import deepcopy
import os
import re
import resource
import signal
import subprocess

import pytest

from redesign.pipeline.bounds import analyze
from redesign.pipeline.bundles import normalize, string_prefix
from redesign.pipeline.context_worker import extract
from redesign.pipeline.inventory import ROOT, encode, read_json
from redesign.pipeline.pcode import lift


GHIDRA=os.environ.get('GHIDRA_HOME')
CASES=[('overflow',8,'vulnerable_CWE-122'),('safe',16,'not_vulnerable'),
       ('library_overflow',8,'vulnerable_CWE-122'),('library_safe',16,'not_vulnerable'),
       ('multiple',16,'not_vulnerable'),('unsupported',8,'uncertain'),
       ('infeasible',8,'not_vulnerable'),('missing_capacity',16,'uncertain'),
       ('format_write',2,'uncertain'),('readonly_write',8,'uncertain'),
       ('writable_overlap',8,'vulnerable_CWE-122')]


@pytest.mark.skipif(not GHIDRA,reason='Set GHIDRA_HOME for real baseline lifting/propagation fixtures')
@pytest.mark.parametrize('case,capacity,expected',CASES)
def test_real_public_only_ir_bounds_and_feasibility(tmp_path,case,capacity,expected):
    helper='void helper(char *p) { memcpy(p,"ABCDEFGHIJK",12); }'
    if case=='infeasible':helper='void helper(char *p) { if(0) memcpy(p,"ABCDEFGHIJK",12); }'
    if case=='format_write':helper='void helper(char *p) { printf("count=%n",(int *)p); }'
    if case in ('readonly_write','writable_overlap'):
        helper+='\nvoid touch(char *p) { p[0]=88; }'
    helper_source=tmp_path/'helper.c';helper_source.write_text('#include <string.h>\n#include <stdio.h>\n'+helper+'\n')
    entry_source=tmp_path/'entry.c'
    extra='char*q=malloc(8);if(!q){free(p);return 1;}' if case=='multiple' else ''
    release='free(q);' if case=='multiple' else ''
    before='rand();' if case=='unsupported' else ''
    declarations=''
    if case=='readonly_write':before='touch("read only fixture data");'
    if case=='writable_overlap':
        declarations='char fixture_data[64]="writable fixture data";'
        before='touch(fixture_data);'
    entry_source.write_text('#include <stdlib.h>\nextern void helper(char*);extern void touch(char*);'
                            +declarations+'int main(void){char*p=malloc('
                            +str(capacity)+');if(!p)return 1;'+extra+before+'helper(p);free(p);'+release+'return 0;}\n')
    objects=[]
    for source in (helper_source,entry_source):
        target=source.with_suffix('.o')
        # fno-builtin is limited to independent contract fixtures; experimental flags are unchanged.
        flags=['-U_FORTIFY_SOURCE','-D_FORTIFY_SOURCE=0','-fno-stack-protector']
        if case.startswith('library_'):flags+=['-fno-builtin']
        subprocess.run(['gcc-15','-O2','-fno-pie',*flags,'-c',str(source),'-o',str(target)],check=True,capture_output=True)
        objects.append(str(target))
    binary=tmp_path/'input.elf'
    subprocess.run(['gcc-15','-no-pie',*objects,'-o',str(binary)],check=True,capture_output=True)
    if case=='readonly_write':
        def disable_core():resource.setrlimit(resource.RLIMIT_CORE,(0,0))
        execution=subprocess.run([str(binary)],capture_output=True,preexec_fn=disable_core)
        assert execution.returncode==-signal.SIGSEGV
    symbols=subprocess.check_output(['nm','-S',str(binary)],text=True)
    selected='helper' if case=='missing_capacity' else 'main'
    entry=hex(int(re.search(r'^(\w+) \w+ T '+selected+r'$',symbols,re.M)[1],16))
    bundle,trace=extract(binary,entry,read_json(ROOT/'context_policy.json'),tmp_path/'context')
    assert bundle['status']=='available',trace
    if case=='writable_overlap':
        window=next(d for d in bundle['data'] if d['writable'] and d['size']>1)
        overlap=deepcopy(window);raw=bytes.fromhex(window['bytes'])[1:]
        overlap.update(address=hex(int(window['address'],16)+1),size=len(raw),
                       bytes=raw.hex(),string_prefix=string_prefix(raw))
        bundle['data'].append(overlap);bundle=normalize(bundle)
    # Remove original binaries and source paths before lifting: only published bytes remain usable.
    binary.rename(tmp_path/'excluded.elf');helper_source.rename(tmp_path/'excluded-helper');entry_source.rename(tmp_path/'excluded-entry')
    policy=read_json(ROOT/'baseline_policy.json')
    ir=lift(bundle,policy,tmp_path/'lift')
    result=analyze(bundle,ir,policy)
    assert result['decision']==expected,encode(result)
    if case=='unsupported':assert 'unsupported_library_call' in result['reason_codes']
    if case=='missing_capacity':assert 'unknown_destination' in result['reason_codes']
    if case=='format_write':assert 'unsupported_output_format' in result['reason_codes']
    if case=='readonly_write':
        assert result['reason_codes']==['static_write_not_writable']
        assert not any(c['outcome']=='exceeds_allocation' for c in result['write_checks'])
    if case=='writable_overlap':
        assert any(c['outcome']=='static_storage_write' for c in result['write_checks'])
    if case in ('overflow','library_overflow'):
        assert any(c['capacity']==8 and c['outcome']=='exceeds_allocation' for c in result['write_checks'])
        assert any(c['site'] not in {i['address'] for f in bundle['functions'] if f['entry']==entry for i in f['instructions']}
                   for c in result['write_checks'])
    if case=='safe':
        # Fresh reconstruction and decompilation have no original ELF/debug source to consult.
        repeated=lift(bundle,policy,tmp_path/'repeat')
        assert repeated==ir
        changed=deepcopy(bundle)
        for f in changed['functions']:f['decompilation']['text']='void function(void) { char object[1]; }'
        assert analyze(changed,ir,policy)==result

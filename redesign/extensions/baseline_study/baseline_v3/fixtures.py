"""Independent compiled fixtures, with truth kept outside public-only lifting."""
import argparse
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from pathlib import Path
import re
import subprocess

from redesign.pipeline.context_worker import extract
from redesign.pipeline.export_context import engine_identity
from redesign.pipeline.inventory import ROOT,read_json,digest,require
from redesign.pipeline.llm_runtime import write_new
from redesign.pipeline.pcode import lift
from .engine import HERE,analyze
from .worker import validate_result

CASES=('fill_safe','fill_overflow','length_safe','length_overflow','copy_safe','copy_overflow','concat_safe','concat_overflow',
       'output','unknown_capacity','stack_overflow')


def sources(case):
    headers='#include <stdlib.h>\n#include <string.h>\n#include <wchar.h>\n'
    if case.startswith('fill'):body='wmemset((wchar_t*)p,65,3);'
    elif case.startswith('length'):body=r'wmemset((wchar_t*)p,65,wcslen(L"AB\0")+1);'
    elif case in ('copy_safe','copy_overflow','unknown_capacity','stack_overflow'):body=r'wcscpy((wchar_t*)p,L"AB\0");'
    elif case.startswith('concat'):body=r'strcat(p,"abc\0paddingpadding");'
    else:body=r'wprintf(L"%ls",L"OK\0");'
    helper=headers+'void apply(char*p){'+body+'}\n'
    capacity=8 if case.endswith('overflow') else 16
    if case.startswith('concat'):capacity=5 if case.endswith('overflow') else 6
    before=r'strcpy(p,"hi\0paddingpadding");' if case.startswith('concat') else ''
    caller=headers+'extern void apply(char*);\nint main(void){char*p=malloc('+str(capacity)+');if(!p)return 1;'+before+'apply(p);free(p);return 0;}\n'
    if case=='output':caller=headers+'extern void apply(char*);int main(void){apply(0);return 0;}\n'
    if case=='stack_overflow':
        caller=headers+'extern void apply(char*);int main(void){struct{wchar_t buffer[2];volatile int marker;} s;s.marker=1;apply((char*)s.buffer);return s.marker;}\n'
    return caller,helper


def one(directory,case,opt,symbols,forcing):
    job=directory/(f'{case}-{opt}-{symbols}-'+('contract' if forcing else 'ordinary'))
    job.mkdir(parents=True,exist_ok=False)
    caller,helper=sources(case)
    commands=[]
    for name,content in (('caller',caller),('helper',helper)):
        source=job/(name+'.c');source.write_text(content)
        argv=['gcc-15','-'+opt,'-fno-pie','-fno-stack-protector','-U_FORTIFY_SOURCE','-D_FORTIFY_SOURCE=0']
        if forcing:argv+=['-fno-builtin']
        argv+=['-c',str(source),'-o',str(job/(name+'.o'))]
        subprocess.run(argv,check=True,capture_output=True);commands.append(argv)
    binary=job/'original.elf'
    subprocess.run(['gcc-15','-no-pie',str(job/'caller.o'),str(job/'helper.o'),'-o',str(binary)],check=True,capture_output=True)
    names=subprocess.check_output(['nm','-S',str(binary)],text=True)
    selected='apply' if case=='unknown_capacity' else 'main'
    entry=hex(int(re.search(r'^(\w+) \w+ T '+selected+r'$',names,re.M)[1],16))
    public=job/'analysis.elf'
    subprocess.run(['objcopy','--strip-debug',str(binary),str(public)],check=True,capture_output=True)
    if symbols=='stripped':subprocess.run(['strip','--strip-all',str(public)],check=True,capture_output=True)
    bundle,trace=extract(public,entry,read_json(ROOT/'context_policy.json'),job/'context')
    require(bundle['status']=='available','Independent fixture extraction failed')
    write_new(job/'public.json',bundle)
    # Neither lifting nor prediction receives a path to original source or ELF.
    for name in ('caller.c','helper.c','original.elf','analysis.elf','caller.o','helper.o'):
        (job/name).rename(job/('excluded-'+name))
    ir=lift(bundle,read_json(HERE/'policy.json'),job/'lift')
    result=analyze(bundle,ir,read_json(HERE/'policy.json'))
    validate_result({'schema_version':3,'method_id':'ghidra-library-contract-bounds-v3',
        'bundle_sha256':digest(job/'public.json'),'ir_sha256':digest(job/'lift/pcode.json'),
        'status':'completed','prediction':result,'error_code':None},bundle)
    repeated=None
    if case=='copy_safe' and opt=='O2' and symbols=='stripped' and forcing:
        repeated=lift(bundle,read_json(HERE/'policy.json'),job/'repeat')
        require(repeated==ir,'Independent repeat lifting differs')
        require(analyze(bundle,repeated,read_json(HERE/'policy.json'))==result,'Repeat fixture prediction differs')
    record={'case':case,'optimization':opt,'symbols':symbols,'contract_forcing':forcing,
        'declared_binary_label':'unresolved' if case=='unknown_capacity' else 'vulnerable_CWE-121' if case=='stack_overflow' else
             'vulnerable_CWE-122' if case.endswith('overflow') else 'not_vulnerable',
        'classification_support_required':opt=='O2' and forcing and case.startswith(('fill_','length_','copy_','concat_')),
        'source_private_to_predictor':True,'commands':commands,'bundle_sha256':digest(job/'public.json'),
        'ir_sha256':digest(job/'lift/pcode.json'),'prediction':result,
        'repeat_identical':True if repeated is not None else None,
        'recovered_stack_variables':{f['entry']:f['stack_variables'] for f in ir['functions']}}
    write_new(job/'fixture.json',record)
    return record


def run(directory,stage='full'):
    directory.mkdir(parents=True,exist_ok=False)
    options=('O0','O2') if stage=='smoke' else ('O0','O1','O2','O3')
    cases=('copy_safe','copy_overflow','concat_safe','concat_overflow','output') if stage=='smoke' else CASES
    forcing_options=(True,) if stage=='smoke' else (True,False)
    jobs=[(case,opt,symbols,forcing) for case in cases for opt in options
          for symbols in ('retained','stripped') for forcing in forcing_options]
    rows=[]
    with ThreadPoolExecutor(max_workers=2) as workers:
        for row in workers.map(lambda args:one(directory,*args),jobs):
            rows.append(row);print(f'{len(rows)}/{len(jobs)} {row["case"]} {row["optimization"]} {row["prediction"]["decision"]}',flush=True)
    required=[r for r in rows if r['classification_support_required']]
    require(all(r['prediction']['decision']==r['declared_binary_label'] for r in required),
            'Supported heap fixture failed safe/overflow distinction; inspect before corpus evaluation')
    report={'schema_version':1,'stage':stage,'status':'passed','observations':rows,
        'engine':engine_identity(read_json(ROOT/'context_policy.json')),
        'cases':list(cases),'matrix':{'optimization':list(options),'symbols':['retained','stripped'],'forcing':list(forcing_options)},
        'development_formats':['%ls','%ls\\n','%d %u %lc %%\\n','%n','%*ls','%1$ls','%f'],
        'stack_limit':'Heuristic recovered extents/known errors are recorded, not forced to match source sizes.',
        'flags_note':'-fno-builtin, stack volatile neighbor and trailing literal padding are independent-fixture-only; no campaign flag/source changes. Padding keeps the unchanged 16-byte unknown data window inside the ELF section.'}
    write_new(directory/'fixtures.json',report)
    return {'status':'passed','observations':len(rows)}


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--directory',type=Path,required=True)
    parser.add_argument('--stage',choices=('smoke','full'),default='full');args=parser.parse_args()
    print(run(args.directory.resolve(),args.stage))


if __name__=='__main__':main()

"""Freeze v3 only after fixture validation, then dispatch each public cell once."""
import argparse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime,timezone
import fcntl
import hashlib
from pathlib import Path
import subprocess
import shutil
import sys
import time

from redesign.pipeline import method_lock
from redesign.pipeline.export_context import engine_identity
from redesign.pipeline.inventory import ROOT,read_json,digest,require
from redesign.pipeline.llm_runtime import write_new
from redesign.pipeline.pcode import validate_ir
from .. import study
from .engine import HERE,analyze
from .worker import validate_result

BUILD=study.BUILD
RUN=BUILD/'v3-run-a'


def methods():
    paths=[p for p in HERE.rglob('*') if p.is_file() and p.suffix in ('.py','.json','.md')]
    return {p.relative_to(ROOT.parent).as_posix():digest(p) for p in sorted(paths)}


def fixture_files(directory):
    # Keep source/ELF exclusion evidence, public bytes, lifted IR and logs; omit
    # disposable Ghidra caches/profile settings from the identity inventory.
    return {p.relative_to(directory).as_posix():digest(p) for p in sorted(directory.rglob('*'))
            if p.is_file() and not any(part in ('cache','profile','settings','tmp') for part in p.relative_to(directory).parts)}


def freeze(directory,fixtures,tests):
    require(not directory.exists(),'V3 run already exists')
    original=study.verify_originals()
    study.verify(study.EXPERIMENT/'checkpoint-a-v1',check_originals=False)
    fixture=read_json(fixtures/'fixtures.json')
    require(fixture['status']=='passed' and fixture['stage']=='full' and len(fixture['observations'])==176,
            'Full independent fixture matrix incomplete')
    require(any(r['repeat_identical'] is True for r in fixture['observations']),'Independent lifting repeat missing')
    require(all(r['prediction']['decision']==r['declared_binary_label'] for r in fixture['observations']
                if r['classification_support_required']),'Supported fixture behavior failed')
    gate=study.test_gate(tests)
    require('tests/test_baseline_v3.py' in gate['test_sources'],'V3 semantic tests missing')
    macros=subprocess.check_output(['gcc-15','-dM','-E','-x','c','/dev/null'],text=True)
    require('#define __SIZEOF_WCHAR_T__ 4' in macros and '#define __SIZEOF_INT__ 4' in macros and '#define __SIZEOF_POINTER__ 8' in macros
            and '#define __SIZEOF_LONG__ 8' in macros,'Unsupported target wide-character ABI')
    identity=engine_identity(read_json(ROOT/'context_policy.json'))
    require(identity==fixture['engine'],'Fixture Ghidra/Java identity changed')
    compiler=Path(shutil.which('gcc-15')).resolve()
    directory.mkdir(parents=True)
    write_new(directory/'policy.json',read_json(HERE/'policy.json'))
    write_new(directory/'tests.xml',tests.read_text())
    write_new(directory/'fixture-report.json',fixture)
    write_new(directory/'compiler-macros.txt',macros)
    parent=read_json(study.CAMPAIGN/'release/freeze.json')
    eligibility=read_json(study.CAMPAIGN/'build/final/preflight'/parent['context_run_id']/'shared-eligibility.json')['observations']
    schedule=[]
    for row in eligibility:
        identifier=row['observation_id'];source=study.CAMPAIGN/'data/final/records'/f'{identifier}.json'
        require(digest(source)==row['bundle_sha256'],'Public bundle changed')
        write_new(directory/'inputs'/f'{identifier}.json',source.read_text())
        schedule.append({'observation_id':identifier,'bundle_sha256':row['bundle_sha256'],'shared_status':row['status'],
                         'order_sha256':hashlib.sha256(f'20261021\nbaseline-v3\n{identifier}'.encode()).hexdigest()})
    schedule.sort(key=lambda r:(r['order_sha256'],r['observation_id']))
    require(len(schedule)==160,'V3 full matrix differs')
    files=methods()
    imported={**read_json(method_lock.LOCK)['methods'],
              **{name:digest(ROOT.parent/name) for name in ('redesign/extensions/baseline_study/scoring.py',
                  'redesign/extensions/baseline_study/study.py')}}
    for name in {**files,**imported,**gate['test_sources']}:
        target=directory/'method-snapshot'/name;target.parent.mkdir(parents=True,exist_ok=True)
        with target.open('xb') as stream:stream.write((ROOT.parent/name).read_bytes())
    frozen={'schema_version':1,'method_id':'ghidra-library-contract-bounds-v3','status':'frozen_before_v3_corpus_prediction',
        'created_at_utc':datetime.now(timezone.utc).isoformat(),'post_hoc':True,'methods':files,'imported_methods':imported,
        'policy_sha256':digest(directory/'policy.json'),'engine':identity,'tests':gate,
        'compiler':{'path':str(compiler),'sha256':digest(compiler),
                    'version':subprocess.check_output([str(compiler),'--version'],text=True)},
        'python_environment':method_lock.python_environment(),
        'tests_sha256':digest(directory/'tests.xml'),'compiler_macros_sha256':digest(directory/'compiler-macros.txt'),
        'original_references':original['references'],
        'checkpoint_a_release_sha256':digest(study.EXPERIMENT/'checkpoint-a-v1/release.json'),
        'fixture_directory':str(fixtures),'fixture_files':fixture_files(fixtures),
        'fixture_report_sha256':digest(directory/'fixture-report.json'),'schedule':schedule,
        'controls':'No corpus prediction inspected for v3 while adjusting code; existing final results were inspected before this post-hoc study.'}
    write_new(directory/'freeze.json',frozen)
    for path in directory.rglob('*'):
        if path.is_file():path.chmod(path.stat().st_mode & ~0o222)
    return verify_freeze(directory)


def verify_freeze(directory):
    frozen=read_json(directory/'freeze.json')
    require(frozen['status']=='frozen_before_v3_corpus_prediction' and
            frozen['method_id']=='ghidra-library-contract-bounds-v3','Unexpected v3 freeze')
    require(frozen['methods']==methods(),'V3 changed after freeze; preserve run and declare a new revision')
    require(method_lock.python_environment()==frozen['python_environment'],'V3 Python/dependency environment differs')
    require(digest(Path(frozen['compiler']['path']))==frozen['compiler']['sha256'],'Pinned fixture compiler differs')
    method_lock.check_files(frozen['imported_methods']);method_lock.check_files(frozen['original_references'])
    require(digest(study.EXPERIMENT/'checkpoint-a-v1/release.json')==frozen['checkpoint_a_release_sha256'],
            'Checkpoint A changed')
    require(digest(directory/'policy.json')==frozen['policy_sha256'] and digest(directory/'tests.xml')==frozen['tests_sha256'],
            'V3 policy/tests changed')
    require(study.test_gate(directory/'tests.xml')==frozen['tests'],'V3 test source evidence changed')
    require(digest(directory/'compiler-macros.txt')==frozen['compiler_macros_sha256'],'Target ABI evidence changed')
    for name,sha in {**frozen['methods'],**frozen['imported_methods'],**frozen['tests']['test_sources']}.items():
        require(digest(directory/'method-snapshot'/name)==sha,'V3 method snapshot differs')
    require(digest(directory/'fixture-report.json')==frozen['fixture_report_sha256'],'Fixture evidence changed')
    fixture_root=directory/'fixture-evidence' if (directory/'fixture-evidence').exists() else Path(frozen['fixture_directory'])
    require(fixture_files(fixture_root)==frozen['fixture_files'],'Compiled fixture artifacts changed')
    require(len(frozen['schedule'])==160 and len({r['observation_id'] for r in frozen['schedule']})==160,
            'V3 inventory differs')
    require(frozen['schedule']==sorted(frozen['schedule'],key=lambda r:(r['order_sha256'],r['observation_id'])),'V3 schedule changed')
    for row in frozen['schedule']:
        require(digest(directory/'inputs'/f"{row['observation_id']}.json")==row['bundle_sha256'],'V3 public input differs')
    return {'status':'verified','observations':160,'freeze_sha256':digest(directory/'freeze.json')}


def failed(policy,sha):
    return {'schema_version':3,'method_id':policy['method_id'],'bundle_sha256':sha,'ir_sha256':None,
            'status':'runtime_failed','prediction':None,'error_code':'runtime_failure'}


def run(directory):
    with (directory/'runner.lock').open('a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        verify(directory);frozen=read_json(directory/'freeze.json');policy=read_json(directory/'policy.json')
        require(engine_identity(read_json(ROOT/'context_policy.json'))==frozen['engine'],'V3 Ghidra environment changed')
        def one(row):
            identifier=row['observation_id'];job=directory/'jobs'/identifier
            if (job/'result.json').exists():return read_json(job/'result.json')['status']
            if (job/'dispatch.json').exists():
                write_new(job/'result.json',failed(policy,row['bundle_sha256']));return 'runtime_failed'
            require(methods()==frozen['methods'] and digest(directory/'policy.json')==frozen['policy_sha256'],
                    'V3 changed before dispatch')
            require(digest(directory/'inputs'/f'{identifier}.json')==row['bundle_sha256'],'V3 input changed before dispatch')
            write_new(job/'dispatch.json',{'freeze_sha256':digest(directory/'freeze.json'),
                'bundle_sha256':row['bundle_sha256'],'started_at':datetime.now(timezone.utc).isoformat()})
            if row['shared_status']!='available':
                result=failed(policy,row['bundle_sha256']);result.update(status='input_unavailable',error_code='input_unavailable')
                write_new(job/'result.json',result);return result['status']
            began=time.monotonic()
            argv=[sys.executable,'-m','redesign.extensions.baseline_study.baseline_v3.worker',
                  '--input',str(directory/'inputs'/f'{identifier}.json'),'--policy',str(directory/'policy.json'),
                  '--work',str(job),'--output',str(job/'result.json')]
            write_new(job/'command.json',argv)
            try:
                process=subprocess.run(argv,capture_output=True,text=True,timeout=policy['process_timeout_seconds']+60)
                write_new(job/'console.log',process.stdout+process.stderr)
                require(process.returncode==0 and (job/'result.json').exists(),'V3 worker failed before durable result')
            except Exception as error:
                write_new(job/'runner-error.txt',str(error))
                if not (job/'result.json').exists():write_new(job/'result.json',failed(policy,row['bundle_sha256']))
            write_new(job/'timing.json',{'wall_seconds':time.monotonic()-began})
            validate_result(read_json(job/'result.json'),read_json(directory/'inputs'/f'{identifier}.json'))
            return read_json(job/'result.json')['status']
        counts=Counter()
        with ThreadPoolExecutor(max_workers=2) as workers:
            for status in workers.map(one,frozen['schedule']):
                counts[status]+=1;print(f'{sum(counts.values())}/160 {dict(counts)}',flush=True)
        verify(directory)
        return {'status':'terminal','counts':dict(counts)}


def verify(directory):
    verify_freeze(directory);frozen=read_json(directory/'freeze.json');policy=read_json(directory/'policy.json')
    if (directory/'jobs').exists():
        require({p.name for p in (directory/'jobs').iterdir()} <= {r['observation_id'] for r in frozen['schedule']},
                'Unexpected v3 job outside frozen inventory')
    counts=Counter()
    for row in frozen['schedule']:
        job=directory/'jobs'/row['observation_id'];path=directory/'inputs'/f"{row['observation_id']}.json"
        if not (job/'result.json').exists():
            if (job/'dispatch.json').exists():
                pending=read_json(job/'dispatch.json')
                require(pending['freeze_sha256']==digest(directory/'freeze.json') and pending['bundle_sha256']==digest(path),
                        'Incomplete V3 dispatch binding differs')
            counts['dispatched_unresolved' if (job/'dispatch.json').exists() else 'pending']+=1;continue
        dispatch=read_json(job/'dispatch.json')
        require(dispatch['freeze_sha256']==digest(directory/'freeze.json') and dispatch['bundle_sha256']==digest(path),
                'V3 dispatch binding differs')
        require(dispatch['started_at']>=frozen['created_at_utc'],'V3 prediction predates freeze')
        result=validate_result(read_json(job/'result.json'),read_json(path));counts[result['status']]+=1
        if result['status']=='completed':
            ir=read_json(job/'ir/pcode.json');validate_ir(ir,read_json(path))
            require(digest(job/'ir/pcode.json')==result['ir_sha256'],'V3 IR changed')
            require(digest(job/'ir/input.json')==row['bundle_sha256'],'V3 lifter input differs')
            require(read_json(job/'ir/policy.json')==policy,'V3 lifter policy differs')
            require(analyze(read_json(path),ir,policy)==result['prediction'],'V3 prediction does not replay')
            ablations=read_json(job/'ablations.json')
            require(set(ablations)=={'without_memory','without_output'},'V3 ablation inventory differs')
            for mode,prediction in ablations.items():
                require(analyze(read_json(path),ir,policy,mode)==prediction,'V3 ablation does not replay')
    return {'status':'verified','counts':dict(counts)}


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('action',choices=('freeze','run','verify'))
    parser.add_argument('--directory',type=Path,default=RUN);parser.add_argument('--fixtures',type=Path)
    parser.add_argument('--tests',type=Path);args=parser.parse_args();directory=args.directory.resolve()
    if args.action=='freeze':
        require(args.fixtures is not None and args.tests is not None,'Freeze requires fixtures and tests')
        result=freeze(directory,args.fixtures.resolve(),args.tests.resolve())
    elif args.action=='run':result=run(directory)
    else:result=verify(directory)
    print(result)


if __name__=='__main__':main()

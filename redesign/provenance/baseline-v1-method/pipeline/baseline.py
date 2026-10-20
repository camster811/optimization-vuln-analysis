"""Pilot baseline preparation, public-only worker execution, regeneration and private reporting."""
import argparse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import shutil
import subprocess
import sys
import time

from .baseline_worker import validate_result
from .bounds import analyze, policy_check
from .bundles import canonical
from .export_context import engine_identity
from .inventory import ROOT, check_record_inventory, digest, encode, generate, read_json, require
from .pcode import validate_ir


LIFT_METHODS=('pipeline/pcode.py','ghidra/LiftBundle.java','pipeline/context_worker.py',
              'pipeline/bundles.py','pipeline/baseline_worker.py','pipeline/baseline.py',
              'pipeline/inventory.py','schemas/bundle-v2.json','context_policy.json')
METHODS=(*LIFT_METHODS,'pipeline/bounds.py',
         'schemas/baseline-result-v1.json','baseline_policy.json')


def directory(kind, run_id):
    from .inventory import IDENTIFIER
    require(IDENTIFIER.fullmatch(run_id), 'Invalid baseline run ID')
    return ROOT / 'build/pilot' / kind / run_id


def inputs():
    policy=policy_check(read_json(ROOT/'baseline_policy.json'))
    plan=generate(read_json(ROOT/'config.json'),read_json(ROOT/'corpus/manifest.json'),ROOT,'pilot',require_assigned=True)
    hashes=check_record_inventory(plan,ROOT)
    return policy,plan,hashes


def run(mode, run_id, lift_run=None, write=False):
    started=time.monotonic()
    policy,plan,hashes=inputs()
    out=directory('baseline-lifts' if mode=='lift' else 'baseline',run_id)
    out.mkdir(parents=True,exist_ok=False)
    previous=verify_lift(lift_run) if mode=='analyze' else None
    saved={r['observation_id']:r for r in previous['observations']} if previous else {}
    report={'schema_version':1,'mode':mode,'run_id':run_id,'policy':policy,'record_hashes':hashes,
            'methods':{name:digest(ROOT/name) for name in (LIFT_METHODS if mode=='lift' else METHODS)},
            'policy_sha256':digest(ROOT/'baseline_policy.json'),'plan':plan,'observations':[]}
    if mode=='lift': report['engine']=engine_identity(read_json(ROOT/'context_policy.json'))
    else:
        report['lift_run']=lift_run
        report['lift_manifest_sha256']=digest(directory('baseline-lifts',lift_run)/'manifest.json')
    (out/'policy.json').write_text(encode(policy))
    def one(observation):
        began=time.monotonic()
        job=out/observation['observation_id'];job.mkdir()
        source=ROOT/observation['record_path'];staged=job/'input.json';shutil.copyfile(source,staged)
        output=job/'result.json'
        argv=[sys.executable,'-m','redesign.pipeline.baseline_worker',mode,'--input',str(staged),
              '--policy',str(out/'policy.json'),'--work',str(job/'ir' if mode=='lift' else job/'analysis'),
              '--output',str(output)]
        if mode=='analyze':
            prior=saved[observation['observation_id']]
            if prior['status']!='lifted':
                result=read_json(directory('baseline-lifts',lift_run)/observation['observation_id']/'result.json')
                output.write_text(encode(result))
            else:
                ir=directory('baseline-lifts',lift_run)/observation['observation_id']/'ir/pcode.json'
                argv+=['--ir',str(ir)]
        if not output.exists():
            try:
                process=subprocess.run(argv,capture_output=True,text=True,timeout=policy['process_timeout_seconds']+60)
                (job/'console.log').write_text(process.stdout+process.stderr)
                require(process.returncode==0 and output.is_file(),'Baseline worker failed before recording a disposition')
                validate_result(read_json(output),read_json(staged))
            except Exception as error:
                (job/'failure.txt').write_text(str(error)+'\n')
                output.write_text(encode({'schema_version':1,'method_id':policy['method_id'],
                    'bundle_sha256':digest(staged),'ir_sha256':None,'status':'runtime_failed',
                    'prediction':None,'error_code':'runtime_failure'}))
        result=read_json(output);validate_result(result,read_json(staged))
        return {**observation,'status':result['status'],'result_sha256':digest(output),
                'bundle_sha256':digest(staged),'ir_sha256':result['ir_sha256'],
                'wall_seconds':round(time.monotonic()-began,6),
                'decision':result['prediction']['decision'] if result['prediction'] else None}
    with ThreadPoolExecutor(max_workers=2) as workers:
        for row in workers.map(one,plan['observations']):
            report['observations'].append(row)
            (out/'manifest.json').write_text(encode(report))
            print(f"{len(report['observations'])}/{len(plan['observations'])} {row['status']} {row['decision'] or ''}",flush=True)
    report['counts']=dict(Counter(r['status'] for r in report['observations']))
    report['wall_seconds']=round(time.monotonic()-started,6)
    (out/'manifest.json').write_text(encode(report))
    if mode=='analyze':
        verify(run_id)
        if write: publish(report)
    else: verify_lift(run_id)
    return report


def common(report,kind,run_id,names):
    policy,plan,hashes=inputs()
    require(report['schema_version']==1 and report['run_id']==run_id and report['plan']==plan
            and report['record_hashes']==hashes,'Baseline plan/input identity differs')
    require(report['methods']=={n:digest(ROOT/n) for n in names},'Baseline methods changed')
    # Lifting signatures and limits are inputs too; changing them requires a fresh lift.
    require(report['policy']==policy and report['policy_sha256']==digest(ROOT/'baseline_policy.json'),'Baseline policy changed')
    require(read_json(directory(kind,run_id)/'policy.json')==policy,'Staged baseline policy changed')
    rows=report['observations']
    require(len(rows)==len(plan['observations']) and [{k:r[k] for k in o} for r,o in zip(rows,plan['observations'])]
            ==plan['observations'],'Baseline inventory missing, duplicate or unexpected')
    for row in rows:
        job=directory(kind,run_id)/row['observation_id'];bundle=read_json(job/'input.json')
        require(digest(job/'input.json')==row['bundle_sha256']==hashes[row['record_path']], 'Staged public input changed')
        require(digest(job/'result.json')==row['result_sha256'],'Baseline result changed')
        result=read_json(job/'result.json');validate_result(result,bundle)
        require(row['status']==result['status'] and row['ir_sha256']==result['ir_sha256']
                and row['decision']==(result['prediction']['decision'] if result['prediction'] else None),'Baseline row differs')
    require(report['counts']==dict(Counter(r['status'] for r in rows)),'Baseline status counts differ')
    return report


def verify_lift(run_id):
    out=directory('baseline-lifts',run_id);report=common(read_json(out/'manifest.json'),'baseline-lifts',run_id,LIFT_METHODS)
    require(report['mode']=='lift' and all(r['status'] in ('lifted','runtime_failed','input_unavailable') for r in report['observations']), 'Invalid lifting disposition')
    for row in report['observations']:
        if row['status']=='lifted':
            path=out/row['observation_id']/'ir/pcode.json'
            require(digest(path)==row['ir_sha256'],'P-code changed')
            validate_ir(read_json(path),read_json(out/row['observation_id']/'input.json'))
    for name,expected in report['engine']['files'].items():
        require(digest(Path(report['engine']['home'])/name)==expected,'Ghidra lifting environment changed')
    require(digest(report['engine']['java']['path'])==report['engine']['java']['sha256'],'Java lifting environment changed')
    return report


def verify(run_id):
    out=directory('baseline',run_id);report=common(read_json(out/'manifest.json'),'baseline',run_id,METHODS)
    require(report['mode']=='analyze' and all(r['status'] in ('completed','runtime_failed','input_unavailable') for r in report['observations']), 'Invalid prediction disposition')
    lift=verify_lift(report['lift_run']);by_id={r['observation_id']:r for r in lift['observations']}
    require(report['lift_manifest_sha256']==digest(directory('baseline-lifts',report['lift_run'])/'manifest.json'),'Lifting manifest changed')
    for row in report['observations']:
        if row['status']=='completed':
            path=directory('baseline-lifts',report['lift_run'])/row['observation_id']/'ir/pcode.json'
            require(row['ir_sha256']==by_id[row['observation_id']]['ir_sha256']==digest(path),'Prediction P-code differs')
            result=read_json(out/row['observation_id']/'result.json')
            regenerated=analyze(read_json(out/row['observation_id']/'input.json'),read_json(path),report['policy'])
            require(result['prediction']==regenerated,'Saved baseline prediction does not regenerate')
    return report


def predictions(report):
    out=directory('baseline',report['run_id'])
    return [{**read_json(out/r['observation_id']/'result.json'),'observation_id':r['observation_id']}
            for r in report['observations']]


def publish(report):
    path=ROOT/'results/pilot/baseline'/f"{report['run_id']}.json"
    path.parent.mkdir(parents=True,exist_ok=True)
    text=encode(predictions(report))
    require(not path.exists() or path.read_text()==text,'Existing baseline results differ; preserve them')
    path.write_text(text)


def audit(run_id,write=False):
    report=verify(run_id);rows=predictions(report)
    result={'schema_version':1,'phase':5,'run_id':run_id,'methods':report['methods'],'policy':report['policy'],
            'manifest_sha256':digest(directory('baseline',run_id)/'manifest.json'),
            'counts':report['counts'],'decisions':dict(Counter(r['prediction']['decision'] for r in rows if r['prediction'])),
            'reason_codes':dict(Counter(c for r in rows if r['prediction'] for c in r['prediction']['reason_codes'])),
            'record_hashes':report['record_hashes'],'regeneration':'passed','predictions':rows}
    lift=verify_lift(report['lift_run'])
    result['engine']=lift['engine']
    result['lift_manifest_sha256']=report['lift_manifest_sha256']
    result['wall_seconds']={'lifting':lift['wall_seconds'],'prediction':report['wall_seconds']}
    # Private evaluation is separate from both the worker and IR preparation.
    oracle={r['build_id']:r for r in read_json(ROOT/'corpus/private/pilot-oracle.json')['reviews']}
    by_id={r['observation_id']:r for r in report['observations']}
    classified=[r for r in rows if r['prediction'] and r['prediction']['status']=='classified']
    result['pilot_review']={'classified':len(classified),
                           'correct_classifications':sum(r['prediction']['decision']==oracle[by_id[r['observation_id']]['build_id']]['binary_label'] for r in classified),
                           'not_final_effect_estimation':True}
    if write:(ROOT/'provenance/phase5-validation.json').write_text(encode(result))
    return result


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action',choices=('lift','predict','verify','audit'))
    parser.add_argument('--run-id',required=True)
    parser.add_argument('--lift-run')
    parser.add_argument('--write',action='store_true')
    args=parser.parse_args()
    if args.action=='lift':result=run('lift',args.run_id)
    elif args.action=='predict':
        require(args.lift_run,'Specify the preserved --lift-run')
        result=run('analyze',args.run_id,args.lift_run,args.write)
    elif args.action=='verify':result=verify(args.run_id)
    else:result=audit(args.run_id,args.write)
    print(encode({k:v for k,v in result.items() if k in ('counts','decisions','reason_codes','regeneration','pilot_review')}),end='')


if __name__=='__main__':main()

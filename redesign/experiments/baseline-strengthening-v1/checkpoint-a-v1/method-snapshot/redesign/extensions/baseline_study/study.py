"""Checkpoint A: immutable supplementary controls, scoring and publication.

Run/checkpoint publications are exclusive. Verify regenerates every comparison
byte from saved evaluation/eligibility inputs and checks original identities.
No LLM transport or baseline lifting is called by this extension.
"""
import argparse
from datetime import datetime, timezone
import gzip
import io
from pathlib import Path
import shutil
import tarfile
import xml.etree.ElementTree as ET

from redesign.pipeline import context_campaign, final_run, method_lock, phase9_closeout
from redesign.pipeline.bundles import canonical
from redesign.pipeline.final_freeze import verify_archive
from redesign.pipeline.inventory import ROOT, IDENTIFIER, digest, read_json, require
from redesign.pipeline.llm_runtime import write_new
from . import controls, reporting, scoring

HERE = Path(__file__).resolve().parent
BUILD = ROOT/'build/extensions/baseline-study'
EXPERIMENT = ROOT/'experiments/baseline-strengthening-v1'
CAMPAIGN = context_campaign.AMENDED
PLAN = ROOT.parent/'documentation/juliet-redesign/baseline_strengthening_plan.md'
TESTS = ROOT.parent/'tests/test_baseline_study.py'


def method_files():
    paths = sorted(HERE.glob('*.py')) + [ROOT/'extensions/__init__.py']
    return {p.relative_to(ROOT.parent).as_posix(): digest(p) for p in paths}


def historical_references():
    paths = [method_lock.LOCK, context_campaign.CAMPAIGN/'release/freeze.json',
             context_campaign.CAMPAIGN/'release/final-v1-inputs.tar.gz',
             CAMPAIGN/'release/freeze.json', CAMPAIGN/'release/final-v2-context12288-inputs.tar.gz',
             CAMPAIGN/'release/phase9-results.json', CAMPAIGN/'release/phase9-results.tar.gz',
             CAMPAIGN/'provenance/phase9-execution.json', CAMPAIGN/'build/final/llm-runs/phase9-a/manifest.json',
             CAMPAIGN/'corpus/private/final-oracle.json']
    paths += sorted((CAMPAIGN/'results/final/phase9-a').glob('*.*'))
    return {p.relative_to(ROOT.parent).as_posix(): digest(p) for p in paths}


def verify_originals():
    locked = method_lock.verify()
    frozen = context_campaign.verify()
    package = phase9_closeout.verify_package(CAMPAIGN)
    # Includes execution, raw response/majority replay, baseline IR regeneration,
    # core analysis and supplemental tables/figures, without a model server.
    checked = phase9_closeout.closeout(CAMPAIGN, CAMPAIGN/'build/final/llm-runs/phase9-a',
                                     CAMPAIGN/'results/final/phase9-a', check=True)
    return {'method_lock': locked, 'input_freeze': frozen, 'results_package': package,
            'analysis_regeneration': checked['status'], 'references': historical_references()}


def test_gate(path):
    tree = ET.parse(path).getroot()
    cases = list(tree.iter('testcase'))
    require(cases and not any(list(tree.iter(tag)) for tag in ('failure','error','skipped')),
            'Supplement test gate failed or skipped')
    require(any('test_baseline_study' in c.get('classname','') for c in cases), 'Missing checkpoint A tests')
    sources = {}
    for case in cases:
        module = next((part for part in case.get('classname','').split('.') if part.startswith('test_')), None)
        require(module is not None, 'Unidentified test source')
        source = ROOT.parent/'tests'/f'{module}.py'
        require(source.is_file(), 'Test source unavailable')
        sources[source.relative_to(ROOT.parent).as_posix()] = digest(source)
    require('tests/test_baseline_study.py' in sources, 'Missing control/scoring regression source')
    return {'tests':len(cases),'failures':0,'errors':0,'skipped':0,
            'report_sha256':digest(path),'test_sources':sources}


def artifacts(historical, eligibility):
    require(historical['bootstrap']['replicates']==10000 and historical['bootstrap']['seed']==20261019 and
            historical['bootstrap']['generator']=='PCG64', 'Historical bootstrap settings differ')
    rows = historical['rows']
    require(len(rows)==160 and len(eligibility)==160 and
            {r['observation_id']:r['status'] for r in eligibility} ==
            {r['observation_id']:r['shared_availability'] for r in rows}, 'Shared control inventory differs')
    predictions = controls.generate(eligibility)
    comparison = scoring.evaluate(rows)
    scoring.verify_historical(comparison, historical)
    counts = scoring.verify_counts(comparison)
    generated = {r['observation_id']: r['predictions'] for r in predictions}
    require(all({m:r['predictions'][m] for m in controls.CONTROL_LABELS} == generated[r['observation_id']]
                for r in comparison['rows']), 'Private scoring join changed a control')
    return {'controls/predictions.json':canonical(predictions), 'comparison.json':canonical(comparison),
            'comparison.csv':reporting.csv_report(comparison), 'report.md':reporting.report_text(comparison),
            'claims.md':reporting.claims(comparison),
            'acceptance.json':canonical({'status':'checkpoint_A_passed','historical_metrics_and_intervals':'identical',
                'control_inventory':{m:len(predictions) for m in controls.CONTROL_LABELS},
                'independent_counts':counts,'new_llm_requests':0,'new_lifting_runs':0,'post_hoc':True})}


def file_inventory(directory):
    return {p.relative_to(directory).as_posix():digest(p) for p in sorted(directory.rglob('*'))
            if p.is_file() and p.relative_to(directory).as_posix() not in
            ('study-manifest.json','release.json','checkpoint-a.tar.gz')}


def run(run_id, tests):
    require(IDENTIFIER.fullmatch(run_id), 'Invalid supplementary run ID')
    directory = BUILD/run_id
    require(not directory.exists(), 'Supplementary run ID already exists; verify instead')
    require(not (EXPERIMENT/run_id).exists(), 'Supplementary publication already exists')
    # Preserve these hashes before any extension artifacts or scores are made.
    before = verify_originals()
    gate = test_gate(tests)
    directory.mkdir(parents=True, exist_ok=False)
    write_new(directory/'original-verification.json', before)
    source = CAMPAIGN/'results/final/phase9-a/evaluation.json'
    write_new(directory/'evaluation-inputs/phase9-evaluation.json', source.read_text())
    frozen = read_json(CAMPAIGN/'release/freeze.json')
    public = read_json(CAMPAIGN/'build/final/preflight'/frozen['context_run_id']/'shared-eligibility.json')
    eligibility = [{'observation_id':r['observation_id'],'status':r['status']} for r in public['observations']]
    write_new(directory/'control-inputs/eligibility.json', eligibility)
    write_new(directory/'tests.xml', Path(tests).read_text())
    write_new(directory/'study-plan.md', PLAN.read_text())
    methods = method_files()
    snapshot = {**methods, **gate['test_sources']}
    for name in snapshot:
        write_new(directory/'method-snapshot'/name, (ROOT.parent/name).read_text())
    output = artifacts(read_json(source), eligibility)
    for name, value in output.items(): write_new(directory/name, value)
    require(before['references']==historical_references(), 'Historical artifact changed during supplement')
    manifest = {'schema_version':1,'study':'baseline-strengthening-v1','checkpoint':'A',
        'run_id':run_id,'status':'checkpoint_A_passed','post_hoc':True,
        'created_at_utc':datetime.now(timezone.utc).isoformat(), 'new_llm_requests':0,'new_lifting_runs':0,
        'method_files':methods,'tests':gate,'study_plan_sha256':digest(PLAN),
        'original_references':before['references'], 'files':file_inventory(directory),
        'scoring_definition':'Explicit method IDs; unchanged frozen outcomes/statistics/interval; same 10,000 PCG64 family draws, seed 20261019.',
        'private_evaluation_inputs':True,'control_inputs':'Only control-inputs/eligibility.json; private labels/saved outputs join afterward in evaluator.',
        'scope':'Checkpoint A only; no v3 engine/library-contract implementation or evaluation.'}
    write_new(directory/'study-manifest.json', manifest)
    verify(directory, check_originals=False)
    return publish(directory)


def verify(directory, check_originals=True):
    manifest = read_json(directory/'study-manifest.json')
    require(manifest['status']=='checkpoint_A_passed' and manifest['checkpoint']=='A', 'Unexpected study manifest')
    require(manifest['method_files']==method_files(), 'Supplement implementation changed; preserve the version')
    require(file_inventory(directory)==manifest['files'], 'Supplement inventory/content differs')
    require(test_gate(directory/'tests.xml')==manifest['tests'], 'Supplement test evidence differs')
    require(digest(directory/'study-plan.md')==manifest['study_plan_sha256'], 'Study plan snapshot differs')
    method_lock.check_files(manifest['original_references'])
    for name, sha in {**manifest['method_files'], **manifest['tests']['test_sources']}.items():
        require(digest(directory/'method-snapshot'/name)==sha, 'Supplement source snapshot differs')
    historical = read_json(directory/'evaluation-inputs/phase9-evaluation.json')
    require(digest(directory/'evaluation-inputs/phase9-evaluation.json') ==
            manifest['original_references'][(CAMPAIGN/'results/final/phase9-a/evaluation.json').relative_to(ROOT.parent).as_posix()],
            'Historical evaluation snapshot differs')
    eligibility = read_json(directory/'control-inputs/eligibility.json')
    for name, content in artifacts(historical, eligibility).items():
        require((directory/name).read_bytes()==content.encode('utf-8'), f'Supplement does not regenerate: {name}')
    if check_originals:
        checked = verify_originals()
        require(checked['references']==manifest['original_references'], 'Historical references changed')
    if (directory/'release.json').exists(): verify_release(directory)
    return {'status':'verified','checkpoint':'A','run_id':manifest['run_id'],
            'historical_hashes':'unchanged','supplement_regeneration':'identical bytes'}


def publish(directory):
    manifest = read_json(directory/'study-manifest.json')
    destination = EXPERIMENT/manifest['run_id']
    require(not destination.exists(), 'Publication exists; refusing replacement')
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(directory, destination)
    files = {p.relative_to(destination).as_posix():digest(p) for p in sorted(destination.rglob('*')) if p.is_file()}
    archive_path = destination/'checkpoint-a.tar.gz'
    with archive_path.open('xb') as stream:
        with gzip.GzipFile(filename='',fileobj=stream,mode='wb',mtime=0) as compressed:
            with tarfile.open(fileobj=compressed,mode='w') as archive:
                for name in files:
                    content=(destination/name).read_bytes()
                    item=tarfile.TarInfo(name);item.size=len(content);item.mode=0o444
                    archive.addfile(item,io.BytesIO(content))
    release = {'schema_version':1,'study':'baseline-strengthening-v1','checkpoint':'A',
               'run_id':manifest['run_id'],'archive':'checkpoint-a.tar.gz','archive_sha256':digest(archive_path),
               'study_manifest_sha256':digest(destination/'study-manifest.json'),'files':files,
               'private_evaluation_inputs':True,'replay':'Same repository original releases/methods/environment; no model server or new lifting.'}
    write_new(destination/'release.json',release)
    verify_release(destination)
    for path in destination.rglob('*'):
        if path.is_file(): path.chmod(path.stat().st_mode & ~0o222)
    return {'status':'checkpoint_A_passed','publication':str(destination),
            'archive_sha256':release['archive_sha256'],'tests':manifest['tests']['tests']}


def verify_release(directory):
    release=read_json(directory/'release.json')
    require(release['study_manifest_sha256']==digest(directory/'study-manifest.json'), 'Release manifest changed')
    require(digest(directory/release['archive'])==release['archive_sha256'], 'Supplement archive changed')
    method_lock.check_files(release['files'],directory)
    verify_archive(directory/release['archive'],release['files'])


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action',choices=('run','verify'))
    parser.add_argument('--run-id',default='checkpoint-a-v1')
    parser.add_argument('--directory',type=Path)
    parser.add_argument('--tests',type=Path)
    args=parser.parse_args()
    require(IDENTIFIER.fullmatch(args.run_id), 'Invalid study run ID')
    if args.action=='run':
        require(args.tests is not None and args.directory is None, 'Run requires --tests, without --directory')
        result=run(args.run_id,args.tests.resolve())
    else: result=verify(args.directory.resolve() if args.directory else EXPERIMENT/args.run_id)
    print(canonical(result))


if __name__=='__main__':main()

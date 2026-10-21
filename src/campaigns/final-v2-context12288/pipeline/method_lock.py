"""Phase 7 method lock: immutable methods and pilot evidence, not a final-input freeze."""
import argparse
from datetime import datetime, timezone
import gzip
import io
import importlib.metadata
import sys
from pathlib import Path
import tarfile

from . import evaluate, run_llm
from .inventory import ROOT, digest, generate, read_json, require
from .llm_runtime import write_new

LOCK = ROOT/'provenance/method-lock.json'


def method_files():
    files = set()
    for directory in ('pipeline', 'ghidra', 'schemas', 'llm'):
        files.update(p for p in (ROOT/directory).rglob('*') if p.is_file() and '__pycache__' not in p.parts and p.suffix != '.pyc')
    files.update(ROOT/name for name in ('config.json', 'context_policy.json', 'baseline_policy.json', 'llm_policy.json'))
    files.update(ROOT.parent/'pipeline'/name for name in ('run_llm.py','serve_llm.py','runtime.py'))
    docs = ROOT.parent/'documentation/juliet-redesign'
    files.update(docs/name for name in ('analysis_plan.md','selection_spec.md','candidate_families.csv',
        'candidate_snapshot.json','context_bundle_spec.md','baseline_spec.md','phase7_decisions.md'))
    return {p.relative_to(ROOT.parent).as_posix(): digest(p) for p in sorted(files)}


def runtime_configuration(server):
    """A new final server may have a new PID; computational settings must match."""
    return {**{key: server[key] for key in ('policy_sha256','model_sha256','props','libraries','source','gpu_layers','flash_attention')},
            'binary_sha256':server['process']['binary_sha256']}


def python_environment():
    return {'version': sys.version, 'executable_sha256': digest(Path(sys.executable).resolve()),
            'packages': {name: importlib.metadata.version(name) for name in ('numpy','jsonschema','requests','urllib3')}}


def check_files(files, root=ROOT.parent):
    for name, expected in files.items():
        path = (root/name).resolve()
        require(path.is_relative_to(root.resolve()) and path.is_file() and digest(path)==expected,
                f'Locked artifact changed: {name}')


def archive_run(run, output):
    files = sorted(p for p in run.rglob('*') if p.is_file() and p.name != 'runner.lock' and not p.name.startswith('.pending-'))
    with output.open('xb') as stream:
        with gzip.GzipFile(filename='',mode='wb',fileobj=stream,mtime=0) as compressed:
            with tarfile.open(fileobj=compressed,mode='w') as archive:
                for path in files:
                    content = path.read_bytes()
                    item = tarfile.TarInfo(path.relative_to(run).as_posix()); item.size=len(content); item.mode=0o644
                    archive.addfile(item,io.BytesIO(content))
    return digest(output)


def create(run, evaluation_path, rebuild_path, tests_path):
    run, evaluation_path, rebuild_path, tests_path = (p.resolve() for p in (run, evaluation_path, rebuild_path, tests_path))
    require(not LOCK.exists(), 'Method lock already exists')
    report = evaluate.pilot(run)
    require(report == read_json(evaluation_path), 'Published evaluation does not reproduce')
    require(len(report['rows'])==32 and sum(report['compute']['attempt_statuses'].values())==96, 'Incomplete pilot')
    rebuild = read_json(rebuild_path)
    require(rebuild['status']=='verified' and len(rebuild['builds'])==16 and len(rebuild['records'])==32,
            'Incomplete independent rebuild')
    require(all(all(b['artifacts_identical'].values()) and b['private_evidence_identical'] for b in rebuild['builds'])
            and all(r['identical'] for r in rebuild['records']), 'Rebuild mismatch')
    require({r['observation_id']:r['sha256'] for r in rebuild['records']} ==
            {r['observation_id']:r['bundle_sha256'] for r in report['rows']}, 'Rebuild input binding mismatch')
    for name, expected in rebuild['methods'].items():
        require(digest(ROOT/name)==expected, 'Rebuild method changed')
    require(rebuild['oracle_sha256']==report['inputs']['oracle_sha256'], 'Rebuild reviewed different truth')
    rebuild_archive = ROOT/rebuild['archive']
    require(digest(rebuild_archive)==rebuild['archive_sha256'], 'Rebuild archive changed')
    tests = read_json(tests_path)
    require(tests['exit_code']==0 and tests['skipped']==0 and tests['ghidra_enabled'] is True, 'Full test gate incomplete')
    check_files(tests['test_sources'])
    decisions = ROOT.parent/'documentation/juliet-redesign/phase7_decisions.md'
    require(decisions.is_file(), 'Missing explicit method-lock decisions')
    manifest, server = run_llm.validate_manifest(run, ROOT)
    archive = ROOT/'provenance/llm/phase7-pilot.tar.gz'
    archive_hash = archive_run(run, archive)
    evidence_paths = [evaluation_path, rebuild_path, rebuild_archive, tests_path, archive, ROOT/'provenance/phase4-validation.json',
        ROOT/'provenance/phase5-validation.json', ROOT/'provenance/phase5-v2-stack-fixtures.json',
        ROOT/'provenance/phase6-validation.json', ROOT/'corpus/private/pilot-oracle.json', ROOT/'corpus/manifest.json',
        ROOT/'results/pilot/baseline/phase5-v2-c.json', ROOT/'provenance/phase5-pcode.json', ROOT/'provenance/phase5-pcode.tar.gz']
    final_plan = generate(read_json(ROOT/'config.json'), read_json(ROOT/'corpus/manifest.json'), ROOT, 'final')
    lock = {'schema_version':1,'lock_id':'juliet-redesign-methods-v1','status':'locked_after_pilot',
        'created_at_utc':datetime.now(timezone.utc).isoformat(), 'final_input_freeze':False,
        'final_inference_authorized':False, 'methods':method_files(),
        'pilot_evidence':{p.relative_to(ROOT.parent).as_posix():digest(p) for p in evidence_paths},
        'pilot_archive_sha256':archive_hash, 'pilot_run_manifest_sha256':digest(run/'manifest.json'),
        'runtime_configuration':runtime_configuration(server), 'python_environment':python_environment(), 'runtime_process_is_campaign_specific':True,
        'pilot_hardware':read_json(ROOT/'provenance/phase6-validation.json')['hardware_measurement'],
        'method_ids':{'baseline':'ghidra-inferred-stack-bounds-v2','llm':manifest['policy']['method_id']},
        'development_families':sorted({r['family_id'] for r in report['rows']}),
        'additional_development_inputs':['independent native/Ghidra regression fixtures in tests; not final candidates'],
        'final_matrix':{**final_plan['counts'], 'families':final_plan['counts']['pairs']},
        'shared_eligibility':'Exact frozen prompt/template tokens plus 4096 <= 8192; otherwise context_unavailable for both methods.',
        'claim_limits':['heuristic baseline with explicit abstentions and known stack false negatives',
                        'classification conditional on private-assisted localization',
                        'two pilot families do not estimate final effect size', 'no independent human oracle adjudication'],
        'chronology':'Local timestamp and immutable hashes; no independent timestamped deposit or external preregistration.'}
    write_new(LOCK, lock)
    return verify()


def verify():
    lock = read_json(LOCK)
    require(lock['status']=='locked_after_pilot' and lock['final_input_freeze'] is False, 'Unexpected method lock')
    require(lock['python_environment']==python_environment(), 'Python/dependency environment changed')
    check_files(lock['methods']); check_files(lock['pilot_evidence'])
    require(set(lock['methods']) <= set(method_files()), 'Locked method file removed')
    return {'status':'verified','lock_id':lock['lock_id'],'method_files':len(lock['methods']),
            'pilot_evidence_files':len(lock['pilot_evidence']),'final_input_freeze':False}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action',choices=['create','verify'])
    parser.add_argument('--run-directory',type=Path)
    parser.add_argument('--evaluation',type=Path)
    parser.add_argument('--rebuild',type=Path)
    parser.add_argument('--tests',type=Path)
    args=parser.parse_args()
    if args.action=='verify': result=verify()
    else:
        require(all((args.run_directory,args.evaluation,args.rebuild,args.tests)), 'Creation requires pilot, evaluation, rebuild and tests')
        result=create(args.run_directory,args.evaluation,args.rebuild,args.tests)
    print(result)


if __name__=='__main__': main()

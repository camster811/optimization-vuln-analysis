"""Phase 8: final input preflight and content-addressed release, without predictions.

Only llm_runtime.budget reaches the model server (template/tokenizer endpoints).
The private audit never becomes part of payload() or public eligibility records.
"""
import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import io
from pathlib import Path
import tarfile

from . import build, export_context, llm, llm_runtime, method_lock, oracle, sanitize
from .bundles import canonical, validate
from .run_llm import wire
from .final_sources import CAMPAIGN, select
from .inventory import ROOT, digest, generate, read_json, require


def now():
    return datetime.now(timezone.utc).isoformat()


def no_predictions(root):
    for directory in (root/'results/final', root/'build/final/llm-runs'):
        require(not directory.exists() or not any(p.is_file() for p in directory.rglob('*')),
                'Final predictions already exist; cannot assert a pre-prediction freeze')


def check_methods(root):
    method_lock.verify()
    lock = read_json(method_lock.LOCK)
    for name, expected in lock['methods'].items():
        path = Path(name)
        if path.parts[0] == 'redesign':
            relative = Path(*path.parts[1:])
            require(digest(root/relative) == expected, f'Campaign method changed: {relative}')
    return lock


def check_sources(root):
    selection = read_json(root/'corpus/final_selection.json')
    require(selection == select(read_json(root/'corpus/private/prior-adaptation-ledger.json')),
            'Final source selection differs from locked ordering/exclusions')
    pairs = [p for p in read_json(root/'corpus/manifest.json')['pairs'] if p['split']=='final']
    require([p['family_id'] for p in sorted(pairs,key=lambda p:p['pair_id'])] ==
            [r['family_id'] for r in selection['selected']], 'Final families differ from selection')
    plan = generate(read_json(root/'config.json'), read_json(root/'corpus/manifest.json'), root, 'final', True)
    require(plan['counts'] == {'pairs':10,'reference_builds':80,'observations':160,'inference_slots':480},
            'Final matrix differs')
    for pair in read_json(root/'corpus/manifest.json')['pairs']:
        if pair['split'] != 'final':
            continue
        transform = read_json(root/pair['sanitization_manifest'])
        for row in transform['files']:
            original, cleaned = root/row['original'], root/row['sanitized']
            require(digest(original) == row['original_sha256'] and digest(cleaned) == row['sanitized_sha256'],
                    'Source transformation hash differs')
            require(original.stat().st_mode & 0o222 == 0, 'Upstream original is not read-only')
            sanitize.verify_preservation(original.read_text(), cleaned.read_text(), row['identifiers'],
                                         transform['includes'], transform['diagnostics'])
            sanitize.scan_metadata(cleaned.read_text())
        for path_key, hash_key in [('diff_path','diff_sha256'),('harness','harness_sha256')]:
            require(digest(root/transform[path_key]) == transform[hash_key], 'Source provenance changed')
    return plan


def check_audit(audit):
    require(audit['oracle_coverage_gate'], 'Public scope omits oracle evidence')
    require(audit['scope_parity_gate'], 'Retained/stripped code/data scopes differ')
    # Unavailable extraction is a declared disposition, not a reason to replace a family.
    require(len(audit['observations']) == 160 and len(audit['symbol_partners']) == 80,
            'Incomplete final context audit')


def slot_name(slot):
    return f"{slot['observation_id']}-{slot['repetition']}"


def preflight(root=CAMPAIGN, run_id='phase8-a', server_path=None):
    no_predictions(root)
    lock = check_methods(root)
    plan = check_sources(root)
    audit = export_context.audit_run(root, 'final', run_id)
    check_audit(audit)
    policy, prompt, schema = llm.settings(root)
    server_path = server_path or ROOT/'build/pilot/llm-runtime/phase6-a/server.json'
    server = read_json(server_path)
    llm_runtime.verify_live(server, policy)
    require(method_lock.runtime_configuration(server) == lock['runtime_configuration'], 'Locked runtime differs')
    target = root/'build/final/preflight'/run_id
    target.mkdir(parents=True, exist_ok=False)
    llm_runtime.write_new(target/'server.json', server)
    for name in ('launch.json','startup.log'):
        source = server_path.parent/name
        if source.is_file():
            llm_runtime.write_new(target/('runtime-'+name), source.read_text())
    llm_runtime.write_new(target/'context-audit.json', audit)
    rows = []
    by_id = {r['observation_id']:r for r in plan['observations']}
    for slot in plan['inference_slots']:
        observation = by_id[slot['observation_id']]
        bundle = read_json(root/observation['record_path'])
        validate(bundle)
        name = slot_name(slot)
        row = {**slot, 'bundle_sha256':digest(root/observation['record_path'])}
        if bundle['status'] != 'available':
            row.update(status='context_unavailable', reason='extraction_unavailable', request=None, budget=None)
        else:
            request = llm.payload(bundle, prompt, schema, policy, slot['repetition'])
            budget = llm_runtime.budget(request, policy)
            request_path, budget_path = f'requests/{name}.json', f'budgets/{name}.json'
            llm_runtime.write_new(target/request_path, wire(request))
            llm_runtime.write_new(target/budget_path, budget)
            row.update(status=budget['status'], reason='exact_runtime_token_budget', request=request_path,
                       budget=budget_path, request_sha256=digest(target/request_path), budget_sha256=digest(target/budget_path))
        rows.append(row)
        if len(rows)%30 == 0:
            print(f'{len(rows)}/480 token preflights', flush=True)
    llm_runtime.verify_live(server, policy)
    manifest = {'schema_version':1, 'phase':8, 'created_at_utc':now(), 'run_id':run_id,
                'method_lock_sha256':digest(method_lock.LOCK), 'server_sha256':digest(target/'server.json'),
                'audit_sha256':digest(target/'context-audit.json'), 'slots':rows,
                'counts':dict(Counter(r['status'] for r in rows)), 'prediction_requests_sent':0}
    llm_runtime.write_new(target/'manifest.json', manifest)
    eligibility = []
    for observation in plan['observations']:
        statuses = {r['status'] for r in rows if r['observation_id'] == observation['observation_id']}
        require(len(statuses) == 1, 'Repetitions disagree about shared eligibility')
        eligibility.append({'observation_id':observation['observation_id'], 'bundle_sha256':digest(root/observation['record_path']),
                            'status':statuses.pop()})
    llm_runtime.write_new(target/'shared-eligibility.json', {'schema_version':1,'observations':eligibility,
        'rule':'Both predictors use the same availability; no truncation, replacement, or private truth inputs.'})
    return verify_preflight(root, run_id)


def verify_preflight(root=CAMPAIGN, run_id='phase8-a'):
    target = root/'build/final/preflight'/run_id
    manifest = read_json(target/'manifest.json')
    plan = check_sources(root)
    lock = check_methods(root)
    require(manifest['prediction_requests_sent'] == 0, 'Not a preflight')
    require(manifest['method_lock_sha256'] == digest(method_lock.LOCK), 'Preflight method lock differs')
    require(digest(target/'server.json') == manifest['server_sha256'], 'Preflight server changed')
    require(method_lock.runtime_configuration(read_json(target/'server.json')) == lock['runtime_configuration'],
            'Preflight runtime configuration differs')
    audit = export_context.audit_run(root, 'final', run_id)
    check_audit(audit)
    require(audit == read_json(target/'context-audit.json') and digest(target/'context-audit.json') == manifest['audit_sha256'],
            'Preflight context audit differs')
    policy, prompt, schema = llm.settings(root)
    slots = manifest['slots']
    require([{k:r[k] for k in s} for r,s in zip(slots,plan['inference_slots'])] == plan['inference_slots']
            and len(slots) == 480, 'Scheduled slots differ')
    by_id = {r['observation_id']:r for r in plan['observations']}
    eligibility = []
    for row in slots:
        bundle_path = root/by_id[row['observation_id']]['record_path']
        bundle = read_json(bundle_path)
        require(digest(bundle_path) == row['bundle_sha256'], 'Preflight bundle changed')
        if bundle['status'] != 'available':
            require(row['status'] == 'context_unavailable' and row['request'] is None and row['budget'] is None,
                    'Unavailable extraction dispatched')
            continue
        name = slot_name(row)
        require(row['request'] == f'requests/{name}.json' and row['budget'] == f'budgets/{name}.json', 'Unexpected slot paths')
        request = llm.payload(bundle,prompt,schema,policy,row['repetition'])
        require((target/row['request']).read_text() == wire(request)
                and digest(target/row['request']) == row['request_sha256'], 'Public request changed')
        budget = read_json(target/row['budget'])
        require(digest(target/row['budget']) == row['budget_sha256'], 'Token evidence changed')
        require(isinstance(budget['rendered_prompt'],str) and budget['rendered_prompt']
                and all(type(t) is int for t in budget['token_ids']) and budget['token_ids'], 'Invalid runtime token evidence')
        require(budget['prompt_tokens'] == len(budget['token_ids'])
                and budget['reserved_completion_tokens'] == policy['llm']['max_tokens']
                and budget['total_budget'] == len(budget['token_ids'])+policy['llm']['max_tokens'], 'Budget arithmetic differs')
        expected = 'available' if budget['total_budget'] <= policy['llm']['context_limit'] else 'context_unavailable'
        require(row['status'] == budget['status'] == expected, 'Budget disposition differs')
    for observation in plan['observations']:
        rows = [r for r in slots if r['observation_id'] == observation['observation_id']]
        require(len({r['status'] for r in rows}) == 1, 'Inconsistent repetition eligibility')
        eligibility.append({'observation_id':observation['observation_id'], 'bundle_sha256':rows[0]['bundle_sha256'],
                            'status':rows[0]['status']})
    require(read_json(target/'shared-eligibility.json')['observations'] == eligibility, 'Shared eligibility differs')
    counts = dict(Counter(r['status'] for r in slots))
    require(counts == manifest['counts'], 'Preflight counts differ')
    return {'status':'verified', 'slots':480, 'observations':160, 'slot_statuses':counts,
            'observation_statuses':dict(Counter(r['status'] for r in eligibility))}


def inventory(root, run_id):
    files = set()
    for directory in ('provenance/method-snapshot','corpus','pipeline','ghidra','schemas','llm','data/final', 'build/final/oracle',
                      'build/final/retained','build/final/stripped','build/final/private',f'build/final/preflight/{run_id}'):
        files.update(p for p in (root/directory).rglob('*') if p.is_file() and '__pycache__' not in p.parts)
    files.update(root/name for name in ('config.json','context_policy.json','baseline_policy.json','llm_policy.json',
        'provenance/final-import.json','provenance/phase8-tests.json','build/final/build-manifest.json','build/final/dispositions.json'))
    context = root/'build/final/context'/run_id
    files.update(context/name for name in ('extraction-manifest.json','localization.json'))
    files.update((context/'records').glob('*.json'))
    for job in context.iterdir():
        if not job.is_dir() or job.name=='records':
            continue
        for name in ('input.elf','engine/worker.json','engine/raw.json','engine/stdout.txt','engine/stderr.txt'):
            path=job/name
            if path.is_file():
                files.add(path)
    return {p.relative_to(root).as_posix():digest(p) for p in sorted(files)}


def verify_archive(path, files):
    with tarfile.open(path, 'r:gz') as archive:
        members = archive.getmembers()
        require(len(members) == len(files) and {m.name for m in members} == set(files), 'Release archive inventory differs')
        for member in members:
            require(member.isfile(), 'Non-file archive member')
            require(hashlib.sha256(archive.extractfile(member).read()).hexdigest() == files[member.name],
                    f'Release archive content differs: {member.name}')


def freeze(root=CAMPAIGN, run_id='phase8-a'):
    no_predictions(root)
    checked = verify_preflight(root, run_id)
    tests = read_json(root/'provenance/phase8-tests.json')
    require(tests['exit_code']==0 and tests['skipped']==0, 'Phase 8 test gate incomplete')
    method_lock.check_files(tests['test_sources'])
    report = read_json(root/'build/final/build-manifest.json')
    disposition = oracle.adjudicate(report,read_json(root/'corpus/private/final-oracle.json'),root)
    # Include exact repository-relative methods and selection specifications for replay.
    snapshot = root/'provenance/method-snapshot'
    methods = {**read_json(method_lock.LOCK)['methods'], **{
        p.relative_to(ROOT.parent).as_posix():digest(p) for p in
        (ROOT/'pipeline/final_sources.py',ROOT/'pipeline/final_review.py',ROOT/'pipeline/final_freeze.py',method_lock.LOCK)}}
    for name, expected in methods.items():
        target = snapshot/name
        if target.exists():
            require(digest(target)==expected, 'Stale method snapshot')
        else:
            llm_runtime.write_new(target,(ROOT.parent/name).read_text())
    files = inventory(root,run_id)
    release = root/'release'; release.mkdir(exist_ok=True)
    path = release/'final-v1-inputs.tar.gz'
    with path.open('xb') as output:
        import gzip
        with gzip.GzipFile(filename='',fileobj=output,mode='wb',mtime=0) as compressed:
            with tarfile.open(fileobj=compressed,mode='w') as archive:
                for name in files:
                    content = (root/name).read_bytes()
                    item = tarfile.TarInfo(name); item.size=len(content)
                    item.mode=(root/name).stat().st_mode & 0o555
                    archive.addfile(item,io.BytesIO(content))
    verify_archive(path,files)
    data = {'schema_version':1,'freeze_id':'juliet-redesign-final-v1','phase':8,'status':'frozen_before_predictions',
            'created_at_utc':now(),'context_run_id':run_id,'method_lock_sha256':digest(method_lock.LOCK),
            'method_files':read_json(method_lock.LOCK)['methods'],
            'preparation_methods':{p.relative_to(ROOT.parent).as_posix():digest(p) for p in
                (ROOT/'pipeline/final_sources.py',ROOT/'pipeline/final_review.py',ROOT/'pipeline/final_freeze.py')},
            'files':files, 'archive':path.relative_to(root).as_posix(),'archive_sha256':digest(path),
            'matrix':report['plan']['counts'],'preflight':checked,'binary_labels':disposition['binary_labels'],
            'operation_dispositions':disposition['operation_dispositions'],'final_predictor_runs':0,
            'chronology':'Local UTC timestamp and content-addressed versioned release; no independent timestamp authority or external preregistration.',
            'review_limit':'Codex emitted-code review, no independent human adjudication.',
            'private_archive':True,'predictor_inputs':'Only public bundle/request and shared eligibility; oracle, source, debug and private mappings are excluded.'}
    llm_runtime.write_new(release/'freeze.json', data)
    # Hashes establish immutability; permissions also deter accidental changes.
    for name in files:
        (root/name).chmod((root/name).stat().st_mode & ~0o222)
    path.chmod(0o444); (release/'freeze.json').chmod(0o444)
    return verify(root)


def verify(root=CAMPAIGN):
    frozen = read_json(root/'release/freeze.json')
    require(frozen['status']=='frozen_before_predictions' and frozen['final_predictor_runs']==0, 'Invalid freeze chronology')
    require(frozen['method_lock_sha256']==digest(method_lock.LOCK), 'Freeze method lock changed')
    method_lock.check_files(frozen['method_files'])
    method_lock.check_files(frozen['preparation_methods'])
    method_lock.check_files(frozen['files'],root)
    require(digest(root/frozen['archive'])==frozen['archive_sha256'], 'Release archive changed')
    verify_archive(root/frozen['archive'],frozen['files'])
    checked = verify_preflight(root,frozen['context_run_id'])
    require(checked==frozen['preflight'], 'Frozen preflight differs')
    return {'status':'verified','freeze_id':frozen['freeze_id'],'bound_files':len(frozen['files']),
            'archive_sha256':frozen['archive_sha256'],**checked}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command',choices=('preflight','freeze','verify'))
    parser.add_argument('--root',type=Path,default=CAMPAIGN)
    parser.add_argument('--run-id',default='phase8-a')
    parser.add_argument('--server',type=Path)
    args=parser.parse_args()
    if args.command=='preflight': result=preflight(args.root,args.run_id,args.server)
    elif args.command=='freeze': result=freeze(args.root,args.run_id)
    else: result=verify(args.root)
    print(canonical(result))

if __name__=='__main__':
    main()

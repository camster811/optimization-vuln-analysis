"""Explicit 12,288-token amendment; preserve the original lock and input release."""
import argparse
from copy import deepcopy
from datetime import datetime, timezone
import os
from pathlib import Path
import shutil

from . import final_freeze, llm, llm_runtime as runtime, method_lock
from .bundles import canonical
from .final_sources import CAMPAIGN
from .inventory import ROOT, digest, read_json, require
from .run_llm import wire

AMENDED = ROOT/'campaigns/final-v2-context12288'


def amended_policy(policy):
    result = deepcopy(policy)
    result['llm']['context_limit'] = 12288
    return result


def expected_runtime(policy):
    result = deepcopy(read_json(method_lock.LOCK)['runtime_configuration'])
    result['policy_sha256'] = llm.sha(policy)
    result['props']['default_generation_settings']['n_ctx'] = 12288
    return result


def prepare(root=AMENDED):
    final_freeze.verify(CAMPAIGN)
    require(not root.exists(), 'Amended campaign already exists')
    original = read_json(CAMPAIGN/'release/freeze.json')
    root.mkdir(parents=True)
    for name in original['files']:
        path = root/name
        path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(CAMPAIGN/name, path)
    path = root/'llm_policy.json'
    path.chmod(0o644)
    path.write_text(canonical(amended_policy(read_json(path))))
    runtime.write_new(root/'provenance/context-amendment.json', {
        'schema_version':1, 'campaign_id':'juliet-redesign-final-v2-context12288',
        'created_at_utc':datetime.now(timezone.utc).isoformat(),
        'parent_freeze_sha256':digest(CAMPAIGN/'release/freeze.json'),
        'parent_archive_sha256':original['archive_sha256'],
        'change':{'llm.context_limit':{'from':8192,'to':12288}},
        'reason':'User requested larger context to address final shared input availability.',
        'evidence_inspected':'Phase 8 prompt lengths/availability and pilot results; no final answer content inspected for this amendment.',
        'parent_execution_claim_present':(CAMPAIGN/'provenance/phase9-execution.json').exists(),
        'completion_reservation':4096,
        'method': 'Same source selection, oracle, public bundles, prompt, model, sampling, seeds, schedule, evaluator and no-retry policy. Recompute shared eligibility for both methods.',
        'status':'prepared_pending_live_runtime_preflight'})
    return {'status':'prepared', 'root':str(root), 'context_limit':12288}


def check_inputs(root):
    final_freeze.verify(CAMPAIGN)
    parent = read_json(CAMPAIGN/'release/freeze.json')
    amendment = read_json(root/'provenance/context-amendment.json')
    require(amendment['parent_freeze_sha256'] == digest(CAMPAIGN/'release/freeze.json') and
            amendment['parent_archive_sha256'] == parent['archive_sha256'], 'Amendment parent differs')
    for name, sha in parent['files'].items():
        if name == 'llm_policy.json': continue
        require(digest(root/name) == sha, f'Amendment changed unrelated input: {name}')
    policy = read_json(root/'llm_policy.json')
    require(policy == amended_policy(read_json(CAMPAIGN/'llm_policy.json')), 'Only context_limit may change')
    return parent, policy


def freeze(server, root=AMENDED):
    require(not (root/'release').exists(), 'Amended release already exists')
    final_freeze.no_predictions(root)
    parent, policy = check_inputs(root)
    evidence = read_json(server)
    require(method_lock.runtime_configuration(evidence) == expected_runtime(policy), 'Amended runtime differs')
    runtime.verify_live(evidence, policy)
    previous = root/'build/final/preflight'/parent['context_run_id']
    target = root/'build/final/preflight/context12288-a'
    target.mkdir(parents=True, exist_ok=False)
    runtime.write_new(target/'server.json', evidence)
    runtime.write_new(target/'context-audit.json', read_json(previous/'context-audit.json'))
    for name in ('launch.json','startup.log'):
        source = server.parent/name
        if source.is_file(): runtime.write_new(target/('runtime-'+name), source.read_text())
    slots = []
    for row in read_json(previous/'manifest.json')['slots']:
        updated = dict(row)
        if row['request'] is not None:
            request = read_json(previous/row['request'])
            budget = runtime.budget(request, policy)
            old = read_json(previous/row['budget'])
            require(budget['token_ids'] == old['token_ids'] and budget['rendered_prompt'] == old['rendered_prompt'],
                    'Context amendment changed template/tokenizer output')
            runtime.write_new(target/row['request'], wire(request))
            runtime.write_new(target/row['budget'], budget)
            updated.update(status=budget['status'], budget_sha256=digest(target/row['budget']))
        slots.append(updated)
    runtime.verify_live(evidence, policy)
    eligibility = []
    plan = read_json(root/'build/final/build-manifest.json')['plan']
    for observation in plan['observations']:
        related = [r for r in slots if r['observation_id']==observation['observation_id']]
        require(len(related)==3 and len({r['status'] for r in related})==1, 'Incomplete amended schedule')
        eligibility.append({'observation_id':observation['observation_id'],
            'bundle_sha256':related[0]['bundle_sha256'], 'status':related[0]['status']})
    runtime.write_new(target/'manifest.json', {'schema_version':1,'phase':8,'run_id':'context12288-a',
        'slots':slots,'prediction_requests_sent':0,'server_sha256':digest(target/'server.json')})
    runtime.write_new(target/'shared-eligibility.json', {'schema_version':1, 'observations':eligibility,
        'rule':'Complete prompt plus 4096 reserved tokens <= 12288, shared by both methods.'})
    files = {p.relative_to(root).as_posix():digest(p) for p in sorted(root.rglob('*')) if p.is_file()}
    release = root/'release'; release.mkdir()
    archive = release/'final-v2-context12288-inputs.tar.gz'
    sha = method_lock.archive_run(root,archive)
    frozen = {'schema_version':1,'freeze_id':'juliet-redesign-final-v2-context12288',
        'status':'frozen_before_predictions','final_predictor_runs':0,
        'created_at_utc':datetime.now(timezone.utc).isoformat(),
        'context_amendment':True,'context_run_id':'context12288-a',
        'parent_freeze_sha256':digest(CAMPAIGN/'release/freeze.json'),
        'files':files,'archive':archive.relative_to(root).as_posix(),'archive_sha256':sha,
        'method_files':parent['method_files'],
        'amendment_method_sha256':digest(Path(__file__)),
        'runtime_configuration':expected_runtime(policy)}
    runtime.write_new(release/'freeze.json',frozen)
    for name in files: (root/name).chmod((root/name).stat().st_mode & ~0o222)
    archive.chmod(0o444); (release/'freeze.json').chmod(0o444)
    return verify(root)


def verify(root=AMENDED):
    frozen = read_json(root/'release/freeze.json')
    require(frozen['context_amendment'] is True and frozen['final_predictor_runs']==0 and
            frozen['status']=='frozen_before_predictions', 'Invalid amended freeze')
    parent, policy = check_inputs(root)
    require(frozen['parent_freeze_sha256']==digest(CAMPAIGN/'release/freeze.json') and
            frozen['method_files']==parent['method_files'] and
            frozen['amendment_method_sha256']==digest(Path(__file__)), 'Amended method binding differs')
    require(frozen['runtime_configuration']==expected_runtime(policy), 'Amended runtime configuration differs')
    method_lock.check_files(frozen['files'],root)
    require(digest(root/frozen['archive'])==frozen['archive_sha256'], 'Amended archive changed')
    final_freeze.verify_archive(root/frozen['archive'],frozen['files'])
    preflight = root/'build/final/preflight'/frozen['context_run_id']
    previous = root/'build/final/preflight'/parent['context_run_id']
    evidence = read_json(preflight/'server.json')
    require(method_lock.runtime_configuration(evidence)==expected_runtime(policy), 'Amended server differs')
    slots = read_json(preflight/'manifest.json')['slots']
    old_slots = read_json(previous/'manifest.json')['slots']
    require(len(slots)==len(old_slots)==480, 'Amended schedule incomplete')
    for row,old in zip(slots,old_slots):
        expected = dict(old)
        if old['request'] is not None:
            budget = read_json(previous/old['budget'])
            budget['status'] = 'available' if budget['total_budget']<=12288 else 'context_unavailable'
            require(read_json(preflight/row['budget'])==budget and
                    (preflight/row['request']).read_bytes()==(previous/old['request']).read_bytes(),
                    'Amended request/token evidence differs')
            expected.update(status=budget['status'],budget_sha256=digest(preflight/row['budget']))
        require(row==expected, 'Amended slot differs')
    from collections import Counter
    observations = read_json(preflight/'shared-eligibility.json')['observations']
    expected_observations = []
    for row in read_json(previous/'shared-eligibility.json')['observations']:
        statuses = {s['status'] for s in slots if s['observation_id']==row['observation_id']}
        require(len(statuses)==1, 'Amended repetition eligibility differs')
        expected_observations.append({**row,'status':statuses.pop()})
    require(observations==expected_observations, 'Amended shared eligibility differs')
    return {'status':'verified','freeze_id':frozen['freeze_id'],'context_limit':12288,
            'observations':len(observations),'observation_statuses':dict(Counter(r['status'] for r in observations)),
            'slots':len(slots),'slot_statuses':dict(Counter(r['status'] for r in slots))}


def verify_campaign(root):
    frozen = read_json(root/'release/freeze.json')
    return verify(root) if frozen.get('context_amendment') else final_freeze.verify(root)


def runtime_configuration(root):
    frozen = read_json(root/'release/freeze.json')
    return frozen['runtime_configuration'] if frozen.get('context_amendment') else read_json(method_lock.LOCK)['runtime_configuration']


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action',choices=('prepare','serve','capture','freeze','verify'))
    parser.add_argument('--root',type=Path,default=AMENDED)
    parser.add_argument('--directory',type=Path)
    parser.add_argument('--server',type=Path)
    args = parser.parse_args()
    root = args.root.resolve()
    if args.action=='prepare': result=prepare(root)
    elif args.action=='verify': result=verify(root)
    elif args.action=='freeze':
        require(args.server is not None,'freeze requires --server')
        result=freeze(args.server,root)
    else:
        require(args.directory is not None,'runtime requires --directory')
        _,policy=check_inputs(root)
        directory=args.directory.resolve()
        if args.action=='serve':
            from pipeline.serve_llm import server_command, server_environment, verify_model
            command=server_command(policy);verify_model(policy,command)
            directory.mkdir(parents=True,exist_ok=False)
            runtime.write_new(directory/'launch.json',{'pid':os.getpid(),'command':command})
            log=os.open(directory/'startup.log',os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
            os.dup2(log,1);os.dup2(log,2);os.close(log)
            os.execve(command[0],command,server_environment(command))
        launch=read_json(directory/'launch.json')
        runtime.write_new(directory/'server.json',runtime.capture(launch['pid'],directory/'startup.log',policy))
        result={'status':'captured','server':str(directory/'server.json')}
    print(canonical(result))


if __name__=='__main__':main()

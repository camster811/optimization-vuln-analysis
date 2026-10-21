"""Phase 9 execution over the immutable Phase 8 release. No selective retries."""
import argparse
from collections import Counter
from datetime import datetime, timezone
import fcntl
from pathlib import Path
import subprocess
import sys
import time

from . import baseline_worker, bounds, final_freeze, llm, llm_runtime as runtime, method_lock, run_llm
from .context_campaign import verify_campaign, runtime_configuration
from .bundles import canonical
from .export_context import engine_identity
from .final_sources import CAMPAIGN
from .inventory import ROOT, digest, read_json, require


def methods():
    return {p.relative_to(ROOT.parent).as_posix(): digest(p) for p in
            (Path(__file__), ROOT/'pipeline/final_analysis.py', ROOT/'pipeline/context_campaign.py')}


def claim_path(root):
    return root/'provenance/phase9-execution.json'


def claim_execution(directory, root):
    """One execution identity per freeze, shared by both predictors."""
    path = claim_path(root)
    identity = {'freeze_sha256':digest(root/'release/freeze.json'),
                'run_manifest_sha256':digest(directory/'manifest.json')}
    if not path.exists():
        try: runtime.write_new(path, identity)
        except FileExistsError: pass  # Concurrent baseline/LLM startup.
    require(read_json(path) == identity,
            'This final campaign already has an execution; resume its saved directory')


def frozen_inputs(root):
    frozen = read_json(root/'release/freeze.json')
    preflight = root/'build/final/preflight'/frozen['context_run_id']
    plan = read_json(root/'build/final/build-manifest.json')['plan']
    return frozen, preflight, plan


def prepare(directory, server=None, root=CAMPAIGN):
    verify_campaign(root)
    frozen, preflight, plan = frozen_inputs(root)
    policy, prompt, schema = llm.settings(root)
    evidence = read_json(server or preflight/'server.json')
    require(method_lock.runtime_configuration(evidence) ==
            runtime_configuration(root), 'Locked runtime differs')
    # Preparation is offline: use exact frozen requests and token evidence.
    directory.mkdir(parents=True, exist_ok=False)
    runtime.write_new(directory/'server.json', evidence)
    inputs = {}
    for row in plan['observations']:
        identifier = row['observation_id']
        runtime.write_new(directory/'inputs'/f'{identifier}.json', (root/row['record_path']).read_text())
        inputs[identifier] = digest(root/row['record_path'])
    slots = []
    for row, slot in zip(read_json(preflight/'manifest.json')['slots'], plan['inference_slots']):
        path = directory/'slots'/run_llm.slot_name(slot)
        if row['request'] is not None:
            runtime.write_new(path/'request.json', (preflight/row['request']).read_text())
            runtime.write_new(path/'budget.json', read_json(preflight/row['budget']))
        else:
            runtime.write_new(path/'budget.json', {'status': 'context_unavailable'})
        slots.append({**slot, 'request_sha256': row.get('request_sha256'),
                      'budget_sha256': digest(path/'budget.json')})
    runtime.write_new(directory/'manifest.json', {
        'schema_version': 1, 'split': 'final', 'created_at_utc': datetime.now(timezone.utc).isoformat(),
        'freeze_sha256': digest(root/'release/freeze.json'), 'archive_sha256': frozen['archive_sha256'],
        'methods': methods(), 'policy': policy, 'prompt': prompt, 'schema': schema,
        'server_sha256': llm.sha(evidence), 'inputs': inputs, 'slots': slots})
    return verify(directory, root)


def validate_manifest(directory, root=CAMPAIGN):
    manifest = read_json(directory/'manifest.json')
    frozen, preflight, plan = frozen_inputs(root)
    require(manifest['split'] == 'final' and manifest['freeze_sha256'] == digest(root/'release/freeze.json')
            and manifest['archive_sha256'] == frozen['archive_sha256'], 'Final freeze differs')
    require(manifest['methods'] == methods(), 'Phase 9 implementation changed')
    method_lock.check_files(frozen['method_files'])
    require((manifest['policy'], manifest['prompt'], manifest['schema']) == llm.settings(root), 'LLM settings changed')
    evidence = read_json(directory/'server.json')
    require(llm.sha(evidence) == manifest['server_sha256'] and
            method_lock.runtime_configuration(evidence) == runtime_configuration(root),
            'Runtime evidence differs')
    expected = {r['observation_id']: digest(root/r['record_path']) for r in plan['observations']}
    require(manifest['inputs'] == expected, 'Final public inventory differs')
    for identifier, sha in expected.items():
        require(digest(directory/'inputs'/f'{identifier}.json') == sha, 'Staged public input changed')
    require(len(manifest['slots']) == len(plan['inference_slots']), 'Final slot inventory differs')
    for slot, expected_slot, frozen_slot in zip(manifest['slots'], plan['inference_slots'],
                                               read_json(preflight/'manifest.json')['slots']):
        require({k: slot[k] for k in expected_slot} == expected_slot, 'Final schedule changed')
        path = directory/'slots'/run_llm.slot_name(slot)
        require(digest(path/'budget.json') == slot['budget_sha256'], 'Staged budget changed')
        if frozen_slot['request'] is not None:
            require(digest(path/'request.json') == slot['request_sha256'] == frozen_slot['request_sha256'],
                    'Staged request changed')
            require(read_json(path/'budget.json') == read_json(preflight/frozen_slot['budget']), 'Frozen budget differs')
        else:
            require(slot['request_sha256'] is None and not (path/'request.json').exists() and
                    read_json(path/'budget.json') == {'status':'context_unavailable'}, 'Missing input dispatched')
    return manifest, evidence


def verify(directory, root=CAMPAIGN, replay=False):
    manifest, _ = validate_manifest(directory, root)
    statuses = Counter(); grouped = {}; availability = {}
    baseline = Counter()
    for slot in manifest['slots']:
        path = directory/'slots'/run_llm.slot_name(slot)
        availability[slot['observation_id']] = read_json(path/'budget.json')['status']
        if (path/'result.json').exists():
            result = run_llm.result_for(directory, slot, manifest)
            grouped.setdefault(slot['observation_id'], []).append(result)
            statuses[result['status']] += 1
        else:
            statuses['dispatched_unresolved' if (path/'dispatch.json').exists() else 'pending'] += 1
        if (path/'dispatch.json').exists():
            dispatch = read_json(path/'dispatch.json')
            sha = dispatch['server_sha256']
            server = read_json(directory/'server.json') if sha == manifest['server_sha256'] else read_json(directory/'runtime-sessions'/f'{sha}.json')
            require(llm.sha(server) == sha and method_lock.runtime_configuration(server) ==
                    method_lock.runtime_configuration(read_json(directory/'server.json')), 'Dispatched runtime differs')
    for identifier in manifest['inputs']:
        path = directory/'baseline'/identifier
        if (path/'result.json').exists():
            result = read_json(path/'result.json')
            require(read_json(path/'dispatch.json')['bundle_sha256'] == manifest['inputs'][identifier], 'Baseline dispatch differs')
            if availability[identifier] != 'available':
                require(result == {'status':availability[identifier], 'prediction':None}, 'Blocked baseline differs')
            else:
                bundle = read_json(directory/'inputs'/f'{identifier}.json')
                baseline_worker.validate_result(result, bundle)
                require(result['status'] in ('completed','runtime_failed','input_unavailable'),
                        'Nonterminal baseline result')
                if result['status'] == 'completed':
                    ir = path/'ir/pcode.json'
                    require(digest(ir) == result['ir_sha256'], 'Baseline IR changed')
                    if replay:
                        require(bounds.analyze(bundle, read_json(ir), read_json(root/'baseline_policy.json')) ==
                                result['prediction'], 'Baseline prediction does not regenerate')
            baseline[result['status']] += 1
        else:
            baseline['dispatched_unresolved' if (path/'dispatch.json').exists() else 'pending'] += 1
    if (directory/'baseline-engine.json').exists():
        _, preflight, _ = frozen_inputs(root)
        require(read_json(directory/'baseline-engine.json') == read_json(preflight/'context-audit.json')['engine'],
                'Saved baseline engine differs')
    if (directory/'baseline-policy.json').exists():
        require(read_json(directory/'baseline-policy.json') == read_json(root/'baseline_policy.json'),
                'Saved baseline policy differs')
    return {'slots':len(manifest['slots']), 'attempt_statuses':dict(statuses),
            'baseline_statuses':dict(baseline), 'shared_availability':availability,
            'aggregates':{k:llm.aggregate(v) for k,v in grouped.items() if len(v)==3}}


def run(directory, root=CAMPAIGN, max_slots=None, server=None):
    require(max_slots is None or max_slots > 0, 'max-slots must be positive')
    with (directory/'runner.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        verify_campaign(root)
        manifest, evidence = validate_manifest(directory, root)
        verify(directory, root)
        claim_execution(directory, root)
        if server is not None:
            evidence = read_json(server)
            require(method_lock.runtime_configuration(evidence) ==
                    method_lock.runtime_configuration(read_json(directory/'server.json')), 'Locked runtime differs')
            runtime.verify_live(evidence, manifest['policy'])
            session = directory/'runtime-sessions'/f'{llm.sha(evidence)}.json'
            if session.exists(): require(read_json(session) == evidence, 'Runtime session changed')
            else: runtime.write_new(session, evidence)
        count = 0
        for slot in manifest['slots']:
            path = directory/'slots'/run_llm.slot_name(slot)
            if (path/'result.json').exists(): continue
            if (path/'dispatch.json').exists():
                runtime.write_new(path/'result.json', {'slot':slot, 'status':'interrupted', 'parsed':None,
                    'error':'Durable dispatch without completion; no retry permitted', 'response_body':None})
                continue
            accounting = read_json(path/'budget.json')
            if accounting['status'] != 'available':
                runtime.write_new(path/'result.json', {'slot':slot, 'status':accounting['status'], 'parsed':None})
                continue
            if max_slots is not None and count >= max_slots: continue
            validate_manifest(directory, root)
            runtime.verify_live(evidence, manifest['policy'])
            runtime.write_new(path/'dispatch.json', {'request_sha256':slot['request_sha256'],
                'server_sha256':llm.sha(evidence), 'started_at':datetime.now(timezone.utc).isoformat()})
            result = llm.attempt(read_json(path/'request.json'),
                read_json(directory/'inputs'/f"{slot['observation_id']}.json"), manifest['policy'], manifest['schema'])
            try:
                validate_manifest(directory, root)
                runtime.verify_live(evidence, manifest['policy'])
            except Exception as error:
                result.update(status='runtime_changed', parsed=None, error=str(error))
                runtime.write_new(path/'result.json', {**result, 'slot':slot})
                raise
            runtime.write_new(path/'result.json', {**result, 'slot':slot})
            count += 1
            print(f'{count} new dispatches; {run_llm.slot_name(slot)} {result["status"]}', flush=True)
        verify_campaign(root)
        return verify(directory, root)


def baseline(directory, root=CAMPAIGN):
    """Stage only public bundles/policy for the unchanged worker subprocess."""
    with (directory/'baseline.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        verify_campaign(root)
        manifest, _ = validate_manifest(directory, root)
        report = verify(directory, root)
        claim_execution(directory, root)
        policy = read_json(root/'baseline_policy.json')
        engine = engine_identity(read_json(root/'context_policy.json'))
        _, preflight, _ = frozen_inputs(root)
        require(engine == read_json(preflight/'context-audit.json')['engine'], 'Frozen Ghidra engine differs')
        metadata = directory/'baseline-engine.json'
        if metadata.exists(): require(read_json(metadata) == engine, 'Baseline engine changed')
        else: runtime.write_new(metadata, engine)
        policy_path = directory/'baseline-policy.json'
        if policy_path.exists(): require(read_json(policy_path) == policy, 'Baseline policy changed')
        else: runtime.write_new(policy_path, policy)
        for identifier, sha in manifest['inputs'].items():
            path = directory/'baseline'/identifier
            if (path/'result.json').exists(): continue
            if (path/'dispatch.json').exists():
                runtime.write_new(path/'result.json', failure(policy, sha)
                    if report['shared_availability'][identifier] == 'available' else
                    {'status':report['shared_availability'][identifier], 'prediction':None})
                continue
            validate_manifest(directory, root)
            runtime.write_new(path/'dispatch.json', {'bundle_sha256':sha, 'started_at':datetime.now(timezone.utc).isoformat()})
            if report['shared_availability'][identifier] != 'available':
                runtime.write_new(path/'result.json', {'status':report['shared_availability'][identifier], 'prediction':None})
                continue
            began = time.monotonic()
            source = directory/'inputs'/f'{identifier}.json'
            result = None
            for mode in ('lift', 'analyze'):
                output = path/f'{mode}.json'
                argv = [sys.executable, '-m', 'redesign.pipeline.baseline_worker', mode,
                    '--input', str(source), '--policy', str(policy_path), '--work', str(path/'ir'), '--output', str(output)]
                if mode == 'analyze': argv += ['--ir', str(path/'ir/pcode.json')]
                try:
                    process = subprocess.run(argv, capture_output=True, text=True, timeout=policy['process_timeout_seconds']+60)
                    runtime.write_new(path/f'{mode}.log', process.stdout+process.stderr)
                    require(process.returncode == 0 and output.is_file(), 'Baseline worker failed')
                    result = baseline_worker.validate_result(read_json(output), read_json(source))
                except Exception as error:
                    runtime.write_new(path/'failure.txt', str(error))
                    result = failure(policy, sha)
                if result['status'] != 'lifted': break
            runtime.write_new(path/'timing.json', {'wall_seconds':time.monotonic()-began})
            runtime.write_new(path/'result.json', result)
            print(identifier, result['status'], flush=True)
        verify_campaign(root)
        return verify(directory, root, replay=True)


def failure(policy, sha):
    return {'schema_version':2, 'method_id':policy['method_id'], 'bundle_sha256':sha,
            'ir_sha256':None, 'status':'runtime_failed', 'prediction':None, 'error_code':'runtime_failure'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('prepare','run','baseline','verify'))
    parser.add_argument('--directory', type=Path, required=True)
    parser.add_argument('--root', type=Path, default=CAMPAIGN)
    parser.add_argument('--server', type=Path)
    parser.add_argument('--max-slots', type=int)
    args = parser.parse_args()
    directory, root = args.directory.resolve(), args.root.resolve()
    if args.action == 'prepare': result = prepare(directory, args.server, root)
    elif args.action == 'run': result = run(directory, root, args.max_slots, args.server)
    else:
        if args.action == 'verify':
            verify_campaign(root)
            result = verify(directory, root, replay=True)
        else: result = baseline(directory, root)
    print(canonical({k:v for k,v in result.items() if k not in ('aggregates','shared_availability')}))


if __name__ == '__main__': main()

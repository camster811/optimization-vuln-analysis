"""Prepare and run immutable pilot-only LLM attempts; uncertain dispatches never retry."""
import argparse
from collections import Counter
from datetime import datetime, timezone
import fcntl
import hashlib
from pathlib import Path

from pipeline.run_llm import canonical_json
from . import llm, llm_runtime as runtime
from .inventory import ROOT, check_record_inventory, generate, read_json, require


def methods():
    paths = [Path(__file__), Path(llm.__file__), Path(runtime.__file__),
             ROOT/'pipeline/bundles.py', ROOT/'pipeline/inventory.py',
             ROOT.parent/'pipeline/run_llm.py', ROOT.parent/'pipeline/serve_llm.py', ROOT.parent/'pipeline/runtime.py']
    return {str(p.relative_to(ROOT.parent)): runtime.digest(p) for p in paths}


def slot_name(slot):
    return f"{slot['observation_id']}-{slot['repetition']}"


def wire(request):
    return canonical_json(request)


def prepare(directory, server, root=ROOT):
    policy, prompt, schema = llm.settings(root)
    evidence = read_json(server)
    runtime.verify_live(evidence, policy)
    plan = generate(read_json(root/'config.json'), read_json(root/'corpus/manifest.json'), root, 'pilot', True)
    check_record_inventory(plan, root)
    directory.mkdir(parents=True, exist_ok=False)
    runtime.write_new(directory/'server.json', evidence)
    inputs = {}
    for row in plan['observations']:
        identifier = row['observation_id']
        bundle = read_json(root/row['record_path'])
        inputs[identifier] = llm.sha(bundle)
        runtime.write_new(directory/'inputs'/f'{identifier}.json', bundle)
    slots = []
    for slot in plan['inference_slots']:
        bundle = read_json(directory/'inputs'/f"{slot['observation_id']}.json")
        request = llm.payload(bundle, prompt, schema, policy, slot['repetition'])
        accounting = runtime.budget(request, policy)
        if bundle['status'] != 'available': accounting['status'] = 'input_unavailable'
        name = slot_name(slot)
        runtime.write_new(directory/'slots'/name/'request.json', wire(request))
        runtime.write_new(directory/'slots'/name/'budget.json', accounting)
        slots.append({**slot, 'request_sha256': hashlib.sha256(wire(request).encode()).hexdigest(),
                      'budget_sha256': llm.sha(accounting)})
    runtime.verify_live(evidence, policy)
    # Manifest is the completion marker: a partially prepared directory cannot run.
    manifest = {'schema_version': 1, 'split': 'pilot', 'policy': policy, 'prompt': prompt, 'schema': schema,
                'methods': methods(), 'server_sha256': llm.sha(evidence), 'inputs': inputs, 'slots': slots}
    runtime.write_new(directory/'manifest.json', manifest)
    return verify(directory, root)


def validate_manifest(directory, root):
    manifest = read_json(directory/'manifest.json')
    policy, prompt, schema = llm.settings(root)
    require(manifest['split'] == 'pilot', 'Only pilot inference is enabled before method lock')
    require((manifest['policy'], manifest['prompt'], manifest['schema']) == (policy, prompt, schema), 'LLM settings/prompt/schema changed')
    require(manifest['methods'] == methods(), 'Implementation changed since preparation')
    evidence = read_json(directory/'server.json')
    require(llm.sha(evidence) == manifest['server_sha256'], 'Runtime evidence changed')
    expected = []
    for identifier, digest in manifest['inputs'].items():
        bundle = read_json(directory/'inputs'/f'{identifier}.json')
        require(llm.sha(bundle) == digest, 'Public input changed')
        for repetition, seed in enumerate(policy['llm']['seeds'], 1):
            order = hashlib.sha256(f"20261019\n{identifier}\n{repetition}".encode()).hexdigest()
            expected.append((order, identifier, repetition, seed))
    actual = [(s['order_sha256'], s['observation_id'], s['repetition'], s['seed']) for s in manifest['slots']]
    require(actual == sorted(expected), 'Schedule changed')
    for slot in manifest['slots']:
        path = directory/'slots'/slot_name(slot)
        request = read_json(path/'request.json')
        bundle = read_json(directory/'inputs'/f"{slot['observation_id']}.json")
        require(request == llm.payload(bundle, prompt, schema, policy, slot['repetition']), 'Request changed')
        require(runtime.digest(path/'request.json') == slot['request_sha256'], 'Request bytes changed')
        accounting = read_json(path/'budget.json')
        require(llm.sha(accounting) == slot['budget_sha256'], 'Budget changed')
        require(accounting['prompt_tokens'] == len(accounting['token_ids']) and
                accounting['total_budget'] == accounting['prompt_tokens'] + policy['llm']['max_tokens'], 'Invalid budget')
        status = ('input_unavailable' if bundle['status'] != 'available' else
                  'available' if accounting['total_budget'] <= policy['llm']['context_limit'] else 'context_unavailable')
        require(accounting['status'] == status, 'Invalid availability status')
    return manifest, evidence


def result_for(directory, slot, manifest):
    path = directory/'slots'/slot_name(slot)
    result = read_json(path/'result.json')
    require(result['slot'] == slot, 'Result slot changed')
    dispatch = path/'dispatch.json'
    if result['status'] in ('context_unavailable', 'input_unavailable'):
        require(not dispatch.exists() and result['status'] == read_json(path/'budget.json')['status'], 'Invalid unavailable result')
    else:
        require(read_json(dispatch)['request_sha256'] == slot['request_sha256'], 'Missing or altered dispatch')
        if result.get('response_body') is not None:
            bundle = read_json(directory/'inputs'/f"{slot['observation_id']}.json")
            decoded = llm.decode(result['response_body'], result['http_status'], bundle, manifest['schema'])
            if result['status'] != 'runtime_changed':
                require(all(result[k] == v for k, v in decoded.items()), 'Stored response validation changed')
        else:
            require(result['status'] in ('interrupted', 'timeout', 'transport_error', 'runtime_changed'), 'Invalid failed attempt')
    return result


def verify(directory, root=ROOT):
    manifest, _ = validate_manifest(directory, root)
    statuses = Counter(); grouped = {}; availability = {}
    for slot in manifest['slots']:
        path = directory/'slots'/slot_name(slot)
        availability[slot['observation_id']] = read_json(path/'budget.json')['status']
        if (path/'result.json').exists():
            result = result_for(directory, slot, manifest)
            grouped.setdefault(slot['observation_id'], []).append(result)
            statuses[result['status']] += 1
        else: statuses['dispatched_unresolved' if (path/'dispatch.json').exists() else 'pending'] += 1
    return {'slots': len(manifest['slots']), 'attempt_statuses': dict(statuses),
            'shared_availability': availability,
            'aggregates': {key: llm.aggregate(rows) for key, rows in grouped.items() if len(rows) == 3}}


def run(directory, root=ROOT, max_slots=None):
    with (directory/'runner.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        manifest, evidence = validate_manifest(directory, root)
        # Validate every saved result before any new network side effect.
        verify(directory, root)
        count = 0
        for slot in manifest['slots']:
            path = directory/'slots'/slot_name(slot)
            if (path/'result.json').exists(): continue
            if (path/'dispatch.json').exists():
                runtime.write_new(path/'result.json', {'slot': slot, 'status': 'interrupted', 'parsed': None,
                    'error': 'Dispatch was durable but completion was not; no retry permitted', 'response_body': None})
                continue
            if max_slots is not None and count >= max_slots: break
            accounting = read_json(path/'budget.json')
            if accounting['status'] != 'available':
                runtime.write_new(path/'result.json', {'slot': slot, 'status': accounting['status'], 'parsed': None})
                continue
            # Recheck files and live ownership immediately before each dispatch.
            validate_manifest(directory, root)
            runtime.verify_live(evidence, manifest['policy'])
            request = read_json(path/'request.json')
            bundle = read_json(directory/'inputs'/f"{slot['observation_id']}.json")
            runtime.write_new(path/'dispatch.json', {'request_sha256': slot['request_sha256'],
                'server_sha256': manifest['server_sha256'], 'started_at': datetime.now(timezone.utc).isoformat()})
            result = llm.attempt(request, bundle, manifest['policy'], manifest['schema'])
            try:
                validate_manifest(directory, root)
                runtime.verify_live(evidence, manifest['policy'])
            except Exception as error:
                result.update(status='runtime_changed', parsed=None, error=str(error))
                runtime.write_new(path/'result.json', {**result, 'slot': slot})
                raise
            runtime.write_new(path/'result.json', {**result, 'slot': slot})
            count += 1
        return verify(directory, root)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['prepare', 'run', 'verify'])
    parser.add_argument('--directory', type=Path, required=True)
    parser.add_argument('--server', type=Path)
    parser.add_argument('--max-slots', type=int)
    args = parser.parse_args()
    require(args.max_slots is None or args.max_slots > 0, 'max-slots must be positive')
    if args.action == 'prepare':
        require(args.server is not None, 'prepare requires --server')
        result = prepare(args.directory, args.server)
    elif args.action == 'run': result = run(args.directory, max_slots=args.max_slots)
    else: result = verify(args.directory)
    print(canonical_json(result))


if __name__ == '__main__': main()

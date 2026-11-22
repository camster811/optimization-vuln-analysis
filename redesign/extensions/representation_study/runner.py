"""Frozen requests, durable no-retry dispatch and append-only runtime evidence."""
import argparse
from collections import Counter, defaultdict
from contextlib import contextmanager
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import math
import os
from pathlib import Path
import re

from redesign.pipeline import bundles, llm_runtime as runtime
from redesign.pipeline.inventory import IDENTIFIER, digest, local_path, read_json, require
from . import adapter, inventory, views


MANIFEST = 'coordinator/manifest.json'
PREFLIGHT = 'coordinator/preflight.json'
PROTOCOL = ('policy.json', 'prompt.md', 'response.json', 'view.json', 'bundle-v2.json')
RESPONSE_FIELDS = {'status', 'parsed', 'error', 'validation_failure', 'finish_reason', 'usage',
                   'raw_content', 'raw_reasoning', 'response_body', 'http_status', 'elapsed_seconds'}


def _now():
    return datetime.now(timezone.utc).isoformat()


def _publish(path, value, *, journal=False):
    # Escaping raw journals also preserves malformed surrogate strings losslessly.
    if journal:
        value = json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False)+'\n'
    runtime.write_new(path, value)
    Path(path).chmod(0o444)


@contextmanager
def _ownership(directory, *, readonly=False):
    path = Path(directory)/'runner.lock'
    if readonly and not path.exists():
        yield
        return
    flags = os.O_RDONLY if readonly else os.O_RDWR | os.O_CREAT
    fd = os.open(path, flags | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(fd, (fcntl.LOCK_SH if readonly else fcntl.LOCK_EX) | fcntl.LOCK_NB)
        yield
    finally:
        os.close(fd)


def computational_identity(evidence, policy):
    """Pure offline identity: process start/PID and file stat may change on restart."""
    require(evidence['policy_sha256'] == inventory.identity(policy), 'Runtime policy differs')
    require(evidence['model_sha256'] == policy['llama_cpp']['model_sha256'], 'Runtime model differs')
    process, props = evidence['process'], evidence['props']
    require(type(process['pid']) is int and process['pid'] > 0 and str(process['start_ticks']).isdigit(),
            'Invalid runtime process identity')
    require(props['model_alias'] == policy['llm']['model_id'] and props['total_slots'] == 1
            and props['default_generation_settings']['n_ctx'] == policy['llm']['context_limit'],
            'Runtime model/context/slots differ')
    require(isinstance(props['chat_template'], str) and props['chat_template']
            and type(evidence['gpu_layers']) is int and evidence['gpu_layers'] > 0
            and evidence['flash_attention'] == 'enabled', 'Incomplete computational settings')
    hashes = [process['binary_sha256'], evidence['model_sha256'], evidence['source']['source_tree_sha256'],
              *evidence['libraries'].values()]
    require(all(isinstance(h, str) and re.fullmatch('[0-9a-f]{64}', h) for h in hashes), 'Invalid runtime hashes')
    return {'policy_sha256': evidence['policy_sha256'], 'model_sha256': evidence['model_sha256'],
            'binary_sha256': process['binary_sha256'], **{k: evidence[k] for k in
                ('props', 'libraries', 'source', 'gpu_layers', 'flash_attention')}}


def _plan(conditions, public, policy, prompt, schemas):
    observations = {}
    for row in conditions:
        minimal = {k: row[k] for k in ('observation_id', 'parent_bundle_sha256', 'bundle_path')}
        obs = row['observation_id']
        require(IDENTIFIER.fullmatch(obs), 'Invalid observation ID')
        require(obs not in observations or observations[obs] == minimal, 'Condition source identities differ')
        observations[obs] = minimal
    expected, slots = inventory.conditions_and_slots(list(observations.values()), policy)
    require(expected == conditions, 'Condition ledger differs from declared matrix')
    require(set(public) == {c['view_path'] for c in conditions}, 'View inventory differs')
    by_condition = {c['condition_id']: c for c in conditions}
    templates = {}
    for row in conditions:
        view = public[row['view_path']]
        require(view['representation'] == row['representation'], 'View representation differs')
        templates[row['condition_id']] = adapter.payload(view, prompt, schemas['response.json'], policy, 1,
            view_schema=schemas['view.json'], parent_schema=schemas['bundle-v2.json'])
    requests = {}
    for slot in slots:
        row = by_condition[slot['condition_id']]
        path = row['view_path']
        require(path == f"public/views/{slot['representation']}/{slot['observation_id']}.json", 'Unexpected view path')
        view = public[path]
        # The protocol varies repetition only through seed; retain exact per-slot wire bytes.
        request = {**templates[slot['condition_id']], 'seed': slot['seed']}
        wire = adapter.wire(request)
        slot.update(view_path=path, view_sha256=inventory.identity(view),
                    request_path=slot['slot_path']+'/request.json',
                    request_sha256=hashlib.sha256(wire.encode('utf-8')).hexdigest())
        requests[slot['request_path']] = wire
    require(len(slots) == policy['matrix']['final_slots'], 'Slot inventory count differs')
    return slots, requests


def prepare(projection, directory, *, protocol_root=adapter.HERE, projection_manifest_sha256=None,
            run_id=None, purpose='engineering'):
    """Offline preparation only; runtime/token budgets are bound separately."""
    projection, directory = Path(projection).resolve(), Path(directory).absolute()
    require(not directory.exists() and not directory.is_symlink(), 'Runner destination already exists')
    require(not directory.resolve().is_relative_to(projection)
            and not projection.is_relative_to(directory.resolve()), 'Runner destination overlaps projection')
    run_id = run_id or directory.name
    require(IDENTIFIER.fullmatch(run_id) and purpose in {'engineering', 'final'}, 'Invalid run identity/purpose')
    receipt = views.verify(projection, projection_manifest_sha256)
    policy, prompt, response = adapter.settings(protocol_root)
    conditions = read_json(projection/'coordinator/conditions.json')
    public = {c['view_path']: read_json(projection/c['view_path']) for c in conditions}
    schemas = {'response.json': response, **{n: read_json(projection/'schemas'/n) for n in ('view.json', 'bundle-v2.json')}}
    slots, requests = _plan(conditions, public, policy, prompt, schemas)
    content = {**requests, **{p: bundles.canonical(v) for p, v in public.items()},
               'protocol/policy.json': bundles.canonical(policy), 'protocol/prompt.md': prompt,
               **{'protocol/'+n: bundles.canonical(s) for n, s in schemas.items()},
               'coordinator/conditions.json': bundles.canonical(conditions),
               'coordinator/schedule.json': bundles.canonical(slots)}
    dependencies = inventory.dependencies('redesign.extensions.representation_study.runner')
    content['coordinator/dependencies.json'] = bundles.canonical(dependencies)
    for name in (*dependencies['source_files'], 'requirements.txt'):
        content['coordinator/dependency-snapshot/'+name] = (inventory.REPO/name).read_text(encoding='utf-8')
    manifest = {'schema_version': 1, 'status': 'requests_prepared', 'run_id': run_id, 'purpose': purpose,
                'projection_manifest_sha256': receipt['manifest_sha256'],
                'counts': {'observations': receipt['observations'], 'conditions': receipt['views'], 'slots': len(slots)},
                'files': {name: hashlib.sha256(text.encode('utf-8')).hexdigest() for name, text in sorted(content.items())}}
    directory.mkdir(parents=True, exist_ok=False)
    for name, text in sorted(content.items()):
        _publish(local_path(directory, name), text)
    _publish(directory/MANIFEST, manifest)
    return verify(directory)


def _load(directory, expected_manifest_sha256=None):
    manifest_path = inventory.plain_file(directory, MANIFEST)
    manifest_hash = digest(manifest_path)
    require(expected_manifest_sha256 is None or manifest_hash == expected_manifest_sha256, 'Runner manifest changed')
    manifest = read_json(manifest_path)
    require(manifest['schema_version'] == 1 and manifest['status'] == 'requests_prepared'
            and IDENTIFIER.fullmatch(manifest['run_id']) and manifest['purpose'] in {'engineering', 'final'},
            'Unknown runner manifest')
    for name, expected in manifest['files'].items():
        require(digest(inventory.plain_file(directory, name)) == expected, f'Changed runner input: {name}')
    policy = adapter.policy_check(read_json(directory/'protocol/policy.json'))
    prompt = (directory/'protocol/prompt.md').read_text(encoding='utf-8')
    schemas = {n: read_json(directory/'protocol'/n) for n in ('response.json', 'view.json', 'bundle-v2.json')}
    conditions = read_json(directory/'coordinator/conditions.json')
    public = {c['view_path']: read_json(directory/c['view_path']) for c in conditions}
    slots, requests = _plan(conditions, public, policy, prompt, schemas)
    require(read_json(directory/'coordinator/schedule.json') == slots, 'Frozen schedule differs')
    require(manifest['counts'] == {'observations': len({c['observation_id'] for c in conditions}),
                                   'conditions': len(conditions), 'slots': len(slots)}
            and len(public) == len(conditions), 'Runner counts differ')
    for name, wire in requests.items():
        require((directory/name).read_bytes() == wire.encode('utf-8'), 'Request wire bytes differ')
    deps = read_json(directory/'coordinator/dependencies.json')
    for name, expected in {**deps['source_files'], 'requirements.txt': deps['requirements_sha256']}.items():
        require(digest(inventory.plain_file(directory, 'coordinator/dependency-snapshot/'+name)) == expected,
                f'Dependency snapshot differs: {name}')
    return {'manifest': manifest, 'hash': manifest_hash, 'policy': policy, 'prompt': prompt,
            'schemas': schemas, 'slots': slots, 'public': public, 'dependencies': deps}


def _methods(context):
    deps = context['dependencies']
    for name, expected in {**deps['source_files'], 'requirements.txt': deps['requirements_sha256']}.items():
        require(digest(inventory.plain_file(inventory.REPO, name)) == expected, f'Executing dependency changed: {name}')


def _events(directory, context):
    files = sorted((directory/'runtime').glob('*.json'))
    events, previous, configuration = [], None, None
    for index, path in enumerate(files, 1):
        require(path.name == f'{index:06d}.json', 'Runtime event sequence differs')
        event = read_json(inventory.plain_file(directory, path.relative_to(directory).as_posix()))
        require(event['sequence'] == index and event['previous_sha256'] == previous
                and event['manifest_sha256'] == context['hash'], 'Runtime event binding differs')
        identity = computational_identity(event['evidence'], context['policy'])
        require(configuration is None or identity == configuration, 'Restart computational settings differ')
        configuration = identity
        previous = digest(path)
        events.append({**event, 'sha256': previous})
    return events


def _append_runtime(directory, context, evidence):
    identity = computational_identity(evidence, context['policy'])
    events = _events(directory, context)
    if events:
        require(identity == computational_identity(events[0]['evidence'], context['policy']),
                'Restart computational settings differ')
        if evidence == events[-1]['evidence']:
            return events[-1]
    event = {'sequence': len(events)+1, 'previous_sha256': events[-1]['sha256'] if events else None,
             'manifest_sha256': context['hash'], 'created_at': _now(), 'evidence': evidence}
    path = directory/'runtime'/f"{event['sequence']:06d}.json"
    _publish(path, event)
    return {**event, 'sha256': digest(path)}


def _budget_check(budget, policy):
    tokens = budget['token_ids']
    require(isinstance(tokens, list) and tokens and all(type(t) is int for t in tokens)
            and isinstance(budget['rendered_prompt'], str), 'Invalid token preflight')
    require(budget['prompt_tokens'] == len(tokens)
            and budget['reserved_completion_tokens'] == policy['llm']['max_tokens']
            and budget['total_budget'] == len(tokens)+policy['llm']['max_tokens'], 'Invalid token accounting')
    expected = 'available' if budget['total_budget'] <= policy['llm']['context_limit'] else 'context_unavailable'
    require(budget['status'] == expected, 'Invalid token eligibility')


def _preflight(directory, context, events):
    if not (directory/PREFLIGHT).exists():
        return None
    preflight = read_json(inventory.plain_file(directory, PREFLIGHT))
    require(events and preflight['manifest_sha256'] == context['hash']
            and preflight['configuration'] == computational_identity(events[0]['evidence'], context['policy']),
            'Preflight runtime binding differs')
    require(set(preflight['budgets']) == {s['slot_id'] for s in context['slots']}, 'Preflight slot inventory differs')
    eligible = {}
    for slot in context['slots']:
        record = preflight['budgets'][slot['slot_id']]
        require(record['request_sha256'] == slot['request_sha256'], 'Preflight request differs')
        _budget_check(record['accounting'], context['policy'])
        obs = slot['observation_id']
        eligible[obs] = eligible.get(obs, True) and record['accounting']['status'] == 'available'
    require(preflight['eligibility'] == eligible, 'Common observation eligibility differs')
    return preflight


def _response(directory, slot, context, dispatch_hash):
    path = directory/slot['slot_path']/'response.json'
    if not path.exists():
        return None
    record = read_json(path)
    require(record['slot_id'] == slot['slot_id'] and record['dispatch_sha256'] == dispatch_hash, 'Response binding differs')
    response = record['attempt']
    require(set(response) == RESPONSE_FIELDS and type(response['elapsed_seconds']) in (int, float)
            and math.isfinite(response['elapsed_seconds']) and response['elapsed_seconds'] >= 0, 'Invalid response record')
    if response['response_body'] is not None:
        require(isinstance(response['response_body'], str) and type(response['http_status']) is int, 'Invalid HTTP record')
        decoded = adapter.decode(response['response_body'], response['http_status'], context['public'][slot['view_path']],
                                 context['schemas']['response.json'], view_schema=context['schemas']['view.json'],
                                 parent_schema=context['schemas']['bundle-v2.json'])
        require(all(response[k] == v for k, v in decoded.items()), 'Saved response decoding differs')
    else:
        require(response['status'] in {'timeout', 'transport_error'} and response['http_status'] is None
                and response['parsed'] is None and isinstance(response['error'], str) and response['error']
                and response['usage'] == {'prompt_tokens': None, 'completion_tokens': None}
                and response['finish_reason'] is None and response['raw_reasoning'] is None
                and response['raw_content'] == '' and response['validation_failure'] == {
                    'stage': 'transport', 'code': response['status'], 'path': []}, 'Invalid transport failure record')
    return response


def _state(directory, context):
    nodes = list(directory.rglob('*'))
    require(not any(p.is_symlink() for p in nodes), 'Runner symlinks are not allowed')
    events = _events(directory, context)
    preflight = _preflight(directory, context, events)
    event_hashes = {e['sha256']: e['sequence'] for e in events}
    expected = set(context['manifest']['files']) | {MANIFEST}
    expected.update(f"runtime/{e['sequence']:06d}.json" for e in events)
    if preflight is not None: expected.add(PREFLIGHT)
    write_dirs = {'runtime', 'coordinator'} | {s['slot_path'] for s in context['slots']}
    statuses, grouped, previous_dispatch, last_event, gap = Counter(), defaultdict(list), None, 0, False
    for index, slot in enumerate(context['slots']):
        path = directory/slot['slot_path']
        present = {n for n in ('dispatch.json', 'response.json', 'result.json') if (path/n).exists()}
        expected.update(slot['slot_path']+'/'+n for n in present)
        eligible = preflight is not None and preflight['eligibility'][slot['observation_id']]
        response, dispatch_hash = None, None
        if 'dispatch.json' in present:
            dispatch = read_json(path/'dispatch.json')
            require(eligible and not gap and dispatch['slot_id'] == slot['slot_id']
                    and dispatch['schedule_index'] == index and dispatch['previous_dispatch_sha256'] == previous_dispatch
                    and dispatch['manifest_sha256'] == context['hash']
                    and dispatch['request_sha256'] == slot['request_sha256']
                    and dispatch['preflight_sha256'] == digest(directory/PREFLIGHT)
                    and dispatch['runtime_event_sha256'] in event_hashes, 'Dispatch binding/order differs')
            sequence = event_hashes[dispatch['runtime_event_sha256']]
            require(sequence >= last_event, 'Runtime dispatch order differs')
            last_event = sequence
            previous_dispatch = dispatch_hash = digest(path/'dispatch.json')
            response = _response(directory, slot, context, dispatch_hash)
        else:
            require('response.json' not in present, 'Response without dispatch')
            if eligible: gap = True
        if 'result.json' in present:
            result = read_json(path/'result.json')
            require(result['slot_id'] == slot['slot_id'] and result['response_sha256'] ==
                    (digest(path/'response.json') if response is not None else None), 'Result binding differs')
            status = result['status']
            if dispatch_hash is None:
                require(preflight is not None and not eligible and status == 'input_blocked'
                        and response is None, 'Invalid input-blocked slot')
            elif response is None:
                require(status == 'interrupted' and result['error'], 'Invalid interruption record')
            else:
                require((status == response['status'] and result['error'] is None)
                        or (status in {'interrupted', 'runtime_changed'} and result['error']), 'Invalid terminal response')
        else:
            status = 'interrupted' if dispatch_hash is not None else 'pending'
        statuses[status] += 1
        if status != 'pending':
            grouped[slot['condition_id']].append({'status': status,
                'parsed': response['parsed'] if status == 'valid' else None})
    pending = []
    for p in nodes:
        if not p.is_file(): continue
        name = p.relative_to(directory).as_posix()
        if name == 'runner.lock': expected.add(name)
        if p.name.startswith('.pending-') and p.parent.relative_to(directory).as_posix() in write_dirs:
            expected.add(name); pending.append(name)
    require({p.relative_to(directory).as_posix() for p in nodes if p.is_file()} == expected, 'Runner file inventory differs')
    conditions = {s['condition_id']: (s['observation_id'], s['representation']) for s in context['slots']}
    return {'status': 'complete' if not statuses['pending'] else 'incomplete', 'run_id': context['manifest']['run_id'],
            'purpose': context['manifest']['purpose'], 'manifest_sha256': context['hash'], 'slots': len(context['slots']),
            'terminal_slots': len(context['slots'])-statuses['pending'], 'attempt_statuses': dict(statuses),
            'runtime_events': len(events), 'preflight_bound': preflight is not None,
            'blocked_observations': sum(not x for x in preflight['eligibility'].values()) if preflight else None,
            'uncommitted_files': sorted(pending),
            'aggregates': {key: {'observation_id': conditions[key][0], 'representation': conditions[key][1],
                                 **adapter.aggregate(rows)} for key, rows in grouped.items() if len(rows) == 3}}


def verify(directory, expected_manifest_sha256=None):
    """Read-only: no requests, runtime queries, result rewrites or workspace fallback."""
    directory = Path(directory).resolve()
    with _ownership(directory, readonly=True):
        return _state(directory, _load(directory, expected_manifest_sha256))


def preflight(directory, evidence):
    """Bind actual-template accounting; this sends tokenizer queries, never generation."""
    directory = Path(directory).resolve()
    with _ownership(directory):
        context = _load(directory); _state(directory, context); _methods(context)
        require(not (directory/PREFLIGHT).exists(), 'Preflight already bound')
        computational_identity(evidence, context['policy'])
        runtime.verify_live(evidence, context['policy'])
        budgets, eligible = {}, {}
        for slot in context['slots']:
            accounting = runtime.budget(read_json(directory/slot['request_path']), context['policy'])
            _budget_check(accounting, context['policy'])
            budgets[slot['slot_id']] = {'request_sha256': slot['request_sha256'], 'accounting': accounting}
            obs = slot['observation_id']
            eligible[obs] = eligible.get(obs, True) and accounting['status'] == 'available'
        runtime.verify_live(evidence, context['policy'])
        _append_runtime(directory, context, evidence)
        _publish(directory/PREFLIGHT, {'manifest_sha256': context['hash'],
            'configuration': computational_identity(evidence, context['policy']), 'budgets': budgets, 'eligibility': eligible})
        return _state(directory, context)


def register_runtime(directory, evidence):
    directory = Path(directory).resolve()
    with _ownership(directory):
        context = _load(directory); _state(directory, context); _methods(context)
        runtime.verify_live(evidence, context['policy'])
        _append_runtime(directory, context, evidence)
        return _state(directory, context)


def _packet_check(directory, context, slot, preflight_hash, event):
    require(digest(directory/MANIFEST) == context['hash'] and digest(directory/PREFLIGHT) == preflight_hash,
            'Frozen execution binding changed')
    files = context['manifest']['files']
    names = ['coordinator/schedule.json', 'coordinator/conditions.json', 'coordinator/dependencies.json',
             *('protocol/'+n for n in PROTOCOL), slot['view_path'], slot['request_path']]
    for name in names:
        require(digest(inventory.plain_file(directory, name)) == files[name], f'Changed dispatch input: {name}')
    require(digest(directory/'runtime'/f"{event['sequence']:06d}.json") == event['sha256'], 'Runtime event changed')
    _methods(context)
    runtime.verify_live(event['evidence'], context['policy'])


def _finish(directory, slot, status, error=None):
    path = directory/slot['slot_path']
    _publish(path/'result.json', {'slot_id': slot['slot_id'], 'status': status, 'error': error,
             'response_sha256': digest(path/'response.json') if (path/'response.json').exists() else None}, journal=True)


def run(directory, *, max_slots=None):
    directory = Path(directory).resolve()
    require(max_slots is None or type(max_slots) is int and max_slots >= 0, 'Invalid dispatch limit')
    with _ownership(directory):
        context = _load(directory); _state(directory, context); _methods(context)
        events = _events(directory, context)
        preflight = _preflight(directory, context, events)
        require(preflight is not None, 'Preflight is not bound')
        preflight_hash, previous_dispatch, count = digest(directory/PREFLIGHT), None, 0
        for index, slot in enumerate(context['slots']):
            path = directory/slot['slot_path']
            if (path/'dispatch.json').exists():
                previous_dispatch = digest(path/'dispatch.json')
                if not (path/'result.json').exists():
                    _finish(directory, slot, 'interrupted', 'Completion publication interrupted; no retry permitted')
                continue
            if (path/'result.json').exists(): continue
            if not preflight['eligibility'][slot['observation_id']]:
                _finish(directory, slot, 'input_blocked', 'A representation exceeds the common context budget')
                continue
            if max_slots is not None and count >= max_slots: continue
            event = events[-1]
            _packet_check(directory, context, slot, preflight_hash, event)
            request = read_json(directory/slot['request_path'])
            _publish(path/'dispatch.json', {'slot_id': slot['slot_id'], 'schedule_index': index,
                'previous_dispatch_sha256': previous_dispatch, 'manifest_sha256': context['hash'],
                'request_sha256': slot['request_sha256'], 'preflight_sha256': preflight_hash,
                'runtime_event_sha256': event['sha256'], 'started_at': _now()}, journal=True)
            previous_dispatch = digest(path/'dispatch.json')
            response = adapter.attempt(request, context['public'][slot['view_path']], context['policy'],
                context['schemas']['response.json'], view_schema=context['schemas']['view.json'],
                parent_schema=context['schemas']['bundle-v2.json'])
            _publish(path/'response.json', {'slot_id': slot['slot_id'], 'dispatch_sha256': previous_dispatch,
                                           'attempt': response}, journal=True)
            try:
                _packet_check(directory, context, slot, preflight_hash, event)
            except Exception as error:
                _finish(directory, slot, 'runtime_changed', str(error))
                raise
            _finish(directory, slot, response['status'])
            count += 1
        return _state(directory, _load(directory))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('prepare', 'verify', 'preflight', 'register-runtime', 'run', 'serve', 'capture'))
    parser.add_argument('--directory', type=Path, required=True)
    parser.add_argument('--projection', type=Path)
    parser.add_argument('--projection-manifest-sha256')
    parser.add_argument('--manifest-sha256')
    parser.add_argument('--protocol-root', type=Path, default=adapter.HERE)
    parser.add_argument('--server', type=Path)
    parser.add_argument('--max-slots', type=int)
    parser.add_argument('--purpose', choices=('engineering', 'final'), default='engineering')
    args = parser.parse_args()
    if args.action == 'serve':
        runtime.serve(args.directory, adapter.settings(args.protocol_root)[0]); return
    if args.action == 'capture':
        launch = read_json(args.directory/'launch.json')
        evidence = runtime.capture(launch['pid'], args.directory/'startup.log', adapter.settings(args.protocol_root)[0])
        _publish(args.directory/'server.json', evidence); return
    if args.action == 'prepare':
        require(args.projection is not None, 'prepare requires --projection')
        result = prepare(args.projection, args.directory, protocol_root=args.protocol_root,
                         projection_manifest_sha256=args.projection_manifest_sha256, purpose=args.purpose)
    elif args.action == 'verify': result = verify(args.directory, args.manifest_sha256)
    elif args.action == 'run': result = run(args.directory, max_slots=args.max_slots)
    else:
        require(args.server is not None, 'Runtime binding requires --server')
        result = (preflight if args.action == 'preflight' else register_runtime)(args.directory, read_json(args.server))
    print(bundles.canonical(result), end='')


if __name__ == '__main__':
    main()

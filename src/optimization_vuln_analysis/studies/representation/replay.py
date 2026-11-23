"""Read and validate saved packets, runtime events and execution journals.

inspect() is the read-only entry point: it returns the original state summary
(including manifest identity and aggregates), projection identity and common
eligibility.
This module never dispatches, queries a runtime, repairs or publishes results.
"""
from collections import Counter, defaultdict
from contextlib import contextmanager
import fcntl
import hashlib
import math
import os
from pathlib import Path
import re

from optimization_vuln_analysis.common import require
from optimization_vuln_analysis.inputs.corpus import IDENTIFIER
from optimization_vuln_analysis.common.artifacts import digest, plain_file
from optimization_vuln_analysis.common.serialization import read_json
from . import adapter, inventory


MANIFEST = 'coordinator/manifest.json'
PREFLIGHT = 'coordinator/preflight.json'
PROTOCOL = ('policy.json', 'prompt.md', 'response.json', 'view.json', 'bundle-v2.json')
RESPONSE_FIELDS = {'status', 'parsed', 'error', 'validation_failure', 'finish_reason', 'usage',
                   'raw_content', 'raw_reasoning', 'response_body', 'http_status', 'elapsed_seconds'}


@contextmanager
def ownership(directory, *, readonly=False):
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


def plan_requests(conditions, public, policy, prompt, schemas):
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


def load_packet(directory, expected_manifest_sha256=None):
    """Validate the protocol, views and requests of an execution packet.

    The internal mapping contains manifest/hash, policy, prompt, schemas, slots,
    public views. Callers hold ownership across writes;
    read-only consumers normally use inspect instead.
    """
    directory = Path(directory)
    manifest_path = plain_file(directory, MANIFEST)
    manifest_hash = digest(manifest_path)
    require(expected_manifest_sha256 is None or manifest_hash == expected_manifest_sha256, 'Runner manifest changed')
    manifest = read_json(manifest_path)
    require(manifest['schema_version'] == 1 and manifest['status'] == 'requests_prepared'
            and IDENTIFIER.fullmatch(manifest['run_id']) and manifest['purpose'] in {'engineering', 'final'},
            'Unknown runner manifest')
    for name, expected in manifest['files'].items():
        require(digest(plain_file(directory, name)) == expected, f'Changed runner input: {name}')
    policy = adapter.policy_check(read_json(directory/'protocol/policy.json'))
    prompt = (directory/'protocol/prompt.md').read_text(encoding='utf-8')
    schemas = {n: read_json(directory/'protocol'/n) for n in ('response.json', 'view.json', 'bundle-v2.json')}
    conditions = read_json(directory/'coordinator/conditions.json')
    public = {c['view_path']: read_json(directory/c['view_path']) for c in conditions}
    slots, requests = plan_requests(conditions, public, policy, prompt, schemas)
    require(read_json(directory/'coordinator/schedule.json') == slots, 'Prepared schedule differs')
    require(manifest['counts'] == {'observations': len({c['observation_id'] for c in conditions}),
                                   'conditions': len(conditions), 'slots': len(slots)}
            and len(public) == len(conditions), 'Runner counts differ')
    for name, wire in requests.items():
        require((directory/name).read_bytes() == wire.encode('utf-8'), 'Request wire bytes differ')
    return {'manifest': manifest, 'hash': manifest_hash, 'policy': policy, 'prompt': prompt,
            'schemas': schemas, 'slots': slots, 'public': public}


def runtime_events(directory, context):
    files = sorted((directory/'runtime').glob('*.json'))
    events, previous, configuration = [], None, None
    for index, path in enumerate(files, 1):
        require(path.name == f'{index:06d}.json', 'Runtime event sequence differs')
        event = read_json(plain_file(directory, path.relative_to(directory).as_posix()))
        require(event['sequence'] == index and event['previous_sha256'] == previous
                and event['manifest_sha256'] == context['hash'], 'Runtime event binding differs')
        identity = computational_identity(event['evidence'], context['policy'])
        require(configuration is None or identity == configuration, 'Restart computational settings differ')
        configuration = identity
        previous = digest(path)
        events.append({**event, 'sha256': previous})
    return events


def check_budget(budget, policy):
    tokens = budget['token_ids']
    require(isinstance(tokens, list) and tokens and all(type(t) is int for t in tokens)
            and isinstance(budget['rendered_prompt'], str), 'Invalid token preflight')
    require(budget['prompt_tokens'] == len(tokens)
            and budget['reserved_completion_tokens'] == policy['llm']['max_tokens']
            and budget['total_budget'] == len(tokens)+policy['llm']['max_tokens'], 'Invalid token accounting')
    expected = 'available' if budget['total_budget'] <= policy['llm']['context_limit'] else 'context_unavailable'
    require(budget['status'] == expected, 'Invalid token eligibility')


def preflight_record(directory, context, events):
    if not (directory/PREFLIGHT).exists():
        return None
    preflight = read_json(plain_file(directory, PREFLIGHT))
    require(events and preflight['manifest_sha256'] == context['hash']
            and preflight['configuration'] == computational_identity(events[0]['evidence'], context['policy']),
            'Preflight runtime binding differs')
    require(set(preflight['budgets']) == {s['slot_id'] for s in context['slots']}, 'Preflight slot inventory differs')
    eligible = {}
    for slot in context['slots']:
        record = preflight['budgets'][slot['slot_id']]
        require(record['request_sha256'] == slot['request_sha256'], 'Preflight request differs')
        check_budget(record['accounting'], context['policy'])
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


def reconstruct(directory, context):
    """Reconstruct state and eligibility under a caller-held packet lock."""
    nodes = list(directory.rglob('*'))
    require(not any(p.is_symlink() for p in nodes), 'Runner symlinks are not allowed')
    events = runtime_events(directory, context)
    preflight = preflight_record(directory, context, events)
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
    state = {'status': 'complete' if not statuses['pending'] else 'incomplete', 'run_id': context['manifest']['run_id'],
            'purpose': context['manifest']['purpose'], 'manifest_sha256': context['hash'], 'slots': len(context['slots']),
            'terminal_slots': len(context['slots'])-statuses['pending'], 'attempt_statuses': dict(statuses),
            'runtime_events': len(events), 'preflight_bound': preflight is not None,
            'blocked_observations': sum(not x for x in preflight['eligibility'].values()) if preflight else None,
            'uncommitted_files': sorted(pending),
            'aggregates': {key: {'observation_id': conditions[key][0], 'representation': conditions[key][1],
                                 **adapter.aggregate(rows)} for key, rows in grouped.items() if len(rows) == 3}}
    return {'state': state, 'projection_manifest_sha256': context['manifest']['projection_manifest_sha256'],
            'eligibility': preflight['eligibility'] if preflight is not None else None}


def inspect(directory, expected_manifest_sha256=None):
    """Inspect saved evidence without runtime calls or working-source checks.

    Returns state (the unchanged runner.verify result), projection_manifest_sha256
    and eligibility (None before preflight, otherwise observation-ID booleans).
    No files, including runner.lock, are created during read-only inspection.
    """
    directory = Path(directory).resolve()
    with ownership(directory, readonly=True):
        return reconstruct(directory, load_packet(directory, expected_manifest_sha256))


def records(execution):
    """Read terminal attempt records after a successful integrity inspection."""
    records = []
    for slot in read_json(execution/'coordinator/schedule.json'):
        path = execution/slot['slot_path']
        result = read_json(path/'result.json')
        response = read_json(path/'response.json')['attempt'] if (path/'response.json').exists() else None
        dispatch = read_json(path/'dispatch.json') if (path/'dispatch.json').exists() else None
        records.append({**slot, 'status': result['status'], 'response': response, 'dispatch': dispatch,
                        'response_path': slot['slot_path']+'/response.json' if response is not None else None,
                        'response_sha256': digest(path/'response.json') if response is not None else None})
    return records

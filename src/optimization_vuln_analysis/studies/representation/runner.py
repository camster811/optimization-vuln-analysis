"""Prepare packets and own runtime/dispatch writes; inspect saved state in replay."""
import argparse
from datetime import datetime, timezone
import hashlib
from pathlib import Path

from optimization_vuln_analysis.common import require
from optimization_vuln_analysis.inputs import bundles
from optimization_vuln_analysis.inference import runtime
from optimization_vuln_analysis.common.serialization import journal_json, read_json
from optimization_vuln_analysis.inputs.corpus import IDENTIFIER
from optimization_vuln_analysis.common.artifacts import digest, local_path, plain_file
from . import adapter, replay, views


def _now():
    return datetime.now(timezone.utc).isoformat()


def _publish(path, value, *, journal=False):
    # Escaping raw journals also preserves malformed surrogate strings losslessly.
    if journal:
        value = journal_json(value)
    runtime.write_new(path, value)
    Path(path).chmod(0o444)


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
    slots, requests = replay.plan_requests(conditions, public, policy, prompt, schemas)
    content = {**requests, **{p: bundles.canonical(v) for p, v in public.items()},
               'protocol/policy.json': bundles.canonical(policy), 'protocol/prompt.md': prompt,
               **{'protocol/'+n: bundles.canonical(s) for n, s in schemas.items()},
               'coordinator/conditions.json': bundles.canonical(conditions),
               'coordinator/schedule.json': bundles.canonical(slots)}
    manifest = {'schema_version': 1, 'status': 'requests_prepared', 'run_id': run_id, 'purpose': purpose,
                'projection_manifest_sha256': receipt['manifest_sha256'],
                'counts': {'observations': receipt['observations'], 'conditions': receipt['views'], 'slots': len(slots)},
                'files': {name: hashlib.sha256(text.encode('utf-8')).hexdigest() for name, text in sorted(content.items())}}
    directory.mkdir(parents=True, exist_ok=False)
    for name, text in sorted(content.items()):
        _publish(local_path(directory, name), text)
    _publish(directory/replay.MANIFEST, manifest)
    return verify(directory)


def _append_runtime(directory, context, evidence):
    identity = replay.computational_identity(evidence, context['policy'])
    events = replay.runtime_events(directory, context)
    if events:
        require(identity == replay.computational_identity(events[0]['evidence'], context['policy']),
                'Restart computational settings differ')
        if evidence == events[-1]['evidence']:
            return events[-1]
    event = {'sequence': len(events)+1, 'previous_sha256': events[-1]['sha256'] if events else None,
             'manifest_sha256': context['hash'], 'created_at': _now(), 'evidence': evidence}
    path = directory/'runtime'/f"{event['sequence']:06d}.json"
    _publish(path, event)
    return {**event, 'sha256': digest(path)}


def verify(directory, expected_manifest_sha256=None):
    """Compatibility entry point for the unchanged saved-state summary."""
    return replay.inspect(directory, expected_manifest_sha256)['state']


def preflight(directory, evidence):
    """Bind actual-template accounting; this sends tokenizer queries, never generation."""
    directory = Path(directory).resolve()
    with replay.ownership(directory):
        context = replay.load_packet(directory)
        replay.reconstruct(directory, context)
        require(not (directory/replay.PREFLIGHT).exists(), 'Preflight already bound')
        replay.computational_identity(evidence, context['policy'])
        runtime.verify_live(evidence, context['policy'])
        budgets, eligible = {}, {}
        for slot in context['slots']:
            accounting = runtime.budget(read_json(directory/slot['request_path']), context['policy'])
            replay.check_budget(accounting, context['policy'])
            budgets[slot['slot_id']] = {'request_sha256': slot['request_sha256'], 'accounting': accounting}
            obs = slot['observation_id']
            eligible[obs] = eligible.get(obs, True) and accounting['status'] == 'available'
        runtime.verify_live(evidence, context['policy'])
        _append_runtime(directory, context, evidence)
        _publish(directory/replay.PREFLIGHT, {'manifest_sha256': context['hash'],
            'configuration': replay.computational_identity(evidence, context['policy']), 'budgets': budgets, 'eligibility': eligible})
        return replay.reconstruct(directory, context)['state']


def register_runtime(directory, evidence):
    directory = Path(directory).resolve()
    with replay.ownership(directory):
        context = replay.load_packet(directory)
        replay.reconstruct(directory, context)
        runtime.verify_live(evidence, context['policy'])
        _append_runtime(directory, context, evidence)
        return replay.reconstruct(directory, context)['state']


def _packet_check(directory, context, slot, preflight_hash, event):
    require(digest(directory/replay.MANIFEST) == context['hash'] and digest(directory/replay.PREFLIGHT) == preflight_hash,
            'Execution binding changed')
    files = context['manifest']['files']
    names = ['coordinator/schedule.json', 'coordinator/conditions.json',
             *('protocol/'+n for n in replay.PROTOCOL), slot['view_path'], slot['request_path']]
    for name in names:
        require(digest(plain_file(directory, name)) == files[name], f'Changed dispatch input: {name}')
    require(digest(directory/'runtime'/f"{event['sequence']:06d}.json") == event['sha256'], 'Runtime event changed')
    runtime.verify_live(event['evidence'], context['policy'])


def _finish(directory, slot, status, error=None):
    path = directory/slot['slot_path']
    _publish(path/'result.json', {'slot_id': slot['slot_id'], 'status': status, 'error': error,
             'response_sha256': digest(path/'response.json') if (path/'response.json').exists() else None}, journal=True)


def run(directory, *, max_slots=None):
    directory = Path(directory).resolve()
    require(max_slots is None or type(max_slots) is int and max_slots >= 0, 'Invalid dispatch limit')
    with replay.ownership(directory):
        context = replay.load_packet(directory)
        replay.reconstruct(directory, context)
        events = replay.runtime_events(directory, context)
        preflight = replay.preflight_record(directory, context, events)
        require(preflight is not None, 'Preflight is not bound')
        preflight_hash, previous_dispatch, count = digest(directory/replay.PREFLIGHT), None, 0
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
        return replay.reconstruct(directory, replay.load_packet(directory))['state']


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

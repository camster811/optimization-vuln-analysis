"""Saved-result analysis and deterministic tables/figures for the representation study."""
import argparse
from collections import Counter, defaultdict
import csv
import io
import math
import os
from pathlib import Path
import tempfile

from optimization_vuln_analysis.common import require
from optimization_vuln_analysis.inputs import bundles
from optimization_vuln_analysis.inference import runtime
from optimization_vuln_analysis.common.artifacts import (
    bytes_digest, publish_bytes, digest, plain_file, local_path,
)
from optimization_vuln_analysis.common.serialization import compact_json, report_json, read_json, strict_json
from . import scoring, views, replay as execution_replay


NAMES = {'assembly': 'Assembly', 'decompilation': 'Decompilation', 'combined': 'Combined',
         scoring.CONTROL: 'Always safe'}
ERROR_CODES = {'frame_versus_object_bounds', 'source_destination_region_confusion', 'element_byte_units',
               'infeasible_paths', 'eliminated_writes', 'unsupported_reasoning'}


def _json(value):
    return report_json(value)


def _csv(rows, fields):
    output = io.StringIO(newline='')
    writer = csv.DictWriter(output, fieldnames=fields, lineterminator='\n', extrasaction='raise')
    writer.writeheader(); writer.writerows(rows)
    return output.getvalue().encode('utf-8')


def _compact(value):
    return compact_json(value)


def _outcome(label, prediction):
    if label not in scoring.LABELS: return 'unresolved'
    if prediction['status'] == 'unavailable': return 'M'
    if prediction['status'] == 'abstained': return 'U'
    return 'C' if prediction['decision'] == label else 'E'


def audit(evaluation, records, replay):
    """Independent Python integer/vote recount; does not call scorer event arithmetic."""
    grouped = defaultdict(list)
    for record in records: grouped[record['condition_id']].append(record)
    require(set(grouped) == set(replay['aggregates']), 'Recount condition inventory differs')
    for key, rows in grouped.items():
        require(len(rows) == 3 and {r['repetition'] for r in rows} == {1, 2, 3}, 'Recount repetition inventory differs')
        votes = Counter(r['response']['parsed']['decision'] for r in rows if r['status'] == 'valid')
        winner = next((label for label, count in votes.items() if count >= 2), None)
        decision = winner if winner else 'uncertain' if votes else None
        status = 'unavailable' if not votes else 'abstained' if decision == 'uncertain' else 'classified'
        aggregate = replay['aggregates'][key]
        require((aggregate['status'], aggregate['decision'], aggregate['valid_votes'], aggregate['votes']) ==
                (status, decision, sum(votes.values()), dict(votes)), 'Independent vote recount differs')
    aligned = {(a['observation_id'], a['representation']): a for a in replay['aggregates'].values()}
    for row in evaluation['rows']:
        for method in scoring.REPRESENTATIONS:
            aggregate = aligned[row['observation_id'], method]
            require(row['predictions'][method] == {k: aggregate[k] for k in ('status', 'decision')},
                    'Evaluation rows differ from replayed votes')
        require(row['predictions'][scoring.CONTROL] == scoring.always_not_vulnerable(), 'Control overlay differs')
    recount = {}
    for method in scoring.METHODS:
        c = Counter(P=len(evaluation['rows']))
        for row in evaluation['rows']:
            label, prediction = row['binary_label'], row['predictions'][method]
            if label not in scoring.LABELS: continue
            c['A'] += 1; c[_outcome(label, prediction)] += 1
            positive = label.startswith('vulnerable_')
            alert = prediction['status'] == 'classified' and prediction['decision'].startswith('vulnerable_')
            c['TP' if positive and alert else 'FN' if positive else 'FP' if alert else 'TN'] += 1
        actual = evaluation['primary']['methods'][method]['counts']
        require(all(actual[k] == c[k] for k in ('P', 'A', 'C', 'E', 'U', 'M', 'TP', 'TN', 'FP', 'FN')),
                'Independent integer recount differs')
        recount[method] = {k: c[k] for k in ('P', 'A', 'C', 'E', 'U', 'M', 'TP', 'TN', 'FP', 'FN')}
    agreements = []
    for _, left, right in scoring.CONTRASTS:
        counts = Counter()
        for row in evaluation['rows']:
            a, b = row['predictions'][left], row['predictions'][right]
            counts['planned'] += 1
            counts['same_disposition_and_decision'] += a == b
            counts['both_classified'] += a['status'] == b['status'] == 'classified'
            counts['classified_same_label'] += a['status'] == b['status'] == 'classified' and a['decision'] == b['decision']
            if row['binary_label'] not in scoring.LABELS: continue
            counts['A'] += 1
            ac, bc = _outcome(row['binary_label'], a) == 'C', _outcome(row['binary_label'], b) == 'C'
            counts['both_correct' if ac and bc else 'left_only_correct' if ac else 'right_only_correct' if bc else 'neither_correct'] += 1
        expected = next(c['estimate'] for c in evaluation['primary']['contrasts'] if c['left'] == left and c['right'] == right)
        delta = (counts['left_only_correct']-counts['right_only_correct'])/counts['A'] if counts['A'] else None
        require(delta is None and expected is None or delta is not None and expected is not None
                and math.isclose(delta, expected, abs_tol=1e-12),
                'Independent paired recount differs')
        agreements.append({'left': left, 'right': right, **{k: counts[k] for k in ('planned', 'A',
            'same_disposition_and_decision', 'both_classified', 'classified_same_label',
            'both_correct', 'left_only_correct', 'right_only_correct', 'neither_correct')}})
    for _, _, table in _tables(evaluation):
        for value in table['methods'].values():
            c = value['counts']
            require(c['A'] == sum(c[k] for k in ('C', 'E', 'U', 'M'))
                    and c['A'] == sum(c[k] for k in ('TP', 'TN', 'FP', 'FN'))
                    and c['A'] == c['TP']+c['FP']+sum(c[k] for k in (
                        'explicit_safe_no_alert', 'abstention_no_alert', 'unavailable_no_alert')), 'Table partition differs')
    return {'integer_recount': recount, 'pairwise_agreement': agreements, 'all_partitions_verified': True}


def _tables(evaluation):
    for name in ('primary', 'common_input_eligible', 'source_label_recovery'):
        yield name, 'all', evaluation[name]
    for field, groups in evaluation['subgroups'].items():
        for value, table in groups.items(): yield 'subgroup:'+field, value, table
    for family, table in evaluation['leave_one_family_out'].items(): yield 'leave_one_family_out', family, table
    for rep, table in evaluation['excluding_conflicting_inputs'].items(): yield 'excluding_conflicting_inputs', rep, table


def compute(records):
    result = []
    for rep in (*scoring.REPRESENTATIONS, 'all'):
        selected = [r for r in records if rep == 'all' or r['representation'] == rep]
        sent = [r for r in selected if r['dispatch'] is not None]
        row = {'representation': rep, 'scheduled_slots': len(selected), 'dispatched_slots': len(sent),
               'statuses_json': _compact(dict(Counter(r['status'] for r in selected)))}
        for key in ('prompt_tokens', 'completion_tokens'):
            known = [r['response']['usage'][key] for r in sent
                     if r['response'] is not None and r['response']['usage'][key] is not None]
            row[key] = sum(known)
            row[key+'_known_slots'] = len(known); row[key+'_missing_dispatched_slots'] = len(sent)-len(known)
        elapsed = [r['response']['elapsed_seconds'] for r in sent if r['response'] is not None]
        row.update(recorded_response_seconds=sum(elapsed), elapsed_known_slots=len(elapsed),
                   elapsed_missing_dispatched_slots=len(sent)-len(elapsed),
                   runtime_events_used=len({r['dispatch']['runtime_event_sha256'] for r in sent}))
        result.append(row)
    return result


def _attempt_rows(records):
    result = []
    for record in records:
        response, dispatch = record['response'], record['dispatch']
        parsed = response['parsed'] if response else None
        failure = response['validation_failure'] if response else None
        result.append({**{k: record[k] for k in ('slot_id', 'condition_id', 'observation_id', 'representation',
            'repetition', 'seed', 'status', 'request_sha256', 'view_sha256', 'response_path', 'response_sha256')},
            'dispatched': dispatch is not None, 'started_at': dispatch['started_at'] if dispatch else None,
            'runtime_event_sha256': dispatch['runtime_event_sha256'] if dispatch else None,
            'response_status': response['status'] if response else None,
            'http_status': response['http_status'] if response else None,
            'finish_reason': response['finish_reason'] if response else None,
            'prompt_tokens': response['usage']['prompt_tokens'] if response else None,
            'completion_tokens': response['usage']['completion_tokens'] if response else None,
            'elapsed_seconds': response['elapsed_seconds'] if response else None,
            'failure_stage': failure['stage'] if failure else None, 'failure_code': failure['code'] if failure else None,
            'failure_path_json': _compact(failure['path']) if failure else None,
            'decision': parsed['decision'] if parsed else None, 'confidence': parsed['confidence'] if parsed else None,
            'evidence_json': _compact(parsed['evidence']) if parsed else None,
            'summary': parsed['summary'] if parsed else None,
            'raw_reasoning_characters': len(response['raw_reasoning'] or '') if response else None})
    return result


def _qualitative(evaluation, records, replay, execution, review):
    selected = sorted({g['selected_observation_id'] for g in evaluation['qualitative_selection'] if g['selected_observation_id']})
    require(review is None or set(review['cases']) == set(selected), 'Review cases differ from predeclared selection')
    cases = {}
    for row in evaluation['rows']:
        obs = row['observation_id']
        if obs not in selected: continue
        attempts = [{**{k: r[k] for k in ('representation', 'repetition', 'status', 'response_path', 'response_sha256')},
                     'raw_content': r['response']['raw_content'] if r['response'] else None,
                     'raw_reasoning': r['response']['raw_reasoning'] if r['response'] else None,
                     'parsed': r['response']['parsed'] if r['response'] else None} for r in records if r['observation_id'] == obs]
        aggregates = {a['representation']: a for a in replay['aggregates'].values() if a['observation_id'] == obs}
        note = review['cases'][obs] if review else None
        if note:
            require(set(note['error_codes']) <= ERROR_CODES and isinstance(note['explanation'], str) and note['explanation'].strip(),
                    'Invalid qualitative review')
            references = note.get('view_references', [])
            require(isinstance(references, list) and all(isinstance(r, str) for r in references)
                    and set(references) <= views.visible_references(read_json(execution/f'public/views/combined/{obs}.json')),
                    'Review cites a nonvisible reference')
            require(note.get('oracle_review_sha256', row.get('review_sha256')) == row.get('review_sha256'),
                    'Review oracle binding differs')
        cases[obs] = {'metadata': row, 'aggregates': aggregates, 'attempts': attempts, 'review': note,
                      'views': {rep: {'sha256': row['input_sha256'][rep],
                                      'path': f'public/views/{rep}/{obs}.json',
                                      'view': read_json(execution/f'public/views/{rep}/{obs}.json')}
                                for rep in scoring.REPRESENTATIONS}}
    return {'selection': evaluation['qualitative_selection'], 'cases': cases,
            'interpretation': 'Exploratory explanation of saved outputs; error codes do not mechanically establish model reasoning.'}


def _figures(evaluation):
    os.environ.setdefault('MPLCONFIGDIR', str(Path(tempfile.gettempdir())/'representation-study-matplotlib'))
    from matplotlib import rc_context, rcdefaults, rcParams
    from matplotlib.figure import Figure
    from matplotlib.backends.backend_agg import FigureCanvasAgg

    result = {}
    with rc_context():
        rcdefaults()
        rcParams.update({'font.family': 'DejaVu Sans', 'svg.hashsalt': 'representation-study-reporting-v1', 'font.size': 10})
        fig = Figure(figsize=(10, 4.5), layout='constrained'); FigureCanvasAgg(fig)
        left, right = fig.subplots(1, 2)
        colors = {'C': '#277f8e', 'E': '#cc6677', 'U': '#ddbb55', 'M': '#999999'}
        bottom = [0.0]*4
        for category in ('C', 'E', 'U', 'M'):
            values = [100*evaluation['primary']['methods'][m]['counts'][category]/evaluation['primary']['methods'][m]['counts']['A']
                      if evaluation['primary']['methods'][m]['counts']['A'] else 0 for m in scoring.METHODS]
            left.barh(range(4), values, left=bottom, color=colors[category], label=category)
            bottom = [a+b for a, b in zip(bottom, values)]
        left.set(yticks=range(4), yticklabels=[NAMES[m] for m in scoring.METHODS], xlim=(0, 100),
                 xlabel='Percent of adjudicated observations', title='Exact outcome partition')
        left.invert_yaxis(); left.legend(ncol=4, loc='lower center', bbox_to_anchor=(.5, -.35))
        for i, method in enumerate(scoring.METHODS):
            value = evaluation['primary']['methods'][method]['rates']['correct_rate']
            if value['lower'] is not None: right.hlines(i, 100*value['lower'], 100*value['upper'], color=colors['C'], linewidth=2)
            if value['estimate'] is not None: right.plot(100*value['estimate'], i, 'o', color=colors['C'])
        right.set(yticks=range(4), yticklabels=[NAMES[m] for m in scoring.METHODS], xlim=(0, 100),
                  xlabel='Exact correct / adjudicated (%)', title='Family-cluster percentile intervals')
        right.invert_yaxis(); figures = {'outcomes': fig}
        fig = Figure(figsize=(9, 4.5), layout='constrained'); FigureCanvasAgg(fig); ax = fig.subplots()
        contrasts = evaluation['primary']['contrasts']
        for i, value in enumerate(contrasts):
            color = '#882255' if i == 0 else '#4477aa'
            if value['lower'] is not None: ax.hlines(i, 100*value['lower'], 100*value['upper'], color=color, linewidth=2)
            if value['estimate'] is not None: ax.plot(100*value['estimate'], i, 'o', color=color)
        ax.axvline(0, color='#777777', linewidth=.8)
        ax.set(yticks=range(len(contrasts)), yticklabels=[NAMES[c['left']]+' minus '+NAMES[c['right']] for c in contrasts],
               xlabel='Difference in correct / adjudicated (percentage points)', title='Paired representation effects; first contrast is primary')
        ax.invert_yaxis(); figures['contrasts'] = fig
        fig = Figure(figsize=(10, 4.5), layout='constrained'); FigureCanvasAgg(fig)
        for ax, field, values in zip(fig.subplots(1, 2), ('optimization', 'symbols'), (('O0', 'O1', 'O2', 'O3'), ('retained', 'stripped'))):
            for method in scoring.METHODS:
                y = [evaluation['subgroups'][field].get(v, {}).get('methods', {}).get(method, {}).get('rates', {}).get('correct_rate', {}).get('estimate') for v in values]
                ax.plot(range(len(values)), [100*v if v is not None else float('nan') for v in y],
                        '--o' if method == scoring.CONTROL else '-o', label=NAMES[method])
            ax.set(xticks=range(len(values)), xticklabels=values, ylim=(0, 100), xlabel=field,
                   ylabel='Exact correct / adjudicated (%)')
        fig.legend(*fig.axes[0].get_legend_handles_labels(), loc='outside lower center', ncol=4)
        figures['treatments'] = fig
        for name, figure in figures.items():
            for extension, metadata in [('png', {'Software': 'representation-study-reporting-v1'}),
                                        ('svg', {'Date': None, 'Creator': 'representation-study-reporting-v1'})]:
                stream = io.BytesIO(); figure.savefig(stream, format=extension, dpi=160, metadata=metadata, bbox_inches='tight')
                result[f'figures/{name}.{extension}'] = stream.getvalue()
    return result


def render(evaluation, records, replay, execution, review=None):
    """Pure table/figure construction from validated saved evidence."""
    audited = audit(evaluation, records, replay)
    costs = compute(records); attempts = _attempt_rows(records)
    content = {'evaluation.json': _json(evaluation), 'phase8-check.json': _json(replay),
               'audit.json': _json(audited), 'compute.csv': _csv(costs, list(costs[0])),
               'attempts.csv': _csv(attempts, list(attempts[0])),
               'agreement.csv': _csv(audited['pairwise_agreement'], list(audited['pairwise_agreement'][0]))}
    metrics, contrasts = [], []
    for scope, subset, table in _tables(evaluation):
        for method, value in table['methods'].items():
            row = {'scope': scope, 'subset': subset, 'method': method, **value['counts']}
            for key, rate in value['rates'].items():
                row.update({key+('_'+field if field != 'estimate' else ''): number for field, number in rate.items()})
            metrics.append(row)
        for value in table['contrasts']:
            contrasts.append({'scope': scope, 'subset': subset, **{k: v for k, v in value.items() if k != 'role'},
                              'analysis_role': 'primary' if scope == 'primary' and value['role'] == 'primary' else 'secondary'})
    content.update({'metrics.csv': _csv(metrics, list(metrics[0])), 'contrasts.csv': _csv(contrasts, list(contrasts[0]))})
    mapping = {(a['observation_id'], a['representation']): a for a in replay['aggregates'].values()}
    conditions, control, disagreements = [], [], []
    for row in evaluation['rows']:
        common = {k: row[k] for k in ('observation_id', 'family_id', 'cwe', 'variant', 'optimization', 'symbols',
                                      'binary_label', 'source_label', 'operation_status', 'input_eligible')}
        for rep in scoring.REPRESENTATIONS:
            aggregate = mapping[row['observation_id'], rep]
            conditions.append({**common, 'representation': rep, 'condition_id': next(r['condition_id'] for r in records
                               if r['observation_id'] == row['observation_id'] and r['representation'] == rep),
                'view_sha256': row['input_sha256'][rep], 'decision': aggregate['decision'], 'status': aggregate['status'],
                'outcome': _outcome(row['binary_label'], aggregate), 'valid_votes': aggregate['valid_votes'],
                'confidence': aggregate['confidence'], 'votes_json': _compact(aggregate['votes']),
                'attempt_statuses_json': _compact(aggregate['attempt_statuses'])})
        prediction = row['predictions'][scoring.CONTROL]
        control.append({**common, **prediction, 'outcome': _outcome(row['binary_label'], prediction), 'inference_requests': 0})
        if len({(p['status'], p['decision']) for m, p in row['predictions'].items() if m != scoring.CONTROL}) > 1:
            disagreements.append({**common, **{rep+'_'+k: v for rep in scoring.REPRESENTATIONS
                                               for k, v in row['predictions'][rep].items()}})
    content['observation-condition.csv'] = _csv(conditions, list(conditions[0]))
    content['control.csv'] = _csv(control, list(control[0]))
    disagreement_fields = [*list(control[0])[:10], *(rep+'_'+k for rep in scoring.REPRESENTATIONS for k in ('status', 'decision'))]
    content['disagreements.csv'] = _csv(disagreements, disagreement_fields)
    matched, pairs = [], []
    for contrast in evaluation['matched_contrasts']:
        identifier = contrast['left']+'_minus_'+contrast['right']
        for method, value in contrast['methods'].items():
            matched.append({'id': identifier, 'method': method, 'matched_cells': contrast['matched_cells'],
                'matched_families': len(contrast['matched_families']), 'omissions_json': _compact(contrast['omissions']),
                **{k: v for k, v in value.items() if k != 'availability_transitions'},
                'availability_transitions_json': _compact(value['availability_transitions']),
                'transitions_json': _compact(contrast['transitions'])})
        pairs.extend({'id': identifier, **p} for p in contrast['pairs'])
    content['matched-contrasts.csv'] = _csv(matched, list(matched[0]))
    content['matched-pairs.csv'] = _csv(pairs, ['id', 'left', 'right'])
    stability = [r for r in contrasts if r['scope'] in {'leave_one_family_out', 'excluding_conflicting_inputs'}]
    content['stability.csv'] = _csv(stability, list(contrasts[0]))
    content['transitions.json'] = _json({'source_to_binary': evaluation['binary_label_transitions'],
                                        'operation_survival': evaluation['operation_survival']})
    content['collisions.json'] = _json({'representations': evaluation['collisions'], 'parent': evaluation['parent_diagnostics']})
    failures = []
    for record in records:
        if record['status'] in {'valid', 'input_blocked'}: continue
        response = record['response']; parsed = None
        try: parsed = strict_json(response['raw_content']) if response else None
        except ValueError: pass
        refs = parsed.get('evidence') if isinstance(parsed, dict) else None
        visible = views.visible_references(read_json(execution/record['view_path']))
        failures.append({'slot_id': record['slot_id'], 'observation_id': record['observation_id'],
            'representation': record['representation'], 'repetition': record['repetition'], 'status': record['status'],
            'failure_json': _compact(response['validation_failure']) if response else None,
            'nonvisible_references_json': _compact([r for r in refs if isinstance(r, str) and r not in visible]) if isinstance(refs, list) else None,
            'duplicate_references': len(refs) != len(set(refs)) if isinstance(refs, list) and all(isinstance(r, str) for r in refs) else None,
            'response_path': record['response_path'], 'response_sha256': record['response_sha256']})
    fields = ['slot_id', 'observation_id', 'representation', 'repetition', 'status', 'failure_json',
              'nonvisible_references_json', 'duplicate_references', 'response_path', 'response_sha256']
    content['failed-slots.csv'] = _csv(failures, fields)
    content['qualitative.json'] = _json(_qualitative(evaluation, records, replay, execution, review))
    content.update(_figures(evaluation))
    return content


def _build(inputs, projection, execution, parent_audit, review):
    state = execution_replay.inspect(execution)['state']
    require(state['status'] == 'complete' and state['terminal_slots'] == state['slots']
            and len(state['aggregates']) == state['slots']//3 and not state['uncommitted_files'],
            'Execution is incomplete or has uncommitted files requiring review')
    records = execution_replay.records(execution)
    preflight = read_json(execution/'coordinator/preflight.json')
    for record in records:
        response = record['response']
        if response is not None and response['usage']['prompt_tokens'] is not None:
            require(response['usage']['prompt_tokens'] == preflight['budgets'][record['slot_id']]['accounting']['prompt_tokens'],
                    'Actual prompt usage differs from preflight token accounting')
    evaluation = scoring.score_execution(inputs, projection, execution, parent_diagnostics=parent_audit)
    content = render(evaluation, records, state, execution, review)
    content['parent-input-audit.json'] = _json(parent_audit)
    content['qualitative-review.json'] = _json(review)
    return content, evaluation['bindings'], state


def prepare(inputs, projection, execution, directory, *, parent_audit=None, review=None):
    """Export tables and figures from study data; no freeze or saved environment needed."""
    inputs, projection, execution = (Path(p).resolve() for p in (inputs, projection, execution))
    directory = Path(directory).absolute()
    require(not directory.exists() and not directory.is_symlink() and all(
        not directory.resolve().is_relative_to(p) and not p.is_relative_to(directory.resolve())
        for p in (inputs, projection, execution)), 'Analysis destination exists or overlaps evidence')
    content, bindings, state = _build(inputs, projection, execution, parent_audit, review)
    directory.mkdir(parents=True, exist_ok=False)
    for name, raw in sorted(content.items()):
        path = local_path(directory, name)
        publish_bytes(path, raw)
        path.chmod(0o444)
    manifest = {'schema_version': 1, 'status': 'saved_result_analysis_complete',
                'bindings': bindings, 'privacy': 'internal_private_oracle_and_saved_model_outputs',
                'generation_requests': 0, 'files': {n: bytes_digest(raw) for n, raw in sorted(content.items())}}
    runtime.write_new(directory/'manifest.json', manifest)
    (directory/'manifest.json').chmod(0o444)
    return {'status': manifest['status'], 'manifest_sha256': digest(directory/'manifest.json'),
            'observations': state['slots']//9, 'condition_rows': len(state['aggregates']),
            'terminal_slots': state['terminal_slots'], 'generation_requests': 0, 'files': len(content)}


def verify(directory, expected_manifest_sha256=None):
    """Check exported file hashes without rerunning analysis or loading input data."""
    from optimization_vuln_analysis.common.artifacts import file_inventory

    directory = Path(directory).resolve()
    manifest = read_json(plain_file(directory, 'manifest.json'))
    require(expected_manifest_sha256 is None or digest(directory/'manifest.json') == expected_manifest_sha256,
            'Analysis manifest identity differs')
    require(manifest['schema_version'] == 1 and manifest['status'] == 'saved_result_analysis_complete'
            and file_inventory(directory) == {**manifest['files'], 'manifest.json': digest(directory/'manifest.json')},
            'Analysis file inventory/hashes differ')
    return {'status': 'verified', 'manifest_sha256': digest(directory/'manifest.json'),
            'files': len(manifest['files']), 'generation_requests': 0}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('prepare', 'verify'))
    parser.add_argument('--directory', type=Path, required=True)
    parser.add_argument('--inputs', type=Path)
    parser.add_argument('--projection', type=Path)
    parser.add_argument('--execution', type=Path)
    parser.add_argument('--parent-audit', type=Path)
    parser.add_argument('--review', type=Path)
    parser.add_argument('--manifest-sha256')
    args = parser.parse_args()
    if args.action == 'prepare':
        for name in ('inputs', 'projection', 'execution'):
            if getattr(args, name) is None:
                parser.error('--'+name+' is required for prepare')
        result = prepare(args.inputs, args.projection, args.execution, args.directory,
            parent_audit=read_json(args.parent_audit) if args.parent_audit else None,
            review=read_json(args.review) if args.review else None)
    else:
        result = verify(args.directory, args.manifest_sha256)
    print(bundles.canonical(result), end='')


if __name__ == '__main__':
    main()

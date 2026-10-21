"""Private, post-prediction evaluation with shared eligibility and family resampling."""
import argparse
from collections import Counter, defaultdict
from pathlib import Path

import numpy as np

from . import baseline_snapshot, export_context, import_juliet, oracle, run_llm
from .inventory import ROOT, digest, read_json, require
from .llm_runtime import write_new

LABELS = {'vulnerable_CWE-121', 'vulnerable_CWE-122', 'not_vulnerable'}
METHODS = ('baseline', 'llm')


def divide(numerator, denominator):
    return np.divide(numerator, denominator, out=np.full_like(np.asarray(numerator, dtype=float), np.nan), where=np.asarray(denominator) != 0)


def outcomes(rows, method, truth='binary_label'):
    events = defaultdict(list)
    for row in rows:
        target = row[truth]; prediction = row['predictions'][method]
        known = target in LABELS
        decision = prediction['decision']; status = prediction['status']
        available = row['shared_availability'] == 'available' and status in ('classified', 'abstained')
        classified = available and decision in LABELS
        positive = target.startswith('vulnerable_')
        alert = classified and decision.startswith('vulnerable_')
        for key, value in {
            'P': True, 'A': known, 'C': known and classified and decision == target,
            'E': known and classified and decision != target,
            'U': known and available and not classified, 'M': known and not available,
            'TP': known and positive and alert, 'FN': known and positive and not alert,
            'FP': known and not positive and alert, 'TN': known and not positive and not alert,
            'explicit_safe_no_alert': known and available and decision == 'not_vulnerable',
            'abstention_no_alert': known and available and not classified,
            'unavailable_no_alert': known and not available,
        }.items(): events[key].append(int(value))
    return {key: np.asarray(value, dtype=float) for key, value in events.items()}


def statistics(events, weights):
    counts = {key: weights @ value for key, value in events.items()}
    c = counts
    recall = divide(c['TP'], c['TP'] + c['FN']); fpr = divide(c['FP'], c['FP'] + c['TN'])
    return {**counts, 'truth_availability': divide(c['A'], c['P']), 'correct_rate': divide(c['C'], c['A']), 'coverage': divide(c['C'] + c['E'], c['A']),
            'abstention_rate': divide(c['U'], c['A']), 'unavailable_rate': divide(c['M'], c['A']),
            'selective_accuracy': divide(c['C'], c['C'] + c['E']),
            'recall': recall, 'false_positive_rate': fpr, 'precision': divide(c['TP'], c['TP'] + c['FP']),
            'f1': divide(2*c['TP'], 2*c['TP'] + c['FP'] + c['FN']),
            'balanced_accuracy': (recall + 1 - fpr)/2}


def interval(values):
    finite = np.asarray(values)[np.isfinite(values)]
    return {'lower': float(np.quantile(finite, .025, method='linear')) if len(finite) else None,
            'upper': float(np.quantile(finite, .975, method='linear')) if len(finite) else None,
            'defined_replicates': len(finite)}


def summarize(rows, weights, truth='binary_label'):
    result = {}
    for method in METHODS:
        values = statistics(outcomes(rows, method, truth), weights)
        result[method] = {key: {'estimate': float(v[0]) if np.isfinite(v[0]) else None,
                                      'interval': interval(v[1:])} for key, v in values.items()}
    left = statistics(outcomes(rows, 'llm', truth), weights)['correct_rate']
    right = statistics(outcomes(rows, 'baseline', truth), weights)['correct_rate']
    difference = left - right
    result['llm_minus_baseline_correct_rate'] = {'estimate': float(difference[0]) if np.isfinite(difference[0]) else None,
                                               'interval': interval(difference[1:])}
    result['planned_cells'] = len(rows)
    return result


def matched(rows, weights, field, first, second):
    other = ('symbols',) if field == 'optimization' else ('optimization',)
    groups = defaultdict(dict)
    for index, row in enumerate(rows):
        key = (row['family_id'], row['variant'], *(row[k] for k in other))
        groups[key][row[field]] = index
    pairs = []; omitted = Counter()
    for group in groups.values():
        if first not in group or second not in group:
            omitted['missing_partner'] += 1; continue
        a, b = group[first], group[second]
        if rows[a]['binary_label'] not in LABELS or rows[b]['binary_label'] not in LABELS:
            omitted['unresolved_truth'] += 1; continue
        pairs.append((a, b))
    answer = {'matched_cells': len(pairs), 'families': len({rows[a]['family_id'] for a, _ in pairs}),
              'omitted': dict(omitted), 'binary_label_transitions': dict(Counter(
                  rows[a]['binary_label']+' -> '+rows[b]['binary_label'] for a, b in pairs)),
              'shared_availability_transitions': dict(Counter(rows[a]['shared_availability']+' -> '+rows[b]['shared_availability'] for a,b in pairs)),
              'operation_transitions': dict(Counter(rows[a]['operation_status']+' -> '+rows[b]['operation_status'] for a,b in pairs)),
              'methods': {}}
    for method in METHODS:
        correct = outcomes(rows, method)['C']
        numerator = sum((weights[:, a] * (correct[b] - correct[a]) for a, b in pairs), np.zeros(weights.shape[0]))
        denominator = sum((weights[:, a] for a, _ in pairs), np.zeros(weights.shape[0]))
        value = divide(numerator, denominator)
        answer['methods'][method] = {'second_minus_first_correct_rate': float(value[0]) if np.isfinite(value[0]) else None,
                                    'interval': interval(value[1:])}
    return answer


def evaluate(rows, repetitions=10000, seed=20261019):
    require(rows and len({r['observation_id'] for r in rows}) == len(rows), 'Empty or duplicate evaluation inventory')
    families = sorted({r['family_id'] for r in rows})
    rng = np.random.Generator(np.random.PCG64(seed))
    draws = rng.integers(0, len(families), size=(repetitions, len(families)))
    multiplicities = np.stack([(draws == i).sum(axis=1) for i in range(len(families))], axis=1)
    weights = np.vstack([np.ones(len(rows)), multiplicities[:, [families.index(r['family_id']) for r in rows]]])
    def subset(indices, truth='binary_label'):
        if not indices: return {'planned_cells': 0, 'status': 'empty_subset'}
        return summarize([rows[i] for i in indices], weights[:, indices], truth)
    result = {'schema_version': 1, 'rows': rows, 'primary': summarize(rows, weights),
              'bootstrap': {'unit': 'family_id', 'families': families, 'draws_per_replicate': len(families),
                            'replicates': repetitions, 'seed': seed, 'generator': 'PCG64',
                            'shared_multiplicities': True, 'interpretation': 'exploratory; pilot has only two families'},
              'common_input': subset([i for i, r in enumerate(rows) if r['shared_availability'] == 'available']),
              'source_label_recovery': summarize(rows, weights, 'source_label'), 'subgroups': {}}
    for field in ('optimization', 'symbols', 'cwe', 'binary_label', 'family_id', 'operation_status', 'shared_availability'):
        result['subgroups'][field] = {value: subset([i for i, r in enumerate(rows) if r[field] == value])
                                     for value in sorted({r[field] for r in rows})}
    result['matched_contrasts'] = {f'{opt}_minus_O0': matched(rows, weights, 'optimization', 'O0', opt) for opt in ('O1', 'O2', 'O3')}
    result['matched_contrasts']['stripped_minus_retained'] = matched(rows, weights, 'symbols', 'retained', 'stripped')
    result['leave_one_family_out'] = {f: subset([i for i, r in enumerate(rows) if r['family_id'] != f]) for f in families}
    collisions = defaultdict(list)
    for i, row in enumerate(rows): collisions[row['bundle_sha256']].append(i)
    conflicting = set(); groups = []
    for sha, indices in sorted(collisions.items()):
        if len(indices) < 2: continue
        binary_conflict = len({rows[i]['binary_label'] for i in indices}) > 1
        source_conflict = len({rows[i]['source_label'] for i in indices}) > 1
        if binary_conflict or source_conflict: conflicting.update(indices)
        groups.append({'sha256': sha, 'observations': [rows[i]['observation_id'] for i in indices],
                       'binary_label_conflict': binary_conflict, 'source_label_conflict': source_conflict})
    result['identical_input_groups'] = groups
    retained = [i for i in range(len(rows)) if i not in conflicting]
    result['excluding_conflicting_identical_inputs'] = {'excluded_cells': len(conflicting),
        'binary': subset(retained), 'source': subset(retained, 'source_label')}
    pairs = defaultdict(dict)
    for row in rows: pairs[(row['family_id'], row['optimization'], row['symbols'])][row['variant']] = row
    result['source_variant_discrimination'] = {}
    for method in METHODS:
        both = [(p['vulnerable'], p['safe']) for p in pairs.values() if {'vulnerable','safe'} <= set(p)]
        result['source_variant_discrimination'][method] = {
            'pairs': len(both), 'both_source_labels_correct': sum(
                all(r['shared_availability']=='available' and r['predictions'][method]['decision']==r['source_label'] for r in pair)
                for pair in both),
            'binary_labels_differ': sum(a['binary_label'] != b['binary_label'] for a, b in both)}
    result['dispositions'] = {field: dict(Counter(r[field] for r in rows)) for field in
                              ('binary_label', 'operation_status', 'shared_availability', 'build_status', 'public_context_status')
                              if all(field in r for r in rows)}
    result['confidence'] = {}
    for method in METHODS:
        candidates = [r for r in rows if r['predictions'][method].get('confidence') is not None and r['shared_availability']=='available']
        high = [r for r in candidates if r['predictions'][method]['confidence'] >= .8]
        result['confidence'][method] = {'valid_aggregates': len(candidates),
            'median': float(np.median([r['predictions'][method]['confidence'] for r in candidates])) if candidates else None,
            'high_confidence': len(high), 'high_confidence_exact_errors': sum(
                r['binary_label'] in LABELS and r['predictions'][method]['decision'] in LABELS and
                r['predictions'][method]['decision'] != r['binary_label'] for r in high)}
    return result


def pilot(run_directory):
    baseline_snapshot.replay()
    llm_report = run_llm.verify(run_directory)
    require(not any(llm_report['attempt_statuses'].get(k, 0) for k in ('pending', 'dispatched_unresolved')), 'Pilot LLM slots are incomplete')
    manifest, _ = run_llm.validate_manifest(run_directory, ROOT)
    builds = read_json(ROOT/'build/pilot/build-manifest.json')
    truth = oracle.adjudicate(builds, read_json(ROOT/'corpus/private/pilot-oracle.json'))
    plan = builds['plan']; expected = {r['observation_id'] for r in plan['observations']}
    require(set(llm_report['aggregates']) == expected, 'LLM aggregate inventory differs')
    baseline_path = ROOT/'results/pilot/baseline/phase5-v2-c.json'
    baseline_rows = read_json(baseline_path)
    baseline = {r['observation_id']: r for r in baseline_rows}
    require(len(baseline) == len(baseline_rows) and set(baseline) == expected, 'Baseline inventory differs')
    pairs = {p['pair_id']: p for p in read_json(ROOT/'corpus/manifest.json')['pairs']}
    build_statuses = {b['build_id']:b['status'] for b in builds['builds']}
    rows = []
    for cell in truth['observations']:
        identifier = cell['observation_id']; b = baseline[identifier]
        require(digest(ROOT/cell['record_path']) == b['bundle_sha256'], 'Baseline public input changed')
        require(read_json(run_directory/'inputs'/f'{identifier}.json') == read_json(ROOT/cell['record_path']), 'Methods saw different public input')
        prediction = b['prediction'] if b['status']=='completed' else None
        base = {'status': prediction['status'] if prediction else 'unavailable',
                'decision': prediction['decision'] if prediction else None,
                'reasons': prediction['reason_codes'] if prediction else [b['error_code']]}
        rows.append({**cell, 'family_id': pairs[cell['pair_id']]['family_id'], 'cwe': pairs[cell['pair_id']]['cwe'],
                     'bundle_sha256': digest(ROOT/cell['record_path']),
                     'build_status':build_statuses[cell['build_id']],
                     'public_context_status':read_json(ROOT/cell['record_path'])['status'],
                     'shared_availability': llm_report['shared_availability'][identifier],
                     'predictions': {'baseline': base, 'llm': llm_report['aggregates'][identifier]}})
    config = read_json(ROOT/'config.json')
    report = evaluate(rows, config['evaluation']['bootstrap_repetitions'], config['evaluation']['bootstrap_seed'])
    attempts = [run_llm.result_for(run_directory, s, manifest) for s in manifest['slots']]
    report['compute'] = {'attempt_statuses': llm_report['attempt_statuses'],
        'actual_dispatches': sum((run_directory/'slots'/run_llm.slot_name(s)/'dispatch.json').exists() for s in manifest['slots']),
        'llm_elapsed_seconds': sum(a.get('elapsed_seconds', 0) for a in attempts),
        'prompt_tokens': sum(a.get('usage', {}).get('prompt_tokens') or 0 for a in attempts),
        'completion_tokens': sum(a.get('usage', {}).get('completion_tokens') or 0 for a in attempts),
        'baseline': read_json(ROOT/'provenance/phase5-validation.json')['wall_seconds']}
    report['inputs'] = {'llm_manifest_sha256': digest(run_directory/'manifest.json'),
        'baseline_predictions_sha256': digest(baseline_path),
        'oracle_sha256': digest(ROOT/'corpus/private/pilot-oracle.json'),
        'evaluator_sha256': digest(Path(__file__))}
    context = export_context.audit_run(run_id='phase4-c', compare='phase4-d')
    require(context['status']=='passed', 'Context audit no longer passes')
    baseline_audit = read_json(ROOT/'provenance/phase5-validation.json')
    report['joint_review'] = {
        'source_preservation': import_juliet.verify_import(),
        'reference_operation_dispositions': truth['operation_dispositions'],
        'context_status': context['status'], 'context_counts': context['counts'],
        'symbol_partners': context['symbol_partners'], 'context_equality_groups': context['equality_groups'],
        'baseline_support_reasons_before_shared_overlay': baseline_audit['reason_codes'],
        'baseline_heuristic_fixture_results': {k:v for k,v in read_json(ROOT/'provenance/phase5-v2-stack-fixtures.json').items()
                                             if k not in ('observations','methods')},
        'adjudication': {'reference_reviews':len(builds['builds']), 'observation_truths':len(rows),
                         'independent_human_reviewers':0, 'review_time_hours':None,
                         'note':'Review time was not recorded; no independent human adjudication.'}}
    report['review_provenance'] = truth['review_provenance']
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run-directory', type=Path, required=True)
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument('--output', type=Path)
    target.add_argument('--check', type=Path)
    args = parser.parse_args()
    report = pilot(args.run_directory)
    if args.check:
        require(read_json(args.check)==report, 'Published evaluation does not reproduce')
    else:
        write_new(args.output, report)
    print({m: {k: report['primary'][m][k]['estimate'] for k in ('A','C','E','U','M')} for m in METHODS})


if __name__ == '__main__': main()

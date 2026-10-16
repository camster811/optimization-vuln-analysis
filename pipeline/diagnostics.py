"""Exploratory post-review diagnostics; exclusions depend only on input equality."""
from collections import Counter, defaultdict
import copy
import hashlib
import json

if __package__:
    from . import evaluate as ev, run_llm
else:
    import evaluate as ev
    import run_llm


def normalized(record):
    value = copy.deepcopy(record)
    name = value['function']['name']
    value['function']['name'] = 'FUNCTION'
    value['decompilation']['text'] = value['decompilation']['text'].replace(name, 'FUNCTION')
    return value


def collisions(truth, records, neutral=False):
    by_id = {row['observation_id']: row for row in truth}
    groups = defaultdict(list)
    for identifier, record in records.items():
        value = normalized(record) if neutral else record
        groups[hashlib.sha256(run_llm.canonical_json(value).encode()).hexdigest()].append(identifier)
    rows = [{'sha256': sha, 'ids': sorted(ids),
             'truth_counts': dict(sorted(Counter(by_id[key]['truth'] for key in ids).items()))}
            for sha, ids in sorted(groups.items())]
    conflicting = [row for row in rows if len(row['truth_counts']) > 1]
    return {'unique_inputs': len(rows), 'groups': rows, 'conflicting_groups': conflicting,
            'conflicting_ids': sorted(key for row in conflicting for key in row['ids']),
            'consistent_classifier_exact_label_ceiling': sum(max(row['truth_counts'].values()) for row in rows),
            'observations': len(truth)}


def metrics(truth, predictions):
    pairs = sorted({row['pair_id'] for row in truth})
    values = ev.compute_metrics(ev.cluster_counts(truth, predictions, pairs).sum(axis=0))
    return {name: float(value) if name in ev.RATES and value == value else None if value != value else int(value)
            for name, value in values.items()}


def analyze(truth, records, methods, runs):
    pairs = sorted({row['pair_id'] for row in truth})
    by_cell = {tuple(row[field] for field in ('pair_id', 'variant', 'optimization', 'symbols')): row['observation_id']
               for row in truth}
    by_id = {row['observation_id']: row for row in truth}
    full, neutral = collisions(truth, records), collisions(truth, records, neutral=True)
    excluded = set(full['conflicting_ids'])
    distinguishable = [row for row in truth if row['observation_id'] not in excluded]
    result = {'analysis_status': 'exploratory post-review; primary full analysis retained',
              'collision_audit': {'full_record': full, 'neutral_function_name': neutral},
              'distinguishable_sensitivity': {'exclusion_rule': 'Exclude all members of full-record groups with conflicting source truth',
                                            'excluded_ids': sorted(excluded),
                                            'methods': {method: metrics(distinguishable, predictions) for method, predictions in methods.items()}},
              'per_pair': [], 'paired_repair': {}, 'stripping_matches': [],
              'treatment_transitions': {}, 'leave_one_pair_out': []}
    for method, predictions in methods.items():
        for pair in pairs:
            group = [row for row in truth if row['pair_id'] == pair]
            result['per_pair'].append({'method': method, 'pair_id': pair, **metrics(group, predictions)})
        cells = []
        for pair in pairs:
            for opt in ('O0', 'O2'):
                for symbols in ('retained', 'stripped'):
                    ids = [by_cell[pair, variant, opt, symbols] for variant in ('vulnerable', 'fixed')]
                    cells.append({'pair_id': pair, 'optimization': opt, 'symbols': symbols, 'ids': ids,
                                  'both_exact_correct': all(predictions[key]['decision'] == by_id[key]['truth'] for key in ids),
                                  'same_decision': predictions[ids[0]]['decision'] == predictions[ids[1]]['decision']})
        result['paired_repair'][method] = {'cells': len(cells), 'both_exact_correct': sum(row['both_exact_correct'] for row in cells),
                                         'same_decision': sum(row['same_decision'] for row in cells), 'details': cells}
        transitions = Counter()
        changed = 0
        for pair in pairs:
            for variant in ('vulnerable', 'fixed'):
                for opt in ('O0', 'O2'):
                    a, b = [by_cell[pair, variant, opt, symbols] for symbols in ('retained', 'stripped')]
                    outcomes = [ev.score_three_way(by_id[key]['truth'], predictions[key]['decision']) for key in (a, b)]
                    transitions[tuple(outcomes)] += 1
                    changed += predictions[a]['decision'] != predictions[b]['decision']
                    if method == 'static':
                        result['stripping_matches'].append({'ids': [a, b],
                            'instructions_calls_equal': all(records[a][field] == records[b][field] for field in ('instructions', 'calls')),
                            'equal_after_name_normalization': normalized(records[a]) == normalized(records[b])})
        result['treatment_transitions'][method] = {'matches': len(pairs)*4, 'decision_changes': changed,
            'outcomes': [{'retained': a, 'stripped': b, 'count': n} for (a, b), n in sorted(transitions.items())]}
    for omitted in pairs:
        group = [row for row in truth if row['pair_id'] != omitted]
        point = {method: metrics(group, predictions) for method, predictions in methods.items()}
        result['leave_one_pair_out'].append({'omitted': omitted, 'methods': point,
            'llm_minus_static_correct_rate': point['llm_majority']['correct_rate'] - point['static']['correct_rate']})
    attempts = [run for group in runs.values() for run in group]
    tokens = [run['usage']['prompt_tokens'] for run in attempts if run['usage']['prompt_tokens'] is not None]
    result['compute'] = {'attempts': len(attempts), 'summed_request_seconds': sum(run['elapsed_seconds'] for run in attempts),
                         'prompt_tokens_min': min(tokens) if tokens else None, 'prompt_tokens_max': max(tokens) if tokens else None,
                         'completion_tokens': sum(run['usage']['completion_tokens'] or 0 for run in attempts),
                         'missing_usage_attempts': sum(any(value is None for value in run['usage'].values()) for run in attempts),
                         'status_counts': dict(sorted(Counter(run['status'] for run in attempts).items()))}
    return result


def write(destination, truth, records, methods, runs):
    result = analyze(truth, records, methods, runs)
    (destination / 'diagnostics.json').write_text(json.dumps(result, indent=2, allow_nan=False) + '\n')
    full = result['collision_audit']['full_record']
    neutral = result['collision_audit']['neutral_function_name']
    lines = ['# Exploratory diagnostics', '',
        'These post-review additions retain the prespecified full analysis. Exclusions use input equality, never prediction performance.', '',
        f"Full records: {full['unique_inputs']} unique inputs across {len(truth)} observations; {len(full['conflicting_ids'])} observations have conflicting source labels within identical-input groups. Neutralizing only function names leaves {neutral['unique_inputs']} unique inputs.", '',
        f"A classifier consistent on identical inputs has an empirical exact-label ceiling of {full['consistent_classifier_exact_label_ceiling']}/{len(truth)}. A stochastic finite run can fluctuate above this value. Uncertainty remains an abstention, not a correct source label.", '',
        '| Identical input IDs with conflicting truth | Truth counts |', '|---|---|']
    for group in full['conflicting_groups']:
        lines.append(f"| {', '.join(group['ids'])} | {json.dumps(group['truth_counts'], sort_keys=True)} |")
    lines += ['', '| Method | Both variants exact correct | Same decision for both variants | Distinguishable correct/N |', '|---|---:|---:|---:|']
    for method, values in result['paired_repair'].items():
        sensitivity = result['distinguishable_sensitivity']['methods'][method]
        lines.append(f"| {method} | {values['both_exact_correct']}/{values['cells']} | {values['same_decision']}/{values['cells']} | {sensitivity['correct']}/{sensitivity['n']} |")
    matches = result['stripping_matches']
    lines += ['', f"Stripping: {sum(row['instructions_calls_equal'] for row in matches)}/{len(matches)} matches have identical instructions/calls; {sum(row['equal_after_name_normalization'] for row in matches)}/{len(matches)} are identical after neutralizing function names.", '',
        'The static method consumes instructions/calls, so identical consumed inputs guarantee invariance as a negative control. With neutral retained names, the LLM treatment measures name sensitivity plus sampling variation. Extraction uses an oracle address: classification is conditional on successful target localization.', '',
        '| Method | Changed decision | Retained outcome → stripped outcome | Count |', '|---|---:|---|---:|']
    for method, values in result['treatment_transitions'].items():
        for row in values['outcomes']:
            lines.append(f"| {method} | {values['decision_changes']}/{values['matches']} | {row['retained']} → {row['stripped']} | {row['count']} |")
    differences = [row['llm_minus_static_correct_rate'] for row in result['leave_one_pair_out']]
    compute = result['compute']
    lines += ['', f"Leave-one-pair-out LLM minus static correct/N ranges from {100*min(differences):.1f} to {100*max(differences):.1f} percentage points.", '',
        f"Compute: {compute['attempts']} attempts; {compute['summed_request_seconds']:.1f} summed request seconds; {compute['completion_tokens']} completion tokens; prompt tokens {compute['prompt_tokens_min']}–{compute['prompt_tokens_max']}. Status counts: {json.dumps(compute['status_counts'], sort_keys=True)}.", '',
        'Per-pair counts, leave-one-pair-out results, equality groups, exclusions, and matched repair cells are in diagnostics.json.', '']
    (destination / 'exploratory.md').write_text('\n'.join(lines))
    return result

"""Offline four-method evaluation with paired family-cluster uncertainty.

The pure evaluator accepts complete condition aggregates, never raw code. Runtime
replay and private truth binding remain at the file adapter boundary below.
"""
import argparse
from collections import Counter, defaultdict
import hashlib
from pathlib import Path
import re

import numpy as np

from optimization_vuln_analysis.inputs import bundles
from optimization_vuln_analysis.common import metrics, require
from optimization_vuln_analysis.common.artifacts import digest
from optimization_vuln_analysis.common.serialization import read_json


REPRESENTATIONS = ('assembly', 'decompilation', 'combined')
CONTROL = 'always_not_vulnerable'
METHODS = (*REPRESENTATIONS, CONTROL)
LABELS = ('vulnerable_CWE-121', 'vulnerable_CWE-122', 'not_vulnerable')
SEED = 20261019
REPLICATES = 10000
CONTRASTS = (
    ('combined_minus_decompilation_correct_rate', 'combined', 'decompilation'),
    ('combined_minus_assembly_correct_rate', 'combined', 'assembly'),
    ('decompilation_minus_assembly_correct_rate', 'decompilation', 'assembly'),
    *((f'{m}_minus_{CONTROL}_correct_rate', m, CONTROL) for m in REPRESENTATIONS),
)


def always_not_vulnerable():
    """Unconditional control: no inputs, repetitions, inference or confidence."""
    return {'status': 'classified', 'decision': 'not_vulnerable'}


def _prediction(prediction):
    status, decision = prediction['status'], prediction['decision']
    require((status == 'classified' and decision in LABELS)
            or (status == 'abstained' and decision == 'uncertain')
            or (status == 'unavailable' and decision is None), 'Invalid aggregate disposition')
    return {'status': status, 'decision': decision}


def align(observations, aggregates, eligibility, input_hashes):
    """Require all three conditions, including explicit preparation failures."""
    rows = sorted(observations, key=lambda r: r['observation_id'])
    ids = {r['observation_id'] for r in rows}
    require(rows and len(ids) == len(rows), 'Empty/duplicate observation inventory')
    require(set(eligibility) == ids and all(type(v) is bool for v in eligibility.values()),
            'Common eligibility inventory differs')
    cells = set()
    for row in rows:
        require(all(isinstance(row[k], str) and row[k] for k in ('observation_id', 'family_id')),
                'Invalid observation/family identity')
        require(row['binary_label'] in (*LABELS, 'unresolved') and row['source_label'] in (*LABELS, 'unresolved'),
                'Unknown truth label')
        require(row['cwe'] in ('CWE-121', 'CWE-122') and row['variant'] in ('safe', 'vulnerable')
                and row['optimization'] in ('O0', 'O1', 'O2', 'O3')
                and row['symbols'] in ('retained', 'stripped')
                and row['operation_status'] in ('present', 'inlined/merged', 'eliminated', 'unresolved'),
                'Unknown treatment/operation')
        cell = tuple(row[k] for k in ('family_id', 'variant', 'optimization', 'symbols'))
        require(cell not in cells, 'Duplicate treatment cell')
        cells.add(cell)
    expected = {(obs, rep) for obs in ids for rep in REPRESENTATIONS}
    indexed = {(p['observation_id'], p['representation']): _prediction(p) for p in aggregates}
    require(len(indexed) == len(aggregates) and set(indexed) == expected, 'Condition aggregate inventory differs')
    require(set(input_hashes) == expected and all(isinstance(v, str) and re.fullmatch('[0-9a-f]{64}', v)
                                               for v in input_hashes.values()), 'Input hash inventory differs')
    result = []
    for row in rows:
        obs = row['observation_id']
        predictions = {rep: indexed[obs, rep] for rep in REPRESENTATIONS}
        require(eligibility[obs] or all(p['status'] == 'unavailable' for p in predictions.values()),
                'Blocked observation has available LLM prediction')
        result.append({**row, 'input_eligible': eligibility[obs],
                       'input_sha256': {rep: input_hashes[obs, rep] for rep in REPRESENTATIONS},
                       'predictions': {**predictions, CONTROL: always_not_vulnerable()}})
    return result


def events(rows, method, truth='binary_label'):
    """One event per planned observation; unresolved truth only contributes P."""
    result = defaultdict(list)
    for row in rows:
        label, prediction = row[truth], row['predictions'][method]
        adjudicated = label in LABELS
        classified = prediction['status'] == 'classified'
        alert = classified and prediction['decision'] != 'not_vulnerable'
        positive = label != 'not_vulnerable'
        counts = {
            'P': True, 'A': adjudicated,
            'C': adjudicated and classified and prediction['decision'] == label,
            'E': adjudicated and classified and prediction['decision'] != label,
            'U': adjudicated and prediction['status'] == 'abstained',
            'M': adjudicated and prediction['status'] == 'unavailable',
            'TP': adjudicated and positive and alert,
            'TN': adjudicated and not positive and not alert,
            'FP': adjudicated and not positive and alert,
            'FN': adjudicated and positive and not alert,
            'explicit_safe_no_alert': adjudicated and classified and not alert,
            'abstention_no_alert': adjudicated and prediction['status'] == 'abstained',
            'unavailable_no_alert': adjudicated and prediction['status'] == 'unavailable',
        }
        require(counts['A'] == sum(counts[k] for k in ('C', 'E', 'U', 'M')), 'Disposition partition differs')
        for key, value in counts.items():
            result[key].append(int(value))
    return {k: np.asarray(v, dtype=np.int64) for k, v in result.items()}


def family_draws(families, replicates=REPLICATES, seed=SEED):
    """PCG64 draws from sorted unique families; rows are cluster multiplicities."""
    families = sorted(set(families))
    require(families and type(replicates) is int and replicates > 0, 'Invalid family resampling inventory')
    draws = np.random.Generator(np.random.PCG64(seed)).integers(0, len(families), (replicates, len(families)))
    return families, np.asarray([np.bincount(row, minlength=len(families)) for row in draws], dtype=np.int64)


def _estimate(observed, samples):
    return {'estimate': float(observed) if np.isfinite(observed) else None, **metrics.interval(samples)}


class _Analysis:
    def __init__(self, rows, replicates):
        self.rows = rows
        self.families, self.draws = family_draws((r['family_id'] for r in rows), replicates=replicates)
        indices = [self.families.index(r['family_id']) for r in rows]
        self.weights = np.vstack((np.ones(len(rows), dtype=np.int64), self.draws[:, indices]))
        self.events = {truth: {m: events(rows, m, truth) for m in METHODS}
                       for truth in ('binary_label', 'source_label')}

    def values(self, method, mask, truth='binary_label'):
        # One global draw matrix, including for subsets and matched contrast sides.
        return metrics.statistics(self.events[truth][method], self.weights * np.asarray(mask, dtype=np.int64))

    def table(self, mask, truth='binary_label'):
        values = {m: self.values(m, mask, truth) for m in METHODS}
        count_keys = self.events[truth][CONTROL]
        methods = {m: {'counts': {k: int(v[k][0]) for k in count_keys},
                       'rates': {k: _estimate(a[0], a[1:]) for k, a in v.items() if k not in count_keys}}
                   for m, v in values.items()}
        contrasts = []
        for index, (name, left, right) in enumerate(CONTRASTS):
            delta = values[left]['correct_rate'] - values[right]['correct_rate']
            contrasts.append({'id': name, 'role': 'primary' if index == 0 else 'secondary',
                              'left': left, 'right': right, 'metric': 'correct_rate',
                              **_estimate(delta[0], delta[1:])})
        return {'methods': methods, 'contrasts': contrasts}

    def matched(self, field, left, right, match_by):
        cells = defaultdict(dict)
        for index, row in enumerate(self.rows):
            cell = cells[tuple(row[k] for k in match_by)]
            if row[field] in (left, right):
                cell[row[field]] = index
        pairs, omissions = [], []
        for key, cell in sorted(cells.items()):
            missing = [v for v in (left, right) if v not in cell]
            unresolved = [v for v, i in cell.items() if self.rows[i]['binary_label'] == 'unresolved']
            if missing or unresolved:
                omissions.append({'cell': dict(zip(match_by, key)), 'missing': missing, 'unresolved': sorted(unresolved)})
            else:
                pairs.append((cell[left], cell[right]))
        masks = [[i in {p[side] for p in pairs} for i in range(len(self.rows))] for side in (0, 1)]
        methods = {}
        for method in METHODS:
            sides = [self.values(method, mask) for mask in masks]
            delta = sides[0]['correct_rate'] - sides[1]['correct_rate']
            methods[method] = {**_estimate(delta[0], delta[1:]),
                               'left_correct': int(sides[0]['C'][0]), 'right_correct': int(sides[1]['C'][0]),
                               'availability_transitions': _transitions(
                                   (self.rows[i]['predictions'][method]['status'],
                                    self.rows[j]['predictions'][method]['status']) for i, j in pairs)}
        return {'field': field, 'left': left, 'right': right, 'match_by': match_by,
                'matched_cells': len(pairs), 'matched_families': sorted({self.rows[i]['family_id'] for i, _ in pairs}),
                'pairs': [{'left': self.rows[i]['observation_id'], 'right': self.rows[j]['observation_id']}
                          for i, j in pairs], 'omissions': omissions, 'methods': methods,
                'transitions': {name: _transitions((self.rows[i][name], self.rows[j][name]) for i, j in pairs)
                                for name in ('binary_label', 'operation_status', 'input_eligible')}}


def _transitions(pairs):
    return [{'left': left, 'right': right, 'count': count}
            for (left, right), count in sorted(Counter(pairs).items())]


def _collisions(rows, hash_for):
    groups = defaultdict(list)
    for row in rows:
        sha = hash_for(row)
        if sha is not None:
            groups[sha].append(row)
    result = []
    for sha, members in sorted(groups.items()):
        if len(members) < 2:
            continue
        binary = sorted({r['binary_label'] for r in members if r['binary_label'] in LABELS})
        source = sorted({r['source_label'] for r in members if r['source_label'] in LABELS})
        result.append({'sha256': sha, 'observation_ids': sorted(r['observation_id'] for r in members),
                       'binary_labels': binary, 'source_labels': source,
                       'unresolved_binary': sum(r['binary_label'] == 'unresolved' for r in members),
                       'binary_conflict': len(binary) > 1, 'source_conflict': len(source) > 1})
    return result


def evaluate(observations, aggregates, *, eligibility, input_hashes, parent_diagnostics=None,
             replicates=REPLICATES):
    """Pure evaluator. Reduced replicate counts are for engineering fixtures only.

    input_hashes binds exact canonical view bytes under the single common prompt,
    schema and sampler protocol. It excludes observation IDs and repetition seeds.
    Supplied parent scope diagnostics are retained separately, never substituted
    for the new per-representation equality groups.
    """
    rows = align(observations, aggregates, eligibility, input_hashes)
    analysis = _Analysis(rows, replicates)
    full = [True] * len(rows)
    collisions, sensitivity = {}, {}
    for rep in REPRESENTATIONS:
        groups = _collisions(rows, lambda r: r['input_sha256'][rep])
        excluded = sorted({obs for g in groups if g['binary_conflict'] or g['source_conflict']
                           for obs in g['observation_ids']})
        collisions[rep] = groups
        sensitivity[rep] = {'excluded_observation_ids': excluded,
                            **analysis.table([r['observation_id'] not in excluded for r in rows])}
    qualitative = []
    for rep in ('assembly', 'decompilation'):
        correct = analysis.events['binary_label']
        for winner, loser in (('combined', rep), (rep, 'combined')):
            members = [r['observation_id'] for i, r in enumerate(rows)
                       if r['binary_label'] in LABELS and correct[winner]['C'][i] and not correct[loser]['C'][i]]
            qualitative.append({'winner': winner, 'not_correct': loser, 'members': members,
                                'selected_observation_id': members[0] if members else None})
    return {
        'schema_version': 1, 'endpoint': 'adjudicated_binary_label',
        'bootstrap': {'unit': 'family_id', 'families': analysis.families, 'generator': 'PCG64',
                      'seed': SEED, 'replicates': replicates, 'draws_per_replicate': len(analysis.families),
                      'shared_multiplicities': True, 'quantile_method': 'linear', 'percentiles': [2.5, 97.5],
                      'multiplicities_int64_le_sha256': hashlib.sha256(analysis.draws.astype('<i8').tobytes()).hexdigest()},
        'rows': rows, 'primary': analysis.table(full),
        'common_input_eligible': analysis.table([r['input_eligible'] for r in rows]),
        'subgroups': {field: {value: analysis.table([r[field] == value for r in rows])
                              for value in sorted({r[field] for r in rows})}
                     for field in ('binary_label', 'cwe', 'optimization', 'symbols', 'family_id')},
        'source_label_recovery': {'endpoint': 'original_source_label', **analysis.table(full, 'source_label')},
        'binary_label_transitions': {'from': 'source_label', 'to': 'binary_label',
                                     'rows': _transitions((r['source_label'], r['binary_label']) for r in rows)},
        'operation_survival': {value: dict(sorted(Counter(r['binary_label'] for r in rows
                                                         if r['operation_status'] == value).items()))
                               for value in sorted({r['operation_status'] for r in rows})},
        'matched_contrasts': [analysis.matched('optimization', opt, 'O0', ['family_id', 'variant', 'symbols'])
                              for opt in ('O1', 'O2', 'O3')]
                            + [analysis.matched('symbols', 'stripped', 'retained',
                                                ['family_id', 'variant', 'optimization'])],
        'collisions': collisions, 'excluding_conflicting_inputs': sensitivity,
        'parent_diagnostics': {'exact_bundle_groups': _collisions(rows, lambda r: r.get('parent_bundle_sha256')),
                               'scope_audit': parent_diagnostics},
        'leave_one_family_out': {family: analysis.table([r['family_id'] != family for r in rows])
                                  for family in analysis.families},
        'qualitative_selection': qualitative,
    }


def score_execution(inputs, projection, execution, *, input_manifest_sha256=None,
                    projection_manifest_sha256=None, execution_manifest_sha256=None,
                    parent_diagnostics=None):
    """Verify bound inputs and complete saved execution without model/server access."""
    from . import inventory, replay, views

    inputs, projection, execution = (Path(p).resolve() for p in (inputs, projection, execution))
    bound = inventory.verify(inputs, input_manifest_sha256)
    projected = views.verify(projection, projection_manifest_sha256)
    inspection = replay.inspect(execution, execution_manifest_sha256)
    state = inspection['state']
    require(state['status'] == 'complete' and state['preflight_bound'], 'Cannot score pending execution')
    require(projected['input_manifest_sha256'] == bound['manifest_sha256']
            and inspection['projection_manifest_sha256'] == projected['manifest_sha256'], 'Evaluation input binding differs')
    policy = read_json(inputs/'coordinator/policy.json')
    require(read_json(execution/'protocol/policy.json') == policy, 'Evaluation policy differs')
    conditions = read_json(projection/'coordinator/conditions.json')
    require(read_json(execution/'coordinator/conditions.json') == conditions, 'Execution condition binding differs')
    ledger = read_json(projection/'coordinator/views.json')
    for view in ledger:
        require(digest(execution/view['view_path']) == view['view_sha256'], 'Execution view binding differs')
    result = evaluate(read_json(inputs/'private/evaluation.json'), list(state['aggregates'].values()),
                      eligibility=inspection['eligibility'],
                      input_hashes={(r['observation_id'], r['representation']): r['view_sha256'] for r in ledger},
                      parent_diagnostics=parent_diagnostics)
    require(result['primary']['methods'][CONTROL]['counts']['C'] == policy['evaluation']['expected_control_correct']
            and all(v['counts']['A'] == policy['evaluation']['expected_adjudicated']
                    for v in result['primary']['methods'].values()), 'Bound truth expectations differ')
    result['bindings'] = {'input_manifest_sha256': bound['manifest_sha256'],
                          'projection_manifest_sha256': projected['manifest_sha256'],
                          'execution_manifest_sha256': state['manifest_sha256'],
                          'evaluation_ledger_sha256': digest(inputs/'private/evaluation.json'),
                          'purpose': state['purpose'], 'run_id': state['run_id']}
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inputs', type=Path, required=True)
    parser.add_argument('--projection', type=Path, required=True)
    parser.add_argument('--execution', type=Path, required=True)
    parser.add_argument('--input-manifest-sha256')
    parser.add_argument('--projection-manifest-sha256')
    parser.add_argument('--execution-manifest-sha256')
    args = parser.parse_args()
    print(bundles.canonical(score_execution(**vars(args))), end='')


if __name__ == '__main__':
    main()

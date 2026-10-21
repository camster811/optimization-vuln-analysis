"""Thin, explicitly named multi-method adapter to the unchanged frozen metrics.

The frozen evaluator exposes outcomes/statistics/interval, but not its family
weight generator. Reproduce that PCG64 schedule here and check historical
metrics/intervals for equality before publishing any supplementary score.
"""
from copy import deepcopy

import numpy as np

from redesign.pipeline import evaluate as frozen
from redesign.pipeline.inventory import require
from . import controls

SAVED_LLM = 'saved_llm'
SAVED_BASELINE = 'saved_baseline_v2'
METHODS = ('control_not_vulnerable', SAVED_LLM, SAVED_BASELINE,
           'control_cwe121', 'control_cwe122', 'control_uncertain')
GROUPS = ('binary_label', 'cwe', 'optimization', 'symbols', 'family_id', 'source_label')


def attach_controls(historical_rows):
    """Only eligibility/opaque ID are passed to the pure control generator."""
    public = [{'observation_id': r['observation_id'], 'status': r['shared_availability']}
              for r in historical_rows]
    generated = {r['observation_id']: r['predictions'] for r in controls.generate(public)}
    return [{**deepcopy(r), 'predictions': {
        SAVED_LLM: deepcopy(r['predictions']['llm']),
        SAVED_BASELINE: deepcopy(r['predictions']['baseline']),
        **generated[r['observation_id']]}} for r in historical_rows]


def family_weights(rows, repetitions=10000, seed=20261019):
    require(rows and len({r['observation_id'] for r in rows}) == len(rows), 'Empty or duplicate study inventory')
    require(type(repetitions) is int and repetitions > 0, 'Invalid bootstrap repetition count')
    families = sorted({r['family_id'] for r in rows})
    rng = np.random.Generator(np.random.PCG64(seed))
    draws = rng.integers(0, len(families), size=(repetitions, len(families)))
    multiplicities = np.stack([(draws == i).sum(axis=1) for i in range(len(families))], axis=1)
    weights = np.vstack([np.ones(len(rows)), multiplicities[:, [families.index(r['family_id']) for r in rows]]])
    return families, weights


def value_summary(values):
    return {'estimate': float(values[0]) if np.isfinite(values[0]) else None,
            'interval': frozen.interval(values[1:])}


def summarize(rows, weights, truth):
    if not rows: return {'planned_cells': 0, 'status': 'empty_subset'}
    raw = {method: frozen.statistics(frozen.outcomes(rows, method, truth), weights) for method in METHODS}
    return {'planned_cells': len(rows), 'methods': {
        method: {metric: value_summary(values) for metric, values in raw[method].items()} for method in METHODS},
        'paired_llm_minus_comparator': {
            method: {'first_method': method, 'second_method': SAVED_LLM,
                     'correct_rate_difference': value_summary(raw[SAVED_LLM]['correct_rate']-raw[method]['correct_rate'])}
            for method in METHODS if method != SAVED_LLM}}


def evaluate(historical_rows, repetitions=10000, seed=20261019):
    rows = attach_controls(historical_rows)
    families, weights = family_weights(rows, repetitions, seed)
    result = {'schema_version': 1, 'study': 'baseline-strengthening-v1', 'checkpoint': 'A',
              'post_hoc': True, 'rows': rows, 'method_order': list(METHODS),
              'bootstrap': {'unit': 'family_id', 'families': families, 'draws_per_replicate': len(families),
                            'replicates': repetitions, 'seed': seed, 'generator': 'PCG64',
                            'shared_multiplicities': True, 'intervals': '2.5/97.5 percentiles, linear interpolation',
                            'interpretation': 'exploratory; supplementary descriptive controls after final-result inspection'},
              'method_definitions': {
                  SAVED_LLM: {'kind': 'saved_aggregate', 'historical_method_key': 'llm',
                              'source_method_id': 'public-bundle-llm-v1'},
                  SAVED_BASELINE: {'kind': 'saved_prediction', 'historical_method_key': 'baseline',
                                   'source_method_id': 'ghidra-inferred-stack-bounds-v2'},
                  **{method: {'kind': 'uninformative_constant_control', 'version': 1, 'label': label,
                              'observation_inputs': ['shared_availability']}
                     for method, label in controls.CONTROL_LABELS.items()}}}
    for name, truth in (('binary', 'binary_label'), ('source_label_recovery', 'source_label')):
        primary = summarize(rows, weights, truth)
        available = [i for i, r in enumerate(rows) if r['shared_availability'] == 'available']
        result[name] = {'truth_field': truth, 'primary': primary,
                        'common_input': primary if len(available) == len(rows) else summarize(
                            [rows[i] for i in available], weights[:, available], truth), 'subgroups': {}}
        for field in GROUPS:
            result[name]['subgroups'][field] = {}
            for group in sorted({r[field] for r in rows}):
                indices = [i for i, r in enumerate(rows) if r[field] == group]
                result[name]['subgroups'][field][group] = summarize([rows[i] for i in indices], weights[:, indices], truth)
    return result


def verify_historical(comparison, historical):
    """Check every reused historical estimate/interval, not only headline counts."""
    for name, old in (('binary', historical['primary']), ('source_label_recovery', historical['source_label_recovery'])):
        actual = comparison[name]['primary']
        for method, key in ((SAVED_LLM, 'llm'), (SAVED_BASELINE, 'baseline')):
            require(actual['methods'][method] == old[key], f'Historical {name} metrics/intervals differ: {method}')
        require(actual['paired_llm_minus_comparator'][SAVED_BASELINE]['correct_rate_difference'] ==
                old['llm_minus_baseline_correct_rate'], 'Historical paired method contrast differs')
    for method, key in ((SAVED_LLM, 'llm'), (SAVED_BASELINE, 'baseline')):
        require(comparison['binary']['common_input']['methods'][method] == historical['common_input'][key],
                'Historical common-input metrics differ')
        for field in GROUPS:
            if field not in historical['subgroups']: continue
            for group, original in historical['subgroups'][field].items():
                require(comparison['binary']['subgroups'][field][group]['methods'][method] == original[key],
                        f'Historical subgroup metrics differ: {field}/{group}/{method}')


def recount(rows, method, truth='binary_label'):
    counts = dict.fromkeys(('A', 'C', 'E', 'U', 'M'), 0)
    for row in rows:
        label = row[truth]
        if label not in frozen.LABELS: continue
        counts['A'] += 1
        prediction = row['predictions'][method]
        if row['shared_availability'] != 'available' or prediction['status'] not in ('classified', 'abstained'):
            outcome = 'M'
        elif prediction['decision'] not in frozen.LABELS: outcome = 'U'
        else: outcome = 'C' if prediction['decision'] == label else 'E'
        counts[outcome] += 1
    return counts


def verify_counts(comparison):
    expected = {SAVED_LLM: (125, 28, 7, 0), SAVED_BASELINE: (18, 0, 142, 0),
                'control_not_vulnerable': (100, 60, 0, 0), 'control_cwe121': (28, 132, 0, 0),
                'control_cwe122': (32, 128, 0, 0), 'control_uncertain': (0, 0, 160, 0)}
    for endpoint, truth in (('binary', 'binary_label'), ('source_label_recovery', 'source_label')):
        for method in METHODS:
            counts = recount(comparison['rows'], method, truth)
            require(all(counts[k] == comparison[endpoint]['primary']['methods'][method][k]['estimate'] for k in counts),
                    'Independent integer recount differs')
            if endpoint == 'binary':
                require(counts['A'] == 160 and tuple(counts[k] for k in ('C', 'E', 'U', 'M')) == expected[method],
                        f'Unexpected accepted-campaign partition: {method}')
    return {method: recount(comparison['rows'], method) for method in METHODS}

"""Independent integer fixtures for four methods and paired family inference."""
from copy import deepcopy
import hashlib
from itertools import product
import json

import numpy as np
import pytest

from optimization_vuln_analysis.studies.representation import scoring as s
from optimization_vuln_analysis.inputs import bundles
from optimization_vuln_analysis.common import metrics
from optimization_vuln_analysis.inference import attempts as llm


STACK, HEAP, SAFE = s.LABELS


def observation(obs, label, family='family-a', **changes):
    return {'observation_id': obs, 'family_id': family, 'binary_label': label,
            'source_label': label, 'cwe': 'CWE-121', 'variant': 'vulnerable',
            'optimization': 'O0', 'symbols': 'retained', 'operation_status': 'present',
            'parent_bundle_sha256': hashlib.sha256(('parent-'+obs).encode()).hexdigest(), **changes}


def prediction(obs, rep, label):
    return {'observation_id': obs, 'representation': rep, 'decision': label,
            'status': 'unavailable' if label is None else 'abstained' if label == 'uncertain' else 'classified'}


def arguments(rows, labels=None):
    predictions = [prediction(r['observation_id'], rep, labels[i] if labels else SAFE)
                   for i, r in enumerate(rows) for rep in s.REPRESENTATIONS]
    return {'observations': rows, 'aggregates': predictions,
            'eligibility': {r['observation_id']: True for r in rows},
            'input_hashes': {(r['observation_id'], rep): hashlib.sha256((r['observation_id']+rep).encode()).hexdigest()
                             for r in rows for rep in s.REPRESENTATIONS}}


@pytest.fixture
def toy():
    # Six adjudicated and one unresolved, each in a different family. Treatment
    # coordinates deliberately do not coincide, so source/family alignment matters.
    labels = [STACK, SAFE, SAFE, STACK, HEAP, HEAP, 'unresolved']
    rows = [observation(f'r{i}', label, family=f'family-{i}', source_label=STACK if i == 6 else label)
            for i, label in enumerate(labels)]
    return arguments(rows, [HEAP, SAFE, STACK, 'uncertain', None, HEAP, SAFE])


def test_hand_counted_denominator_alerts_control_and_source_endpoint(toy):
    result = s.evaluate(**toy, replicates=40)
    counts = result['primary']['methods']['assembly']['counts']
    assert counts == dict(P=7, A=6, C=2, E=2, U=1, M=1, TP=2, TN=1, FP=1, FN=2,
                          explicit_safe_no_alert=1, abstention_no_alert=1, unavailable_no_alert=1)
    rates = result['primary']['methods']['assembly']['rates']
    for key, expected in {'truth_availability': 6/7, 'correct_rate': 1/3, 'coverage': 2/3,
                           'selective_accuracy': .5, 'abstention_rate': 1/6, 'unavailable_rate': 1/6,
                           'recall': .5, 'false_positive_rate': .5, 'precision': 2/3,
                           'f1': 4/7, 'balanced_accuracy': .5}.items():
        assert rates[key]['estimate'] == pytest.approx(expected)
    control = result['primary']['methods'][s.CONTROL]['counts']
    assert {k: control[k] for k in ('A', 'C', 'E', 'U', 'M', 'TP', 'TN', 'FP', 'FN')} == dict(
        A=6, C=2, E=4, U=0, M=0, TP=0, TN=2, FP=0, FN=4)
    source = result['source_label_recovery']
    assert source['endpoint'] == 'original_source_label'
    assert source['methods']['assembly']['counts']['A'] == 7
    assert source['methods']['assembly']['counts']['E'] == 3
    assert result['subgroups']['binary_label']['unresolved']['methods']['assembly']['counts']['A'] == 0
    assert result['primary']['contrasts'][0]['id'] == 'combined_minus_decompilation_correct_rate'
    assert result['primary']['contrasts'][0]['role'] == 'primary'
    assert len(result['primary']['contrasts']) == 6
    assert {c['estimate'] for c in result['primary']['contrasts'][:3]} == {0}
    # Canonical JSON cannot hide NaNs or non-native NumPy values.
    json.dumps(result, allow_nan=False)


def test_control_has_no_input_or_artificial_llm_fields_and_survives_blocking():
    assert s.always_not_vulnerable() == {'decision': SAFE, 'status': 'classified'}
    args = arguments([observation('x', SAFE)], [None])
    args['eligibility']['x'] = False
    result = s.evaluate(**args, replicates=10)
    assert result['primary']['methods'][s.CONTROL]['counts']['C'] == 1
    for rep in s.REPRESENTATIONS:
        assert result['primary']['methods'][rep]['counts']['M'] == 1
    empty = result['common_input_eligible']['methods'][s.CONTROL]
    assert empty['counts']['P'] == 0
    assert all(v == {'estimate': None, 'lower': None, 'upper': None, 'defined_replicates': 0}
               for v in empty['rates'].values())


@pytest.mark.parametrize('label', [SAFE, STACK, 'unresolved'])
def test_absent_binary_class_and_zero_denominators(label):
    result = s.evaluate(**arguments([observation('x', label)], [None]), replicates=10)
    rates = result['primary']['methods']['assembly']['rates']
    assert rates['balanced_accuracy']['estimate'] is None
    assert rates['precision']['estimate'] is None
    assert rates['selective_accuracy']['estimate'] is None
    if label == 'unresolved':
        assert rates['correct_rate']['defined_replicates'] == 0


@pytest.mark.parametrize('mutation', ['missing', 'duplicate', 'extra', 'control', 'bad_decision', 'bad_status',
                                     'bad_hash', 'missing_hash', 'eligibility', 'blocked', 'truth', 'cell', 'empty'])
def test_misaligned_or_invalid_inventory_is_rejected(toy, mutation):
    args = deepcopy(toy)
    if mutation == 'missing': args['aggregates'].pop()
    elif mutation == 'duplicate': args['aggregates'].append(args['aggregates'][0])
    elif mutation == 'extra': args['aggregates'][0]['observation_id'] = 'foreign'
    elif mutation == 'control': args['aggregates'][0]['representation'] = s.CONTROL
    elif mutation == 'bad_decision': args['aggregates'][0]['decision'] = 'uncertain'
    elif mutation == 'bad_status': args['aggregates'][0]['status'] = 'pending'
    elif mutation == 'bad_hash': args['input_hashes']['r0', 'assembly'] = 'unknown'
    elif mutation == 'missing_hash': args['input_hashes'].pop(('r0', 'assembly'))
    elif mutation == 'eligibility': args['eligibility']['r0'] = 1
    elif mutation == 'blocked': args['eligibility']['r0'] = False
    elif mutation == 'truth': args['observations'][0]['binary_label'] = 'safe'
    elif mutation == 'cell': args['observations'][1]['family_id'] = 'family-0'
    elif mutation == 'empty': args['observations'] = []
    with pytest.raises(ValueError): s.evaluate(**args, replicates=2)


def test_order_is_irrelevant_and_private_truth_cannot_mutate_predictor_arguments(toy):
    before = deepcopy(toy)
    first = bundles.canonical(s.evaluate(**toy, replicates=20))
    assert toy == before
    args = deepcopy(toy)
    args['observations'].reverse(); args['aggregates'].reverse()
    assert bundles.canonical(s.evaluate(**args, replicates=20)) == first
    args['observations'][0]['binary_label'] = HEAP
    s.evaluate(**args, replicates=20)
    assert args['aggregates'] == list(reversed(toy['aggregates']))
    assert args['input_hashes'] == toy['input_hashes'] and args['eligibility'] == toy['eligibility']


def test_pcg64_draws_and_paired_intervals_against_independent_family_loop(toy):
    result = s.evaluate(**toy)  # Actual 10,000-replicate contract.
    families = sorted(r['family_id'] for r in toy['observations'])
    draws = np.random.Generator(np.random.PCG64(20261019)).choice(families, (10000, len(families)), replace=True)
    # Correctness differences per adjudicated family: combined fixes one wrong
    # CWE, compared with decompilation. The unresolved family has zero A.
    toy['aggregates'][2] = prediction('r0', 'combined', STACK)
    paired = s.evaluate(**toy)
    expected = []
    for draw in draws:
        denominator = sum(f != 'family-6' for f in draw)
        if denominator:
            expected.append(sum(f == 'family-0' for f in draw)/denominator)
    contrast = paired['primary']['contrasts'][0]
    assert contrast['estimate'] == pytest.approx(1/6)
    assert contrast['lower'] == pytest.approx(np.quantile(expected, .025, method='linear'))
    assert contrast['upper'] == pytest.approx(np.quantile(expected, .975, method='linear'))
    assert contrast['defined_replicates'] == len(expected)
    ordered, weights = s.family_draws(reversed(families))
    assert ordered == families and weights.shape == (10000, 7)
    assert np.all(weights.sum(axis=1) == 7)
    assert result['bootstrap']['multiplicities_int64_le_sha256'] == hashlib.sha256(weights.astype('<i8').tobytes()).hexdigest()
    # Shared draws make an equal-method difference identically zero in every
    # subgroup and LOFO subset where the denominator exists.
    for table in [result['primary'], *result['leave_one_family_out'].values(),
                  *result['subgroups']['family_id'].values()]:
        for c in table['contrasts'][:3]:
            expected = 0 if table['methods']['assembly']['counts']['A'] else None
            assert c['estimate'] == c['lower'] == c['upper'] == expected
    subset = paired['subgroups']['family_id']['family-0']['contrasts'][0]
    assert subset['estimate'] == subset['lower'] == subset['upper'] == 1
    assert subset['defined_replicates'] == sum(any(f == 'family-0' for f in draw) for draw in draws)


def test_treatment_matching_uses_each_sides_truth_and_retains_failures():
    rows = [observation('o0r', STACK),
            observation('o1r', SAFE, optimization='O1', operation_status='eliminated', source_label=STACK),
            observation('o0s', STACK, symbols='stripped'),
            observation('o1s', 'unresolved', symbols='stripped', optimization='O1'),
            observation('other', HEAP, family='family-b', optimization='O2')]
    args = arguments(rows, [None, SAFE, STACK, None, HEAP])
    args['eligibility']['o0r'] = False
    result = s.evaluate(**args, replicates=200)
    opt, opt2, opt3, symbols = result['matched_contrasts']
    assert opt['matched_cells'] == 1 and opt['matched_families'] == ['family-a']
    assert opt['pairs'] == [{'left': 'o1r', 'right': 'o0r'}]
    assert opt['methods']['assembly']['estimate'] == 1
    assert opt['methods'][s.CONTROL]['estimate'] == 1  # truth changed, control did not
    assert opt['methods']['assembly']['right_correct'] == 0
    assert opt['methods']['assembly']['availability_transitions'] == [
        {'left': 'classified', 'right': 'unavailable', 'count': 1}]
    assert opt['transitions']['binary_label'] == [{'left': SAFE, 'right': STACK, 'count': 1}]
    assert opt['transitions']['input_eligible'] == [{'left': True, 'right': False, 'count': 1}]
    assert len(opt['omissions']) == 2
    assert any(o['unresolved'] == ['O1'] for o in opt['omissions'])
    assert any(o['missing'] == ['O1', 'O0'] for o in opt['omissions'])
    assert symbols['pairs'] == [{'left': 'o0s', 'right': 'o0r'}]
    assert symbols['methods']['assembly']['estimate'] == 1
    assert opt2['matched_cells'] == opt3['matched_cells'] == 0
    assert opt3['methods']['assembly']['estimate'] is None


def test_family_members_share_multiplicity_in_unbalanced_clusters():
    rows = [observation('a0', STACK), observation('a1', STACK, optimization='O1'),
            observation('b0', STACK, family='family-b')]
    result = s.evaluate(**arguments(rows, [STACK, STACK, SAFE]))
    draws = np.random.Generator(np.random.PCG64(20261019)).integers(0, 2, (10000, 2))
    family_a = np.count_nonzero(draws == 0, axis=1)
    expected = 2*family_a/(2*family_a + 2-family_a)
    rate = result['primary']['methods']['assembly']['rates']['correct_rate']
    assert rate['estimate'] == pytest.approx(2/3)
    assert rate['lower'] == np.quantile(expected, .025, method='linear')
    assert rate['upper'] == np.quantile(expected, .975, method='linear')
    # O1/O0 have only family-a pairs. Replicates that never draw it are undefined,
    # rather than being resampled as a new one-family universe.
    matched = result['matched_contrasts'][0]['methods']['assembly']
    assert matched['estimate'] == matched['lower'] == matched['upper'] == 0
    assert matched['defined_replicates'] == int(np.count_nonzero(family_a))


def test_collisions_exclude_every_member_and_keep_parent_scope_separate():
    args = arguments([observation('a', STACK), observation('b', SAFE, family='family-b'),
                      observation('c', STACK, family='family-c')])
    args['input_hashes']['b', 'assembly'] = args['input_hashes']['a', 'assembly']
    args['observations'][2]['source_label'] = SAFE
    args['input_hashes']['c', 'decompilation'] = args['input_hashes']['a', 'decompilation']
    audit = {'historical_scope_groups': [{'members': ['a', 'b', 'c']}], 'binding': 'independent-audit'}
    result = s.evaluate(**args, parent_diagnostics=audit, replicates=50)
    group, = result['collisions']['assembly']
    assert group['binary_conflict'] and group['source_conflict']
    assert group['observation_ids'] == ['a', 'b']
    group, = result['collisions']['decompilation']
    assert not group['binary_conflict'] and group['source_conflict']
    assert result['excluding_conflicting_inputs']['assembly']['excluded_observation_ids'] == ['a', 'b']
    assert result['excluding_conflicting_inputs']['decompilation']['excluded_observation_ids'] == ['a', 'c']
    for method in s.METHODS:
        assert result['primary']['methods'][method]['counts']['A'] == 3
        assert result['excluding_conflicting_inputs']['assembly']['methods'][method]['counts']['A'] == 1
    assert result['parent_diagnostics']['scope_audit'] == audit


def test_lofo_and_predeclared_example_order_include_abstained_and_unavailable():
    args = arguments([observation('b', STACK), observation('a', HEAP, family='family-b')], [None, 'uncertain'])
    for pred in args['aggregates']:
        if pred['representation'] == 'combined': pred.update(decision=STACK if pred['observation_id'] == 'b' else HEAP,
                                                              status='classified')
    result = s.evaluate(**args, replicates=20)
    assert [g['selected_observation_id'] for g in result['qualitative_selection']] == ['a', None, 'a', None]
    assert all(t['methods']['combined']['counts']['A'] == 1 for t in result['leave_one_family_out'].values())


def test_all_125_vote_patterns_flow_through_retained_voting_into_event_partition():
    choices = [*s.LABELS, 'uncertain', None]
    for labels in product(choices, repeat=3):
        attempts = [{'status': 'valid' if label is not None else 'timeout',
                     'parsed': {'decision': label, 'confidence': .25} if label is not None else None}
                    for label in labels]
        aggregate = llm.aggregate(attempts)
        valid = [label for label in labels if label is not None]
        majority = next((label for label in choices[:-1] if labels.count(label) >= 2), None)
        expected = 'M' if not valid else 'U' if majority in (None, 'uncertain') else 'C' if majority == STACK else 'E'
        args = arguments([observation('x', STACK)])
        args['aggregates'] = [{'observation_id': 'x', 'representation': rep, **aggregate} for rep in s.REPRESENTATIONS]
        aligned = s.align(**args)
        for method in s.REPRESENTATIONS:
            ev = s.events(aligned, method)
            assert ev[expected].tolist() == [1]
            assert sum(int(ev[k][0]) for k in ('C', 'E', 'U', 'M')) == 1


def test_retained_arithmetic_and_intervals_are_called(toy, monkeypatch):
    calls = {'statistics': 0, 'interval': 0}
    for name in calls:
        original = getattr(metrics, name)
        def counted(*args, _name=name, _original=original, **kwargs):
            calls[_name] += 1
            return _original(*args, **kwargs)
        monkeypatch.setattr(metrics, name, counted)
    s.evaluate(**toy, replicates=2)
    assert calls['statistics'] > 0 and calls['interval'] > 0


def test_file_adapter_rejects_incomplete_execution_before_evaluation(tmp_path, monkeypatch):
    from optimization_vuln_analysis.studies.representation import inventory, replay, views
    monkeypatch.setattr(inventory, 'verify', lambda *a: {'manifest_sha256': 'input'})
    monkeypatch.setattr(views, 'verify', lambda *a: {'manifest_sha256': 'projection'})
    monkeypatch.setattr(replay, 'inspect', lambda *a: {'state': {'status': 'incomplete', 'preflight_bound': False}})
    monkeypatch.setattr(s, 'evaluate', lambda *a, **kw: pytest.fail('Pending execution was scored'))
    with pytest.raises(ValueError, match='pending'):
        s.score_execution(tmp_path, tmp_path, tmp_path)


def test_file_adapter_replays_complete_bound_evidence_without_network_or_writes(packet, projection_setup, monkeypatch):
    from optimization_vuln_analysis.studies.representation import runner, views
    from optimization_vuln_analysis.inference import runtime
    directory, control = packet
    projection, _ = projection_setup
    inputs = projection.parent/'inputs'
    runner.preflight(directory, control['evidence'])
    runner.run(directory)
    calls = list(control['calls'])
    before = {p.relative_to(directory): p.read_bytes() for p in directory.rglob('*') if p.is_file()}
    def forbidden(*a, **kw): pytest.fail('Offline evaluation queried model/server')
    monkeypatch.setattr(llm, 'send_request', forbidden)
    monkeypatch.setattr(runtime, 'budget', forbidden)
    monkeypatch.setattr(runtime, 'verify_live', forbidden)
    result = s.score_execution(inputs, projection, directory)
    assert result['bindings']['purpose'] == 'engineering'
    assert result['primary']['methods'][s.CONTROL]['counts']['C'] == 16
    for rep in s.REPRESENTATIONS:
        assert result['primary']['methods'][rep]['counts']['U'] == 32
        assert result['primary']['methods'][rep]['counts']['A'] == 32
    assert control['calls'] == calls
    assert before == {p.relative_to(directory): p.read_bytes() for p in directory.rglob('*') if p.is_file()}
    original = views.verify
    def wrong_binding(*a, **kw):
        return {**original(*a, **kw), 'input_manifest_sha256': 'wrong'}
    monkeypatch.setattr(views, 'verify', wrong_binding)
    with pytest.raises(ValueError, match='binding'):
        s.score_execution(inputs, projection, directory)

"""Hand-counted scoring fixtures independent of any campaign or predictor."""
import numpy as np
import pytest

from optimization_vuln_analysis.common.metrics import divide, interval, statistics


def test_weighted_arithmetic_keeps_failures_in_adjudicated_denominator():
    # Six adjudicated observations: wrong-CWE alert, correct safe, false alert,
    # abstained positive, unavailable positive, correct positive; one unresolved.
    events = {key: np.asarray(values, dtype=float) for key, values in {
        'P': [1, 1, 1, 1, 1, 1, 1], 'A': [1, 1, 1, 1, 1, 1, 0],
        'C': [0, 1, 0, 0, 0, 1, 0], 'E': [1, 0, 1, 0, 0, 0, 0],
        'U': [0, 0, 0, 1, 0, 0, 0], 'M': [0, 0, 0, 0, 1, 0, 0],
        'TP': [1, 0, 0, 0, 0, 1, 0], 'TN': [0, 1, 0, 0, 0, 0, 0],
        'FP': [0, 0, 1, 0, 0, 0, 0], 'FN': [0, 0, 0, 1, 1, 0, 0],
        'explicit_safe_no_alert': [0, 1, 0, 0, 0, 0, 0],
        'abstention_no_alert': [0, 0, 0, 1, 0, 0, 0],
        'unavailable_no_alert': [0, 0, 0, 0, 1, 0, 0],
    }.items()}
    # A second row of weights doubles the first three observations as one family.
    result = statistics(events, np.asarray([[1]*7, [2, 2, 2, 0, 0, 0, 0]]))
    for key, expected in {'P': [7, 6], 'A': [6, 6], 'C': [2, 2], 'E': [2, 4],
                           'U': [1, 0], 'M': [1, 0], 'TP': [2, 2], 'TN': [1, 2],
                           'FP': [1, 2], 'FN': [2, 0]}.items():
        np.testing.assert_array_equal(result[key], expected)
    np.testing.assert_array_equal(result['A'], result['C']+result['E']+result['U']+result['M'])
    for key, expected in {'correct_rate': 1/3, 'coverage': 2/3, 'selective_accuracy': .5,
                           'recall': .5, 'false_positive_rate': .5, 'precision': 2/3,
                           'f1': 4/7, 'balanced_accuracy': .5,
                           'abstention_rate': 1/6, 'unavailable_rate': 1/6}.items():
        assert result[key][0] == pytest.approx(expected)
    assert result['coverage'][1] == 1 and result['selective_accuracy'][1] == pytest.approx(1/3)


def test_empty_denominators_and_finite_percentiles():
    np.testing.assert_array_equal(divide([2, 0, 1], [4, 0, 0]), [.5, np.nan, np.nan])
    assert interval([np.nan, np.inf, -np.inf]) == {'lower': None, 'upper': None, 'defined_replicates': 0}
    result = interval([3, np.nan, 1, 2, np.inf])
    assert result['defined_replicates'] == 3
    assert result['lower'] == pytest.approx(1.05) and result['upper'] == pytest.approx(2.95)

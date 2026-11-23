"""Method-independent weighted metrics and finite-replicate intervals."""
import numpy as np

def divide(numerator, denominator):
    return np.divide(numerator, denominator, out=np.full_like(np.asarray(numerator, dtype=float), np.nan), where=np.asarray(denominator) != 0)


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

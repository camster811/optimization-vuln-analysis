"""Constant predictions: the only observation input is shared availability."""
from redesign.pipeline.inventory import require


CONTROL_LABELS = {
    'control_not_vulnerable': 'not_vulnerable',
    'control_cwe121': 'vulnerable_CWE-121',
    'control_cwe122': 'vulnerable_CWE-122',
    'control_uncertain': 'uncertain',
}


def predict(method_id, shared_availability):
    """No labels, identifiers, bundles, evidence, confidence or votes are inputs."""
    require(method_id in CONTROL_LABELS, 'Unknown constant control')
    require(shared_availability in ('available', 'context_unavailable', 'input_unavailable',
                                    'extraction_unavailable', 'build_unavailable'),
            'Unknown shared availability')
    label = CONTROL_LABELS[method_id]
    available = shared_availability == 'available'
    return {'method_id': method_id, 'kind': 'uninformative_constant_control',
            'status': ('abstained' if label == 'uncertain' else 'classified') if available else 'unavailable',
            'decision': label if available else None}


def generate(eligibility):
    """Attach opaque IDs outside prediction; accept eligibility records only."""
    require(len({r['observation_id'] for r in eligibility}) == len(eligibility), 'Duplicate control inventory')
    require(all(set(r) == {'observation_id', 'status'} for r in eligibility),
            'Controls accept only opaque IDs and shared eligibility')
    return [{'observation_id': r['observation_id'], 'predictions': {
        method: predict(method, r['status']) for method in CONTROL_LABELS}} for r in eligibility]

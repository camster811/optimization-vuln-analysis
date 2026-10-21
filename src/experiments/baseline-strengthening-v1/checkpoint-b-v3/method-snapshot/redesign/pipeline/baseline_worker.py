"""Analyze public bundle inputs only. Case IDs, source labels and oracle files are not inputs."""
import argparse
from pathlib import Path

from jsonschema import Draft202012Validator

from .bounds import analyze, policy_check
from .bundles import apply_budget, canonical, evidence_addresses, validate
from .inventory import ROOT, digest, encode, read_json, require
from .pcode import lift, validate_ir


def validate_result(result, bundle):
    Draft202012Validator(read_json(ROOT / 'schemas/baseline-result-v2.json')).validate(result)
    require(result['bundle_sha256'] == __import__('hashlib').sha256(canonical(bundle).encode()).hexdigest(),
            'Baseline result input differs')
    prediction = result['prediction']
    if result['status'] in ('input_unavailable', 'runtime_failed'):
        require(prediction is None and result['error_code'] is not None, 'Failure must not masquerade as abstention')
    elif result['status'] == 'lifted':
        require(prediction is None and result['ir_sha256'] is not None and result['error_code'] is None, 'Invalid lifted state')
    else:
        require(prediction is not None and result['ir_sha256'] is not None and result['error_code'] is None, 'Missing prediction')
        evidence_addresses(bundle, prediction['evidence'])
        require(prediction['evidence'] == sorted(set(prediction['evidence']), key=lambda a: int(a,16)), 'Invalid evidence ordering')
        require((prediction['decision'] == 'uncertain') == (prediction['status'] == 'abstained'), 'Decision/status differs')
        for check in prediction['write_checks']:
            evidence_addresses(bundle, check['evidence'] + [check['site']])
            if check['outcome'] in ('within_bounds','exceeds_allocation','within_inferred_extent','exceeds_inferred_extent'):
                require(all(type(check[k]) is int for k in ('offset','size','capacity'))
                        and check['size'] > 0 and check['capacity'] >= 0, 'Missing allocation/write bound evidence')
                within = 0 <= check['offset'] <= check['offset'] + check['size'] <= check['capacity']
                require(within == (check['outcome'] in ('within_bounds','within_inferred_extent')), 'Contradictory write bound conclusion')
                require((check['region']=='heap' and check['bound_basis']=='requested_allocation'
                         and check['object_offset'] is None and check['outcome'] in ('within_bounds','exceeds_allocation'))
                        or (check['region']=='stack' and type(check['object_offset']) is int
                            and ((check['bound_basis']=='inferred_stack_object_extent' and check['outcome'] in
                                  ('within_inferred_extent','exceeds_inferred_extent'))
                                 or (check['bound_basis']=='recovered_scalar_slot' and check['outcome']=='within_bounds'))),
                        'Missing or contradictory bound basis')
            if check['outcome'] == 'zero_extent': require(check['size'] == 0, 'Nonzero empty write')
        assumptions={c for c in prediction['reason_codes'] if c in ('inferred_stack_object_extent','instruction_pcode_store_fallback')}
        codes=set(prediction['reason_codes'])-assumptions
        require(('inferred_stack_object_extent' in assumptions)==any(c['bound_basis']=='inferred_stack_object_extent'
                for c in prediction['write_checks']), 'Missing inferred-stack qualification')
        if prediction['decision'] == 'vulnerable_CWE-122':
            require(codes == {'heap_write_exceeds_allocation'}
                    and any(c['region'] == 'heap' and c['outcome'] == 'exceeds_allocation' for c in prediction['write_checks']), 'Unsupported definite finding')
        if prediction['decision'] == 'vulnerable_CWE-121':
            require(codes == {'stack_write_exceeds_inferred_extent'} and 'inferred_stack_object_extent' in assumptions
                    and any(c['region']=='stack' and c['outcome']=='exceeds_inferred_extent'
                            for c in prediction['write_checks']), 'Unsupported heuristic stack finding')
        if prediction['decision'] == 'not_vulnerable':
            require(codes == {'all_selected_writes_accounted_for'}
                    and all(c['outcome'] in ('within_bounds','within_inferred_extent','zero_extent','static_storage_write') for c in prediction['write_checks']), 'Unsupported safety conclusion')
    return result


def execute(mode, input_path, work, policy, ir_path=None):
    bundle = read_json(input_path); validate(bundle); policy_check(policy)
    require(input_path.read_text() == canonical(bundle), 'Noncanonical public input')
    result = {'schema_version':2, 'method_id':policy['method_id'], 'bundle_sha256':digest(input_path),
              'ir_sha256':None, 'status':'input_unavailable', 'prediction':None, 'error_code':'input_unavailable'}
    if bundle['status'] != 'available' or apply_budget(bundle, read_json(ROOT / 'context_policy.json')) != bundle:
        return result
    try:
        if mode == 'lift':
            lift(bundle, policy, work)
            ir_path = work / 'pcode.json'
            result.update(status='lifted', error_code=None, ir_sha256=digest(ir_path))
        else:
            ir = read_json(ir_path); validate_ir(ir, bundle)
            result.update(status='completed', error_code=None, ir_sha256=digest(ir_path),
                          prediction=analyze(bundle, ir, policy))
        validate_result(result, bundle)
    except Exception as error:
        work.mkdir(parents=True, exist_ok=True)
        (work / 'failure.txt').write_text(str(error) + '\n')
        result.update(status='runtime_failed', error_code='runtime_failure', prediction=None)
    return result


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode',choices=('lift','analyze'))
    parser.add_argument('--input',type=Path,required=True)
    parser.add_argument('--policy',type=Path,required=True)
    parser.add_argument('--work',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--ir',type=Path)
    args=parser.parse_args()
    result=execute(args.mode,args.input.resolve(),args.work.resolve(),read_json(args.policy),args.ir)
    args.output.write_text(encode(result))


if __name__ == '__main__': main()

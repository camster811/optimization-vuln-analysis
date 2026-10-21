"""Public-only v3 worker; private truth is an evaluator input, never a worker input."""
import argparse
from copy import deepcopy
import hashlib
from pathlib import Path

from jsonschema import Draft202012Validator

from redesign.pipeline import baseline_worker as v2
from redesign.pipeline.bundles import validate,canonical,apply_budget,evidence_addresses
from redesign.pipeline.inventory import ROOT,digest,read_json,require
from redesign.pipeline.llm_runtime import write_new
from redesign.pipeline.pcode import lift,validate_ir
from .engine import HERE,NEW_REASONS,policy_check,analyze


def validate_result(result,bundle):
    Draft202012Validator(read_json(HERE/'result-schema.json')).validate(result)
    projected=deepcopy(result)
    projected.update(schema_version=2,method_id='ghidra-inferred-stack-bounds-v2')
    if projected['prediction'] is not None:
        evidence_addresses(bundle,[event['site'] for event in result['prediction']['contract_events']])
        prediction=projected['prediction'];prediction.pop('contract_events')
        prediction['reason_codes']=sorted(set('unsupported_library_call' if r in NEW_REASONS else r
                                             for r in prediction['reason_codes']))
    v2.validate_result(projected,bundle)
    return result


def execute(bundle_path,work,policy):
    bundle=validate(read_json(bundle_path));policy_check(policy)
    require(bundle_path.read_bytes()==canonical(bundle).encode(),'Noncanonical worker input')
    result={'schema_version':3,'method_id':policy['method_id'],'bundle_sha256':digest(bundle_path),
            'ir_sha256':None,'status':'input_unavailable','prediction':None,'error_code':'input_unavailable'}
    if bundle['status']!='available' or apply_budget(bundle,read_json(ROOT/'context_policy.json'))!=bundle:return result
    lift(bundle,policy,work/'ir')
    ir=read_json(work/'ir/pcode.json');validate_ir(ir,bundle)
    result.update(status='completed',ir_sha256=digest(work/'ir/pcode.json'),error_code=None,
                  prediction=analyze(bundle,ir,policy))
    validate_result(result,bundle)
    ablations={name:analyze(bundle,ir,policy,name) for name in ('without_memory','without_output')}
    for name,prediction in ablations.items():
        validate_result({**result,'prediction':prediction},bundle)
    write_new(work/'ablations.json',ablations)
    return result


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input',type=Path,required=True);parser.add_argument('--policy',type=Path,required=True)
    parser.add_argument('--work',type=Path,required=True);parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();policy=read_json(args.policy)
    try:result=execute(args.input.resolve(),args.work.resolve(),policy)
    except Exception as error:
        write_new(args.work/'failure.txt',str(error))
        result={'schema_version':3,'method_id':policy['method_id'],'bundle_sha256':digest(args.input),
                'ir_sha256':None,'status':'runtime_failed','prediction':None,'error_code':'runtime_failure'}
    write_new(args.output,result)


if __name__=='__main__':main()

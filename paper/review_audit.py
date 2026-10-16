"""Post-hoc repository review. Reads frozen inputs; writes only paper/review_audit.json."""
from collections import Counter, defaultdict
import copy
import csv
import hashlib
import json
from pathlib import Path
import statistics
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from pipeline import evaluate as ev, static_baseline as sb, run_llm as llm, extract


def digest(value):
    return hashlib.sha256(llm.canonical_json(value).encode()).hexdigest()


def fixture(operations):
    instructions = [dict(address=hex(0x1000 + 16*i), mnemonic=m, operands=o)
                    for i, (m, o) in enumerate(operations)]
    return dict(schema_version=1, architecture="x86-64",
                function=dict(name="example", entry="0x1000", end=hex(0x1000 + 16*len(operations))),
                instructions=instructions, calls=[],
                decompilation=dict(status="ok", text="void example(void) {}"))


def main():
    config = ev.load_config()
    truth = ev.load_truth()
    ev.verify_input_freeze(truth)
    records = ev.load_records(truth)
    static = ev.load_static_predictions(records)
    runs = ev.load_llm_runs(records, config)
    aggregates = {key: ev.aggregate_three_runs(value) for key, value in runs.items()}
    methods = {"static": static, "llm": aggregates}
    pairs = sorted({r['pair_id'] for r in truth})
    by_id = {r['observation_id']: r for r in truth}
    by_cell = {(r['pair_id'], r['variant'], r['optimization'], r['symbols']): r['observation_id'] for r in truth}
    result = {}
    regenerated = {key: dict(observation_id=key, **sb.analyze_record(record)) for key, record in records.items()}
    result['static_mismatches'] = [key for key in static if static[key] != regenerated[key]]
    result['duplicates'] = {}
    for mode in ('full_record', 'instructions_calls', 'neutral_function_name'):
        groups = defaultdict(list)
        for key, original in records.items():
            record = copy.deepcopy(original)
            if mode == 'instructions_calls':
                record = {k: record[k] for k in ('instructions', 'calls')}
            elif mode == 'neutral_function_name':
                name = record['function']['name']
                record['function']['name'] = 'FUNCTION'
                record['decompilation']['text'] = record['decompilation']['text'].replace(name, 'FUNCTION')
            groups[digest(record)].append(key)
        result['duplicates'][mode] = dict(unique=len(groups),
            groups=[dict(ids=ids, truth_counts=dict(Counter(by_id[key]['truth'] for key in ids)))
                    for ids in groups.values() if len(ids) > 1],
            consistent_classifier_ceiling=sum(max(Counter(by_id[key]['truth'] for key in ids).values()) for ids in groups.values()))
    result['stripping'] = []
    result['variant_matches'] = []
    for pair in pairs:
        for opt in ('O0', 'O2'):
            for variant in ('vulnerable', 'fixed'):
                a, b = [by_cell[pair, variant, opt, symbols] for symbols in ('retained', 'stripped')]
                normalized = []
                for key in (a,b):
                    value = copy.deepcopy(records[key])
                    name = value['function']['name']
                    value['function']['name'] = 'FUNCTION'
                    value['decompilation']['text'] = value['decompilation']['text'].replace(name,'FUNCTION')
                    normalized.append(value)
                result['stripping'].append(dict(pair=pair, optimization=opt, variant=variant, ids=[a,b],
                    changed_fields=[key for key in records[a] if records[a][key] != records[b][key]],
                    same_instructions_calls=all(records[a][key] == records[b][key] for key in ('instructions','calls')),
                    same_after_function_name_normalization=normalized[0] == normalized[1],
                    llm_decision_changed=aggregates[a]['decision'] != aggregates[b]['decision']))
            for symbols in ('retained', 'stripped'):
                a, b = [by_cell[pair, variant, opt, symbols] for variant in ('vulnerable', 'fixed')]
                if records[a] == records[b]:
                    result['variant_matches'].append(dict(pair=pair, optimization=opt, symbols=symbols, ids=[a,b]))
    result['pair_metrics'] = []
    result['paired_variants'] = []
    for method, predictions in methods.items():
        for pair in pairs:
            group = [r for r in truth if r['pair_id'] == pair]
            scores = Counter(ev.score_three_way(r['truth'], predictions[r['observation_id']]['decision']) for r in group)
            forced = Counter(ev.score_forced_alert(r['truth'], predictions[r['observation_id']]['decision']) for r in group)
            result['pair_metrics'].append(dict(method=method, pair=pair, **dict(scores), **dict(forced)))
        both_correct = same_decision = 0
        for pair in pairs:
            for opt in ('O0', 'O2'):
                for symbols in ('retained', 'stripped'):
                    a,b = [by_cell[pair, variant, opt, symbols] for variant in ('vulnerable','fixed')]
                    both_correct += all(predictions[key]['decision'] == by_id[key]['truth'] for key in (a,b))
                    same_decision += predictions[a]['decision'] == predictions[b]['decision']
        result['paired_variants'].append(dict(method=method, cells=40, both_correct=both_correct, same_decision=same_decision))
    result['same_request_repetitions'] = []
    groups = defaultdict(list)
    for key, group in runs.items():
        for run in group:
            groups[run['request_sha256']].append(run)
    for sha, group in groups.items():
        if len(group) > 1:
            result['same_request_repetitions'].append(dict(hash=sha, n=len(group),
                ids=[f"{run['observation_id']}/rep{run['repetition']}" for run in group],
                decisions=[run['parsed']['decision'] if run['status']=='valid' else run['status'] for run in group]))
    result['envelope_mismatches'] = []
    for key, group in runs.items():
        for run in group:
            if run['response_body'] is not None and run['http_status'] == 200:
                body = json.loads(run['response_body'])
                if (body['choices'][0]['message'].get('content') or '') != run['raw_response']:
                    result['envelope_mismatches'].append([key, run['repetition']])
    all_runs = [r for group in runs.values() for r in group]
    result['runtime'] = dict(seconds=sum(r['elapsed_seconds'] for r in all_runs),
        median_seconds=statistics.median(r['elapsed_seconds'] for r in all_runs),
        prompt_tokens_range=[min(r['usage']['prompt_tokens'] for r in all_runs), max(r['usage']['prompt_tokens'] for r in all_runs)],
        completion_tokens=sum(r['usage']['completion_tokens'] for r in all_runs),
        failed=[dict(id=r['observation_id'], rep=r['repetition'], status=r['status'], **{k: by_id[r['observation_id']][k] for k in ('pair_id','variant','optimization','symbols')}) for r in all_runs if r['status'] != 'valid'])
    with (ROOT/'data/private/manual_oracle.csv').open() as stream:
        oracle = {(r['pair_id'],r['variant'],r['optimization']):r for r in csv.DictReader(stream)}
    result['oracle_issues'] = []
    checked = set()
    for row in truth:
        key = tuple(row[k] for k in ('pair_id','variant','optimization'))
        if key in checked:
            continue
        checked.add(key)
        review = oracle[key]
        valid = (review['oracle_binary'] == row['oracle_binary'] and review['conclusion'] == row['truth']
                 and review['intended_operation_survived']=='yes' and review['review_status']=='reviewed')
        for path, sha in ((review['source_path'],review['source_sha256']), (review['oracle_binary'],review['oracle_sha256'])):
            valid &= hashlib.sha256((ROOT/path).read_bytes()).hexdigest() == sha
        if not valid:
            result['oracle_issues'].append(key)
    result['oracle_builds_checked'] = len(checked)
    result['binary_hash_issues'] = [row['observation_id'] for row in truth
        if any(extract.binary_hashes((ROOT/row['analysis_binary']).read_bytes())[field] != row[field]
               for field in ('text_sha256','analysis_sha256'))]
    # Safe reuse of an already-popped saved-RBP slot as local storage.
    popped = fixture([('push','RBP'), ('mov','RBP,RSP'), ('pop','RBP'), ('sub','RSP,0x10'),
                      ('mov','qword ptr [RSP + 0x8],0x0'), ('add','RSP,0x10'), ('ret','')])
    # A second test of the unchanged argument cannot take the opposite branch.
    impossible = fixture([('test','EDI,EDI'), ('je','0x1060'), ('test','EDI,EDI'), ('je','0x1050'),
                          ('jmp','0x1060'), ('mov','qword ptr [RSP],0x0'), ('ret','')])
    result['baseline_counterexamples'] = {}
    for name, record in [('popped_frame_slot',popped), ('infeasible_branch',impossible)]:
        sb.validate_record(record)
        result['baseline_counterexamples'][name] = dict(record=record, actual=sb.analyze_record(record), expected='uncertain or a safe decision; no overflow')
    result['leave_one_pair_out'] = []
    for omitted in pairs:
        group = [r for r in truth if r['pair_id'] != omitted]
        point = {m: ev.compute_metrics(ev.cluster_counts(group, predictions, pairs).sum(axis=0)) for m,predictions in methods.items()}
        result['leave_one_pair_out'].append(dict(omitted=omitted,
            correct_rate_llm_minus_static=float(point['llm']['correct_rate']-point['static']['correct_rate']),
            forced_accuracy_llm_minus_static=float(point['llm']['accuracy']-point['static']['accuracy'])))
    destination=ROOT/'paper/review_audit.json'
    destination.write_text(json.dumps(result, indent=2)+'\n')
    summary = {k:v for k,v in result.items() if k not in ('duplicates','stripping','same_request_repetitions','baseline_counterexamples','pair_metrics')}
    summary['duplicate_counts'] = {k:dict(unique=v['unique'],ceiling=v['consistent_classifier_ceiling'],conflicting_groups=[g for g in v['groups'] if len(g['truth_counts'])>1]) for k,v in result['duplicates'].items()}
    summary['stripping_identical_instructions_calls'] = sum(r['same_instructions_calls'] for r in result['stripping'])
    summary['stripping_identical_after_name_normalization'] = sum(r['same_after_function_name_normalization'] for r in result['stripping'])
    summary['same_request_groups'] = len(result['same_request_repetitions'])
    summary['same_request_groups_different_decisions'] = sum(len(set(g['decisions']))>1 for g in result['same_request_repetitions'])
    summary['counterexample_decisions'] = {k:v['actual'] for k,v in result['baseline_counterexamples'].items()}
    print(json.dumps(summary,indent=2))


if __name__ == '__main__':
    main()

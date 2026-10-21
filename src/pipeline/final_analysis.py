"""Regenerate Phase 9 tables from saved attempts, frozen truth, and saved baseline IR."""
import argparse
from collections import Counter
import csv
import io
from pathlib import Path

import numpy as np

from . import evaluate, final_freeze, final_run, llm_runtime, run_llm
from .context_campaign import verify_campaign
from .bundles import canonical
from .final_sources import CAMPAIGN
from .inventory import digest, read_json, require


def diagnostics(rows):
    table = []
    for opt in ('O0','O1','O2','O3'):
        for cwe in ('CWE-121','CWE-122'):
            subset = [r for r in rows if r['optimization']==opt and r['cwe']==cwe]
            table.append({'optimization':opt, 'cwe':cwe, 'planned':len(subset),
                'operations':dict(Counter(r['operation_status'] for r in subset)),
                'source_classes':dict(Counter(r['source_label'] for r in subset)),
                'binary_classes':dict(Counter(r['binary_label'] for r in subset)),
                'unresolved_truth':sum(r['binary_label'] not in evaluate.LABELS for r in subset),
                'extraction_failures':sum(r['public_context_status']!='available' for r in subset),
                'context_failures':sum(r['public_context_status']=='available' and r['shared_availability']!='available' for r in subset),
                'methods':{m:({k:int(v[0]) for k,v in evaluate.statistics(evaluate.outcomes(subset,m),
                    np.ones((1,len(subset)))).items() if k in ('A','C','E','U','M')}
                    if subset else dict.fromkeys(('A','C','E','U','M'),0)) for m in evaluate.METHODS}})
    return table


def analyze(directory, root=CAMPAIGN):
    verify_campaign(root)
    saved = final_run.verify(directory, root, replay=True)
    for field in ('attempt_statuses','baseline_statuses'):
        require(not any(saved[field].get(k,0) for k in ('pending','dispatched_unresolved')), 'Final slots are incomplete')
    manifest, _ = final_run.validate_manifest(directory, root)
    require(set(saved['aggregates']) == set(manifest['inputs']), 'Final aggregate inventory differs')
    _, preflight, plan = final_run.frozen_inputs(root)
    truth = read_json(root/'build/final/dispositions.json')
    pairs = {p['pair_id']:p for p in read_json(root/'corpus/manifest.json')['pairs']}
    builds = {b['build_id']:b['status'] for b in read_json(root/'build/final/build-manifest.json')['builds']}
    rows = []
    for cell in truth['observations']:
        identifier = cell['observation_id']
        result = read_json(directory/'baseline'/identifier/'result.json')
        prediction = result['prediction']
        base = {'status':prediction['status'] if prediction else 'unavailable',
                'decision':prediction['decision'] if prediction else None,
                'reasons':prediction['reason_codes'] if prediction else [result.get('error_code', result['status'])]}
        rows.append({**cell, 'family_id':pairs[cell['pair_id']]['family_id'], 'cwe':pairs[cell['pair_id']]['cwe'],
            'bundle_sha256':manifest['inputs'][identifier], 'build_status':builds[cell['build_id']],
            'public_context_status':read_json(directory/'inputs'/f'{identifier}.json')['status'],
            'shared_availability':saved['shared_availability'][identifier],
            'predictions':{'baseline':base, 'llm':saved['aggregates'][identifier]}})
    require(len(rows)==len(plan['observations']) and {r['observation_id'] for r in rows}==set(manifest['inputs']),
            'Truth inventory differs')
    config = read_json(root/'config.json')['evaluation']
    report = evaluate.evaluate(rows, config['bootstrap_repetitions'], config['bootstrap_seed'])
    report['bootstrap']['interpretation'] = 'exploratory; ten source-family clusters'
    report['disposition_by_optimization_cwe'] = diagnostics(rows)
    # Recreate the SAME PCG64 family draws used by the locked evaluator, for
    # level-specific symbol contrasts and scope-collision sensitivity.
    families = report['bootstrap']['families']
    draws = np.random.Generator(np.random.PCG64(config['bootstrap_seed'])).integers(
        0,len(families),size=(config['bootstrap_repetitions'],len(families)))
    mult = np.stack([(draws==i).sum(axis=1) for i in range(len(families))],axis=1)
    weights = np.vstack([np.ones(len(rows)), mult[:,[families.index(r['family_id']) for r in rows]]])
    report['symbol_contrasts_by_level'] = {}
    for opt in ('O0','O1','O2','O3'):
        indices = [i for i,r in enumerate(rows) if r['optimization']==opt]
        report['symbol_contrasts_by_level'][opt] = evaluate.matched(
            [rows[i] for i in indices],weights[:,indices],'symbols','retained','stripped')
    audit = read_json(preflight/'context-audit.json')
    report['input_audit'] = {'symbol_partners':audit['symbol_partners'], 'equality_groups':audit['equality_groups']}
    excluded = {identifier for group in audit['equality_groups']['binary_code_data_scope']
                if group['conflicting_source_labels'] for identifier in group['observations']}
    indices = [i for i,r in enumerate(rows) if r['observation_id'] not in excluded]
    report['excluding_conflicting_code_data_scopes'] = {'excluded_cells':len(excluded),
        **{truth_name:evaluate.summarize([rows[i] for i in indices],weights[:,indices],label)
           if indices else {'planned_cells':0} for truth_name,label in
           (('binary','binary_label'),('source','source_label'))}}
    attempts = [run_llm.result_for(directory,s,manifest) for s in manifest['slots']]
    report['compute'] = {'attempt_statuses':saved['attempt_statuses'], 'baseline_statuses':saved['baseline_statuses'],
        'actual_dispatches':sum((directory/'slots'/run_llm.slot_name(s)/'dispatch.json').exists() for s in manifest['slots']),
        'llm_elapsed_seconds':sum(a.get('elapsed_seconds',0) for a in attempts),
        'prompt_tokens':sum(a.get('usage',{}).get('prompt_tokens') or 0 for a in attempts),
        'completion_tokens':sum(a.get('usage',{}).get('completion_tokens') or 0 for a in attempts),
        'baseline_worker_seconds':sum(read_json(p)['wall_seconds'] for p in (directory/'baseline').glob('*/timing.json')),
        'finish_reasons':dict(Counter(str(a.get('finish_reason')) for a in attempts if a.get('response_body') is not None))}
    report['inputs'] = {'freeze_sha256':digest(root/'release/freeze.json'),
        'run_manifest_sha256':digest(directory/'manifest.json'), 'methods':final_run.methods(),
        'saved_attempt_files':{p.relative_to(directory).as_posix():digest(p) for p in sorted(directory.rglob('*'))
            if p.is_file() and p.name not in ('runner.lock','baseline.lock') and not p.name.startswith('.pending-')}}
    report['review_provenance'] = truth['review_provenance']
    return report


def artifacts(report):
    stream = io.StringIO()
    fields = ['observation_id','family_id','cwe','variant','optimization','symbols','source_label',
              'binary_label','operation_status','shared_availability','baseline_status','baseline_decision','llm_status','llm_decision']
    writer = csv.DictWriter(stream,fieldnames=fields); writer.writeheader()
    for row in report['rows']:
        writer.writerow({**{k:row[k] for k in fields if k in row},
            **{m+'_'+k:row['predictions'][m][k] for m in evaluate.METHODS for k in ('status','decision')}})
    lines = ['# Phase 9 final results', '',
        'Exploratory family-cluster intervals; ten families. Shared missingness remains in the primary denominator.', '',
        '| Method | A | Correct | Incorrect | Abstain | Unavailable | C/A | Coverage | Selective accuracy |',
        '|---|---:|---:|---:|---:|---:|---:|---:|---:|']
    for method in evaluate.METHODS:
        values = [report['primary'][method][k]['estimate'] for k in
                  ('A','C','E','U','M','correct_rate','coverage','selective_accuracy')]
        lines.append('| '+method+' | '+' | '.join('NA' if v is None else f'{v:.4g}' for v in values)+' |')
    lines += ['', 'Full intervals, optimization/CWE dispositions, class balance, matched contrasts, per-family and collision sensitivities, confidence and compute accounting are in `evaluation.json`.',
              '', 'Private localization and Codex oracle review were used; there was no independent human adjudication.', '']
    return {'evaluation.json':canonical(report), 'observations.csv':stream.getvalue(), 'report.md':'\n'.join(lines)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory',type=Path,required=True)
    parser.add_argument('--root',type=Path,default=CAMPAIGN)
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument('--output',type=Path)
    target.add_argument('--check',type=Path)
    args = parser.parse_args()
    if args.output:
        require(not args.output.resolve().is_relative_to(args.directory.resolve()),
                'Analysis output must be outside the saved attempt directory')
    output = artifacts(analyze(args.directory.resolve(),args.root.resolve()))
    if args.check:
        for name, content in output.items():
            require((args.check/name).read_text()==content, f'Final analysis differs: {name}')
    else:
        args.output.mkdir(parents=True,exist_ok=False)
        for name, content in output.items(): llm_runtime.write_new(args.output/name,content)
    print('Final analysis regenerated and verified' if args.check else 'Final analysis written')


if __name__ == '__main__': main()

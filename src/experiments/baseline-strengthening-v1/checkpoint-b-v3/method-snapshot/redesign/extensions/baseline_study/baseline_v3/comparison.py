"""Post-prediction v3/ablation comparison, with unchanged shared-family scoring."""
from collections import Counter
from copy import deepcopy
import csv
import io

from redesign.pipeline import evaluate as frozen
from redesign.pipeline.inventory import read_json,require
from .. import scoring,study
from . import campaign

METHODS=('v3','saved_baseline_v2','saved_llm','control_not_vulnerable','without_memory','without_output')
PAIRS=(('v3','saved_baseline_v2'),('saved_llm','v3'),('v3','control_not_vulnerable'),
       ('v3','without_memory'),('v3','without_output'))


def summary(rows,weights,truth):
    if not rows:return {'planned_cells':0}
    raw={m:frozen.statistics(frozen.outcomes(rows,m,truth),weights) for m in METHODS}
    return {'planned_cells':len(rows),'methods':{m:{k:scoring.value_summary(v) for k,v in raw[m].items()} for m in METHODS},
        'paired':{a+'_minus_'+b:{metric:scoring.value_summary(raw[a][metric]-raw[b][metric])
            for metric in ('correct_rate','coverage','recall','false_positive_rate')} for a,b in PAIRS}}


def generate(directory):
    verified=campaign.verify(directory)
    require(not any(verified['counts'].get(s,0) for s in ('pending','dispatched_unresolved'))
            and sum(verified['counts'].values())==160,'V3 slots incomplete')
    # This is the first private-truth join for the new run, after all predictions.
    historical=read_json(study.CAMPAIGN/'results/final/phase9-a/evaluation.json')
    policy=read_json(directory/'policy.json');rows=[];failures=[];events=Counter();reasons=Counter();ir_bindings={}
    for old in scoring.attach_controls(historical['rows']):
        identifier=old['observation_id'];job=directory/'jobs'/identifier
        result=read_json(job/'result.json')
        predicted=result['prediction'] if result['status']=='completed' else {'status':'unavailable','decision':None,'reason_codes':[result['error_code']]}
        ablations=read_json(job/'ablations.json') if result['status']=='completed' else {'without_memory':predicted,'without_output':predicted}
        bundle=read_json(directory/'inputs'/f'{identifier}.json')
        apis=sorted({c['target_name'] for c in bundle['calls'] if c['resolution']=='external'})
        rows.append({**old,'apis':apis,'predictions':{'v3':predicted,
            **{m:old['predictions'][m] for m in ('saved_baseline_v2','saved_llm','control_not_vulnerable')},
            **ablations}})
        if result['status']!='completed':failures.append({'observation_id':identifier,'status':result['status']})
        for event in predicted.get('contract_events',[]):events[(event['api'],event['outcome'])]+=1
        reasons.update(predicted['reason_codes']);ir_bindings[identifier]=result['ir_sha256']
    families,weights=scoring.family_weights(rows)
    report={'schema_version':1,'method_id':policy['method_id'],'post_hoc':True,'rows':rows,
        'bootstrap':{'families':families,'replicates':10000,'generator':'PCG64','seed':20261019,'unit':'family_id',
                     'shared_multiplicities':True,'interpretation':'exploratory'},
        'ablations':'Identical v3 IR/prototypes; evaluator-only disabled new effects. These are not the saved v2 representation.',
        'ir_sha256':ir_bindings,'worker_statuses':verified['counts'],'failures':failures,
        'reason_codes':dict(reasons),'contract_events':[{'api':api,'outcome':outcome,'events':n} for (api,outcome),n in sorted(events.items())]}
    for endpoint,truth in (('binary','binary_label'),('source_label_recovery','source_label')):
        report[endpoint]={'primary':summary(rows,weights,truth),'subgroups':{}}
        for field in ('cwe','optimization','symbols','family_id','binary_label','operation_status'):
            report[endpoint]['subgroups'][field]={}
            for value in sorted({r[field] for r in rows}):
                indices=[i for i,r in enumerate(rows) if r[field]==value]
                report[endpoint]['subgroups'][field][value]=summary([rows[i] for i in indices],weights[:,indices],truth)
        available=[i for i,r in enumerate(rows) if r['shared_availability']=='available']
        report[endpoint]['common_input']=summary([rows[i] for i in available],weights[:,available],truth)
    report['api_presence']={}
    for api in ('wmemset','wcslen','wcscpy','strcat','wprintf'):
        indices=[i for i,r in enumerate(rows) if api in r['apis']]
        report['api_presence'][api]=summary([rows[i] for i in indices],weights[:,indices],'binary_label')
    conflicting={identifier for group in historical['identical_input_groups'] if group['source_label_conflict'] or group['binary_label_conflict']
                 for identifier in group['observations']}
    indices=[i for i,r in enumerate(rows) if r['observation_id'] not in conflicting]
    report['collision_sensitivity']={'excluded_cells':len(conflicting),
        'binary':summary([rows[i] for i in indices],weights[:,indices],'binary_label'),
        'source':summary([rows[i] for i in indices],weights[:,indices],'source_label')}
    transitions=Counter();gains=[];new_errors=[];introduced=[]
    for r in rows:
        before=r['predictions']['saved_baseline_v2'];after=r['predictions']['v3'];truth=r['binary_label']
        transitions[(before['status'],after['status'])]+=1
        if after['status']=='classified' and before['status']!='classified':
            gains.append({'observation_id':r['observation_id'],'binary_label':truth,'decision':after['decision'],
                          'correct':after['decision']==truth})
        if after['status']=='classified' and after['decision']!=truth and before['decision']==truth:
            new_errors.append(r['observation_id'])
        if after['status']=='classified' and after['decision']!=truth and not (before['status']=='classified' and before['decision']!=truth):
            introduced.append(r['observation_id'])
    report['incremental']={'classification_transitions':[{'before':a,'after':b,'count':n} for (a,b),n in sorted(transitions.items())],
        'new_classifications':gains,'gained_safe_correct':sum(g['correct'] and g['binary_label']=='not_vulnerable' for g in gains),
        'gained_vulnerable_correct':sum(g['correct'] and g['binary_label'].startswith('vulnerable_') for g in gains),
        'new_errors_in_previously_correct_cells':new_errors,
        'new_exact_errors':introduced,
        'corrected_previous_errors':[r['observation_id'] for r in rows if r['predictions']['saved_baseline_v2']['status']=='classified'
             and r['predictions']['saved_baseline_v2']['decision']!=r['binary_label'] and r['predictions']['v3']['decision']==r['binary_label']]}
    for method,old in (('saved_baseline_v2','baseline'),('saved_llm','llm')):
        require(report['binary']['primary']['methods'][method]==historical['primary'][old],'Historical primary metrics/intervals differ')
    report['runtime_seconds']=sum(read_json(p)['wall_seconds'] for p in (directory/'jobs').glob('*/timing.json'))
    report['implementation_cost']={'production_python_lines':{p.name:len(p.read_text().splitlines())
        for p in campaign.HERE.glob('*.py') if p.name!='fixtures.py'},
        'fixture_python_lines':len((campaign.HERE/'fixtures.py').read_text().splitlines()),
        'new_library_contracts':5,'modified_historical_lines':0,'new_lifter_java_lines':0,
        'reused_interpreter_lines':531,'reused_stack_helper_lines':116}
    return report


def artifacts(report):
    stream=io.StringIO(newline='');fields=['endpoint','scope','group','method','metric','estimate','lower','upper','defined_replicates']
    writer=csv.DictWriter(stream,fieldnames=fields,lineterminator='\n');writer.writeheader()
    for endpoint in ('binary','source_label_recovery'):
        scopes=[('primary','all',report[endpoint]['primary']),('common_input','available',report[endpoint]['common_input'])]
        scopes += [(field,value,s) for field,groups in report[endpoint]['subgroups'].items() for value,s in groups.items()]
        for scope,group,s in scopes:
            for method,metrics in s.get('methods',{}).items():
                for metric,value in metrics.items():writer.writerow({'endpoint':endpoint,'scope':scope,'group':group,
                    'method':method,'metric':metric,'estimate':value['estimate'],**value['interval']})
            for method,metrics in s.get('paired',{}).items():
                for metric,value in metrics.items():writer.writerow({'endpoint':endpoint,'scope':scope,'group':group,
                    'method':method,'metric':'paired_'+metric,'estimate':value['estimate'],**value['interval']})
    lines=['# Checkpoint B: bounded five-contract v3 extension','',
        'Post-hoc study on the same inspected ten families. Original Phase 9 and Checkpoint A remain unchanged.','',
        '| Method | C | E | U | M | Correct / A | Coverage | Selective accuracy | Recall | FPR |',
        '|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|']
    for method in METHODS:
        values=report['binary']['primary']['methods'][method]
        cells=[str(int(values[k]['estimate'])) for k in ('C','E','U','M')]
        cells += ['NA' if values[k]['estimate'] is None else f"{100*values[k]['estimate']:.3f}%" for k in
                  ('correct_rate','coverage','selective_accuracy','recall','false_positive_rate')]
        lines.append('| '+method+' | '+' | '.join(cells)+' |')
    lines += ['',f"New classifications: {len(report['incremental']['new_classifications'])}; correct safe gains: {report['incremental']['gained_safe_correct']}; correct vulnerable gains: {report['incremental']['gained_vulnerable_correct']}.",
        '',f"Worker statuses: {report['worker_statuses']}. Recorded worker seconds including fresh lifting and both evaluator ablations: {report['runtime_seconds']:.2f}.",
        '', 'Ablations reuse exactly the same v3 IR/prototypes and abstain at disabled effects. They do not reconstruct the saved v2 lifter.',
        '', 'Full class/optimization/symbol/family/API and reason/event accounting, binary/source endpoints, collision sensitivity and paired family-cluster intervals are retained in comparison.json. Reason/API counts overlap.',
        '', 'No safe label is inferred from abstention. Heap requests and heuristic recovered stack extents remain distinct. Ten-family intervals are exploratory; no outcome threshold on this already inspected corpus is confirmatory.',
        '', 'Scope remains five standard-library effects: no loop solver, new stack bounds, custom instruction decoder, testcase summaries, modified research sources or new LLM inference.', '']
    from redesign.pipeline.bundles import canonical
    return {'comparison.json':canonical(report),'comparison.csv':stream.getvalue(),'report.md':'\n'.join(lines)}

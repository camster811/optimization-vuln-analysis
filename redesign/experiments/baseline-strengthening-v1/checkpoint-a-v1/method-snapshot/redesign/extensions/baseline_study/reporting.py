"""Checkpoint A tables and explicitly supplementary interpretation."""
import csv
import io

from . import scoring

NAMES = {'control_not_vulnerable': 'Constant no overflow', 'saved_llm': 'Saved LLM aggregate',
         'saved_baseline_v2': 'Saved v2 baseline', 'control_cwe121': 'Constant CWE-121',
         'control_cwe122': 'Constant CWE-122', 'control_uncertain': 'Always uncertain'}


def percent(value):
    return 'NA' if value is None else f'{100*value:.3f}%'


def interval(value):
    return '['+percent(value['interval']['lower'])+', '+percent(value['interval']['upper'])+']'


def points(value):
    return 'NA' if value is None else f'{100*value:.3f} percentage points'


def point_interval(value):
    bounds=value['interval']
    if bounds['lower'] is None: return 'NA'
    return f'[{100*bounds["lower"]:.3f}, {100*bounds["upper"]:.3f}] percentage points'


def counts_table(summary):
    lines = ['| Method | C | E | U | M | Correct / A | Coverage | Selective accuracy |',
             '|---|---:|---:|---:|---:|---:|---:|---:|']
    for method in scoring.METHODS:
        values = summary['methods'][method]
        cells = [str(int(values[k]['estimate'])) for k in ('C','E','U','M')]
        cells += [percent(values[k]['estimate']) for k in ('correct_rate','coverage','selective_accuracy')]
        lines.append('| '+NAMES[method]+' | '+' | '.join(cells)+' |')
    return '\n'.join(lines)


def csv_report(report):
    fields = ['endpoint','scope','group','method_id','metric','estimate','lower','upper','defined_replicates']
    stream = io.StringIO(newline='')
    writer = csv.DictWriter(stream, fieldnames=fields, lineterminator='\n'); writer.writeheader()
    for endpoint in ('binary','source_label_recovery'):
        data = report[endpoint]
        groups = [('primary','all',data['primary']), ('common_input','available',data['common_input'])]
        groups += [(field, group, value) for field, values in data['subgroups'].items() for group, value in values.items()]
        for scope, group, summary in groups:
            if summary['planned_cells'] == 0: continue
            for method, values in summary['methods'].items():
                for metric, value in values.items():
                    writer.writerow({'endpoint':endpoint,'scope':scope,'group':group,'method_id':method,
                                     'metric':metric,'estimate':value['estimate'],**value['interval']})
            for method, contrast in summary['paired_llm_minus_comparator'].items():
                value = contrast['correct_rate_difference']
                writer.writerow({'endpoint':endpoint,'scope':scope,'group':group,
                                 'method_id':scoring.SAVED_LLM+' minus '+method,
                                 'metric':'paired_correct_rate_difference','estimate':value['estimate'],**value['interval']})
    return stream.getvalue()


def claims(report):
    contrast = report['binary']['primary']['paired_llm_minus_comparator']['control_not_vulnerable']['correct_rate_difference']
    return f'''# Claims and proposed manuscript wording: checkpoint A

This is a post-hoc supplement after inspection of the completed Phase 9 results. The original results and reports remain historical evidence. No new LLM requests or lifting were performed. These fixed-label controls are uninformative descriptive controls, not trained models, oracle-selected majority-class predictors, or sound analyzers.

## Supported interpretation

On these ten Juliet-derived source families, this configured LLM recognized more adjudicated emitted behaviors than this bounded custom heuristic. Its 125 correct, 28 incorrect, seven abstained and zero unavailable outcomes compare with the original v2 baseline's 18 correct, zero incorrect, 142 abstained and zero unavailable outcomes. Baseline abstention is neither an incorrect explicit class label nor a conclusion of safety. Its 100% selective accuracy concerns only 18 safe classifications and does not establish vulnerability-detection ability.

The constant no-overflow control is correct on 100/160 cells (62.5%) while detecting none of the 60 vulnerable binaries. Safe-only correctness can therefore be high under the observed class imbalance. The LLM's 125/160 (78.125%) exceeds this control by {points(contrast['estimate'])}, with exploratory family-cluster interval {point_interval(contrast)}. All four constants are declared and published; none was selected by fitting the final truth labels.

## Proposed manuscript paragraph

“On 160 matched binary observations from ten Juliet-derived families, the configured local LLM achieved 78.125% exact-label correctness, compared with 11.25% for our bounded custom heuristic and 62.5% for an always-no-overflow control. The LLM-minus-no-overflow difference was 15.625 percentage points; the exploratory shared family-cluster percentile interval was {point_interval(contrast)}. The heuristic abstained on 142 observations, and its 18 classifications were all safe eliminated-operation cells. The LLM detected 39/60 vulnerable binaries at the alert level and produced seven alerts on 100 safe binaries; two detected vulnerabilities received the wrong CWE. These results describe the tested tool configurations and sampled benchmark, and do not establish superiority over static analysis generally.”

## Claims to avoid and remaining limits

Do not claim a sound safety detector, general superiority over static analysis, or generalization to arbitrary production binaries. The constants do not inspect code and cannot establish safe behavior; the no-overflow control and always-uncertain control both have zero vulnerability recall. Wrong-CWE predictions remain exact-label errors even when they are correct alerts. No-alert outcomes caused by explicit safe decisions, abstentions and unavailable predictions remain distinct in the metric tables.

Ten related source families, template similarity and input collisions, private-assisted entry localization, and Codex oracle review without an independent human adjudicator limit interpretation. Public Juliet may have appeared in pretraining. Family-cluster intervals are exploratory; cells and the three LLM repetitions are not independent source samples. The context amendment and this control study occurred after earlier evidence inspection and are reported as separate configurations/supplements.

Treatment-specific results and LLM-minus-control intervals are descriptive. Optimization changes binary class balance and operation survival as well as predictions. The supplementary results do not identify a particular GCC pass's causal effect. Source-label recovery is a separate endpoint and must not replace binary-vulnerability accuracy.

Checkpoint A does not implement or evaluate the proposed v3 library contracts. Track B, if undertaken, remains a separately versioned post-hoc extension requiring its own specification, fixtures and freeze.
'''


def report_text(report):
    primary = report['binary']['primary']
    contrast = primary['paired_llm_minus_comparator']['control_not_vulnerable']['correct_rate_difference']
    lines = ['# Baseline strengthening, checkpoint A', '',
        '**The constant no-overflow control scores 100/160 (62.5%) while detecting zero vulnerable binaries.**', '',
        'This post-hoc supplement preserves the original Phase 9 results. The controls are four declared constant labels, with the same shared eligibility and no code inspection, instruction evidence, confidence or voting records. The no-overflow control leads the report without selecting a favorable constant from the final labels.', '',
        'All 160 cells have adjudicated binary truth. C/E/U/M are correct/incorrect/abstained/unavailable; every metric keeps the frozen denominators and NA rules.', '',
        counts_table(primary), '',
        f'The saved LLM exceeds no-overflow by {points(contrast["estimate"])}; the exploratory shared-family interval is {point_interval(contrast)}. Intervals use 10,000 PCG64 family draws with seed 20261019 and shared multiplicities across all six methods, subgroups and both truth endpoints. Treatment cells and LLM repetitions are not independently resampled.', '',
        '## Alert tradeoffs', '',
        '| Method | TP | TN | FP | FN | Recall | FPR | Precision | F1 | Balanced accuracy |',
        '|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|']
    for method in scoring.METHODS:
        values = primary['methods'][method]
        cells = [str(int(values[k]['estimate'])) for k in ('TP','TN','FP','FN')]
        cells += [percent(values[k]['estimate']) for k in ('recall','false_positive_rate','precision','f1','balanced_accuracy')]
        lines.append('| '+NAMES[method]+' | '+' | '.join(cells)+' |')
    lines += ['', 'No alert from abstention or unavailability is not a safety classification. Wrong-CWE alerts can be true positives while remaining exact-label errors. Zero-denominator precision and selective accuracy are NA.', '',
              '## Descriptive treatment patterns', '',
              '| Treatment | LLM correct / A | No-overflow correct / A | Original baseline correct / A | LLM minus no-overflow (points) | Family interval |',
              '|---|---:|---:|---:|---:|---|']
    for field in ('optimization','symbols','cwe'):
        for group, summary in report['binary']['subgroups'][field].items():
            values = [percent(summary['methods'][m]['correct_rate']['estimate']) for m in
                      (scoring.SAVED_LLM,'control_not_vulnerable',scoring.SAVED_BASELINE)]
            difference = summary['paired_llm_minus_comparator']['control_not_vulnerable']['correct_rate_difference']
            lines.append('| '+group+' | '+' | '.join(values)+' | '+points(difference['estimate'])+' | '+point_interval(difference)+' |')
    lines += ['', '## Source-label recovery (separate endpoint)', '', counts_table(report['source_label_recovery']['primary']), '',
        'Binary truth is 100 safe / 28 CWE-121 / 32 CWE-122, whereas source provenance is 80 safe / 40 CWE-121 / 40 CWE-122. Recovery of source labels is not binary-vulnerability accuracy.', '',
        'The common-input subset equals the primary matrix in this campaign. `comparison.json` and `comparison.csv` include all estimates, intervals, defined-replicate counts, integer counts, no-alert reasons, binary/source endpoints, common-input results and actual-binary-class, source-CWE, optimization, symbol and family breakdowns. Method IDs are explicit; historical estimates and intervals reproduce before controls are accepted. `claims.md` supplies the narrowed interpretation and proposed manuscript wording.', '',
        'Reproduce with the separately versioned baseline-study CLI. The manifest binds source/test/plan snapshots, original input/result hashes and all supplementary files. No historical artifacts are changed, and no new LLM request or lifting occurs.', '']
    return '\n'.join(lines)

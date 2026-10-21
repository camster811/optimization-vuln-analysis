"""Source-only final selection/import in an isolated campaign; no predictors."""
import argparse
import csv
import difflib
from pathlib import Path
import re
import shutil
import zipfile

from . import method_lock
from .import_juliet import SUPPORT, INCLUDES, DIAGNOSTICS, store, sha, verify_archive
from .inventory import ROOT, digest, encode, read_json, require, validate_manifest, generate
from .sanitize import sanitize, tokens, verify_preservation, scan_metadata
from .llm_runtime import write_new

CAMPAIGN = ROOT/'campaigns/final-v1'
# Source-reviewed choices in required inter/intra/inter/intra/inter slot order.
CHOICES = {'CWE-121': [(4,'21','goodG2B1'),(5,'01','goodG2B'),(6,'21','goodG2B1'),(7,'01','goodG2B'),(8,'21','goodB2G1')],
           'CWE-122': [(3,'21','goodG2B1'),(4,'01','goodG2B'),(12,'21','goodG2B1'),(13,'01','goodG2B'),(21,'21','goodG2B1')]}
REJECTIONS = {('CWE-122',1):'Overflowing destination is stack storage, not a heap object.',
              ('CWE-122',8):'Requires an unspecified external socket peer/input environment.',
              ('CWE-122',10):'Heap source feeds an overflowing stack destination; wrong destination storage.',
              ('CWE-122',11):'Requires unspecified interactive standard input.',
              ('CWE-122',19):'Heap source feeds an overflowing stack destination; wrong destination storage.',
              ('CWE-122',20):'Requires unspecified interactive standard input.'}


def family(path): return re.sub(r'_\d\d[a-z]?$', '', Path(path).stem)


def select(exposure):
    candidates=list(csv.DictReader((ROOT.parent/'documentation/juliet-redesign/candidate_families.csv').open()))
    used={family(r['original_path']) for r in exposure if r['sanitization_status']!='not_attempted'}
    used.update(p['family_id'] for p in read_json(ROOT/'corpus/manifest.json')['pairs'] if p['status']=='assigned')
    decisions=[]; selected=[]
    for cwe,choices in CHOICES.items():
        for position,(rank,flow,safe) in enumerate(choices):
            structure='interprocedural' if position%2==0 else 'intraprocedural'
            for row in (r for r in candidates if r['cwe']==cwe and int(r['rank'])<=rank):
                key=(cwe,int(row['rank'])); name=row['family_id']
                if name in used:
                    decisions.append({'slot':position+1,**row,'decision':'development_or_already_selected','reason':'Earlier source adaptation, pilot exposure, or an earlier final slot.'});continue
                if key in REJECTIONS:
                    decisions.append({'slot':position+1,**row,'decision':'source_ineligible','reason':REJECTIONS[key]});continue
                require(int(row['rank'])==rank, 'Earlier eligible family was skipped')
                require(flow in row['flow_ids'].split(';'), 'Chosen flow absent')
                selected.append({**row,'flow':flow,'safe_entry':safe,'structure':structure,'slot':position+1})
                decisions.append({'slot':position+1,**row,'decision':'selected','flow':flow,'safe_entry':safe,
                    'reason':'Original deterministic Linux C path with relevant buffer/extent/index crossing a direct helper.' if flow=='21' else 'Original deterministic Linux C path with buffer reasoning in one function.'})
                used.add(name)
    return {'schema_version':1,'reviewer':'Codex source review; no independent human reviewer',
            'selection_seed':20261019,'selection_basis':'Locked ranked source-only review; no final predictor runs',
            'exposure_rule':'All earlier candidates with attempted sanitization are development-only, even when inference use is uncertain.',
            'earlier_flows':'01–18 keep relevant buffer reasoning within one function; 21 is the first direct pointer/index source/sink flow for selected interprocedural families.',
            'assumptions':'One invocation, no external input, LP64 x86-64 Linux (wchar_t=4, int64_t=8, pointer=8), ordinary libc semantics, allocation failure exits.',
            'platform_note':'sizeof_int64_t is retained under its original Juliet source label; sizeof(pointer)==sizeof(int64_t) on the fixed platform may make both binaries safe. No replacement is allowed.',
            'decisions':decisions,'selected':selected,
            'reserve': [r for r in candidates if r['family_id'] not in used]}


def mapping(source,stem,safe):
    identifiers={v for k,v in tokens(source) if k=='identifier'}
    result={'OMITBAD':'EXCLUDE_BRANCH_ALPHA','OMITGOOD':'EXCLUDE_BRANCH_BETA','INCLUDEMAIN':'BUILD_STANDALONE',
            '_STD_TESTCASE_H':'RUNTIME_SUPPORT_H','_STD_TESTCASE_IO_H':'OUTPUT_SUPPORT_H',
            stem+'_bad':'process_case',safe:'process_case',stem+'_good':'run_paths'}
    names=sorted(n for n in identifiers if n not in result and (re.search(r'good|bad',n,re.I) or n.startswith('CWE')))
    result.update({n:f'flow_component_{i:02d}' for i,n in enumerate(names)})
    return result


def prepare(archive,extracted,exposure_path,root=CAMPAIGN):
    method_lock.verify();require(not root.exists(),'Final workspace already exists')
    provenance=verify_archive(archive,extracted)
    exposure=read_json(exposure_path);selection=select(exposure)
    root.mkdir(parents=True)
    for name in ('pipeline','ghidra','schemas','llm','corpus'):
        shutil.copytree(ROOT/name,root/name,ignore=shutil.ignore_patterns('__pycache__'))
    for name in ('config.json','context_policy.json','baseline_policy.json','llm_policy.json'):
        shutil.copyfile(ROOT/name,root/name)
    write_new(root/'corpus/final_selection.json',selection)
    write_new(root/'corpus/private/prior-adaptation-ledger.json',exposure)
    manifest=read_json(root/'corpus/manifest.json')
    slots={cwe:sorted([p for p in manifest['pairs'] if p['split']=='final' and p['cwe']==cwe],key=lambda p:p['pair_id']) for cwe in CHOICES}
    with zipfile.ZipFile(archive) as zipped:
        for choice in selection['selected']:
            # Pair IDs encode the pre-existing declared structural sequence.
            candidates=[p for p in slots[choice['cwe']] if p['status']=='unassigned' and p['structure']==choice['structure']]
            pair=candidates[0];identifier=pair['pair_id'];stem=choice['family_id']+'_'+choice['flow']
            names=[n for n in zipped.namelist() if n.startswith('C/testcases/') and n.endswith('/'+stem+'.c')]
            require(len(names)==1,'Source file ambiguous');original_name=names[0][2:]
            original=zipped.read(names[0]).decode();maps=mapping(original,stem,choice['safe_entry'])
            # Keep the established shared support map byte-identical to the pilot.
            support_mapping=read_json(ROOT/'corpus/private/pilot-01/sanitization.json')['identifiers']
            transforms=[];diff=[];unit=f'corpus/pairs/{identifier}/unit.c'
            for source,target in {original_name:unit,**SUPPORT}.items():
                before=zipped.read('C/'+source).decode();active=maps if source==original_name else support_mapping
                after,changes=sanitize(before,active,INCLUDES,DIAGNOSTICS);scan_metadata(after)
                store(root/'corpus/upstream'/source,zipped.read('C/'+source),readonly=True);store(root/target,after)
                transforms.append({'original':'corpus/upstream/'+source,'sanitized':target,'original_sha256':sha(before.encode()),
                    'sanitized_sha256':sha(after.encode()),'identifiers':active,'changes':changes,
                    'executable_tokens_checked':verify_preservation(before,after,active,INCLUDES,DIAGNOSTICS)})
                diff.extend(difflib.unified_diff(before.splitlines(True),after.splitlines(True),fromfile=source,tofile=target))
            driver=f'corpus/pairs/{identifier}/driver.c';store(root/driver,'#include "unit.c"\nint main(void) { process_case(); return 0; }\n')
            transform=f'corpus/private/{identifier}/sanitization.json';diff_path=f'corpus/private/{identifier}/sanitization.diff'
            store(root/diff_path,''.join(diff));store(root/transform,encode({'schema_version':1,'files':transforms,'includes':INCLUDES,'diagnostics':DIAGNOSTICS,
                'diff_path':diff_path,'diff_sha256':digest(root/diff_path),'harness':driver,'harness_sha256':digest(root/driver),
                'original_entries':{'vulnerable':stem+'_bad','safe':choice['safe_entry']}}))
            sources=[unit,driver];support=['corpus/support/output.c'];headers=['corpus/support/runtime.h','corpus/support/output.h']
            pair.update(status='assigned',family_id=choice['family_id'],upstream_case_id=stem,sources=sources,support_sources=support,
                headers=headers,translation_units=[driver],include_dirs=['corpus/support'],entries={'vulnerable':'process_case','safe':'process_case'},
                variant_selection={v:{'defines':[macro],'driver_sources':[driver]} for v,macro in [('vulnerable','EXCLUDE_BRANCH_BETA'),('safe','EXCLUDE_BRANCH_ALPHA')]},
                sanitization_manifest=transform,selection_record='corpus/final_selection.json',
                file_sha256={n:digest(root/n) for n in sources+support+headers+[transform,'corpus/final_selection.json']})
    validate_manifest(read_json(root/'config.json'),manifest,root,'final')
    (root/'corpus/manifest.json').write_text(encode(manifest))
    write_new(root/'provenance/final-import.json',{**provenance,'prior_adaptation_ledger_sha256':digest(exposure_path),
        'method_lock_sha256':digest(method_lock.LOCK),'selected_pairs':10,'final_predictor_runs':0})
    return generate(read_json(root/'config.json'),manifest,root,'final',True)['counts']


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--archive',type=Path,required=True);p.add_argument('--extracted-root',type=Path,required=True)
    p.add_argument('--prior-ledger',type=Path,required=True);a=p.parse_args();print(prepare(a.archive,a.extracted_root,a.prior_ledger))

if __name__=='__main__':main()

"""Durable v3 results, ablations, fixture evidence and replayable post-hoc release."""
import argparse
from datetime import datetime,timezone
import gzip
import io
from pathlib import Path
import shutil
import tarfile

from redesign.pipeline import method_lock
from redesign.pipeline.bundles import canonical
from redesign.pipeline.final_freeze import verify_archive
from redesign.pipeline.inventory import ROOT,read_json,digest,require
from redesign.pipeline.llm_runtime import write_new
from .. import study
from . import campaign,comparison

PUBLICATION=study.EXPERIMENT/'checkpoint-b-v3'


def decision(report,directory):
    values=report['binary']['primary']['methods']['v3']
    incremental=report['incremental'];fixture=read_json(directory/'fixture-report.json')
    stack=[r for r in fixture['observations'] if r['case']=='stack_overflow']
    wrong=[r for r in fixture['observations'] if r['prediction']['status']=='classified'
           and r['declared_binary_label']!='unresolved' and r['prediction']['decision']!=r['declared_binary_label']]
    lines=['# Complexity, support and benefit decision','',
        'This is a post-hoc engineering decision on already inspected families, not a confirmatory outcome threshold.', '',
        f"V3 has {int(values['C']['estimate'])} correct, {int(values['E']['estimate'])} incorrect, {int(values['U']['estimate'])} abstained and {int(values['M']['estimate'])} unavailable cells. Correct new safe classifications: {incremental['gained_safe_correct']}; correct new vulnerability classifications: {incremental['gained_vulnerable_correct']}; new exact errors relative to v2: {len(incremental['new_exact_errors'])}.", '',
        'Decision: stop expansion at the five declared effects and preserve this version as an additional post-hoc comparator, with the supported heap behavior and measured errors documented. Do not replace the original v2 comparison. Further solver, loop, native-write or stack-inference work would be a new method and requires additional held-out validation.', '',
        'A gain confined to safe classifications is weak evidence of a stronger vulnerability detector. Gained vulnerability detections and false-positive changes must be read with the complete denominators, not coverage alone.', '',
        f"Independent compiled matrix: {len(fixture['observations'])} observations across O0–O3, retained/stripped and ordinary/contract-forcing modes. Classified fixture errors: {len(wrong)}. Stack observations: {len(stack)}; their recovered extents and outcomes remain in the fixture report rather than being forced to match source sizes.", '',
        'The engine inherits the existing 531-line v2 interpreter and 116-line stack helper. The new effects do not add a decoder, loop solver, alias engine or new stack-bound guesses. Existing Ghidra lifting/IR validation is reused unchanged, with only policy-supplied external prototypes differing. Maintenance includes five contracts, explicit units/ABI checks, worker/schema projection, fixture matrix, no-retry execution and reproducibility checks.', '',
        f"Added production Python lines by file (including orchestration/reporting): {report['implementation_cost']['production_python_lines']}. Fixture Python lines: {report['implementation_cost']['fixture_python_lines']}. Modified historical/lifter-Java lines: zero.", '',
        'Known limits include inherited O0 parameter-spill/stack recovery, enlarged inferred arrays, unaccounted native writes, cyclic flow, unsupported or unrecovered output arguments, unknown terminators and incomplete public memory windows. Reason/API/event counts overlap and do not promise coverage.', '',
        'Development extraction probes exposed truncated unknown-data windows at the ELF section end. Independent literal padding was added before the accepted fixture run; the initial failed smoke attempts remain under build/extensions. Neither research inputs nor extraction budgets changed. O0 abstention was retained rather than repaired with new stack assumptions.', '',
        'Same-IR ablations isolate the new memory/string effects and wide-output effects under the v3 prototypes. They are not equivalent to the saved v2 representation. No LLM requests or new source selections were made.', '']
    return '\n'.join(lines)


def analyze(directory):
    require(not (directory/'analysis').exists(),'V3 analysis exists; verify rather than overwrite')
    report=comparison.generate(directory)
    target=directory/'analysis';target.mkdir()
    for name,value in comparison.artifacts(report).items():write_new(target/name,value)
    write_new(target/'decision.md',decision(report,directory))
    # Label join/saved outputs are introduced only in the evaluator directory.
    write_new(target/'historical-evaluation.json',(study.CAMPAIGN/'results/final/phase9-a/evaluation.json').read_text())
    return verify_analysis(directory)


def verify_analysis(directory):
    report=comparison.generate(directory)
    for name,value in comparison.artifacts(report).items():
        require((directory/'analysis'/name).read_bytes()==value.encode('utf-8'),'V3 comparison does not regenerate: '+name)
    require((directory/'analysis/decision.md').read_bytes()==decision(report,directory).encode('utf-8'),
            'V3 decision does not regenerate')
    require(digest(directory/'analysis/historical-evaluation.json')==
            digest(study.CAMPAIGN/'results/final/phase9-a/evaluation.json'),'Historical comparison snapshot differs')
    return {'status':'verified','counts':{m:{k:report['binary']['primary']['methods'][m][k]['estimate']
                                         for k in ('C','E','U','M')} for m in comparison.METHODS}}


def inventory(directory):
    return {p.relative_to(directory).as_posix():digest(p) for p in sorted(directory.rglob('*'))
            if p.is_file() and p.relative_to(directory).as_posix() not in ('release.json','checkpoint-b.tar.gz')
            and not any(part in ('cache','profile','settings','tmp') for part in p.relative_to(directory).parts)
            and p.name!='runner.lock'}


def publish(directory):
    verify_analysis(directory)
    study.verify_originals();study.verify(study.EXPERIMENT/'checkpoint-a-v1',check_originals=False)
    require(not PUBLICATION.exists(),'V3 publication exists; preserve it')
    PUBLICATION.mkdir(parents=True)
    for name in inventory(directory):
        target=PUBLICATION/name;target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(directory/name,target)
    frozen=read_json(directory/'freeze.json')
    for name in frozen['fixture_files']:
        target=PUBLICATION/'fixture-evidence'/name;target.parent.mkdir(parents=True,exist_ok=True)
        shutil.copyfile(Path(frozen['fixture_directory'])/name,target)
    files=inventory(PUBLICATION)
    archive_path=PUBLICATION/'checkpoint-b.tar.gz'
    with archive_path.open('xb') as stream:
        with gzip.GzipFile(filename='',fileobj=stream,mode='wb',mtime=0) as compressed:
            with tarfile.open(fileobj=compressed,mode='w') as archive:
                for name in files:
                    content=(PUBLICATION/name).read_bytes();item=tarfile.TarInfo(name);item.size=len(content);item.mode=0o444
                    archive.addfile(item,io.BytesIO(content))
    manifest={'schema_version':1,'status':'checkpoint_B_complete','method_id':frozen['method_id'],
        'created_at_utc':datetime.now(timezone.utc).isoformat(),'post_hoc':True,'files':files,
        'archive':'checkpoint-b.tar.gz','archive_sha256':digest(archive_path),'freeze_sha256':digest(PUBLICATION/'freeze.json'),
        'private_evaluation_inputs':True,'new_llm_requests':0,
        'dependencies':'Original campaign releases and repository methods; pinned compiler/Ghidra identities. No live model server.'}
    write_new(PUBLICATION/'release.json',manifest)
    result=verify(PUBLICATION)
    for path in PUBLICATION.rglob('*'):
        if path.is_file():path.chmod(path.stat().st_mode & ~0o222)
    return result


def verify(directory):
    manifest=read_json(directory/'release.json')
    require(manifest['status']=='checkpoint_B_complete' and manifest['freeze_sha256']==digest(directory/'freeze.json'),
            'V3 release identity differs')
    require(inventory(directory)==manifest['files'],'V3 publication file membership/content differs')
    require(digest(directory/manifest['archive'])==manifest['archive_sha256'],'V3 archive changed')
    verify_archive(directory/manifest['archive'],manifest['files'])
    verified=verify_analysis(directory)
    study.verify_originals();study.verify(study.EXPERIMENT/'checkpoint-a-v1',check_originals=False)
    return {'status':'verified','archive_sha256':manifest['archive_sha256'],'files':len(manifest['files']),**verified}


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('action',choices=('analyze','check','publish','verify'))
    parser.add_argument('--directory',type=Path);args=parser.parse_args()
    directory=args.directory.resolve() if args.directory else PUBLICATION if args.action=='verify' else campaign.RUN
    result={'analyze':analyze,'check':verify_analysis,'publish':publish,'verify':verify}[args.action](directory)
    print(canonical(result))


if __name__=='__main__':main()

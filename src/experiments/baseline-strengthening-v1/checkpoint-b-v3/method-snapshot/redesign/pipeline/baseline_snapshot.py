"""Capture/replay public-input P-code artifacts without Ghidra or materialized build directories."""
import argparse
import gzip
import hashlib
import io
import re
import tarfile

from .baseline import METHODS, directory, verify
from .baseline_worker import validate_result
from .bounds import analyze
from .inventory import ROOT, digest, encode, local_path, read_json, require, strict_json


def capture(run_id):
    report=verify(run_id)
    out=ROOT/'provenance/phase5-pcode.tar.gz'
    index_path=ROOT/'provenance/phase5-pcode.json'
    require(not out.exists() and not index_path.exists(),'Baseline replay snapshot already exists')
    files={}
    # Reuse the predecessor snapshot's deterministic gzip/tar recipe (provenance.capture).
    with out.open('xb') as raw:
        with gzip.GzipFile(filename='',mode='wb',fileobj=raw,mtime=0) as compressed:
            with tarfile.open(fileobj=compressed,mode='w') as archive:
                for row in report['observations']:
                    if row['status']!='completed':continue
                    name=row['observation_id']+'.json'
                    content=(directory('baseline-lifts',report['lift_run'])/row['observation_id']/'ir/pcode.json').read_bytes()
                    require(hashlib.sha256(content).hexdigest()==row['ir_sha256'],'P-code snapshot identity differs')
                    member=tarfile.TarInfo(name);member.size=len(content);member.mode=0o644
                    archive.addfile(member,io.BytesIO(content));files[name]=row['ir_sha256']
    predictions=ROOT/'results/pilot/baseline'/f'{run_id}.json'
    index={'schema_version':1,'run_id':run_id,'archive_sha256':digest(out),'files':files,
           'prediction_path':predictions.relative_to(ROOT).as_posix(),'predictions_sha256':digest(predictions),
           'methods':report['methods'],'snapshot_method_sha256':digest(ROOT/'pipeline/baseline_snapshot.py'),
           'policy_sha256':report['policy_sha256'],'record_hashes':report['record_hashes']}
    index_path.write_text(encode(index))
    return replay()


def replay():
    index=read_json(ROOT/'provenance/phase5-pcode.json')
    require(index['schema_version']==1,'Unknown baseline replay snapshot')
    require(index['methods']=={name:digest(ROOT/name) for name in METHODS},'Baseline replay methods changed')
    require(index['snapshot_method_sha256']==digest(ROOT/'pipeline/baseline_snapshot.py'),'Replay implementation changed')
    require(index['policy_sha256']==digest(ROOT/'baseline_policy.json'),'Replay policy changed')
    path=ROOT/'provenance/phase5-pcode.tar.gz'
    require(digest(path)==index['archive_sha256'],'P-code replay archive changed')
    predictions_path=local_path(ROOT,index['prediction_path'])
    require(digest(predictions_path)==index['predictions_sha256'],'Published baseline predictions changed')
    predictions=read_json(predictions_path)
    require(len({p['observation_id'] for p in predictions})==len(predictions),'Duplicate replay predictions')
    records={name.rsplit('/',1)[1][:-5]:local_path(ROOT,name) for name in index['record_hashes']}
    require({p['observation_id'] for p in predictions}==set(records),'Replay observation inventory differs')
    for name,expected in index['record_hashes'].items():
        require(digest(local_path(ROOT,name))==expected,'Public replay input changed')
    with tarfile.open(path) as archive:
        members=archive.getmembers()
        require(len(members)==len(index['files']) and {m.name for m in members}==set(index['files'])
                and all(m.isfile() and re.fullmatch(r'r[0-9a-f]+\.json',m.name) for m in members),'Replay archive inventory differs')
        irs={}
        for member in members:
            raw=archive.extractfile(member).read()
            require(hashlib.sha256(raw).hexdigest()==index['files'][member.name],'Replay P-code member changed')
            irs[member.name[:-5]]=strict_json(raw.decode())
    count=0
    for prediction in predictions:
        bundle=read_json(records[prediction['observation_id']])
        result={k:v for k,v in prediction.items() if k!='observation_id'}
        validate_result(result,bundle)
        if result['status']=='completed':
            require(result['ir_sha256']==index['files'][prediction['observation_id']+'.json'],'Replay IR binding differs')
            regenerated=analyze(bundle,irs[prediction['observation_id']],read_json(ROOT/'baseline_policy.json'))
            require(regenerated==result['prediction'],'Baseline prediction does not replay')
            count+=1
    require(set(irs)=={p['observation_id'] for p in predictions if p['status']=='completed'},'Replay includes omitted or extra IR')
    return {'status':'verified','planned_observations':len(predictions),'replayed_predictions':count}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action',choices=('capture','verify'))
    parser.add_argument('--run-id')
    args=parser.parse_args()
    if args.action=='capture':require(args.run_id,'Specify --run-id')
    print(encode(capture(args.run_id) if args.action=='capture' else replay()),end='')


if __name__=='__main__':main()

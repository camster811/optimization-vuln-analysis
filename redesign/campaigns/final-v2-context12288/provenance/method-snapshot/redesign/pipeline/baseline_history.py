"""Replay the preserved v1 baseline in an isolated package with public inputs only."""
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

from .inventory import ROOT, digest, encode, local_path, read_json, require, strict_json


def replay_v1():
    archive=ROOT/'provenance/baseline-v1-method'
    manifest=read_json(archive/'manifest.json')
    for name,expected in manifest['files'].items():
        require(digest(local_path(archive,name))==expected,'Preserved v1 method changed')
    index=read_json(archive/'phase5-pcode.json')
    require(index['run_id']==manifest['accepted_run']=='phase5-d','Preserved v1 run differs')
    with tempfile.TemporaryDirectory(prefix='juliet-baseline-v1-') as temporary:
        package=Path(temporary)/'baseline_v1';package.mkdir()
        def copy(source,name):
            target=local_path(package,name);target.parent.mkdir(parents=True,exist_ok=True)
            shutil.copyfile(source,target)
        for name in manifest['files']:copy(local_path(archive,name),name)
        copy(archive/'phase5-pcode.json','provenance/phase5-pcode.json')
        copy(archive/'phase5-pcode.tar.gz','provenance/phase5-pcode.tar.gz')
        for name,expected in index['record_hashes'].items():
            source=local_path(ROOT,name)
            require(digest(source)==expected,'Preserved v1 public input changed')
            copy(source,name)
        copy(local_path(ROOT,index['prediction_path']),index['prediction_path'])
        environment={k:v for k,v in os.environ.items() if k not in ('GHIDRA_HOME','PYTHONPATH')}
        process=subprocess.run([sys.executable,'-m','baseline_v1.pipeline.baseline_snapshot','verify'],
                               cwd=temporary,env=environment,capture_output=True,text=True,timeout=60)
        require(process.returncode==0,'Preserved v1 replay failed: '+process.stderr)
        return strict_json(process.stdout)


if __name__=='__main__':print(encode(replay_v1()),end='')

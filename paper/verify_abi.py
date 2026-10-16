"""Isolated ABI diagnosis; never replaces frozen records or launches inference."""
import csv
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
HOME = Path('/home/camst/repos/ghidra_12.1.4_PUBLIC')


def main():
    with (ROOT/'data/private/observations.csv').open() as stream:
        truth = {r['observation_id']: r for r in csv.DictReader(stream)}
    examples = {}
    for identifier in ('r0003', 'r0059', 'r0063'):
        row = truth[identifier]
        original = json.loads((ROOT/row['record_path']).read_text())
        with tempfile.TemporaryDirectory(prefix='review-abi-') as directory:
            work = Path(directory)
            (work/'profile').mkdir()
            shutil.copyfile(ROOT/row['analysis_binary'], work/'program')
            environment = dict(os.environ)
            environment['JAVA_TOOL_OPTIONS'] = ' '.join(f'-D{k}={work/v}' for k,v in {
                'user.home':'profile', 'application.settingsdir':'settings',
                'application.cachedir':'cache','application.tempdir':'tmp'}.items())
            command = [str(HOME/'support/analyzeHeadless'), str(work), 'project',
                '-import', str(work/'program'), '-processor','x86:LE:64:default', '-cspec','gcc',
                '-max-cpu','2','-analysisTimeoutPerFile','300',
                '-scriptPath', str(ROOT/'ghidra'), '-postScript','ExtractFunction.java',
                row['target_start'],str(work/'record.json'),'60','-deleteProject']
            completed = subprocess.run(command, env=environment, text=True,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=480)
            if completed.returncode:
                raise RuntimeError(completed.stdout)
            current = json.loads((work/'record.json').read_text())
            assert current['decompilation']['status'] == 'ok'
            assert current['instructions'] == original['instructions']
            assert current['calls'] == original['calls']
            examples[identifier] = dict(pair=row['pair_id'],variant=row['variant'],optimization=row['optimization'],
                loader=[line for line in completed.stdout.splitlines() if 'Using Language/Compiler:' in line],
                original=original['decompilation']['text'], gcc=current['decompilation']['text'],
                instructions_and_calls_unchanged=True)
            print(identifier, examples[identifier]['loader'], current['decompilation']['text'], flush=True)
    (ROOT/'paper/abi_examples.json').write_text(json.dumps(examples,indent=2)+'\n')


if __name__ == '__main__':
    main()

"""Produce private emitted-code review packets; never generate binary truth labels."""
import re
from .inventory import read_json,require
from .final_sources import CAMPAIGN
from .llm_runtime import write_new


def scope(cell,root=CAMPAIGN):
    assembly=(root/cell['evidence_directory']/'assembly.txt').read_text()
    blocks={};current=None
    for line in assembly.splitlines():
        m=re.match(r'^([0-9a-f]+) <([^>]+)>:',line)
        if m:current=m[2];blocks[current]=[]
        elif current is not None and re.match(r'^\s*[0-9a-f]+:\s+[0-9a-f]{2}',line):blocks[current].append(line)
    functions={f['name']:f for f in cell['evidence']['functions']}
    visited=set();todo=['main']
    while todo:
        name=todo.pop()
        if name in visited:continue
        require(name in functions and name in blocks,'Unmapped application function')
        visited.add(name)
        for line in blocks[name]:
            match=re.search(r'\b(?:call|jmp)\s+([0-9a-f]+) <([^>]+)>',line)
            if match and match[2] in functions and '@' not in match[2] and '+' not in match[2]:todo.append(match[2])
    return {'functions':[functions[n] for n in sorted(visited,key=lambda n:functions[n]['start'])],
            'assembly':{n:blocks[n] for n in sorted(visited,key=lambda n:functions[n]['start'])}}


def packets(root=CAMPAIGN):
    manifest=read_json(root/'build/final/build-manifest.json')
    for cell in manifest['builds']:
        require(cell['status']=='built','Unavailable build needs a separate unresolved review')
        data=scope(cell,root)
        write_new(root/'corpus/private/review-packets'/f"{cell['build_id']}.json",{'build_id':cell['build_id'],
            'pair_id':cell['pair_id'],'variant':cell['variant'],'optimization':cell['optimization'],
            'reference_sha256':cell['artifacts']['reference']['sha256'],'evidence_sha256':cell['evidence']['files'],**data})
    print('80 private packets; no binary labels assigned')

if __name__=='__main__':packets()

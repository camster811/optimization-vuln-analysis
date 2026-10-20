"""Final source selection must remain independent of predictor results."""
from copy import deepcopy
import pytest
from redesign.pipeline import final_sources
from redesign.pipeline.inventory import ROOT,read_json
from redesign.pipeline.sanitize import sanitize,verify_preservation,scan_metadata


def exposure():
    # Same public provenance categories; no earlier prediction outputs are inputs.
    from pathlib import Path
    path=final_sources.CAMPAIGN/'corpus/private/prior-adaptation-ledger.json'
    if not path.exists():pytest.skip('Local historical source-use ledger absent')
    return read_json(path)


def test_final_source_sequence():
    result=final_sources.select(exposure())
    chosen=result['selected']
    assert len(chosen)==len({r['family_id'] for r in chosen})==10
    assert sum(r['structure']=='interprocedural' for r in chosen)==6
    assert [int(r['rank']) for r in chosen if r['cwe']=='CWE-121']==[4,5,6,7,8]
    assert [int(r['rank']) for r in chosen if r['cwe']=='CWE-122']==[3,4,12,13,21]
    assert all(r['family_id'] not in {p['family_id'] for p in read_json(ROOT/'corpus/manifest.json')['pairs'] if p['status']=='assigned'} for r in chosen)


def test_cannot_skip_earlier_eligible_family(monkeypatch):
    choices=deepcopy(final_sources.CHOICES);choices['CWE-121'][0]=(5,'21','goodG2B1')
    monkeypatch.setattr(final_sources,'CHOICES',choices)
    with pytest.raises(ValueError,match='Earlier eligible'):final_sources.select(exposure())


def test_sanitizer_preserves_arithmetic_and_qualifiers():
    source='static int badStatic=0; void unit_bad(void){ volatile char a[10]; a[10]=1; } static void goodG2B(void){ char a[11]; a[10]=1; }'
    maps=final_sources.mapping(source,'unit','goodG2B')
    result,_=sanitize(source,maps,{},{});scan_metadata(result)
    assert verify_preservation(source,result,maps,{}, {})>0
    assert 'volatile char a[10]' in result and 'a[10]=1' in result
    with pytest.raises(ValueError):verify_preservation(source,result.replace('a[10]=1','a[9]=1'),maps,{}, {})

"""Campaign derivation, private mapping, and honest failure/uncertainty regressions."""
from copy import deepcopy
import shutil
import subprocess

import pytest

from redesign.pipeline import build as builds
from redesign.pipeline import oracle
from redesign.pipeline.inventory import ROOT, digest, encode, read_json


@pytest.fixture
def campaign(tmp_path):
    config = read_json(ROOT / 'config.json')
    config['splits'] = {s: {c: {'intraprocedural': int(c == 'CWE-121'), 'interprocedural': 0}
                            for c in ('CWE-121', 'CWE-122')} for s in ('pilot', 'final')}
    (tmp_path / 'entry.c').write_text('extern int helper(int); int main(void) { return helper(VALUE); }\n')
    (tmp_path / 'helper.c').write_text('int helper(int value) { return value + 1; }\n')
    (tmp_path / 'mapping.json').write_text('{}')
    (tmp_path / 'selection.json').write_text('{}')
    pair = {'pair_id': 'test-pilot', 'split': 'pilot', 'cwe': 'CWE-121', 'structure': 'intraprocedural',
            'status': 'assigned', 'family_id': 'fixture', 'upstream_case_id': 'fixture',
            'sources': ['entry.c'], 'translation_units': ['entry.c'],
            'support_sources': ['helper.c'], 'entries': {v: 'main' for v in config['matrix']['variants']},
            'variant_selection': {v: {'defines': [f'VALUE={i}'], 'driver_sources': ['entry.c']}
                                  for i, v in enumerate(config['matrix']['variants'])},
            'sanitization_manifest': 'mapping.json', 'selection_record': 'selection.json',
            'file_sha256': {n: digest(tmp_path / n) for n in ('entry.c', 'helper.c', 'mapping.json', 'selection.json')}}
    final = {'pair_id': 'test-final', 'split': 'final', 'cwe': 'CWE-121',
             'structure': 'intraprocedural', 'status': 'unassigned'}
    (tmp_path / 'corpus').mkdir()
    (tmp_path / 'corpus/manifest.json').write_text(encode({'schema_version': 2, 'pairs': [pair, final]}))
    (tmp_path / 'config.json').write_text(encode(config))
    (tmp_path / 'pipeline').mkdir()
    for name in ('build.py', 'inventory.py', 'sanitize.py'):
        shutil.copyfile(ROOT / 'pipeline' / name, tmp_path / 'pipeline' / name)
    return tmp_path


@pytest.fixture
def compiled(campaign):
    return builds.build(campaign), campaign


def unknown_review(cell):
    return {'build_id': cell['build_id'], 'cwe': 'CWE-121',
            'source_label': 'vulnerable_CWE-121' if cell['variant'] == 'vulnerable' else 'not_vulnerable',
            'binary_label': 'unresolved', 'operation_status': 'unresolved',
            'reviewer': 'test', 'review_date': '2026-10-19', 'review_basis': 'emitted_code',
            'assumptions': ['No runtime execution'], 'conclusion': 'Not reviewed',
            'unresolved_reason': 'Test intentionally leaves bounds unreviewed',
            'reference_sha256': cell['artifacts']['reference']['sha256'],
            'evidence_sha256': cell['evidence']['files'],
            'mapping': {'entry_address': None, 'source_entry_status': 'unresolved',
                        'localization_basis': 'private_symbols_and_debug', 'instruction_ranges': []},
            'facts': {k: {'assessment': 'Unknown', 'basis': 'instructions', 'instruction_addresses': []}
                      for k in ('destination', 'object_bound', 'write_extent', 'path')},
            'elimination_evidence': None, 'safety_scope': None}


def test_real_multifile_campaign_and_tamper_detection(compiled):
    report, root = compiled
    assert builds.verify(report, root) == {'reference_builds': 8, 'built': 8, 'build_unavailable': 0}
    for cell in report['builds']:
        assert cell['translation_units'] == ['entry.c', 'helper.c']
        assert 'helper' in {f['name'] for f in cell['evidence']['functions']}
        assert any(n.endswith('stdc-predef.h') for n in cell['dependencies'])
        assert all('.debug' not in n for n in builds.elf_sections(root / cell['artifacts']['retained']['path']))
    with pytest.raises(ValueError, match='already exists'):
        builds.build(root)
    with pytest.raises(ValueError, match='Unassigned'):
        builds.build(root, 'final')
    altered = deepcopy(report); altered['builds'].pop()
    with pytest.raises(ValueError, match='inventory'):
        builds.verify(altered, root)
    clean = root.parent / (root.name + '-clean')
    shutil.copytree(root, clean, ignore=shutil.ignore_patterns('build'))
    rebuilt = builds.build(clean)
    for left, right in zip(report['builds'], rebuilt['builds']):
        assert left['artifacts'] == right['artifacts']
        assert left['evidence'] == right['evidence']
    binary = root / report['builds'][0]['artifacts']['stripped']['path']
    data = bytearray(binary.read_bytes()); data[0x1000] ^= 1; binary.write_bytes(data)
    with pytest.raises(ValueError, match='hash'):
        builds.verify(report, root)


def test_build_failures_keep_every_planned_cell(campaign, monkeypatch):
    def fail(*args):
        raise ValueError('Synthetic compiler failure')
    monkeypatch.setattr(builds, 'build_one', fail)
    report = builds.build(campaign)
    assert builds.verify(report, campaign) == {'reference_builds': 8, 'built': 0, 'build_unavailable': 8}
    assert len(report['plan']['observations']) == 16


def test_oracle_uncertainty_inventory_and_stale_evidence(compiled):
    report, root = compiled
    reviews = {'schema_version': 3, 'split': 'pilot', 'config_sha256': report['config_sha256'],
               'manifest_sha256': report['manifest_sha256'], 'review_provenance': 'Test fixture',
               'reviews': [unknown_review(c) for c in report['builds']]}
    result = oracle.adjudicate(report, reviews, root)
    assert result['binary_labels'] == {'unresolved': 8}
    assert len(result['observations']) == 16
    assert all(o['binary_label'] == 'unresolved' for o in result['observations'])
    reviews['reviews'].append(deepcopy(reviews['reviews'][0]))
    with pytest.raises(ValueError, match='inventory'):
        oracle.adjudicate(report, reviews, root)
    cell = report['builds'][0]
    review = unknown_review(cell); review['reference_sha256'] = '0' * 64
    with pytest.raises(ValueError, match='Stale'):
        oracle.validate_review(review, cell)
    review = unknown_review(cell); review['binary_label'] = 'not_vulnerable'
    with pytest.raises(ValueError):
        oracle.validate_review(review, cell)


def test_shipped_reviews_reject_fabricated_addresses_and_bounds_omissions():
    reviews = read_json(ROOT / 'corpus/private/pilot-oracle.json')
    summary = read_json(ROOT / 'provenance/phase3-validation.json')
    assert summary['oracle_sha256'] == digest(ROOT / 'corpus/private/pilot-oracle.json')
    for name, expected in summary['methods'].items():
        assert digest(ROOT / name) == expected
    # Use only the versioned review/evidence snapshot, so this test needs no materialized campaign.
    for review in reviews['reviews']:
        cell = summary['reviewed_builds'][review['build_id']]
        oracle.validate_review(review, cell)
        altered = deepcopy(review)
        altered['facts']['write_extent']['instruction_addresses'] = [1]
        with pytest.raises(ValueError, match='Evidence outside'):
            oracle.validate_review(altered, cell)
        altered = deepcopy(review); del altered['facts']['object_bound']
        with pytest.raises(ValueError, match='Incomplete'):
            oracle.validate_review(altered, cell)


def test_partner_check_catches_allocated_data_changes(compiled):
    report, root = compiled
    cell = report['builds'][0]
    reference = root / cell['reference_path']
    public = root / cell['artifacts']['retained']['path']
    data = root / 'new-data'; data.write_bytes(b'changed\x00')
    subprocess.run(['objcopy', '--update-section', f'.rodata={data}', str(public)], check=True, capture_output=True)
    with pytest.raises(ValueError, match='allocated code/data'):
        builds.check_partner(reference, public)

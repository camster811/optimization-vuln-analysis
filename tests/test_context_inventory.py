"""Full-inventory failure reporting and public/private export boundary checks."""
from copy import deepcopy
import shutil

import pytest

from redesign.pipeline import export_context as export
from redesign.pipeline.bundles import apply_budget, canonical, validate
from redesign.pipeline.inventory import ROOT, digest, encode, generate, read_json


def test_failed_preparation_keeps_all_cells_and_protects_published_records(tmp_path, monkeypatch):
    root = tmp_path
    for name in export.METHODS:
        target = root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / name, target)
    observations = [dict(observation_id=f'r{i}', build_id='b1', pair_id='pair', variant='safe',
                         optimization='O0', symbols=condition, analysis_path=f'build/pilot/{condition}/b1',
                         record_path=f'data/pilot/records/r{i}.json')
                    for i, condition in enumerate(('retained', 'stripped'))]
    plan = {'observations': observations, 'builds': [{'build_id': 'b1'}]}
    builds = {'builds': [{'build_id': 'b1', 'status': 'build_unavailable'}]}
    reviews = {'reviews': [{'build_id': 'b1', 'source_label': 'not_vulnerable'}]}
    review_path = root / 'corpus/private/pilot-oracle.json'
    review_path.parent.mkdir(parents=True); review_path.write_text(encode(reviews))
    (root / 'build/pilot').mkdir(parents=True)
    (root / 'build/pilot/build-manifest.json').write_text(encode(builds))
    policy = read_json(root / 'context_policy.json')
    monkeypatch.setattr(export, 'load_inputs', lambda *args: (plan, policy, builds, reviews, review_path))
    def missing_engine(*args):
        raise ValueError('Pinned tool absent in this independent fixture')
    monkeypatch.setattr(export, 'engine_identity', missing_engine)
    report = export.extract_run(root, run_id='fixture', write=True)
    assert report['counts'] == {'extraction_unavailable': 2}
    directory = export.run_directory(root, 'pilot', 'fixture')
    tickets = read_json(directory / 'localization.json')
    assert all(set(t) == {'observation_id', 'entry_address', 'analysis_sha256'} for t in tickets)
    assert all(read_json(root / row['record_path'])['completeness']['omissions']
               == [{'reason': 'build_unavailable', 'address': None}] for row in observations)
    audit = export.audit_run(root, run_id='fixture')
    assert audit['all_observations_available'] is False
    assert audit['status'] == 'pending_or_failed_gates'
    altered = deepcopy(report); altered['observations'].pop()
    manifest = directory / 'extraction-manifest.json'
    manifest.write_text(encode(altered))
    with pytest.raises(ValueError, match='inventory'):
        export.verify_run(root, run_id='fixture')
    manifest.write_text(encode(report))
    target = root / observations[0]['record_path']; target.write_text('preserve previous attempt')
    with pytest.raises(ValueError, match='Existing public record differs'):
        export.publish(root, directory, report)
    assert target.read_text() == 'preserve previous attempt'
    # A changed localization artifact cannot be used to sneak private oracle fields into a worker.
    tickets[0]['source_capacity'] = 10
    (directory / 'localization.json').write_text(encode(tickets))
    with pytest.raises(ValueError, match='Localization changed'):
        export.verify_run(root, run_id='fixture')


def test_versioned_pilot_contexts_match_the_declared_inventory_and_private_coverage():
    """Runs without Ghidra or generated build artifacts using the published development snapshot."""
    plan = generate(read_json(ROOT / 'config.json'), read_json(ROOT / 'corpus/manifest.json'),
                    ROOT, 'pilot', require_assigned=True)
    summary = read_json(ROOT / 'provenance/phase4-validation.json')
    reviews = {r['build_id']: r for r in read_json(ROOT / 'corpus/private/pilot-oracle.json')['reviews']}
    policy = read_json(ROOT / 'context_policy.json')
    assert summary['status'] == 'passed' and summary['repeatability']['identical']
    assert summary['counts'] == {'available': len(plan['observations'])}
    assert summary['oracle_coverage_gate'] and summary['scope_parity_gate']
    assert summary['methods'] == {name: digest(ROOT / name) for name in export.METHODS}
    assert {p.name for p in (ROOT / 'data/pilot/records').iterdir()} == {
        row['observation_id'] + '.json' for row in plan['observations']}
    for row in plan['observations']:
        path = ROOT / row['record_path']
        bundle = read_json(path)
        validate(bundle)
        assert path.read_text() == canonical(bundle)
        assert apply_budget(bundle, policy) == bundle
        included = {i['address'] for f in bundle['functions'] for i in f['instructions']}
        required = {hex(a) for fact in reviews[row['build_id']]['facts'].values()
                    for a in fact['instruction_addresses']}
        assert required <= included

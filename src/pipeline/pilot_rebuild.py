"""Independent pilot build/extraction without altering accepted inputs or reviews."""
import argparse
from pathlib import Path
import shutil

from . import build, export_context, oracle
from .inventory import ROOT, digest, read_json, require
from .llm_runtime import write_new


def rebuild(destination):
    destination = destination.resolve()
    require(not destination.exists(), 'Clean rebuild destination already exists')
    destination.mkdir(parents=True)
    for name in ('corpus', 'pipeline', 'ghidra', 'schemas'):
        shutil.copytree(ROOT/name, destination/name, ignore=shutil.ignore_patterns('__pycache__'))
    for name in ('config.json', 'context_policy.json'):
        shutil.copyfile(ROOT/name, destination/name)
    original = read_json(ROOT/'build/pilot/build-manifest.json')
    build.verify(original)
    clean = build.build(destination)
    build.verify(clean, destination)
    reviews = read_json(destination/'corpus/private/pilot-oracle.json')
    dispositions = oracle.adjudicate(clean, reviews, destination)
    comparisons = []
    for first, second in zip(original['builds'], clean['builds']):
        require(first['build_id'] == second['build_id'] and second['status'] == 'built', 'Clean build failed')
        artifacts = {k: first['artifacts'][k]['sha256'] == second['artifacts'][k]['sha256'] for k in first['artifacts']}
        evidence = first['evidence'] == second['evidence']
        require(all(artifacts.values()) and evidence, 'Deterministic build/evidence differs')
        comparisons.append({'build_id': first['build_id'], 'artifacts_identical': artifacts, 'private_evidence_identical': evidence})
    extracted = export_context.extract_run(destination, run_id='phase7-clean', write=True)
    records = []
    for row in extracted['observations']:
        name = row['record_path']
        identical = digest(ROOT/name) == digest(destination/name)
        require(identical and row['status'] == 'available', 'Clean public bundle differs or is unavailable')
        records.append({'observation_id': row['observation_id'], 'sha256': digest(destination/name), 'identical': identical})
    result = {'schema_version': 1, 'status': 'verified', 'workspace': str(destination),
              'builds': comparisons, 'records': records,
              'original_build_manifest_sha256': digest(ROOT/'build/pilot/build-manifest.json'),
              'clean_build_manifest_sha256': digest(destination/'build/pilot/build-manifest.json'),
              'clean_extraction_manifest_sha256': digest(destination/'build/pilot/context/phase7-clean/extraction-manifest.json'),
              'oracle_sha256': digest(destination/'corpus/private/pilot-oracle.json'),
              'review_provenance': dispositions['review_provenance'],
              'methods': {name: digest(ROOT/name) for name in ('pipeline/pilot_rebuild.py', *export_context.METHODS)},
              'comparison_scope': 'Binary bytes, private instruction evidence and public bundles; commands and paths are workspace-specific.'}
    write_new(destination/'rebuild-verification.json', result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--destination', type=Path, required=True)
    args = parser.parse_args()
    result = rebuild(args.destination)
    print('Verified', len(result['builds']), 'builds and', len(result['records']), 'public bundles')


if __name__ == '__main__': main()

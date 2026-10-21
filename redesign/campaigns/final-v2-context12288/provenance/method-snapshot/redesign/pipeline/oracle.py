"""Validate private, manually reviewed emitted-code adjudications; never infer labels from source."""
import argparse
from collections import Counter

from .build import verify
from .inventory import ROOT, digest, encode, local_path, read_json, require


LABELS = {'vulnerable_CWE-121', 'vulnerable_CWE-122', 'not_vulnerable', 'unresolved'}
OPERATIONS = {'present', 'inlined/merged', 'eliminated', 'unresolved'}


def validate_review(review, cell):
    require(review['build_id'] == cell['build_id'], 'Review build differs')
    require(review['source_label'] == ('vulnerable_' + review['cwe'] if cell['variant'] == 'vulnerable'
                                      else 'not_vulnerable'), 'Source provenance label differs')
    require(review['binary_label'] in LABELS and review['operation_status'] in OPERATIONS,
            'Unknown oracle disposition')
    require(review['reviewer'] and review['review_date'] and review['review_basis'] == 'emitted_code',
            'Missing review provenance')
    require(review['assumptions'] and review['conclusion'], 'Missing assumptions/conclusion')
    if cell['status'] == 'build_unavailable':
        require(review['binary_label'] == 'unresolved' and review['operation_status'] == 'unresolved'
                and review['unresolved_reason'], 'Unavailable build must remain unresolved')
        return
    require(review['reference_sha256'] == cell['artifacts']['reference']['sha256'], 'Stale reference review')
    require(review['evidence_sha256'] == cell['evidence']['files'], 'Stale evidence review')
    addresses = set(cell['evidence']['instruction_addresses'])
    functions = cell['evidence']['functions']
    mapping = review['mapping']
    unresolved = review['binary_label'] == 'unresolved'
    require(mapping['entry_address'] in addresses or (unresolved and mapping['entry_address'] is None),
            'Entry is not an instruction')
    require(mapping['localization_basis'] == 'private_symbols_and_debug', 'Localization assistance must be disclosed')
    require(mapping['source_entry_status'] in {'present', 'inlined/merged', 'eliminated', 'unresolved'},
            'Unknown entry mapping status')
    ranges = mapping['instruction_ranges']
    require(ranges or unresolved, 'Missing containing-function ranges')
    for region in ranges:
        start, end = region['start'], region['end']
        require(type(start) is int and type(end) is int and start < end and start in addresses,
                'Invalid instruction range')
        require(any(f['start'] <= start < end <= f['end'] and f['name'] == region['containing_function']
                    for f in functions), 'Range outside containing function')
        require(region['role'] in {'entry', 'operation', 'context'}, 'Unknown range role')
    if mapping['entry_address'] is not None:
        require(any(r['start'] <= mapping['entry_address'] < r['end'] for r in ranges), 'Entry outside mapping')
    facts = review['facts']
    require(set(facts) == {'destination', 'object_bound', 'write_extent', 'path'}, 'Incomplete adjudication facts')
    for fact in facts.values():
        require(fact['assessment'] and fact['basis'] in {'instructions', 'source_debug_and_instructions'},
                'Missing fact assessment/basis')
        require(fact['instruction_addresses'] or unresolved, 'Missing emitted-code support')
        for address in fact['instruction_addresses']:
            require(type(address) is int and address in addresses
                    and any(r['start'] <= address < r['end'] for r in ranges), 'Evidence outside mapped instructions')
    require(bool(review['unresolved_reason']) == (review['binary_label'] == 'unresolved'),
            'Unresolved reason differs from label')
    if review['operation_status'] == 'eliminated':
        require(review['elimination_evidence'], 'Missing whole-selected-scope elimination explanation')
    require(review['binary_label'] != 'not_vulnerable' or review['safety_scope'], 'Missing safety justification')


def adjudicate(report, reviews, root=ROOT):
    counts = verify(report, root)
    require(reviews['schema_version'] == 3 and reviews['split'] == report['split'], 'Oracle schema/split differs')
    require(reviews['config_sha256'] == report['config_sha256']
            and reviews['manifest_sha256'] == report['manifest_sha256'], 'Oracle inputs differ')
    rows = reviews['reviews']
    by_id = {r['build_id']: r for r in rows}
    require(len(by_id) == len(rows) and set(by_id) == {c['build_id'] for c in report['builds']},
            'Oracle review inventory missing, duplicate, or unexpected')
    pairs = {p['pair_id']: p for p in read_json(root / 'corpus/manifest.json')['pairs']}
    for cell in report['builds']:
        review = by_id[cell['build_id']]
        require(review['cwe'] == pairs[cell['pair_id']]['cwe'], 'Oracle CWE provenance differs')
        validate_review(review, cell)
    observations = []
    for observation in report['plan']['observations']:
        review = by_id[observation['build_id']]
        observations.append({**observation, 'binary_label': review['binary_label'],
                             'source_label': review['source_label'], 'operation_status': review['operation_status'],
                             'review_build_id': review['build_id']})
    return {'schema_version': 3, 'phase': 3, 'split': report['split'],
            'status': 'complete' if counts['built'] == counts['reference_builds'] else 'builds_unavailable',
            'counts': {**counts, 'observations': len(observations)},
            'operation_dispositions': dict(Counter(r['operation_status'] for r in rows)),
            'binary_labels': dict(Counter(r['binary_label'] for r in rows)),
            'review_provenance': reviews['review_provenance'],
            'observations': observations}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--split', choices=('pilot', 'final'), default='pilot')
    parser.add_argument('--reviews', default='corpus/private/pilot-oracle.json')
    parser.add_argument('--write', action='store_true')
    args = parser.parse_args()
    report_path = ROOT / 'build' / args.split / 'build-manifest.json'
    reviews_path = local_path(ROOT, args.reviews)
    report = read_json(report_path)
    result = adjudicate(report, read_json(reviews_path))
    result['build_manifest_sha256'] = digest(report_path)
    result['oracle_sha256'] = digest(reviews_path)
    result['oracle_method_sha256'] = digest(ROOT / 'pipeline/oracle.py')
    if args.write:
        (ROOT / 'build' / args.split / 'dispositions.json').write_text(encode(result))
        summary = {**result,
                   'methods': {f'pipeline/{name}': digest(ROOT / 'pipeline' / name)
                               for name in ('build.py', 'oracle.py', 'inventory.py', 'sanitize.py')},
                   'environment': report['environment'],
                   'reviewed_builds': {c['build_id']: {k: v for k, v in c.items() if k != 'commands'}
                                       for c in report['builds']}}
        name = 'phase3-validation.json' if args.split == 'pilot' else 'phase3-final-validation.json'
        (ROOT / 'provenance' / name).write_text(encode(summary))
    print(encode({k: v for k, v in result.items() if k != 'observations'}), end='')


if __name__ == '__main__':
    main()

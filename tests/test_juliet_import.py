"""Juliet source preservation, scope selection, and negative-edit checks."""
import pytest

from redesign.pipeline import import_juliet as importer
from redesign.pipeline import inventory as inv
from redesign.pipeline import sanitize as lexer
from redesign.pipeline.validate_sources import verify_relocations


def test_imported_pilots_and_final_separation():
    result = importer.verify_import()
    assert result['status'] == 'verified'
    config = inv.read_json(inv.ROOT / 'config.json')
    manifest = inv.read_json(inv.ROOT / 'corpus/manifest.json')
    inv.generate(config, manifest, split='pilot', require_assigned=True)
    assert all(p['status'] == 'unassigned' for p in manifest['pairs'] if p['split'] == 'final')
    with pytest.raises(ValueError, match='Unassigned'):
        inv.generate(config, manifest, require_assigned=True)
    for pair in manifest['pairs']:
        if pair['split'] != 'pilot':
            continue
        assert pair['entries'] == {'safe': 'process_case', 'vulnerable': 'process_case'}
        assert pair['translation_units'] == [f'corpus/pairs/{pair["pair_id"]}/driver.c']
        assert len(pair['headers']) == 2


def test_preserve_data_literals_and_token_boundaries():
    original = 'int/**/bad_count=10; const char *data="bad_count /* input data */"; // bad_count\n'
    output, _ = lexer.sanitize(original, {'bad_count': 'item_count'}, {}, {})
    assert ('identifier', 'int') in lexer.significant(output)
    assert ('identifier', 'item_count') in lexer.significant(output)
    assert ('string', '"bad_count /* input data */"') in lexer.significant(output)
    lexer.verify_preservation(original, output, {'bad_count': 'item_count'}, {}, {})


@pytest.mark.parametrize('replacement', [
    'int data[11];', 'volatile int data[10];', 'int data[10]; data[0]=1;', 'char data[10];'
])
def test_reject_executable_changes(replacement):
    with pytest.raises(ValueError, match='token'):
        lexer.verify_preservation('int data[10];', replacement, {}, {}, {})


def test_diagnostic_allowlist_does_not_rewrite_test_data():
    mapping = {'"bad"': '"message"'}
    result, _ = lexer.sanitize('printLine("bad");', {}, {}, mapping)
    assert result == 'printLine("message");'
    with pytest.raises(ValueError, match='Diagnostic'):
        lexer.sanitize('char data[]="bad";', {}, {}, mapping)
    result, _ = lexer.sanitize('#include "std_testcase.h"\nchar *p="std_testcase.h";', {},
                               {'"std_testcase.h"': '"runtime.h"'}, {})
    assert result == '#include "runtime.h"\nchar *p="std_testcase.h";'


@pytest.mark.parametrize('source', ['int na\\\nme;', '/* unfinished', 'char *x="unfinished;', '??=define X 1'])
def test_unsupported_lexical_forms_fail_closed(source):
    with pytest.raises(ValueError):
        lexer.tokens(source)


def test_unexplained_relocation_change_rejected(tmp_path):
    with pytest.raises(ValueError, match='Unexplained'):
        verify_relocations(['0004 R_X86_64_PC32 .bss'], ['0004 R_X86_64_PC32 .bss+0x4'],
                           tmp_path / 'old', tmp_path / 'new', tmp_path, tmp_path / 'log', {})


def test_readonly_original_overwrite_rejected(tmp_path):
    source = tmp_path / 'source.c'
    importer.store(source, 'int original;', readonly=True)
    try:
        importer.store(source, 'int original;', readonly=True)
        with pytest.raises(ValueError, match='differs'):
            importer.store(source, 'int changed;', readonly=True)
    finally:
        source.chmod(0o644)


def test_validation_report_binds_current_inputs():
    report = inv.read_json(inv.ROOT / 'provenance/phase2-validation.json')
    assert report['manifest_sha256'] == inv.digest(inv.ROOT / 'corpus/manifest.json')
    assert report['config_sha256'] == inv.digest(inv.ROOT / 'config.json')
    for name, sha in report['validation_methods'].items():
        assert sha == inv.digest(inv.ROOT / name)
    assert len(report['source_comparisons']) == 16
    assert len(report['sanitizer_runs']) == 8
    assert all(u['text_equal'] and u['relocation_equivalence_verified']
               for case in report['source_comparisons'] for u in case['units'])

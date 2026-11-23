"""Explicit byte formats used by the retained methods.

JSON text is Unicode with sorted keys and finite numbers. HTTP requests have no
final newline; canonical records and escaped journals have one LF. Reports are
UTF-8 bytes. Journal escaping retains unpaired surrogates without repairing them.
"""
import json
from pathlib import Path

from . import require


def strict_json(text):
    def unique(items):
        result = {}
        for key, value in items:
            require(key not in result, f'Duplicate JSON key: {key}')
            result[key] = value
        return result

    def invalid(value):
        raise ValueError(f'Nonfinite JSON number: {value}')

    return json.loads(text, object_pairs_hook=unique, parse_constant=invalid)


def read_json(path):
    return strict_json(Path(path).read_text(encoding='utf-8'))


def compact_json(value):
    """Compact Unicode JSON text, without a trailing newline."""
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False)


def request_json(value):
    """HTTP request text; callers transmit its exact UTF-8 bytes."""
    return compact_json(value)


def canonical_json(value):
    """Canonical bundle/record text, including its final LF."""
    return compact_json(value)+'\n'


def journal_json(value):
    """ASCII-escaped journal text, including its final LF."""
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False)+'\n'


def report_json(value):
    """Canonical report bytes, including their final LF."""
    return canonical_json(value).encode('utf-8')


def inventory_json(value):
    """Indented legacy inventory text, including its final LF."""
    return json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False, allow_nan=False)+'\n'

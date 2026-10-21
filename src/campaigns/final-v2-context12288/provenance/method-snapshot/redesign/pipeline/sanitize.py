"""Restricted C token sanitizer; reject edits outside explicitly reviewed metadata maps."""
from collections import Counter
import re

from .inventory import require


TOKEN = re.compile(
    r'(?P<comment>/\*[\s\S]*?\*/|//[^\r\n]*)'
    r'|(?P<string>(?:u8|u|U|L)?"(?:\\[\s\S]|[^"\\])*")'
    r"|(?P<char>(?:u|U|L)?'(?:\\[\s\S]|[^'\\])*')"
    r'|(?P<space>\s+)'
    r'|(?P<number>(?:[0-9]|\.[0-9])(?:[a-zA-Z0-9_.]|[eEpP][+-])*)'
    r'|(?P<identifier>[a-zA-Z_][a-zA-Z_0-9]*)'
    r'|(?P<punct>##|>>=|<<=|\.\.\.|->|\+\+|--|<<|>>|<=|>=|==|!=|&&|\|\||[+*/%&|^!-]=|.)',
    re.DOTALL,
)
LEAK = re.compile(r'juliet|cwe[-_]?\d+|std_testcase|omitgood|omitbad|goodg2b|goodb2g|'
                  r'(?<![a-z0-9])(?:good|bad|vulnerable|fixed)(?![a-z0-9])', re.I)


def tokens(source):
    # Translation-phase tricks are outside this deliberately bounded importer.
    require(not re.search(r'\\\r?\n|\?\?[=/\'()!<>-]', source),
            'Line splices/trigraphs need explicit lexer support before import')
    result = [(m.lastgroup, m.group()) for m in TOKEN.finditer(source)]
    require(''.join(value for _, value in result) == source, 'Unrecognized source bytes')
    require(not any(kind == 'punct' and value in {'"', "'"} for kind, value in result),
            'Unterminated literal')
    require(not any(result[i:i+2] == [('punct', '/'), ('punct', '*')]
                    for i in range(len(result) - 1)), 'Unterminated comment')
    return result


def significant(source):
    return [(kind, value) for kind, value in tokens(source) if kind not in {'space', 'comment'}]


def mapped_token(kind, value, preceding, identifiers, includes, diagnostics):
    if kind == 'identifier' and value in identifiers:
        return identifiers[value], 'identifier_sanitization'
    if kind == 'string' and preceding[-2:] == [('punct', '#'), ('identifier', 'include')]:
        if value in includes:
            return includes[value], 'include_filename_sanitization'
    if kind == 'string' and value in diagnostics:
        require(preceding[-2:] == [('identifier', 'printLine'), ('punct', '(')],
                'Diagnostic replacement is only permitted as a direct printLine literal')
        return diagnostics[value], 'diagnostic_message_replacement'
    return value, None


def sanitize(source, identifiers, includes, diagnostics):
    require(all(re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', name)
                for pair in identifiers.items() for name in pair), 'Invalid identifier map')
    output, preceding, changes = [], [], Counter()
    for kind, value in tokens(source):
        if kind == 'comment':
            output.append(''.join(c if c in '\r\n' else ' ' for c in value))
            changes['comment_metadata_removal'] += 1
        else:
            replacement, category = mapped_token(kind, value, preceding, identifiers, includes, diagnostics)
            output.append(replacement)
            if category:
                changes[category] += 1
            if kind != 'space':
                preceding.append((kind, value))
    result = ''.join(output)
    verify_preservation(source, result, identifiers, includes, diagnostics)
    return result, dict(changes)


def verify_preservation(original, sanitized, identifiers, includes, diagnostics):
    before, after = significant(original), significant(sanitized)
    require(len(before) == len(after), 'Executable token count changed')
    for i, ((kind, value), actual) in enumerate(zip(before, after)):
        expected, _ = mapped_token(kind, value, before[:i], identifiers, includes, diagnostics)
        require(actual == (kind, expected), f'Unauthorized token edit at index {i}: {value!r}')
    return len(before)


def scan_metadata(value):
    """This detects known label markers, not all possible statistical information leakage."""
    if isinstance(value, bytes):
        value = value.decode('latin1')
    require(not LEAK.search(value), 'Benchmark/label metadata remains')

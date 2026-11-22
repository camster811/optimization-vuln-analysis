"""Known metadata-marker checks for accepted public bundle validation."""
import re

from .inventory import require


LEAK = re.compile(r'juliet|cwe[-_]?\d+|std_testcase|omitgood|omitbad|goodg2b|goodb2g|'
                  r'(?<![a-z0-9])(?:good|bad|vulnerable|fixed)(?![a-z0-9])', re.I)



def scan_metadata(value):
    """This detects known label markers, not all possible statistical information leakage."""
    if isinstance(value, bytes):
        value = value.decode('latin1')
    require(not LEAK.search(value), 'Benchmark/label metadata remains')

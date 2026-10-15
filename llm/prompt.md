You are analyzing one x86-64 function recovered from an ELF binary.

Use only the supplied function record. Decide whether the function contains
the selected target operation as:

- vulnerable_CWE-121: stack-based buffer overflow
- vulnerable_CWE-122: heap-based buffer overflow
- not_vulnerable: the relevant write is within the destination bounds
- uncertain: the available binary evidence cannot establish the destination bound

Return exactly one JSON object with:

{
  "decision": one of the four labels above,
  "confidence": a number from 0.0 through 1.0,
  "evidence": a list of zero to five instruction addresses from the record,
  "summary": a short explanation grounded in allocation size, destination
             capacity, write extent, or missing evidence
}

Do not infer the answer from filenames, presumed dataset balance, function
addresses, or benchmark conventions. If the source-level destination capacity
cannot be recovered from the record, use uncertain rather than guessing.

FUNCTION RECORD:
{{RECORD_JSON}}

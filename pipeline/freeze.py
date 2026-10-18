#!/usr/bin/env python3
"""Create or verify the final 160-record input freeze; never freeze results."""

import argparse
from collections import Counter
import csv
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import tempfile

if __package__:
    from . import extract
else:
    import extract


PROJECT_ROOT = Path(__file__).resolve().parents[1]
FREEZE_PATH = "data/input_freeze.json"
METHOD_FILES = {
    "config.json", "analysis_plan.md", "requirements.txt", "corpus/manifest.csv",
    "ghidra/ExtractFunction.java", "pipeline/extract.py", "pipeline/static_baseline.py",
    "pipeline/run_llm.py", "pipeline/evaluate.py", "pipeline/freeze.py",
    "llm/prompt.md", "llm/response.schema.json", "pipeline/build.py", "compile.sh",
    "pipeline/serve_llm.py",
    "pipeline/runtime.py", "pipeline/diagnostics.py", "pipeline/campaign.py",
}
PRIVATE_FILES = {"data/private/observations.csv", "data/private/manual_oracle.csv"}
RUNTIME_FILES = {"runtime/server.json", "runtime/preflight.json", "runtime/startup.txt",
                 "runtime/extraction_comparison.json", "campaign.json"}
FINAL_RECORDS = {f"data/records/r{i:04d}.json" for i in range(1, 161)}
FINAL_OUTPUTS = {
    "static_predictions.jsonl", "summary.csv", "subgroups.csv", "stability.csv",
    "report.md", "release_manifest.json", "qualitative.md",
    "figures/coverage_accuracy.png", "figures/recall_fpr.png", "figures/treatment_accuracy.png",
    "diagnostics.json", "exploratory.md",
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def project_file(root, name):
    require(isinstance(name, str), "Expected a project-relative filename")
    relative = Path(name)
    require(not relative.is_absolute() and ".." not in relative.parts
            and relative.as_posix() == name, f"Unsafe frozen path: {name}")
    path = root / relative
    require(path.resolve() == path and path.is_file() and not path.is_symlink(),
            f"Missing, linked, or external input: {name}")
    require(path.stat().st_size > 0, f"Empty input: {name}")
    return path


def read_json(path):
    def unique_object(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, f"Duplicate JSON key in {path.name}: {key}")
            result[key] = value
        return result

    def invalid_constant(value):
        raise ValueError(f"Nonfinite JSON value in {path.name}: {value}")

    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique_object,
                      parse_constant=invalid_constant)


def expected_files(root):
    """Recompute scope so additions and removals cannot hide behind old hashes."""
    root = root.resolve()
    with project_file(root, "corpus/manifest.csv").open(newline="", encoding="utf-8") as stream:
        reader = csv.DictReader(stream)
        fields = {"pair_id", "split", "cwe", "source_path", "target_function", "mechanism"}
        require(reader.fieldnames and len(reader.fieldnames) == len(set(reader.fieldnames))
                and fields <= set(reader.fieldnames), "Invalid corpus manifest columns")
        pairs = list(reader)
    require(len(pairs) == 22 and len({row['pair_id'] for row in pairs}) == 22,
            "Expected 22 corpus pairs: two pilot and twenty final")
    require(all(all(isinstance(row.get(field), str) and row[field].strip() for field in fields)
                and None not in row for row in pairs), "Incomplete corpus manifest row")
    require(Counter(row['split'] for row in pairs) == {"pilot": 2, "final": 20},
            "Expected two pilot and twenty final pairs")
    for split, count in (("pilot", 1), ("final", 10)):
        require(Counter(row['cwe'] for row in pairs if row['split'] == split)
                == {"CWE-121": count, "CWE-122": count}, f"Invalid {split} CWE balance")
    sources = {row['source_path'] for row in pairs}
    require(len(sources) == 22, "Duplicate corpus source paths")
    for name in sources:
        source = project_file(root, name)
        require(source.suffix == ".c" and source.is_relative_to(root / "corpus/pairs"),
                f"Source must be a corpus/pairs C file: {name}")
    # Include any additional C support files rather than allowing unfrozen code.
    sources.update(path.relative_to(root).as_posix() for path in (root / "corpus/pairs").rglob("*.c"))
    records = {path.relative_to(root).as_posix() for path in (root / "data/records").rglob("*.json")}
    require(records == FINAL_RECORDS,
            f"Final freeze requires exactly 160 records r0001-r0160: "
            f"missing={len(FINAL_RECORDS - records)}, extra={sorted(records - FINAL_RECORDS)}")
    validate_oracle(root)
    if __package__:
        from . import runtime
    else:
        import runtime
    runtime.validate_evidence(root)
    files = METHOD_FILES | sources | FINAL_RECORDS | PRIVATE_FILES | RUNTIME_FILES
    for name in sorted(files):
        project_file(root, name)
    require((root / "analysis_plan.md").read_text(encoding="utf-8").strip(), "Analysis plan is empty")
    for name in sorted(FINAL_RECORDS):
        record = read_json(project_file(root, name))
        extract.validate_record(record)
        extract.scan_record_for_leaks(record)
    return files


def validate_oracle(root):
    """Bind the worksheet to final truth, source bytes, and binary bytes."""
    with project_file(root, "data/private/observations.csv").open(newline="") as stream:
        observations = list(csv.DictReader(stream))
    with project_file(root, "data/private/manual_oracle.csv").open(newline="") as stream:
        worksheet = list(csv.DictReader(stream))
    key = lambda row: tuple(row[field] for field in ("pair_id", "variant", "optimization"))
    require(len({key(row) for row in worksheet}) == len(worksheet), "Duplicate oracle worksheet entry")
    oracle = {key(row): row for row in worksheet}
    require(len(observations) == 160 and len({row['observation_id'] for row in observations}) == 160,
            "Expected 160 truth rows")
    require(len({key(row) for row in observations}) == 80, "Expected 80 oracle builds")
    for row in observations:
        require(key(row) in oracle, "Missing oracle worksheet entry")
        review = oracle[key(row)]
        require(review['oracle_binary'] == row['oracle_binary'] and review['source_path'] == row['source_path']
                and review['conclusion'] == row['truth'] and review['review_status'] == 'reviewed'
                and review['intended_operation_survived'] == 'yes', "Oracle worksheet disagrees with truth")
        for path, sha in ((review['source_path'], review['source_sha256']),
                          (review['oracle_binary'], review['oracle_sha256'])):
            require(hashlib.sha256(project_file(root, path).read_bytes()).hexdigest() == sha,
                    f"Oracle evidence hash mismatch: {path}")
        actual = extract.binary_hashes(project_file(root, row['analysis_binary']).read_bytes())
        require(all(actual[field] == row[field] for field in actual), "Analysis binary hash mismatch")


def check_analyzer_inputs(root):
    """Verify only analyzer-visible inputs; never open truth, sources, or oracle files.

    The campaign supervisor performs the complete private freeze check before
    launching this process. The runner checks its public subset again here.
    """
    root = Path(root).resolve()
    snapshot = read_json(project_file(root, FREEZE_PATH))
    require(snapshot.get('freeze_version') == 2, "Expected a corrected version 2 freeze")
    records = {path.relative_to(root).as_posix()
               for path in (root / "data/records").rglob("*.json")}
    require(records == FINAL_RECORDS, "Frozen record inventory changed: expected exactly 160 final records")
    names = FINAL_RECORDS | RUNTIME_FILES | {
        "config.json", "llm/prompt.md", "llm/response.schema.json", "pipeline/run_llm.py",
        "pipeline/extract.py", "pipeline/runtime.py", "pipeline/serve_llm.py", "pipeline/freeze.py",
    }
    require(names | PRIVATE_FILES <= set(snapshot['files']), "Incomplete frozen analyzer scope")
    require(hash_files(root, names) == {name: snapshot['files'][name] for name in names},
            "Frozen analyzer inputs changed")


def hash_files(root, names):
    return {name: hashlib.sha256(project_file(root, name).read_bytes()).hexdigest() for name in sorted(names)}


def ensure_campaign_not_started(root):
    directory = root / "results/llm_runs"
    require(not directory.exists() or directory.is_dir() and not any(directory.iterdir()),
            "Final LLM campaign already has files; refusing a retrospective freeze")
    for name in sorted(FINAL_OUTPUTS):
        path = root / "results" / name
        require(not path.exists() or path.is_file() and path.stat().st_size == 0,
                f"Final analysis already has an output ({name}); refusing a retrospective freeze")


def check_freeze(root=PROJECT_ROOT):
    root = Path(root).resolve()
    value = read_json(project_file(root, FREEZE_PATH))
    require(isinstance(value, dict) and set(value) == {"freeze_version", "files"}
            and type(value['freeze_version']) is int and value['freeze_version'] == 2
            and isinstance(value['files'], dict), "Invalid input freeze format")
    names = expected_files(root)
    actual = set(value['files'])
    require(actual == names,
            f"Input freeze scope differs: missing={sorted(names - actual)}, extra={sorted(actual - names)}")
    for name, expected in sorted(value['files'].items()):
        require(isinstance(expected, str) and re.fullmatch(r"[0-9a-f]{64}", expected),
                f"Invalid SHA-256 for {name}")
    current = hash_files(root, names)
    changed = [name for name in sorted(names) if current[name] != value['files'][name]]
    require(not changed, "Frozen inputs changed: " + ", ".join(changed))
    return value


def create_freeze(root=PROJECT_ROOT):
    root = Path(root).resolve()
    data = root / "data"
    require(data.is_dir() and data.resolve() == data, "Missing or linked data directory")
    # Directory flock serializes create invocations without leaving a lock file.
    descriptor = os.open(data, os.O_RDONLY | os.O_DIRECTORY)
    temporary = None
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        destination = data / "input_freeze.json"
        require(not destination.is_symlink() and (not destination.exists()
                or destination.is_file() and destination.stat().st_size == 0),
                "Input freeze already exists; use check. Existing freezes are never overwritten")
        ensure_campaign_not_started(root)
        names = expected_files(root)
        snapshot = {"freeze_version": 2, "files": hash_files(root, names)}
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=data,
                                         prefix=".input-freeze-", suffix=".tmp", delete=False) as stream:
            temporary = Path(stream.name)
            json.dump(snapshot, stream, indent=2, sort_keys=True, ensure_ascii=False, allow_nan=False)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        require(names == expected_files(root) and snapshot['files'] == hash_files(root, names),
                "Inputs changed during freeze creation; nothing published")
        ensure_campaign_not_started(root)
        temporary.replace(destination)
        os.fsync(descriptor)
        return snapshot
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
        os.close(descriptor)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("create", "check"))
    args = parser.parse_args(argv)
    snapshot = create_freeze() if args.command == "create" else check_freeze()
    print(f"{'Created' if args.command == 'create' else 'Verified'} final input freeze: "
          f"{len(snapshot['files'])} files, 160 final records, 22 corpus pairs")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, KeyError, TypeError, OSError) as error:
        print(f"Freeze failed: {error}", file=sys.stderr)
        sys.exit(1)

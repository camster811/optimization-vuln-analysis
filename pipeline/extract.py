#!/usr/bin/env python3
"""Export validated instructions even when the separate decompilation stage fails."""
import argparse
from collections import defaultdict
import csv
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import struct
import subprocess
import sys
import tempfile


PROJECT_ROOT = Path(__file__).resolve().parents[1]
OBSERVATION_FIELDS = {
    "observation_id", "pair_id", "variant", "truth", "cwe", "optimization", "symbols",
    "source_path", "oracle_binary", "analysis_binary", "record_path", "target_function",
    "target_start", "target_end", "text_sha256", "analysis_sha256",
}
RECORD_KEYS = {"schema_version", "architecture", "function", "instructions", "calls", "decompilation"}
HEX_ADDRESS = re.compile(r"0x(?:0|[1-9a-f][0-9a-f]{0,15})\Z")
FORBIDDEN = re.compile(
    r"juliet|cwe[-_]?\d+|std_testcase|goodg2b|goodb2g|"
    r"(?<![a-z0-9])(?:good|bad|vulnerable|fixed|OMITBAD|OMITGOOD|VARIANT_FIXED)"
    r"(?![a-z0-9])|(?<![a-z0-9])O[02](?![a-z0-9])|"
    r"(?<![a-z0-9])(?:retained|stripped)(?![a-z0-9])",
    re.IGNORECASE,
)
PRIVATE_KEYS = OBSERVATION_FIELDS | {
    "source_label", "optimization_level", "symbol_condition", "split",
    "cohort", "volatile_destination",
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def load_config():
    with (PROJECT_ROOT / "config.json").open(encoding="utf-8") as stream:
        config = json.load(stream)
    ghidra = config["ghidra"]
    require(ghidra["language"] == "x86:LE:64:default", "Expected the x86-64 Ghidra language")
    require(ghidra.get("compiler_spec") == "gcc", "Expected the GCC/System V compiler specification")
    require(isinstance(ghidra["expected_version"], str) and ghidra["expected_version"],
            "Missing expected Ghidra version")
    for field in ("analysis_timeout_seconds", "decompiler_timeout_seconds"):
        require(type(ghidra[field]) is int and 0 < ghidra[field] <= 2147483647,
                f"ghidra.{field} must be a positive integer")
    return config


def address(value):
    require(isinstance(value, str) and HEX_ADDRESS.fullmatch(value),
            f"Invalid canonical hexadecimal address: {value!r}")
    return int(value, 16)


def project_path(value, parent):
    path = Path(value)
    require(not path.is_absolute() and ".." not in path.parts,
            f"Expected a project-relative path: {value}")
    absolute = (PROJECT_ROOT / path).resolve()
    require(absolute.is_relative_to((PROJECT_ROOT / parent).resolve()),
            f"Path must be under {parent}: {value}")
    return absolute


def load_observations(split):
    require(split in ("pilot", "final"), "Invalid split")
    filename = "pilot_observations.csv" if split == "pilot" else "observations.csv"
    with (PROJECT_ROOT / "data/private" / filename).open(newline="", encoding="utf-8") as stream:
        reader = csv.DictReader(stream)
        require(reader.fieldnames, f"{filename} is empty; build the {split} split first")
        require(len(reader.fieldnames) == len(OBSERVATION_FIELDS)
                and set(reader.fieldnames) == OBSERVATION_FIELDS, "Invalid observation table columns")
        rows = list(reader)
    expected = 16 if split == "pilot" else 160
    require(len(rows) == expected, f"{split} requires exactly {expected} observations; found {len(rows)}")
    ids = [row["observation_id"] for row in rows]
    require(len(set(ids)) == expected and set(ids) ==
            {f"r{index:04d}" for index in range(1, expected + 1)},
            "Observation IDs must be unique and contiguous from r0001")
    records = "data/pilot_records" if split == "pilot" else "data/records"
    pair_rows = defaultdict(list)
    for row in rows:
        require(set(row) == OBSERVATION_FIELDS and all(row.values()), "Incomplete observation row")
        require(re.fullmatch(r"[A-Za-z0-9_]+", row["pair_id"]), "Invalid pair ID")
        require(row["variant"] in ("vulnerable", "fixed")
                and row["optimization"] in ("O0", "O2")
                and row["symbols"] in ("retained", "stripped"), "Invalid observation treatment")
        require(row["cwe"] in ("CWE-121", "CWE-122"), "Invalid observation CWE")
        truth = "not_vulnerable" if row["variant"] == "fixed" else f"vulnerable_{row['cwe']}"
        require(row["truth"] == truth, "Observation truth disagrees with its variant")
        require(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", row["target_function"])
                and not FORBIDDEN.search(row["target_function"]), "Target name must be neutral")
        require(address(row["target_start"]) < address(row["target_end"]), "Invalid expected bounds")
        require(re.fullmatch(r"[0-9a-f]{64}", row["text_sha256"]), "Invalid .text SHA-256")
        require(re.fullmatch(r"[0-9a-f]{64}", row["analysis_sha256"]), "Invalid analysis SHA-256")
        binary = project_path(row["analysis_binary"], f"build/{row['symbols']}")
        require(binary.is_file(), f"Analysis binary not found: {binary}")
        require(row["record_path"] == f"{records}/{row['observation_id']}.json",
                "Record path does not match the requested split and observation ID")
        project_path(row["record_path"], records)
        pair_rows[row["pair_id"]].append(row)
    require(len(pair_rows) == expected // 8, "Incorrect number of source pairs")
    cells = {(variant, optimization, symbols) for variant in ("vulnerable", "fixed")
             for optimization in ("O0", "O2") for symbols in ("retained", "stripped")}
    for pair, observations in sorted(pair_rows.items()):
        require(len(observations) == 8 and
                {(row["variant"], row["optimization"], row["symbols"]) for row in observations} == cells,
                f"Unbalanced observations for {pair}")
        for field in ("target_function", "source_path", "cwe"):
            require(len({row[field] for row in observations}) == 1,
                    f"Inconsistent {field} for {pair}")
        for variant in ("vulnerable", "fixed"):
            for optimization in ("O0", "O2"):
                partners = [row for row in observations
                            if row["variant"] == variant and row["optimization"] == optimization]
                for field in ("target_start", "target_end", "text_sha256", "oracle_binary"):
                    require(len({row[field] for row in partners}) == 1,
                            f"Analysis partners disagree on {field} for {pair}")
    binaries = [row["analysis_binary"] for row in rows]
    require(len(set(binaries)) == expected, "Duplicate analysis binaries")
    output = PROJECT_ROOT / records
    extra = {path.name for path in output.glob("*.json")} - {f"{item}.json" for item in ids}
    require(not extra, f"Unexpected existing records in {records}: {', '.join(sorted(extra))}")
    return sorted(rows, key=lambda row: row["observation_id"])


def check_ghidra_version(config):
    location = os.environ.get("GHIDRA_HOME")
    require(location, "Set GHIDRA_HOME to the Ghidra installation directory")
    home = Path(location).expanduser().resolve()
    launcher = home / "support/analyzeHeadless"
    require(launcher.is_file() and os.access(launcher, os.X_OK), f"Missing Ghidra launcher: {launcher}")
    properties = (home / "Ghidra/application.properties").read_text(encoding="utf-8")
    versions = re.findall(r"^application\.version=(\S+)\s*$", properties, re.MULTILINE)
    expected = config["ghidra"]["expected_version"]
    require(versions == [expected], f"Expected Ghidra {expected}; installation reports {versions}")
    return launcher


def load_record(path):
    def unique_object(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, f"Duplicate JSON key: {key}")
            result[key] = value
        return result

    def invalid_constant(value):
        raise ValueError(f"Nonstandard JSON value: {value}")

    with path.open(encoding="utf-8") as stream:
        return json.load(stream, object_pairs_hook=unique_object, parse_constant=invalid_constant)


def binary_hashes(data):
    """Hash an ELF64-LE snapshot, including its .text bytes, without reopening it."""
    require(len(data) >= 64 and data[:6] == b"\x7fELF\x02\x01", "Expected an ELF64 little-endian binary")
    require(struct.unpack_from("<H", data, 18)[0] == 62, "Expected an x86-64 ELF")
    offset = struct.unpack_from("<Q", data, 40)[0]
    entry_size, count, strings_index = struct.unpack_from("<HHH", data, 58)
    require(entry_size >= 64 and 0 < count and strings_index < count
            and offset + entry_size * count <= len(data), "Invalid ELF section table")

    def section(index):
        return struct.unpack_from("<IIQQQQIIQQ", data, offset + index * entry_size)

    strings = section(strings_index)
    require(strings[1] == 3 and strings[4] + strings[5] <= len(data), "Invalid ELF section names")
    names = data[strings[4]:strings[4] + strings[5]]
    matches = []
    for index in range(count):
        header = section(index)
        require(header[0] < len(names), "Invalid ELF section name offset")
        end = names.find(b"\0", header[0])
        require(end >= 0, "Unterminated ELF section name")
        if names[header[0]:end] == b".text":
            matches.append(header)
    require(len(matches) == 1, "Expected exactly one .text section")
    text = matches[0]
    require(text[1] == 1 and text[5] > 0 and text[4] + text[5] <= len(data), "Invalid ELF .text section")
    return {"analysis_sha256": hashlib.sha256(data).hexdigest(),
            "text_sha256": hashlib.sha256(data[text[4]:text[4] + text[5]]).hexdigest()}


def copy_verified_binary(observation, destination):
    source = project_path(observation["analysis_binary"], f"build/{observation['symbols']}")
    # Pin one snapshot: changes to the source pathname after this read cannot
    # substitute different bytes between hash validation and workspace import.
    data = source.read_bytes()
    for field, actual in binary_hashes(data).items():
        require(actual == observation[field], f"{field} mismatch for {source}; rebuild the observation table")
    destination.write_bytes(data)
    require(hashlib.sha256(destination.read_bytes()).hexdigest() == observation["analysis_sha256"],
            "Workspace binary differs from the verified snapshot")


def run_headless(observation, config, launcher, script_source=None):
    """Return a raw record; no private table fields are appended to it."""
    log_directory = PROJECT_ROOT / "build/logs/ghidra"
    log_directory.mkdir(parents=True, exist_ok=True)
    projects = PROJECT_ROOT / "build/ghidra-projects"
    projects.mkdir(parents=True, exist_ok=True)
    identifier = observation["observation_id"]
    log = log_directory / f"{identifier}.log"
    ghidra = config["ghidra"]
    with tempfile.TemporaryDirectory(prefix="export-", dir=projects) as directory:
        work = Path(directory)
        binary = work / "program"
        try:
            copy_verified_binary(observation, binary)
        except (ValueError, OSError) as error:
            log.write_text(f"Binary verification failed: {error}\n", encoding="utf-8")
            raise
        scripts = work / "scripts"
        scripts.mkdir()
        if script_source is None:
            script_source = (PROJECT_ROOT / "ghidra/ExtractFunction.java").read_bytes()
        (scripts / "ExtractFunction.java").write_bytes(script_source)
        raw = work / "export.json"
        profile = work / "profile"
        profile.mkdir()
        properties = {
            "user.home": profile, "application.settingsdir": work / "settings",
            "application.cachedir": work / "cache", "application.tempdir": work / "tmp",
        }
        environment = dict(os.environ)
        options = " ".join(f'-D{key}="{value}"' for key, value in properties.items())
        environment["JAVA_TOOL_OPTIONS"] = (environment.get("JAVA_TOOL_OPTIONS", "") + " " + options).strip()
        command = [str(launcher), str(work), "export", "-import", str(binary),
                   "-processor", ghidra["language"], "-cspec", ghidra["compiler_spec"], "-max-cpu", "2",
                   "-analysisTimeoutPerFile", str(ghidra["analysis_timeout_seconds"]),
                   "-scriptPath", str(scripts), "-postScript", "ExtractFunction.java",
                   observation["target_start"], str(raw), str(ghidra["decompiler_timeout_seconds"]),
                   "-deleteProject", "-log", str(log_directory / f"{identifier}.application.log"),
                   "-scriptlog", str(log_directory / f"{identifier}.script.log")]
        try:
            with log.open("w", encoding="utf-8") as stream:
                stream.write(f"Verified analysis_sha256={observation['analysis_sha256']} "
                             f"text_sha256={observation['text_sha256']}\n")
                stream.write("$ " + shlex.join(command) + "\n")
                stream.flush()
                subprocess.run(command, cwd=PROJECT_ROOT, env=environment, check=True,
                               stdout=stream, stderr=subprocess.STDOUT,
                               timeout=ghidra["analysis_timeout_seconds"] +
                               ghidra["decompiler_timeout_seconds"] + 120)
            require("REPORT: Analysis timed out" not in log.read_text(encoding="utf-8"),
                    f"Ghidra analysis timed out; see {log}")
            require(raw.is_file(), f"Ghidra produced no record; see {log}")
            return load_record(raw)
        except (OSError, ValueError, subprocess.SubprocessError):
            if raw.is_file():
                shutil.copyfile(raw, log_directory / f"{identifier}.failed.json")
            raise


def exact_keys(value, keys, description):
    require(isinstance(value, dict) and set(value) == keys, f"Invalid {description} keys")


def validate_record(record):
    require(isinstance(record, dict) and RECORD_KEYS <= set(record)
            and set(record) <= RECORD_KEYS | {"error"}, "Invalid top-level record keys")
    exact_keys(record["decompilation"], {"status", "text"}, "decompilation")
    decompilation = record["decompilation"]
    require(isinstance(decompilation["status"], str) and isinstance(decompilation["text"], str),
            "Invalid decompilation value types")
    if decompilation["status"] != "ok":
        error = record.get("error", {})
        exact_keys(error, {"code", "message"}, "structured error")
        require(all(isinstance(value, str) for value in error.values()), "Invalid error value types")
        # These errors occur after the Java script completes its instruction
        # and call walk. Cancellation/lookup/extraction failures may be partial.
        usable = (decompilation["status"], error["code"]) in {
            ("error", "decompilation_failed"), ("timeout", "decompilation_timeout"),
        }
        require(usable and isinstance(record["function"], dict),
                f"Export failed ({decompilation['status']}): {error['code']}: {error['message']}")
    else:
        exact_keys(record, RECORD_KEYS, "top-level record")
        require(decompilation["text"].strip(), "Successful decompilation has no text")
    require(type(record["schema_version"]) is int and record["schema_version"] == 1,
            "Unsupported schema version")
    require(record["architecture"] == "x86-64", "Unexpected architecture")
    exact_keys(record["function"], {"name", "entry", "end"}, "function")
    function = record["function"]
    require(isinstance(function["name"], str) and function["name"].strip(), "Missing function name")
    entry, end = address(function["entry"]), address(function["end"])
    require(entry < end, "Invalid function bounds")
    require(isinstance(record["instructions"], list) and record["instructions"], "No instructions exported")
    addresses = []
    for instruction in record["instructions"]:
        exact_keys(instruction, {"address", "mnemonic", "operands"}, "instruction")
        value = address(instruction["address"])
        require(entry <= value < end, "Instruction is outside the function bounds")
        require(isinstance(instruction["mnemonic"], str) and instruction["mnemonic"].strip()
                and isinstance(instruction["operands"], str), "Invalid instruction value types")
        addresses.append(value)
    require(addresses == sorted(set(addresses)) and addresses[0] == entry,
            "Instructions must start at entry and be strictly address ordered")
    require(isinstance(record["calls"], list), "Calls must be a list")
    call_addresses = []
    call_pairs = []
    instruction_set = set(addresses)
    for call in record["calls"]:
        exact_keys(call, {"address", "target"}, "call")
        value = address(call["address"])
        require(value in instruction_set and isinstance(call["target"], str) and call["target"].strip(),
                "Invalid call address or target")
        call_addresses.append(value)
        call_pairs.append((value, call["target"]))
    require(call_addresses == sorted(call_addresses) and len(set(call_pairs)) == len(call_pairs),
            "Calls must be address ordered without duplicates")


def string_values(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for child in value.values():
            yield from string_values(child)
    elif isinstance(value, list):
        for child in value:
            yield from string_values(child)


def check_expected_bounds(record, observation):
    function = record["function"]
    require((address(function["entry"]), address(function["end"])) ==
            (address(observation["target_start"]), address(observation["target_end"])),
            f"Recovered bounds {function['entry']}..{function['end']} differ from expected "
            f"{observation['target_start']}..{observation['target_end']}")
    target = observation["target_function"]
    if observation["symbols"] == "retained":
        require(function["name"] == target, "Retained record does not expose the target name")
    else:
        name = re.compile(r"(?<![A-Za-z0-9_])" + re.escape(target) + r"(?![A-Za-z0-9_])")
        # Check values, since 'target' is also a legitimate key in call records.
        require(not any(name.search(value) for value in string_values(record)),
                "Stripped record exposes the neutral target name")


def scan_record_for_leaks(record, observation=None):
    def scan(value):
        if isinstance(value, dict):
            require(not (set(value) & PRIVATE_KEYS), "Record contains private metadata fields")
            for key, child in value.items():
                require(not FORBIDDEN.search(key), "Record contains a forbidden field")
                scan(child)
        elif isinstance(value, list):
            for child in value:
                scan(child)
        elif isinstance(value, str):
            require(not FORBIDDEN.search(value), "Record contains forbidden benchmark or treatment terms")
            require(not re.search(r"(?:/experiment/|corpus/pairs/|build/(?:oracle|retained|stripped)/)", value),
                    "Record contains a private file path")
    scan(record)
    for value in string_values(record):
        require(str(PROJECT_ROOT) not in value, "Record contains the project path")
        if observation:
            for field in ("source_path", "oracle_binary", "analysis_binary", "record_path", "pair_id"):
                private = observation[field]
                pattern = r"(?<![A-Za-z0-9_])" + re.escape(private) + r"(?![A-Za-z0-9_])"
                require(not re.search(pattern, value), f"Record contains private {field}")


def write_record_atomically(record_path, record):
    record_path.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", newline="\n",
                                         dir=record_path.parent, delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(json.dumps(record, ensure_ascii=False, indent=2, allow_nan=False) + "\n")
        temporary.replace(record_path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--split", choices=("pilot", "final"), required=True)
    args = parser.parse_args(argv)
    config = load_config()
    observations = load_observations(args.split)
    launcher = check_ghidra_version(config)
    script = PROJECT_ROOT / "ghidra/ExtractFunction.java"
    require(script.is_file(), "Missing ExtractFunction.java")
    script_source = script.read_bytes()
    records = []
    for observation in observations:
        identifier = observation["observation_id"]
        print(f"Extracting {identifier} ({len(records) + 1}/{len(observations)})", flush=True)
        record = None
        try:
            record = run_headless(observation, config, launcher, script_source)
            validate_record(record)
            check_expected_bounds(record, observation)
            scan_record_for_leaks(record, observation)
        except (ValueError, OSError, subprocess.SubprocessError) as error:
            if record is not None:
                write_record_atomically(PROJECT_ROOT / "build/logs/ghidra" / f"{identifier}.failed.json", record)
            raise ValueError(f"{identifier}: {error}; see build/logs/ghidra/{identifier}.log") from error
        records.append((PROJECT_ROOT / observation["record_path"], record))
    require(script.read_bytes() == script_source,
            "ExtractFunction.java changed during extraction; no records were published. Rerun extraction.")
    for destination, record in records:
        write_record_atomically(destination, record)
    directory = "data/pilot_records" if args.split == "pilot" else "data/records"
    print(f"Validated and wrote {len(records)} records to {directory}")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, KeyError, OSError, subprocess.SubprocessError) as error:
        print(f"Extraction failed: {error}", file=sys.stderr)
        sys.exit(1)

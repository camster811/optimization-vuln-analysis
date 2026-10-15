#!/usr/bin/env python3
import argparse
from collections import Counter
import csv
import hashlib
import json
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import tempfile


PROJECT_ROOT = Path(__file__).resolve().parents[1]
ENABLED_SOURCES = {"corpus/pairs/p01.c", "corpus/pairs/p08.c"}
FIELDS = (
    "observation_id", "pair_id", "variant", "truth", "cwe", "optimization",
    "symbols", "source_path", "oracle_binary", "analysis_binary", "record_path",
    "target_function", "target_start", "target_end", "text_sha256", "analysis_sha256",
)
REQUIRED_FLAGS = [
    "-std=c11", "-Wall", "-Wextra", "-g", "-gdwarf-5",
    "-fno-stack-protector", "-U_FORTIFY_SOURCE", "-D_FORTIFY_SOURCE=0",
    "-fcf-protection=none", "-fno-pie",
    "-fdebug-prefix-map={project_root}=/experiment",
    "-ffile-prefix-map={project_root}=/experiment",
]
PROHIBITED = re.compile(
    rb"juliet|cwe[-_]?\d+|std_testcase|goodg2b|goodb2g|"
    rb"(?<![a-z0-9])(?:good|bad|vulnerable|fixed)(?![a-z0-9])",
    re.IGNORECASE,
)


def test(condition, message):
    if not condition:
        raise ValueError(message)


def run(command, log=None):
    if log is not None:
        with log.open("a", encoding="utf-8") as stream:
            stream.write("$ " + shlex.join(map(str, command)) + "\n")
            stream.flush()
            subprocess.run(command, cwd=PROJECT_ROOT, check=True,
                           stdout=stream, stderr=subprocess.STDOUT)
        return ""
    return subprocess.run(command, cwd=PROJECT_ROOT, check=True, text=True, capture_output=True).stdout


def load_config():
    with (PROJECT_ROOT / "config.json").open(encoding="utf-8") as stream:
        config = json.load(stream)
    compiler = config["compiler"]
    test(compiler["name"] == "gcc-15", "The compiler must be gcc-15")
    test(sorted(compiler["optimizations"]) == ["O0", "O2"],
            "Exactly O0 and O2 are required")
    test(compiler["common_flags"] == REQUIRED_FLAGS,
            "Compiler common_flags differ from the required experimental flags")
    test(compiler["link_flags"] == ["-no-pie", "-Wl,-z,noexecstack"],
            "Link flags differ from the required experimental flags")
    test(config["platform"] == "x86-64-linux-gnu", "Only x86-64 Linux is supported")
    return config


def load_pairs():
    with (PROJECT_ROOT / "corpus/manifest.csv").open(newline="", encoding="utf-8") as stream:
        reader = csv.DictReader(stream)
        test(set(("pair_id", "split", "cwe", "source_path", "target_function",  # noqa: C405
                     "mechanism")) <= set(reader.fieldnames or []),
                "Manifest is missing required columns")
        pairs = list(reader)
    for field in ("pair_id", "source_path"):
        test(len({pair[field] for pair in pairs}) == len(pairs),
                f"Manifest contains duplicate {field} values")
    for pair in pairs:
        test(all(pair.get(field) for field in
                    ("pair_id", "split", "cwe", "source_path", "target_function", "mechanism")),
                "Manifest contains an incomplete row")
        test(re.fullmatch(r"[A-Za-z0-9_]+", pair["pair_id"]), "Invalid pair ID")
        test(pair["split"] in ("pilot", "final"), "Invalid manifest split")
        test(pair["cwe"] in ("CWE-121", "CWE-122"), "Unsupported CWE")
        test(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", pair["target_function"]),
                "Invalid target function name")
        path = Path(pair["source_path"])
        test(not path.is_absolute() and ".." not in path.parts and path.suffix == ".c",
                f"Invalid source path: {path}")
        test((PROJECT_ROOT / path).resolve().is_relative_to(PROJECT_ROOT)
                and (PROJECT_ROOT / path).is_file(), f"Missing or external source: {path}")
    return sorted(pairs, key=lambda pair: pair["pair_id"])


def select_split(pairs, split):
    selected = sorted((pair for pair in pairs if pair["split"] == split),
                      key=lambda pair: pair["pair_id"])
    expected = 2 if split == "pilot" else 12
    test(len(selected) == expected,
            f"{split} requires exactly {expected} pairs ({expected * 8} observations); "
            f"manifest has {len(selected)}. No partial table will be written.")
    disabled = sorted(pair["source_path"] for pair in selected
                      if pair["source_path"] not in ENABLED_SOURCES)
    test(not disabled, "Compilation is currently limited to p01.c and p08.c; "
            f"requested unsupported sources: {', '.join(disabled)}")
    return selected


def check_tool_versions(config):
    compiler = config["compiler"]
    actual = run([compiler["name"], "-dumpfullversion"]).strip()
    test(actual == compiler["expected_version"],
            f"GCC version mismatch: expected {compiler['expected_version']}, got {actual}")
    platform = run([compiler["name"], "-dumpmachine"]).strip()
    test(platform.replace("_", "-") == config["platform"],
            f"Compiler platform mismatch: {platform}")
    versions = {compiler["name"]: actual, "platform": platform}
    for tool in ("objcopy", "strip", "readelf", "objdump"):
        banner = run([tool, "--version"]).splitlines()[0]
        match = re.search(r"(\d+(?:\.\d+)+)$", banner)
        test("GNU" in banner and match is not None
                and match[1] == compiler["expected_binutils_version"],
                f"{tool} must be GNU binutils {compiler['expected_binutils_version']}: {banner}")
        versions[tool] = match[1]
    return versions


def compile_master(pair, variant, optimization, config, artifact_root=None):
    test(variant in (0, 1) and optimization in ("O0", "O2"), "Invalid build treatment")
    test(pair["source_path"] in ENABLED_SOURCES, "Source is outside the pilot build scope")
    name = f"{pair['pair_id']}_v{variant}_{optimization}"
    artifact_root = artifact_root or PROJECT_ROOT / "build"
    master = artifact_root / "oracle" / name
    log = artifact_root / "logs" / f"{name}.log"
    log.write_text("", encoding="utf-8")
    compiler = config["compiler"]
    flags = [flag.format(project_root=PROJECT_ROOT) for flag in compiler["common_flags"]]
    run(["bash", str(PROJECT_ROOT / "compile.sh"), "--master", pair["source_path"],
         str(variant), optimization, str(master), compiler["name"], *flags,
         "--", *compiler["link_flags"]], log)
    return master


def derive_retained(master, artifact_root=None):
    artifact_root = artifact_root or PROJECT_ROOT / "build"
    retained = artifact_root / "retained" / master.name
    log = artifact_root / "logs" / f"{master.name}.log"
    run(["cp", "--", str(master), str(retained)], log)
    run(["objcopy", "--strip-debug", str(retained)], log)
    return retained


def derive_stripped(retained, artifact_root=None):
    artifact_root = artifact_root or PROJECT_ROOT / "build"
    stripped = artifact_root / "stripped" / retained.name
    log = artifact_root / "logs" / f"{retained.name}.log"
    run(["cp", "--", str(retained), str(stripped)], log)
    run(["strip", "--strip-all", str(stripped)], log)
    return stripped


def read_sections(binary):
    sections = {}
    for line in run(["readelf", "--section-headers", "--wide", str(binary)]).splitlines():
        match = re.match(r"\s*\[\s*\d+\]\s+(\S+)\s+(\S+)\s+"
                         r"([0-9a-fA-F]+)\s+([0-9a-fA-F]+)\s+([0-9a-fA-F]+)\b", line)
        if match:
            sections[match[1]] = {"type": match[2], "address": int(match[3], 16),
                                  "offset": int(match[4], 16), "size": int(match[5], 16)}
    test(".text" in sections and sections[".text"]["size"] > 0,
            f"Missing or empty .text in {binary}")
    return sections


def read_function_bounds(binary, target_name):
    symbols = run(["readelf", "--symbols", "--wide", str(binary)])
    matches = []
    for line in symbols.splitlines():
        fields = line.split()
        if len(fields) == 8 and fields[0].endswith(":") and fields[7] == target_name:
            matches.append(fields)
    test(len(matches) == 1, f"Expected exactly one {target_name} symbol in {binary}")
    symbol = matches[0]
    test(symbol[3] == "FUNC" and symbol[6] != "UND" and int(symbol[2]) > 0,
            f"{target_name} is not a defined, nonempty function in {binary}")
    start = int(symbol[1], 16)
    end = start + int(symbol[2])  # Exclusive end, throughout the private table.
    text = read_sections(binary)[".text"]
    test(text["address"] <= start < end <= text["address"] + text["size"],
            f"{target_name} falls outside .text in {binary}")
    return start, end


def extract_text_hash(binary):
    section = read_sections(binary)[".text"]
    data = binary.read_bytes()[section["offset"]:section["offset"] + section["size"]]
    test(len(data) == section["size"], f"Truncated .text in {binary}")
    return hashlib.sha256(data).hexdigest()


def disassemble(binary, start, end):
    return run(["objdump", "-d", "-M", "intel", "--no-show-raw-insn",
                f"--start-address={start}", f"--stop-address={end}", str(binary)])


def check_direct_call(binary, target_name):
    target_start, _ = read_function_bounds(binary, target_name)
    main_start, main_end = read_function_bounds(binary, "main")
    assembly = disassemble(binary, main_start, main_end)
    test(any(int(match[1], 16) == target_start
                for match in re.finditer(r"\bcallq?\s+([0-9a-fA-F]+)\s+<", assembly)),
            f"main does not directly call {target_name} in {binary}")


def check_memory_write(assembly):
    """Early rejection gate only: a spill can pass; this does not prove copy survival.

    Intended-operation survival requires the separate private manual oracle
    worksheet, bound to the exact oracle binary's full-file hash.
    """
    for line in assembly.splitlines():
        match = re.match(r"\s*[0-9a-f]+:\s+([a-z0-9]+)\s*(.*)", line)
        if not match:
            continue
        mnemonic, operands = match.groups()
        if mnemonic in ("call", "jmp") and re.search(
                r"<(?:__)?(?:memcpy|memmove|strcpy|strncpy|strcat|strncat)"
                r"(?:_chk)?(?:@[^>]+)?>", operands):
            return
        # Exclude implicit stack writes such as push/call and address-only lea.
        if mnemonic.startswith(("mov", "vmov")) and "[" in operands.split(",")[0]:
            return
        if mnemonic.startswith("stos") or (mnemonic == "rep" and operands.startswith(("movs", "stos"))):
            return
    raise ValueError("Target has no recognizable memory store or copy call; inspect its disassembly log")


def scan_for_leaks(binary):
    for string in re.findall(rb"[\x20-\x7e]{3,}", binary.read_bytes()):
        match = PROHIBITED.search(string)
        test(match is None, f"Prohibited benchmark label in {binary}: {string!r}")


def verify_artifacts(master, retained, stripped, target_name, log_directory=None):
    bounds = read_function_bounds(master, target_name)
    test(read_function_bounds(retained, target_name) == bounds,
            f"Target bounds changed in {retained}")
    hashes = [extract_text_hash(binary) for binary in (master, retained, stripped)]
    test(len(set(hashes)) == 1, f".text hashes differ for {master.name}")
    original_text = read_sections(master)[".text"]
    for binary in (master, retained, stripped):
        section = read_sections(binary)[".text"]
        test((section["address"], section["size"]) ==
                (original_text["address"], original_text["size"]),
                f".text address or size changed in {binary}")
        # Equal .text bytes at equal virtual addresses preserve the oracle's
        # target entry and exclusive end even without a stripped symbol table.
    test(".debug_info" in read_sections(master), f"Oracle has no DWARF: {master}")
    for binary in (retained, stripped):
        sections = read_sections(binary)
        test(not any(name.startswith((".debug", ".zdebug")) for name in sections),
                f"DWARF remains in {binary}")
        scan_for_leaks(binary)
    test(".symtab" in read_sections(retained), f"Retained symbols missing: {retained}")
    test(".symtab" not in read_sections(stripped), f"Ordinary symbols remain: {stripped}")
    test(target_name.encode() in retained.read_bytes(), "Retained target name missing")
    test(target_name.encode() not in stripped.read_bytes(), "Stripped target name remains")
    check_direct_call(master, target_name)
    check_direct_call(retained, target_name)
    assembly = disassemble(master, *bounds)
    log = (log_directory or PROJECT_ROOT / "build/logs") / f"{master.name}.log"
    with log.open("a", encoding="utf-8") as stream:
        stream.write("\nTarget disassembly (oracle):\n" + assembly)
    check_memory_write(assembly)
    with log.open("a", encoding="utf-8") as stream:
        stream.write("\nPASS: structural artifact checks and memory-write rejection gate\n"
                     "Intended-operation survival requires private manual oracle review.\n")
    return bounds, hashes[0]


def assign_observation_id(index):
    return f"r{index:04d}"


def write_observations(rows, pairs, split, destination=None):
    expected_pairs = 2 if split == "pilot" else 12
    test(len(rows) == expected_pairs * 8, f"Incorrect {split} observation count")
    test(Counter(row["pair_id"] for row in rows) ==
            Counter({pair["pair_id"]: 8 for pair in pairs}), "Incorrect per-pair balance")
    test(len({row["observation_id"] for row in rows}) == len(rows), "Duplicate observation IDs")
    expected_cells = {(variant, optimization, symbols) for variant in ("vulnerable", "fixed")
                      for optimization in ("O0", "O2") for symbols in ("retained", "stripped")}
    for pair in pairs:
        test({(row["variant"], row["optimization"], row["symbols"])
                 for row in rows if row["pair_id"] == pair["pair_id"]} == expected_cells,
                f"Unbalanced treatments for {pair['pair_id']}")
    filename = "pilot_observations.csv" if split == "pilot" else "observations.csv"
    destination = destination or PROJECT_ROOT / "data/private" / filename
    # Only replace the table after every compilation and check has succeeded.
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", newline="",
                                         dir=destination.parent, delete=False) as stream:
            temporary = Path(stream.name)
            writer = csv.DictWriter(stream, fieldnames=FIELDS, lineterminator="\n")
            writer.writeheader()
            writer.writerows(sorted(rows, key=lambda row: row["observation_id"]))
        temporary.replace(destination)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    return destination


def file_sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def generation_id(stage, split):
    inventory = [(f"{kind}/{path.name}", file_sha256(path))
                 for kind in ("oracle", "retained", "stripped")
                 for path in sorted((stage / kind).iterdir())]
    digest = hashlib.sha256(json.dumps(inventory, separators=(",", ":")).encode()).hexdigest()
    return f"{split}-{digest}"


def publish_artifacts(stage, generation):
    """Publish immutable directories; an interrupted publish cannot alter old inputs."""
    for kind in ("oracle", "retained", "stripped"):
        source = stage / kind
        destination = PROJECT_ROOT / "build" / kind / generation
        destination.parent.mkdir(parents=True, exist_ok=True)
        if not destination.exists():
            try:
                source.rename(destination)
                continue
            except FileExistsError:
                pass  # Another identical build may have published this generation.
        test(destination.is_dir() and not destination.is_symlink(), "Invalid existing generation directory")
        expected = {path.name: file_sha256(path) for path in source.iterdir()}
        existing = {path.name: file_sha256(path) for path in destination.iterdir()
                    if path.is_file() and not path.is_symlink()}
        test(existing == expected and len(list(destination.iterdir())) == len(expected),
             f"Published generation changed: {destination}")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--split", choices=("pilot", "final"), required=True)
    args = parser.parse_args(argv)
    config = load_config()
    pairs = select_split(load_pairs(), args.split)
    versions = check_tool_versions(config)
    for directory in ("build/.staging", "build/logs", "data/private"):
        (PROJECT_ROOT / directory).mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=f"{args.split}-", dir=PROJECT_ROOT / "build/.staging") as directory:
        stage = Path(directory)
        for kind in ("oracle", "retained", "stripped", "logs"):
            (stage / kind).mkdir()
        try:
            (stage / "logs/tool_versions.json").write_text(
                json.dumps(versions, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            rows = []
            for pair in pairs:
                for variant in (0, 1):
                    for optimization in sorted(config["compiler"]["optimizations"]):
                        print(f"Building {pair['pair_id']} VARIANT_FIXED={variant} -{optimization}", flush=True)
                        master = compile_master(pair, variant, optimization, config, stage)
                        retained = derive_retained(master, stage)
                        stripped = derive_stripped(retained, stage)
                        (start, end), text_hash = verify_artifacts(
                            master, retained, stripped, pair["target_function"], stage / "logs")
                        for symbols, binary in (("retained", retained), ("stripped", stripped)):
                            observation_id = assign_observation_id(len(rows) + 1)
                            records = "data/pilot_records" if args.split == "pilot" else "data/records"
                            rows.append(dict(  # noqa: C408
                                observation_id=observation_id, pair_id=pair["pair_id"],
                                variant="fixed" if variant else "vulnerable",
                                truth="not_vulnerable" if variant else f"vulnerable_{pair['cwe']}",
                                cwe=pair["cwe"], optimization=optimization, symbols=symbols,
                                source_path=pair["source_path"], oracle_binary=f"build/oracle/{master.name}",
                                analysis_binary=f"build/{symbols}/{binary.name}",
                                record_path=f"{records}/{observation_id}.json", target_function=pair["target_function"],
                                target_start=hex(start), target_end=hex(end), text_sha256=text_hash,
                                analysis_sha256=file_sha256(binary),
                            ))
            generation = generation_id(stage, args.split)
            for row in rows:
                for column in ("oracle_binary", "analysis_binary"):
                    path = Path(row[column])
                    row[column] = (path.parent / generation / path.name).as_posix()
            # Validate the complete table before publishing any new directories.
            write_observations(rows, pairs, args.split, stage / "observations.csv")
            publish_artifacts(stage, generation)
            # This atomic replacement is the commit point. Old tables continue
            # to refer to untouched generations even if publication fails above.
            destination = write_observations(rows, pairs, args.split)
        finally:
            logs = PROJECT_ROOT / "build/logs" / f"build-{stage.name}"
            (stage / "logs").rename(logs)
    print(f"Verified {len(rows)} observations; wrote {destination.relative_to(PROJECT_ROOT)}")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, KeyError, OSError, subprocess.CalledProcessError) as error:
        print(f"Build failed: {error}", file=sys.stderr)
        sys.exit(1)

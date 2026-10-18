"""Schema, privacy, split isolation, and headless orchestration checks."""

import copy
import csv
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from pipeline import extract


def sample_record():
    return {
        "schema_version": 1, "architecture": "x86-64",
        "function": {"name": "target", "entry": "0x401000", "end": "0x401010"},
        "instructions": [
            {"address": "0x401000", "mnemonic": "SUB", "operands": "RSP,0x18"},
            {"address": "0x401005", "mnemonic": "CALL", "operands": "0x401030"},
            {"address": "0x40100f", "mnemonic": "RET", "operands": ""},
        ],
        "calls": [{"address": "0x401005", "target": "puts"}],
        "decompilation": {"status": "ok", "text": 'void target(void) { puts("payload"); }\n'},
    }


class RecordValidationTests(unittest.TestCase):
    def test_successful_record(self):
        record = sample_record()
        extract.validate_record(record)
        extract.scan_record_for_leaks(record)

    def test_unexpected_keys_and_invalid_types(self):
        mutations = [
            lambda record: record.update(optimization="O2"),
            lambda record: record.update(symbols="retained"),
            lambda record: record.update(schema_version=True),
            lambda record: record.update(architecture="aarch64"),
            lambda record: record["function"].update(source_path="corpus/pairs/p01.c"),
            lambda record: record["instructions"][0].update(operands=None),
            lambda record: record["decompilation"].update(text=""),
            lambda record: record.pop("decompilation"),
        ]
        for mutate in mutations:
            record = sample_record()
            mutate(record)
            with self.subTest(record=record), self.assertRaises(ValueError):
                extract.validate_record(record)

    def test_failed_decompilation_keeps_its_diagnostics(self):
        record = sample_record()
        record["function"] = None
        record["decompilation"] = {"status": "timeout", "text": ""}
        record["error"] = {"code": "decompilation_timeout", "message": "Decompiler exceeded its timeout."}
        original = copy.deepcopy(record)
        with self.assertRaisesRegex(ValueError, "Export failed.*decompilation_timeout"):
            extract.validate_record(record)
        self.assertEqual(record, original)

    def test_instruction_order_bounds_and_addresses(self):
        for instructions in ([], list(reversed(sample_record()["instructions"])),
                             sample_record()["instructions"] * 2):
            record = sample_record()
            record["instructions"] = instructions
            with self.subTest(instructions=instructions), self.assertRaises(ValueError):
                extract.validate_record(record)
        for bad_address in ("0x401010", "0x00401000", "401000", "0x40100F", "0x10000000000000000"):
            record = sample_record()
            record["instructions"][0]["address"] = bad_address
            with self.subTest(address=bad_address), self.assertRaises(ValueError):
                extract.validate_record(record)

    def test_call_order_membership_and_duplicates(self):
        for calls in (
            [{"address": "0x401003", "target": "puts"}],
            sample_record()["calls"] * 2,
            [{"address": "0x40100f", "target": "last"}, {"address": "0x401005", "target": "first"}],
        ):
            record = sample_record()
            record["calls"] = calls
            with self.subTest(calls=calls), self.assertRaises(ValueError):
                extract.validate_record(record)

    def test_bounds_and_symbol_conditions(self):
        observation = {"target_start": "0x401000", "target_end": "0x401010",
                       "symbols": "retained", "target_function": "target"}
        extract.check_expected_bounds(sample_record(), observation)
        with self.assertRaisesRegex(ValueError, "differ from expected"):
            extract.check_expected_bounds(sample_record(), {**observation, "target_end": "0x401011"})
        with self.assertRaisesRegex(ValueError, "Stripped record exposes"):
            extract.check_expected_bounds(sample_record(), {**observation, "symbols": "stripped"})
        record = sample_record()
        record["function"]["name"] = "FUN_00401000"
        record["decompilation"]["text"] = "void FUN_00401000(void) { puts(0); }"
        # The legitimate 'target' call-record key is not a leaked name.
        extract.check_expected_bounds(record, {**observation, "symbols": "stripped"})
        with self.assertRaisesRegex(ValueError, "Retained record"):
            extract.check_expected_bounds(record, observation)
        record["decompilation"]["text"] += " target();"
        with self.assertRaisesRegex(ValueError, "Stripped record exposes"):
            extract.check_expected_bounds(record, {**observation, "symbols": "stripped"})

    def test_truth_benchmark_treatment_and_path_leaks(self):
        for text in ("Juliet", "CWE121_Stack", "goodG2B", "sample_bad", "vulnerable_CWE-121",
                     "not_vulnerable", "VARIANT_FIXED", "fixed", "O0", "O2", "retained", "stripped",
                     "/experiment/file.c", "corpus/pairs/p01.c", "build/oracle/p01", str(extract.PROJECT_ROOT)):
            record = sample_record()
            record["decompilation"]["text"] = text
            with self.subTest(text=text), self.assertRaises(ValueError):
                extract.scan_record_for_leaks(record)
        record = sample_record()
        record["decompilation"]["optimization"] = "O2"
        with self.assertRaisesRegex(ValueError, "private metadata"):
            extract.scan_record_for_leaks(record)

    def test_duplicate_json_keys_and_nonstandard_constants(self):
        with tempfile.TemporaryDirectory() as directory:
            raw = Path(directory) / "export.json"
            for content in ('{"schema_version":1,"schema_version":2}', '{"value":NaN}'):
                raw.write_text(content)
                with self.assertRaises(ValueError):
                    extract.load_record(raw)


class ExtractionPipelineTests(unittest.TestCase):
    def setUp(self):
        self.config = extract.load_config()
        temporary = tempfile.TemporaryDirectory(prefix="extract-tests-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        patcher = patch.object(extract, "PROJECT_ROOT", self.root)
        patcher.start()
        self.addCleanup(patcher.stop)
        (self.root / "config.json").write_text(json.dumps(self.config))
        (self.root / "ghidra").mkdir()
        (self.root / "ghidra/ExtractFunction.java").touch()
        self.rows = []
        for pair, cwe in (("p01", "CWE-121"), ("p08", "CWE-122")):
            for variant in ("vulnerable", "fixed"):
                for optimization in ("O0", "O2"):
                    for symbols in ("retained", "stripped"):
                        identifier = f"r{len(self.rows) + 1:04d}"
                        stem = f"{pair}_{variant}_{optimization}"
                        self.rows.append(dict(
                            observation_id=identifier, pair_id=pair, variant=variant,
                            truth="not_vulnerable" if variant == "fixed" else f"vulnerable_{cwe}",
                            cwe=cwe, optimization=optimization, symbols=symbols,
                            source_path=f"corpus/pairs/{pair}.c", oracle_binary=f"build/oracle/{stem}",
                            analysis_binary=f"build/{symbols}/{stem}",
                            record_path=f"data/pilot_records/{identifier}.json", target_function="target",
                            target_start="0x401000", target_end="0x401010", text_sha256="a" * 64,
                            analysis_sha256=hashlib.sha256(b"fixture").hexdigest()))
                        binary = self.root / self.rows[-1]["analysis_binary"]
                        binary.parent.mkdir(parents=True, exist_ok=True)
                        binary.write_bytes(b"fixture")
        self.write_table(self.rows)

    def write_table(self, rows, filename="pilot_observations.csv"):
        directory = self.root / "data/private"
        directory.mkdir(parents=True, exist_ok=True)
        with (directory / filename).open("w", newline="") as stream:
            writer = csv.DictWriter(stream, fieldnames=sorted(extract.OBSERVATION_FIELDS))
            writer.writeheader()
            writer.writerows(rows)

    def test_load_balanced_sorted_pilot_and_reject_invalid_tables(self):
        self.write_table(list(reversed(self.rows)))
        self.assertEqual(extract.load_observations("pilot"), self.rows)
        for mutation in ("incomplete", "duplicate", "path", "condition", "partners"):
            rows = copy.deepcopy(self.rows)
            if mutation == "incomplete":
                rows.pop()
            elif mutation == "duplicate":
                rows[1]["observation_id"] = rows[0]["observation_id"]
            elif mutation == "path":
                rows[0]["record_path"] = "data/records/r0001.json"
            elif mutation == "condition":
                rows[0]["symbols"] = "stripped"
            else:
                rows[0]["target_end"] = "0x401011"
            self.write_table(rows)
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                extract.load_observations("pilot")

    def test_final_count_and_stale_record_rejection(self):
        self.write_table(self.rows, "observations.csv")
        with self.assertRaisesRegex(ValueError, "160 observations"):
            extract.load_observations("final")
        records = self.root / "data/pilot_records"
        records.mkdir()
        (records / "r9999.json").write_text("{}")
        with self.assertRaisesRegex(ValueError, "Unexpected existing records"):
            extract.load_observations("pilot")

    def test_ghidra_version_is_checked(self):
        home = self.root / "installation"
        (home / "support").mkdir(parents=True)
        (home / "Ghidra").mkdir()
        launcher = home / "support/analyzeHeadless"
        launcher.touch(mode=0o700)
        properties = home / "Ghidra/application.properties"
        with patch.dict(os.environ, {"GHIDRA_HOME": str(home)}):
            properties.write_text("application.version=wrong\n")
            with self.assertRaisesRegex(ValueError, "Expected Ghidra"):
                extract.check_ghidra_version(self.config)
            properties.write_text(f"application.version={self.config['ghidra']['expected_version']}\n")
            self.assertEqual(extract.check_ghidra_version(self.config), launcher)

    def test_headless_gets_only_three_script_arguments_and_fresh_projects(self):
        projects = []

        def fake_run(command, **kwargs):
            self.assertEqual(command[command.index("-cspec") + 1], "gcc")
            script = command.index("ExtractFunction.java")
            arguments = command[script + 1:command.index("-deleteProject")]
            self.assertEqual(len(arguments), 3)
            self.assertEqual(arguments[0], self.rows[0]["target_start"])
            self.assertEqual(arguments[2], str(self.config["ghidra"]["decompiler_timeout_seconds"]))
            imported = Path(command[command.index("-import") + 1])
            self.assertEqual(imported.name, "program")
            self.assertEqual(imported.read_bytes(), b"fixture")
            projects.append(imported.parent)
            Path(arguments[1]).write_text(json.dumps(sample_record()))
            self.assertIn(str(imported.parent), kwargs["env"]["JAVA_TOOL_OPTIONS"])
            self.assertTrue(kwargs["check"])
            return subprocess.CompletedProcess(command, 0)

        hashes = {field: self.rows[0][field] for field in ("analysis_sha256", "text_sha256")}
        with patch.object(extract.subprocess, "run", side_effect=fake_run), \
             patch.object(extract, "binary_hashes", return_value=hashes):
            for _ in range(2):
                self.assertEqual(extract.run_headless(self.rows[0], self.config, Path("launcher")), sample_record())
        self.assertNotEqual(projects[0], projects[1])
        self.assertTrue(all(not path.exists() for path in projects))
        self.assertTrue((self.root / "build/logs/ghidra/r0001.log").is_file())

    def test_successful_process_without_export_fails(self):
        hashes = {field: self.rows[0][field] for field in ("analysis_sha256", "text_sha256")}
        with patch.object(extract.subprocess, "run", return_value=subprocess.CompletedProcess([], 0)), \
             patch.object(extract, "binary_hashes", return_value=hashes):
            with self.assertRaisesRegex(ValueError, "produced no record"):
                extract.run_headless(self.rows[0], self.config, Path("launcher"))

    def test_no_records_are_published_when_any_export_fails(self):
        error = sample_record()
        error["decompilation"] = {"status": "error", "text": ""}
        error["error"] = {"code": "extraction_failed", "message": "Function extraction failed."}
        with patch.object(extract, "load_observations", return_value=self.rows[:2]), \
             patch.object(extract, "check_ghidra_version", return_value=Path("launcher")), \
             patch.object(extract, "run_headless", side_effect=[sample_record(), error]):
            with self.assertRaisesRegex(ValueError, "r0002: Export failed"):
                extract.main(["--split", "pilot"])
        self.assertFalse((self.root / "data/pilot_records").exists())
        failure = self.root / "build/logs/ghidra/r0002.failed.json"
        self.assertEqual(json.loads(failure.read_text()), error)

    def test_script_changes_are_detected_before_publication(self):
        script = self.root / "ghidra/ExtractFunction.java"
        original = script.read_bytes()

        def changed_script(observation, config, launcher, script_source):
            self.assertEqual(script_source, original)
            script.write_bytes(b"// changed during extraction\n")
            return sample_record()

        with patch.object(extract, "load_observations", return_value=self.rows[:1]), \
             patch.object(extract, "check_ghidra_version", return_value=Path("launcher")), \
             patch.object(extract, "run_headless", side_effect=changed_script):
            with self.assertRaisesRegex(ValueError, "changed during extraction"):
                extract.main(["--split", "pilot"])
        self.assertFalse((self.root / "data/pilot_records").exists())

    def test_atomic_write_failure_preserves_previous_record(self):
        output = self.root / "record.json"
        output.write_text("previous\n")
        invalid = sample_record()
        invalid["unserializable"] = object()
        with self.assertRaises(TypeError):
            extract.write_record_atomically(output, invalid)
        self.assertEqual(output.read_text(), "previous\n")
        self.assertEqual(list(self.root.glob("tmp*")), [])
        extract.write_record_atomically(output, sample_record())
        first = output.read_bytes()
        extract.write_record_atomically(output, sample_record())
        self.assertEqual(output.read_bytes(), first)


if __name__ == "__main__":
    unittest.main()

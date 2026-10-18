import contextlib
import csv
import io
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from pipeline import build


class BuildValidationTests(unittest.TestCase):
    def test_final_rejects_incomplete_manifest(self):
        pairs = [pair for pair in build.load_pairs() if pair["pair_id"] != "p12"]
        with self.assertRaisesRegex(ValueError, "20 pairs.*160 observations.*19"):
            build.select_split(pairs, "final")

    def test_pilot_scope_is_explicit(self):
        pairs = [dict(pair) for pair in build.select_split(build.load_pairs(), "pilot")]
        pairs[0]["source_path"] = "corpus/pairs/p02.c"
        with self.assertRaisesRegex(ValueError, "limited to p01.c and p08.c"):
            build.select_split(pairs, "pilot")

    def test_tool_version_mismatch_fails(self):
        with patch.object(build, "run", return_value="99.0.0\n"):
            with self.assertRaisesRegex(ValueError, "GCC version mismatch"):
                build.check_tool_versions(build.load_config())

    def test_memory_write_requires_store_or_copy(self):
        for instruction in ("mov QWORD PTR [rsp+0x8],rax", "movups XMMWORD PTR [rax],xmm0",
                            "call 401030 <memcpy@plt>", "jmp 401030 <strcpy@plt>"):
            build.check_memory_write("  401000: " + instruction)
        for instruction in ("lea rdi,[rsp+0x8]", "mov rax,QWORD PTR [rsp]",
                            "push rax", "call 401030 <consume_text>"):
            with self.assertRaisesRegex(ValueError, "no recognizable memory store"):
                build.check_memory_write("  401000: " + instruction)

    def test_failed_command_keeps_combined_log(self):
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "failed.log"
            with self.assertRaises(subprocess.CalledProcessError):
                build.run([sys.executable, "-c",
                           "import sys; print('stdout'); print('stderr', file=sys.stderr); sys.exit(7)"], log)
            self.assertIn("stdout", log.read_text())
            self.assertIn("stderr", log.read_text())


@unittest.skipUnless(all(shutil.which(tool) for tool in
                         ("gcc-15", "objcopy", "strip", "readelf", "objdump")),
                     "Requires GCC 15 and GNU binutils")
class PilotBuildTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="build-tests-")
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.root = Path(cls.temporary.name)
        for source in ("config.json", "compile.sh", "corpus/manifest.csv"):
            destination = cls.root / source
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(build.PROJECT_ROOT / source, destination)
        shutil.copytree(build.PROJECT_ROOT / "corpus/pairs", cls.root / "corpus/pairs")
        cls.root_patch = patch.object(build, "PROJECT_ROOT", cls.root)
        cls.root_patch.start()
        cls.addClassCleanup(cls.root_patch.stop)
        with contextlib.redirect_stdout(io.StringIO()):
            build.main(["--split", "pilot"])
        cls.table = cls.root / "data/private/pilot_observations.csv"
        cls.table_bytes = cls.table.read_bytes()
        with cls.table.open(newline="") as stream:
            cls.rows = list(csv.DictReader(stream))
        cls.master = cls.root / cls.rows[0]["oracle_binary"]
        cls.retained = cls.root / cls.rows[0]["analysis_binary"]
        cls.stripped = cls.root / cls.rows[1]["analysis_binary"]

    def test_complete_pilot_table_and_logs(self):
        self.assertEqual(len(self.rows), 16)
        self.assertEqual(tuple(self.rows[0]), build.FIELDS)
        self.assertEqual({row["pair_id"] for row in self.rows}, {"p01", "p08"})
        self.assertEqual({row["truth"] for row in self.rows},
                         {"vulnerable_CWE-121", "vulnerable_CWE-122", "not_vulnerable"})
        for row in self.rows:
            self.assertTrue(row["record_path"].startswith("data/pilot_records/r"))
            self.assertTrue((self.root / row["analysis_binary"]).is_file())
            self.assertGreater(int(row["target_end"], 16), int(row["target_start"], 16))
        logs = sorted((self.root / "build/logs").rglob("*.log"))
        self.assertEqual(len(logs), 8)
        for log in logs:
            text = log.read_text()
            self.assertEqual(text.count("--master"), 1)
            self.assertIn("--strip-debug", text)
            self.assertIn("--strip-all", text)
            self.assertIn("PASS: structural artifact checks and memory-write rejection gate", text)
        self.assertFalse((self.root / "data/private/observations.csv").exists())

    def test_table_is_deterministic_and_incomplete_write_preserves_it(self):
        pairs = build.select_split(build.load_pairs(), "pilot")
        build.write_observations(list(reversed(self.rows)), pairs, "pilot")
        self.assertEqual(self.table.read_bytes(), self.table_bytes)
        with self.assertRaisesRegex(ValueError, "observation count"):
            build.write_observations(self.rows[:-1], pairs, "pilot")
        self.assertEqual(self.table.read_bytes(), self.table_bytes)

    def test_missing_target_and_non_called_function_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "exactly one"):
            build.read_function_bounds(self.master, "absent_target")
        with self.assertRaisesRegex(ValueError, "does not directly call"):
            build.check_direct_call(self.master, "_start")

    def test_text_corruption_is_rejected(self):
        section = build.read_sections(self.stripped)[".text"]
        data = bytearray(self.stripped.read_bytes())
        data[section["offset"]] ^= 1
        corrupted = self.root / "corrupted"
        corrupted.write_bytes(data)
        with self.assertRaisesRegex(ValueError, ".text hashes differ"):
            build.verify_artifacts(self.master, self.retained, corrupted, "copy_message")

    def test_benchmark_labels_are_rejected(self):
        contaminated = self.root / "contaminated"
        for label in (b"Juliet", b"CWE121_Stack", b"goodG2B", b"sample_bad", b"vulnerable", b"fixed"):
            contaminated.write_bytes(self.stripped.read_bytes() + b"\0" + label + b"\0")
            with self.assertRaisesRegex(ValueError, "Prohibited benchmark label"):
                build.scan_for_leaks(contaminated)

    def test_target_name_leak_is_rejected(self):
        contaminated = self.root / "target-leak"
        contaminated.write_bytes(self.stripped.read_bytes() + b"\0copy_message_extra\0")
        with self.assertRaisesRegex(ValueError, "Stripped target name remains"):
            build.verify_artifacts(self.master, self.retained, contaminated, "copy_message")

    def test_dwarf_and_unstripped_symbols_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "DWARF remains"):
            build.verify_artifacts(self.master, self.master, self.stripped, "copy_message")
        with self.assertRaisesRegex(ValueError, "Ordinary symbols remain"):
            build.verify_artifacts(self.master, self.retained, self.retained, "copy_message")

    def test_final_failure_writes_no_partial_table(self):
        with patch.object(build, "compile_master", side_effect=subprocess.CalledProcessError(1, ["gcc-15"])):
            with self.assertRaises(subprocess.CalledProcessError):
                build.main(["--split", "final"])
        self.assertFalse((self.root / "data/private/observations.csv").exists())

    def test_forbidden_compiler_flags_are_rejected(self):
        config_path = self.root / "config.json"
        original = config_path.read_bytes()
        try:
            config = json.loads(original)
            config["compiler"]["common_flags"].append("-fno-builtin")
            config_path.write_text(json.dumps(config))
            with self.assertRaisesRegex(ValueError, "required experimental flags"):
                build.load_config()
        finally:
            config_path.write_bytes(original)


if __name__ == "__main__":
    unittest.main()

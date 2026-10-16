"""Optional real-Ghidra checks: set GHIDRA_HOME to enable them.

All projects, Java preferences, caches, fixtures, and output stay in a temporary
directory. These tests do not run or modify the corpus binaries.
"""

import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest


PROJECT_ROOT = Path(__file__).resolve().parents[1]
GHIDRA_HOME = os.environ.get("GHIDRA_HOME")
HEADLESS = Path(GHIDRA_HOME) / "support/analyzeHeadless" if GHIDRA_HOME else None
TOOLS_AVAILABLE = all(shutil.which(tool) for tool in ("gcc-15", "objcopy", "strip", "nm"))


@unittest.skipUnless(HEADLESS and HEADLESS.is_file() and TOOLS_AVAILABLE,
                     "Set GHIDRA_HOME; requires Ghidra, GCC 15, and binutils")
class ExtractFunctionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="ghidra-export-tests-")
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.work = Path(cls.temporary.name)
        source = cls.work / "private_CWE121_bad.c"
        source.write_text('''#include <stdio.h>
volatile int selector;
__attribute__((naked, noinline, used)) void report(const char *text) {
    __asm__("jmp puts");
}
__attribute__((noinline, noclone, used)) void target(void) {
    if (selector) {
        report("first");
    } else {
        puts("second");
    }
}
int main(void) { target(); return 0; }
''')
        oracle = cls.work / "oracle"
        subprocess.run(["gcc-15", "-O0", "-g", "-fno-pie", "-no-pie", str(source),
                        "-o", str(oracle)], check=True, capture_output=True)
        symbols = subprocess.run(["nm", "-S", "--defined-only", str(oracle)],
                                 check=True, capture_output=True, text=True).stdout
        match = re.search(r"^(\w+) (\w+) T target$", symbols, re.MULTILINE)
        assert match, symbols
        cls.entry = int(match[1], 16)
        cls.end = cls.entry + int(match[2], 16)
        cls.tail_entry = int(re.search(r"^(\w+) \w+ T report$", symbols, re.MULTILINE)[1], 16)
        retained = cls.work / "retained"
        stripped = cls.work / "stripped"
        subprocess.run(["objcopy", "--strip-debug", str(oracle), str(retained)], check=True)
        subprocess.run(["strip", "--strip-all", "-o", str(stripped), str(retained)], check=True)

        # Redirect Java's state, including LaunchSupport's settings, as well as
        # Ghidra's own settings/cache directories for isolated headless runs.
        profile = cls.work / "profile"
        profile.mkdir()
        properties = {
            "user.home": profile, "application.settingsdir": cls.work / "settings",
            "application.cachedir": cls.work / "cache", "application.tempdir": cls.work / "tmp",
        }
        environment = {**os.environ, "JAVA_TOOL_OPTIONS": " ".join(
            f"-D{key}={value}" for key, value in properties.items())}
        cls.outputs = {}
        for binary in (retained, stripped):
            directory = cls.work / f"{binary.name}-output"
            directory.mkdir()
            command = [str(HEADLESS), str(cls.work), f"project_{binary.name}",
                       "-processor", "x86:LE:64:default", "-cspec", "gcc",
                       "-import", str(binary), "-scriptPath", str(PROJECT_ROOT / "ghidra"),
                       "-max-cpu", "2", "-analysisTimeoutPerFile", "60", "-deleteProject",
                       "-log", str(directory / "headless.log"),
                       "-scriptlog", str(directory / "script.log")]
            for address, filename, timeout in (
                (hex(cls.entry), "one", "60"), (hex(cls.entry), "two", "60"),
                (hex(cls.entry + 1), "inside", "60"), ("0x1", "missing", "60"),
                (hex(cls.entry), "invalid_timeout", "0"), ("invalid", "invalid_address", "60"),
                (hex(cls.tail_entry), "tail", "60"),
            ):
                command += ["-postScript", "ExtractFunction.java", address,
                            str(directory / f"{filename}.json"), timeout]
            with (directory / "console.log").open("w") as log:
                result = subprocess.run(command, check=True, env=environment, stdout=log,
                                        stderr=subprocess.STDOUT, timeout=180)
            assert result.returncode == 0
            cls.outputs[binary.name] = directory

    def record(self, condition, name="one"):
        return json.loads((self.outputs[condition] / f"{name}.json").read_text())

    def test_schema_addresses_and_decompilation(self):
        for condition in self.outputs:
            record = self.record(condition)
            self.assertEqual(set(record), {"schema_version", "architecture", "function",
                                           "instructions", "calls", "decompilation"})
            self.assertEqual(record["schema_version"], 1)
            self.assertEqual(record["architecture"], "x86-64")
            self.assertEqual(record["function"]["entry"], hex(self.entry))
            self.assertEqual(record["function"]["end"], hex(self.end))
            self.assertEqual(record["decompilation"]["status"], "ok")
            self.assertTrue(record["decompilation"]["text"].strip())
            addresses = [int(item["address"], 16) for item in record["instructions"]]
            self.assertEqual(addresses, sorted(set(addresses)))
            self.assertEqual(addresses[0], self.entry)
            for item in record["instructions"]:
                self.assertEqual(set(item), {"address", "mnemonic", "operands"})
                self.assertRegex(item["address"], r"^0x[0-9a-f]+$")
                self.assertIsInstance(item["operands"], str)

    def test_repeated_and_containing_address_exports_are_identical(self):
        for directory in self.outputs.values():
            one = (directory / "one.json").read_bytes()
            self.assertEqual(one, (directory / "two.json").read_bytes())
            self.assertEqual(one, (directory / "inside.json").read_bytes())

    def test_names_follow_the_imported_binary(self):
        self.assertEqual(self.record("retained")["function"]["name"], "target")
        self.assertNotEqual(self.record("stripped")["function"]["name"], "target")
        # The exporter resolves report's jump thunk to the imported puts name.
        self.assertIn("puts", {call["target"] for call in self.record("retained")["calls"]})
        for directory in self.outputs.values():
            self.assertNotIn("CWE121", (directory / "one.json").read_text())
            self.assertNotIn(str(self.work), (directory / "one.json").read_text())

    def test_calls_include_imports_and_tail_jumps_but_exclude_local_branches(self):
        for condition in self.outputs:
            record = self.record(condition)
            calls = record["calls"]
            self.assertIn("puts", {call["target"] for call in calls})
            call_addresses = [int(call["address"], 16) for call in calls]
            self.assertEqual(call_addresses, sorted(call_addresses))
            mnemonics = {item["address"]: item["mnemonic"].lower()
                         for item in record["instructions"]}
            self.assertTrue(any(mnemonic.startswith("j") for mnemonic in mnemonics.values()))
            self.assertTrue(all(mnemonics[call["address"]] == "call" for call in calls))
            tail = self.record(condition, "tail")
            jump = next(item for item in tail["instructions"] if item["mnemonic"].lower() == "jmp")
            self.assertEqual(tail["calls"], [{"address": jump["address"], "target": "puts"}])

    def test_missing_function_and_invalid_arguments_are_structured_errors(self):
        for condition in self.outputs:
            for filename, code in (("missing", "function_not_found"),
                                   ("invalid_timeout", "invalid_arguments"),
                                   ("invalid_address", "invalid_arguments")):
                record = self.record(condition, filename)
                self.assertEqual(record["error"]["code"], code)
                self.assertIsNone(record["function"])
                self.assertEqual(record["instructions"], [])
                self.assertEqual(record["calls"], [])
                self.assertEqual(record["decompilation"], {"status": "not_run", "text": ""})

@unittest.skipUnless(HEADLESS and HEADLESS.is_file() and TOOLS_AVAILABLE,
                     'Set GHIDRA_HOME; requires Ghidra, GCC 15, and binutils')
class ProductionABIExtractionTests(unittest.TestCase):
    def test_known_allocation_and_copy_arguments_through_production(self):
        from unittest.mock import patch
        from pipeline import extract
        with tempfile.TemporaryDirectory(prefix='production-abi-') as directory:
            root = Path(directory)
            source = root / 'fixture.c'
            source.write_text('''#include <stdlib.h>
#include <string.h>
#include <stdio.h>
__attribute__((noinline,used)) void target(char *src) {
    char *p = malloc(10);
    strncpy(p, src, 11);
    puts(p);
    free(p);
}
int main(int argc, char **argv) { target(argv[argc-1]); }
''')
            binary = root / 'build/retained/fixture'
            binary.parent.mkdir(parents=True)
            subprocess.run(['gcc-15', '-O2', '-fno-builtin', '-U_FORTIFY_SOURCE', '-D_FORTIFY_SOURCE=0', '-fno-pie', '-no-pie',
                            str(source), '-o', str(binary)], check=True, capture_output=True)
            symbols = subprocess.check_output(['nm', '-S', '--defined-only', str(binary)], text=True)
            match = re.search(r'^(\w+) (\w+) T target$', symbols, re.MULTILINE)
            entry, size = int(match[1], 16), int(match[2], 16)
            row = dict(observation_id='r0001', analysis_binary='build/retained/fixture', symbols='retained',
                       target_start=hex(entry), target_end=hex(entry+size), target_function='target',
                       **extract.binary_hashes(binary.read_bytes()))
            (root / 'ghidra').mkdir()
            shutil.copy2(PROJECT_ROOT / 'ghidra/ExtractFunction.java', root / 'ghidra/ExtractFunction.java')
            config = extract.load_config()
            with patch.object(extract, 'PROJECT_ROOT', root):
                record = extract.run_headless(row, config, HEADLESS)
                extract.validate_record(record)
                extract.check_expected_bounds(record, row)
                text = record['decompilation']['text']
                self.assertRegex(text, r'malloc\((?:10|0xa)\)')
                self.assertRegex(text, r'strncpy\([^;]+,(?:0xb|11)\)')
                config['ghidra']['compiler_spec'] = 'windows'
                wrong = extract.run_headless(row, config, HEADLESS)
                self.assertEqual(wrong['error']['code'], 'unsupported_compiler_spec')
                with self.assertRaises(ValueError):
                    extract.validate_record(wrong)


if __name__ == "__main__":
    unittest.main()

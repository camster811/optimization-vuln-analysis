"""Build integrity and independent memory-error checks for the added pairs."""
import contextlib
import csv
import io
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from pipeline import build, evaluate, extract


@unittest.skipUnless(all(shutil.which(tool) for tool in
                         ("gcc-15", "objcopy", "strip", "readelf", "objdump")),
                     "Requires GCC 15 and GNU binutils with AddressSanitizer")
class ExtendedCorpusTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="extended-corpus-")
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.root = Path(cls.temporary.name)
        for name in ("config.json", "compile.sh"):
            shutil.copyfile(build.PROJECT_ROOT / name, cls.root / name)
        shutil.copytree(build.PROJECT_ROOT / "corpus", cls.root / "corpus")
        with patch.object(build, "PROJECT_ROOT", cls.root), contextlib.redirect_stdout(io.StringIO()):
            build.main(["--split", "final"])

    def test_complete_balanced_build(self):
        with (self.root / "data/private/observations.csv").open(newline="") as stream:
            rows = list(csv.DictReader(stream))
        self.assertEqual(len(rows), 160)
        self.assertEqual({row["observation_id"] for row in rows},
                         {f"r{i:04d}" for i in range(1, 161)})
        self.assertEqual(len({row["pair_id"] for row in rows}), 20)
        with patch.object(extract, "PROJECT_ROOT", self.root), \
             patch.object(evaluate, "PROJECT_ROOT", self.root):
            self.assertEqual(len(extract.load_observations("final")), 160)
            self.assertEqual(len(evaluate.load_truth()), 160)
        ids = {row["observation_id"] for row in rows}
        static = dict.fromkeys(ids)
        runs = {identifier: [{"repetition": n} for n in (1, 2, 3)] for identifier in ids}
        evaluate.validate_completeness(rows, static, runs)
        with self.assertRaisesRegex(ValueError, "160 observations"):
            evaluate.validate_completeness(rows[:80], static, runs)
        runs["r0160"].pop()
        with self.assertRaisesRegex(ValueError, "three saved runs"):
            evaluate.validate_completeness(rows, static, runs)
        for index in range(13, 23):
            group = [row for row in rows if row["pair_id"] == f"p{index}"]
            self.assertEqual(len(group), 8)
            self.assertEqual({row["cwe"] for row in group},
                             {"CWE-121" if index < 18 else "CWE-122"})

    def test_new_pair_memory_behavior(self):
        # Instrumented builds validate the intended memory error, independently
        # of either analyzer. They never become experimental input binaries.
        for index in range(13, 23):
            for optimization in ("O0", "O2"):
                for variant in (0, 1):
                    with self.subTest(pair=index, optimization=optimization, variant=variant):
                        binary = self.root / f"asan-p{index}-{optimization}-{variant}"
                        compiled = subprocess.run([
                            "gcc-15", "-std=c11", "-g", f"-{optimization}",
                            "-U_FORTIFY_SOURCE", "-D_FORTIFY_SOURCE=0",
                            "-fsanitize=address", "-fno-omit-frame-pointer", "-fno-pie", "-no-pie",
                            f"-DVARIANT_FIXED={variant}",
                            str(self.root / f"corpus/pairs/p{index}.c"), "-o", str(binary),
                        ], capture_output=True, text=True, timeout=30)
                        self.assertEqual(compiled.returncode, 0, compiled.stderr)
                        result = subprocess.run([str(binary)], capture_output=True, text=True,
                                                timeout=10, env={**os.environ,
                                                "ASAN_OPTIONS": "detect_leaks=0:halt_on_error=1"})
                        if variant:
                            self.assertEqual(result.returncode, 0, result.stderr)
                            self.assertNotIn("ERROR: AddressSanitizer", result.stderr)
                        else:
                            self.assertNotEqual(result.returncode, 0)
                            self.assertIn("ERROR: AddressSanitizer", result.stderr)
                            if index < 18:
                                # ASan may call a wide partial stack overrun
                                # unknown-crash while still identifying its object.
                                self.assertRegex(result.stderr, r"stack-buffer-|located in stack")
                                self.assertIn("'destination'", result.stderr)
                            else:
                                self.assertIn("heap-buffer-overflow", result.stderr)
                            self.assertRegex(result.stderr, r"WRITE of size \d+")

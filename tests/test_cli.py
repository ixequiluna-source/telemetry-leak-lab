import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


class CliTests(unittest.TestCase):
    def test_executable_demo(self):
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "telemetry_leak_lab",
                    "demo",
                    "--out",
                    directory,
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(
                json.loads(result.stdout)["verdicts"], ["LEAK", "PASS", "INCONCLUSIVE"]
            )

    def test_invalid_input_replaces_stale_success(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            (target / "report.json").write_text('[{"verdict":"PASS"}]')
            args = [
                "compare",
                "--before",
                "missing",
                "--after",
                "missing",
                "--manifest",
                "missing",
            ]
            result = subprocess.run(
                [sys.executable, "-m", "telemetry_leak_lab", *args, "--out", directory],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(result.returncode, 2)
            self.assertEqual(
                json.loads((target / "report.json").read_text())[0]["verdict"],
                "INCONCLUSIVE",
            )
            self.assertNotIn("Traceback", result.stderr)

import copy
import json
import random
import tempfile
import unittest
from pathlib import Path

from telemetry_leak_lab.core import (
    InvalidExperiment,
    compare,
    load_json,
    lookup,
    scan,
    variants,
)
from telemetry_leak_lab.demo import fixtures, run
from telemetry_leak_lab.report import write_report


class TelemetryTests(unittest.TestCase):
    def setUp(self):
        self.before, self.weak, self.after, self.spec = fixtures()

    def test_demo_has_negative_positive_and_lost_signal_controls(self):
        self.assertEqual(
            [r["verdict"] for r in run()], ["LEAK", "PASS", "INCONCLUSIVE"]
        )

    def test_all_documented_encodings_are_detectable(self):
        canary = "Synthetic +/secret-4829"
        for name, value in variants(canary).items():
            with self.subTest(encoding=name):
                self.assertTrue(scan({"event": value}, {"test": canary}))

    def test_hash_is_still_detected(self):
        report = compare(self.before, self.weak, self.spec)
        self.assertEqual(report["verdict"], "LEAK")
        self.assertEqual(report["findings"][0]["encoding"], "sha256")

    def test_report_contains_no_known_canary_variants(self):
        with tempfile.TemporaryDirectory() as directory:
            write_report(
                directory,
                "telemetry",
                "synthetic",
                [compare(self.before, self.weak, self.spec)],
            )
            for path in Path(directory).iterdir():
                text = path.read_text()
                for value in self.spec["canaries"].values():
                    for encoded in variants(value).values():
                        self.assertNotIn(encoded, text)

    def test_secret_in_key_is_detected_without_echoing_path(self):
        secret = self.spec["canaries"]["patient"]
        finding = scan({secret: "public"}, self.spec["canaries"])
        self.assertTrue(finding)
        self.assertNotIn(secret, json.dumps(finding))

    def test_missing_baseline_is_not_pass(self):
        self.spec["canaries"]["absent"] = "Synthetic-unobserved-4983"
        self.assertEqual(
            compare(self.before, self.after, self.spec)["verdict"], "INCONCLUSIVE"
        )

    def test_lost_control_is_not_pass(self):
        self.after["resourceLogs"] = []
        self.assertEqual(
            compare(self.before, self.after, self.spec)["verdict"], "INCONCLUSIVE"
        )

    def test_failed_control_does_not_hide_real_leak(self):
        self.weak["resourceLogs"] = []
        self.assertEqual(compare(self.before, self.weak, self.spec)["verdict"], "LEAK")

    def test_no_controls_rejected(self):
        self.spec["controls"] = []
        with self.assertRaises(InvalidExperiment):
            compare(self.before, self.after, self.spec)

    def test_empty_output_rejected(self):
        for value in [{}, [], None, "", 42]:
            with self.subTest(value=value), self.assertRaises(InvalidExperiment):
                compare(self.before, value, self.spec)

    def test_duplicate_canaries_rejected(self):
        self.spec["canaries"]["email"] = self.spec["canaries"]["patient"]
        with self.assertRaises(InvalidExperiment):
            compare(self.before, self.after, self.spec)

    def test_duplicate_json_keys_rejected(self):
        self.check_bad_json(b'{"a":1,"a":2}')

    def test_invalid_numbers_rejected(self):
        for raw in [b'{"a":NaN}', b'{"a":Infinity}', b'{"a":1e999}']:
            with self.subTest(raw=raw):
                self.check_bad_json(raw)

    def test_input_limit(self):
        self.check_bad_json(b" " * (2 * 1024 * 1024 + 1))

    def test_invalid_unicode(self):
        self.check_bad_json(b'{"a":"\xff"}')

    def check_bad_json(self, raw):
        with tempfile.TemporaryDirectory() as directory:
            p = Path(directory) / "bad.json"
            p.write_bytes(raw)
            with self.assertRaises(InvalidExperiment):
                load_json(p)

    def test_depth_limit(self):
        document = {"a": "value"}
        for _ in range(35):
            document = {"a": document}
        with self.assertRaises(InvalidExperiment):
            scan(document, self.spec["canaries"])

    def test_pointer_escaping_and_type_exactness(self):
        self.assertEqual(lookup({"a/b": {"~x": [7]}}, "/a~1b/~0x/0"), 7)
        self.spec["controls"] = [{"pointer": "/check", "expected": True}]
        self.before["check"] = 1
        self.after["check"] = 1
        self.assertEqual(
            compare(self.before, self.after, self.spec)["verdict"], "INCONCLUSIVE"
        )

    def test_deterministic_nonmutating(self):
        old = copy.deepcopy((self.before, self.after, self.spec))
        self.assertEqual(
            compare(*[self.before, self.after, self.spec]),
            compare(self.before, self.after, self.spec),
        )
        self.assertEqual(old, (self.before, self.after, self.spec))

    def test_seeded_nested_canaries(self):
        randomizer = random.Random(4829)
        for index in range(60):
            value = "SYNTHETIC-" + str(randomizer.getrandbits(80))
            wrapped = {"log": [{"body": value}]}
            self.assertTrue(scan(wrapped, {"probe": value}), index)

    def test_numeric_only_canaries_are_rejected(self):
        self.spec["canaries"]["patient"] = "123456789012"
        with self.assertRaises(InvalidExperiment):
            compare(self.before, self.after, self.spec)


if __name__ == "__main__":
    unittest.main()

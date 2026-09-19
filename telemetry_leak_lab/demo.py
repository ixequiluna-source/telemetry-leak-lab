"""Synthetic nested telemetry examples, including a pseudonymous identifier."""

import copy

from .core import compare, variants


def fixtures():
    canaries = {
        "patient": "SYNTHETIC-PATIENT-4829",
        "email": "synthetic+lab@example.invalid",
    }
    before = {
        "resourceLogs": [
            {
                "scopeLogs": [
                    {
                        "logRecords": [
                            {
                                "traceId": "public-trace-001",
                                "body": {"stringValue": canaries["email"]},
                                "attributes": [
                                    {
                                        "key": "patient.id",
                                        "value": {"stringValue": canaries["patient"]},
                                    }
                                ],
                            }
                        ]
                    }
                ]
            }
        ],
        "spanEvents": [
            {
                "name": "lookup",
                "attributes": {"patient.hash": variants(canaries["patient"])["sha256"]},
            }
        ],
    }
    spec = {
        "canaries": canaries,
        "controls": [
            {
                "pointer": "/resourceLogs/0/scopeLogs/0/logRecords/0/traceId",
                "expected": "public-trace-001",
            }
        ],
    }
    weak = copy.deepcopy(before)
    weak["resourceLogs"][0]["scopeLogs"][0]["logRecords"][0]["body"] = {
        "stringValue": "[removed]"
    }
    weak["resourceLogs"][0]["scopeLogs"][0]["logRecords"][0]["attributes"] = []
    strong = copy.deepcopy(weak)
    strong["spanEvents"][0]["attributes"] = {}
    return before, weak, strong, spec


def run():
    before, weak, strong, spec = fixtures()
    broken = {"unrelated": "empty processing is not evidence"}
    results = []
    for name, output in [
        ("incomplete redaction", weak),
        ("configured redaction", strong),
        ("dropped useful telemetry", broken),
    ]:
        result = compare(before, output, spec)
        result["experiment"] = name
        results.append(result)
    return results

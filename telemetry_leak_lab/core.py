"""Known-canary detection in parsed JSON exports, not general-purpose PII discovery."""

import base64
import hashlib
import json
import math
import re
from pathlib import Path
from urllib.parse import quote, quote_plus

MAX_BYTES = 2 * 1024 * 1024
MAX_DEPTH = 32


class InvalidExperiment(ValueError):
    """Invalid or unbounded experiment; messages must never include input values."""


def load_json(path):
    with Path(path).open("rb") as source:
        raw = source.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise InvalidExperiment("JSON input exceeds 2 MiB")

    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise InvalidExperiment("Duplicate JSON key")
            result[key] = value
        return result

    def constant(_value):
        raise InvalidExperiment("Non-finite JSON number")

    try:
        data = json.loads(
            raw.decode("utf-8"), object_pairs_hook=pairs, parse_constant=constant
        )
    except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise InvalidExperiment("Invalid JSON document") from exc
    validate_document(data)
    return data


def validate_document(data):
    if not isinstance(data, (list, dict)) or not data:
        raise InvalidExperiment("A nonempty JSON object or array is required")
    list(strings(data))


def strings(value, path="$", depth=0):
    if depth > MAX_DEPTH:
        raise InvalidExperiment("Document exceeds maximum nesting depth")
    if isinstance(value, dict):
        for index, (key, item) in enumerate(value.items()):
            if not isinstance(key, str):
                raise InvalidExperiment("Object keys must be strings")
            # Ordinal paths avoid echoing a secret used as a JSON key.
            child = f"{path}/k{index}"
            yield child + "@key", key
            yield from strings(item, child, depth + 1)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield from strings(item, f"{path}/[{index}]", depth + 1)
    elif isinstance(value, str):
        yield path, value
    elif isinstance(value, float) and not math.isfinite(value):
        raise InvalidExperiment("Non-finite JSON number")
    elif value is not None and not isinstance(value, (int, float, bool)):
        raise InvalidExperiment("Unsupported JSON value")


def variants(value):
    raw = value.encode("utf-8")
    b64 = base64.b64encode(raw).decode()
    url64 = base64.urlsafe_b64encode(raw).decode()
    return {
        "raw": value,
        "url": quote(value, safe=""),
        "form": quote_plus(value),
        "base64": b64,
        "base64-unpadded": b64.rstrip("="),
        "base64url": url64,
        "base64url-unpadded": url64.rstrip("="),
        "hex": raw.hex(),
        "sha256": hashlib.sha256(raw).hexdigest(),
    }


def manifest(data):
    if not isinstance(data, dict) or set(data) != {"canaries", "controls"}:
        raise InvalidExperiment("Manifest requires canaries and controls")
    canaries = data["canaries"]
    controls = data["controls"]
    if not isinstance(canaries, dict) or not 1 <= len(canaries) <= 32:
        raise InvalidExperiment("Use 1 to 32 canaries")
    if not isinstance(controls, list) or not 1 <= len(controls) <= 32:
        raise InvalidExperiment("At least one bounded preservation control is required")
    for key, value in canaries.items():
        if not isinstance(key, str) or not re.fullmatch(r"[a-z][a-z0-9_-]{0,31}", key):
            raise InvalidExperiment("Canary IDs must be short public labels")
        if (
            not isinstance(value, str)
            or not 12 <= len(value) <= 256
            or not re.search(r"[A-Za-z]", value)
        ):
            raise InvalidExperiment(
                "Canaries need 12 to 256 characters and an ASCII letter"
            )
    if len(set(canaries.values())) != len(canaries):
        raise InvalidExperiment("Canary values must be distinct")
    for key in canaries:
        if any(
            v in key for value in canaries.values() for v in variants(value).values()
        ):
            raise InvalidExperiment("Public labels must not contain canaries")
    for control in controls:
        if not isinstance(control, dict) or set(control) != {"pointer", "expected"}:
            raise InvalidExperiment("Controls require pointer and expected")
        pointer = control["pointer"]
        if (
            not isinstance(pointer, str)
            or not pointer.startswith("/")
            or len(pointer) > 512
        ):
            raise InvalidExperiment("Control pointer must be bounded RFC 6901 pointer")
        if (
            not isinstance(control["expected"], (str, int, bool))
            or control["expected"] == ""
        ):
            raise InvalidExperiment("Expected control must be a nonempty scalar")
    return canaries, controls


def lookup(document, pointer):
    value = document
    try:
        for token in pointer[1:].split("/"):
            if re.search(r"~(?![01])", token):
                return object()
            key = token.replace("~1", "/").replace("~0", "~")
            if isinstance(value, list):
                if not re.fullmatch(r"0|[1-9][0-9]*", key):
                    return object()
                value = value[int(key)]
            elif isinstance(value, dict):
                value = value[key]
            else:
                return object()
        return value
    except (KeyError, IndexError, ValueError):
        return object()


def scan(document, canaries):
    findings = []
    compiled = [(label, variants(canary)) for label, canary in canaries.items()]
    for path, value in strings(document):
        for label, patterns in compiled:
            seen = set()
            for encoding, needle in patterns.items():
                if needle not in seen and needle in value:
                    findings.append(
                        {"canary": label, "encoding": encoding, "location": path}
                    )
                    seen.add(needle)
                    if len(findings) > 10000:
                        raise InvalidExperiment(
                            "Too many matches; narrow the experiment"
                        )
    return findings


def compare(before, after, specification):
    validate_document(before)
    validate_document(after)
    canaries, controls = manifest(specification)
    baseline = scan(before, canaries)
    leaks = scan(after, canaries)
    observed = {row["canary"] for row in baseline}
    missing = sorted(set(canaries) - observed)
    failed_controls = []
    for index, control in enumerate(controls):
        for phase, document in [("before", before), ("after", after)]:
            actual = lookup(document, control["pointer"])
            expected = control["expected"]
            if type(actual) is not type(expected) or actual != expected:
                failed_controls.append({"control": index + 1, "phase": phase})
    verdict = (
        "LEAK" if leaks else "INCONCLUSIVE" if missing or failed_controls else "PASS"
    )
    return {
        "experiment": "redaction comparison",
        "verdict": verdict,
        "summary": {
            "LEAK": "Known canary material remains after processing.",
            "INCONCLUSIVE": "Baseline or preservation controls did not establish a measurable experiment.",
            "PASS": "All known canaries were observed before, absent after, and configured controls survived.",
        }[verdict],
        "known_canaries": len(canaries),
        "missing_baseline": missing,
        "failed_controls": failed_controls,
        "findings": leaks,
        "scope": "Known variants in parsed JSON only; absence is not proof that all sensitive data is removed.",
    }

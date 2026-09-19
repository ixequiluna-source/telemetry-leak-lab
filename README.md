![telemetry-leak-lab — Redacted does not mean gone.](assets/cover.svg)

# telemetry-leak-lab

**Test what survives your telemetry redaction. Including the identifier you hashed.**

A small Python tool for comparing **before/after JSON exports** with known synthetic canaries. It looks for literal and encoded values, verifies that the canaries were present before processing, and checks that useful control data survived afterward.

[![Experiments](https://github.com/ixequiluna-source/telemetry-leak-lab/actions/workflows/verify.yml/badge.svg)](https://github.com/ixequiluna-source/telemetry-leak-lab/actions/workflows/verify.yml)
[Español](README.es.md) · [Design and limits](docs/DESIGN.md) · [Example report](docs/example-report.html) · [Author](https://ixequiluna.ai)

## Try the experiment

Python 3.11+, no runtime dependencies, no cloud account:

```sh
git clone https://github.com/ixequiluna-source/telemetry-leak-lab.git
cd telemetry-leak-lab
python -m telemetry_leak_lab demo --out artifacts
```

Open `artifacts/report.html` in your browser. The report is self-contained and works offline.

| Experiment | Expected result | Why |
| --- | --- | --- |
| Incomplete redaction | **LEAK** | Cleartext is gone, but a SHA-256-derived identifier remains. |
| Configured redaction | **PASS** | Known canaries are absent and the configured trace control survives. |
| Dropped useful telemetry | **INCONCLUSIVE** | A pipeline that destroys useful output has not demonstrated successful redaction. |

These are executed comparisons, not hard-coded report verdicts. The demo command exits successfully only when the expected negative and positive controls agree.

## Compare your synthetic exports

```sh
python -m telemetry_leak_lab compare --before examples/before.json --after examples/after.json --manifest examples/manifest.json --out artifacts
```

The manifest declares unique canaries and preservation controls using JSON Pointer:

```json
{
  "canaries": {"person": "SYNTHETIC-PERSON-4829"},
  "controls": [{"pointer": "/traceId", "expected": "public-trace-001"}]
}
```

Every canary must be found in the baseline. Every configured control must match before **and** after. The comparison exits **0** for PASS, **1** for LEAK and **2** for INCONCLUSIVE or invalid input. A processing error replaces a previous report with an inconclusive report when the output directory is writable.

Optional installation: `python -m pip install .`, then `telemetry-leak-lab demo`.

## What gets examined

- Parsed JSON string values and object keys, including nested log bodies, span attributes and exception messages.
- Literal text, standard URL/form encoding, Base64/Base64url (padded and unpadded), lowercase hexadecimal and SHA-256 hex.
- Reports identify public canary labels and ordinal locations; they do not copy raw matches or input keys.
- Input limits: 2 MiB per JSON file, depth 32, up to 32 canaries and 32 preservation controls, and 10,000 findings.
- Duplicate JSON keys, non-finite numbers, missing controls and empty outputs are rejected.

## What it does not prove

This is **known-canary testing**, not a general PII classifier, secret scanner or anonymization certification. Unknown values, different encodings, encryption, numeric-only canaries and data outside the supplied JSON exports are out of scope. The bundled example uses an OTLP-shaped JSON envelope; this tool does not validate the OTLP schema or start an OpenTelemetry Collector. Wire your actual processor separately and supply its exported before/after artifacts.

A PASS means only that the configured experiment passed. It does not establish GDPR, HIPAA or other regulatory compliance.

## Verify and extend

```sh
python -m pip install .
python -m unittest discover -s tests -v
python tools/check_demo.py
```

Tests cover encodings, hashed identifiers, nested keys, input limits, lost controls, contaminated baselines, report non-disclosure, CLI outcomes and reproducibility. CI also installs the package on three operating systems and two Python versions.

## Engineering context

[OpenTelemetry's sensitive-data guidance](https://opentelemetry.io/docs/security/handling-sensitive-data/) explains why applications must determine which data is sensitive. Its [redaction processor](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/processor/redactionprocessor) is a separate component you can evaluate with synthetic exports. Neither project endorses this tool.

Built and maintained by **[Dr. Ixequi Luna](https://ixequiluna.ai)**. MIT licensed; retain the copyright and license notice when reusing the code.

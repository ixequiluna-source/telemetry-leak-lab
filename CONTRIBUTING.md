# Contributing

Start with a reproducible synthetic counterexample. State the expected verdict, actual verdict, Python version and platform. Never attach real tenant tokens, patient data or telemetry from a customer.

Run `python -m unittest discover -s tests -v` and `python tools/check_demo.py`. A new detector needs a failing example, a passing control and a case where evidence is unavailable. Do not weaken an assertion to make CI green. Keep runtime dependencies at zero unless a documented need justifies a change.

Keep README, scope and examples aligned. Contributions follow the repository's MIT license. Do not claim a production integration was verified from fixture tests.

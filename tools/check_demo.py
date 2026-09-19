import json
import subprocess
import sys
from pathlib import Path

subprocess.run(
    [sys.executable, "-I", "-m", "telemetry_leak_lab", "demo", "--out", "artifacts"],
    check=True,
)
results = json.loads(Path("artifacts/report.json").read_text())
assert [r["verdict"] for r in results] == ["LEAK", "PASS", "INCONCLUSIVE"]
assert Path("artifacts/report.html").stat().st_size > 1000
print("Demo controls and report verified.")

"""Static, offline report; only sanitized experiment summaries enter this view."""

import hashlib
import html
import json
from pathlib import Path

CSS = """*{box-sizing:border-box}body{margin:0;background:#0b1017;color:#e8edf2;font:16px/1.65 system-ui,sans-serif}main{max-width:1120px;margin:auto;padding:56px 24px}header{display:flex;justify-content:space-between;border-bottom:1px solid #334252;padding-bottom:20px;gap:20px;flex-wrap:wrap}.label{color:#8bdcca;text-transform:uppercase;font-size:12px;letter-spacing:.14em}h1{font-size:clamp(36px,7vw,74px);line-height:1.05;letter-spacing:-.055em;max-width:900px;margin:64px 0 24px}h2{font-size:24px}.intro{color:#b3c2d0;max-width:780px;font-size:19px}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,260px),1fr));gap:18px;margin:40px 0}article{background:#131e2a;border:1px solid #34475a;border-radius:18px;padding:26px;min-width:0}.verdict{font-size:clamp(22px,3vw,30px);overflow-wrap:anywhere;font-weight:700;color:#a1e8bc}.bad{color:#ffb2b0}.neutral{color:#f5d58c}pre{white-space:pre-wrap;overflow-wrap:anywhere;font:13px/1.8 ui-monospace,monospace;background:#080d14;padding:20px;border-radius:12px}footer{border-top:1px solid #334252;margin-top:60px;padding-top:24px;color:#b3c2d0}a{color:#8bdcca}a:focus-visible{outline:3px solid #fff;outline-offset:5px}details{margin-top:24px}summary{cursor:pointer;min-height:44px}p{overflow-wrap:anywhere}@media print{body{background:white;color:black}article,pre{background:white;color:black}.verdict,.bad,.neutral,.label,a{color:black}}"""


def write_report(directory, title, subtitle, results):
    target = Path(directory)
    target.mkdir(parents=True, exist_ok=True)
    encoded = json.dumps(results, ensure_ascii=True, indent=2, allow_nan=False)
    (target / "report.json").write_text(encoded + "\n", encoding="utf-8")
    digest = hashlib.sha256(encoded.encode()).hexdigest()
    import base64

    style_hash = base64.b64encode(hashlib.sha256(CSS.encode()).digest()).decode()
    esc = html.escape
    cards = []
    for result in results:
        verdict = result["verdict"]
        tone = (
            "bad"
            if verdict in ("LEAK", "FAIL")
            else "neutral"
            if verdict == "INCONCLUSIVE"
            else ""
        )
        cards.append(
            f'<article><p class="label">{esc(result["experiment"])}</p><p class="verdict {tone}">{esc(verdict)}</p><p>{esc(result["summary"])}</p><details><summary>Inspect sanitized evidence</summary><pre>{esc(json.dumps(result, indent=2))}</pre></details></article>'
        )
    document = f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'sha256-{style_hash}'; img-src data:; base-uri 'none'; form-action 'none'"><link rel="icon" href="data:,"><title>{esc(title)} · Evidence report</title><style>{CSS}</style></head><body><main><header><strong>{esc(title)}</strong><span class="label">IX / SECURITY ENGINEERING</span></header><p class="label">Reproducible experiments · v0.1.0</p><h1>{esc(subtitle)}</h1><p class="intro">Synthetic inputs. Executed checks. Explicit failure states. This report describes the configured experiments; it is not a security certification.</p><section class="grid">{"".join(cards)}</section><details><summary>Report integrity</summary><p>SHA-256 of the indented JSON payload, without its final newline:</p><pre>{digest}</pre></details><footer>Built by <a href="https://ixequiluna.ai">Dr. Ixequi Luna</a> · Runs locally with Python. No external assets, analytics or scripts.</footer></main></body></html>"""
    (target / "report.html").write_text(document, encoding="utf-8")

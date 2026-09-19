import argparse
import json
import sys

from .core import InvalidExperiment, compare, load_json
from .demo import run
from .report import write_report


def main():
    parser = argparse.ArgumentParser(
        description="Known-canary telemetry redaction experiments; synthetic inputs only."
    )
    commands = parser.add_subparsers(dest="command", required=True)
    demo = commands.add_parser("demo")
    demo.add_argument("--out", default="artifacts")
    audit = commands.add_parser("compare")
    for name in ["before", "after", "manifest"]:
        audit.add_argument("--" + name, required=True)
    audit.add_argument("--out", default="artifacts")
    args = parser.parse_args()
    try:
        results = (
            run()
            if args.command == "demo"
            else [
                compare(
                    load_json(args.before),
                    load_json(args.after),
                    load_json(args.manifest),
                )
            ]
        )
        write_report(
            args.out, "telemetry-leak-lab", "Redacted does not mean gone.", results
        )
        print(json.dumps({"verdicts": [r["verdict"] for r in results]}))
        if args.command == "demo":
            return (
                0
                if [r["verdict"] for r in results] == ["LEAK", "PASS", "INCONCLUSIVE"]
                else 2
            )
        return {"PASS": 0, "LEAK": 1, "INCONCLUSIVE": 2}[results[0]["verdict"]]
    except (InvalidExperiment, OSError, RecursionError):
        try:
            write_report(
                args.out,
                "telemetry-leak-lab",
                "Experiment incomplete.",
                [
                    {
                        "experiment": "input or execution error",
                        "verdict": "INCONCLUSIVE",
                        "summary": "The experiment did not complete. No security conclusion is available.",
                    }
                ],
            )
        except OSError:
            pass
        print(
            "Experiment could not be completed; inspect input format, limits and output permissions.",
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

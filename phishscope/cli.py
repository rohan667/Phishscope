"""Command-line entry point."""
import argparse
from pathlib import Path
import sys

from .enrich import enrich_report
from .parser import parse_eml
from .report import as_json, as_markdown
from .scoring import analyze


def build_parser():
    parser = argparse.ArgumentParser(prog="phishscope", description="Explainable local phishing email triage (.eml).")
    parser.add_argument("files", nargs="+", help="One or more .eml files to analyze")
    parser.add_argument("-f", "--format", choices=("markdown", "json"), default="markdown", help="Report format")
    parser.add_argument("-o", "--output", help="Write report to a file instead of the terminal")
    parser.add_argument("--fail-on", choices=("benign", "suspicious", "malicious"), help="Return exit code 2 at or above this verdict")
    parser.add_argument("--enrich", action="store_true", help="Opt in to read-only VirusTotal URL/hash lookups")
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    reports = []
    try:
        for filename in args.files:
            path = Path(filename)
            if not path.is_file():
                raise ValueError(f"File not found: {filename}")
            report = analyze(parse_eml(path))
            if args.enrich:
                report = enrich_report(report)
            reports.append(report)
    except (OSError, ValueError) as exc:
        print(f"phishscope: error: {exc}", file=sys.stderr)
        return 1
    output = as_json(reports) if args.format == "json" else "\n\n---\n\n".join(as_markdown(item) for item in reports)
    if args.output:
        try:
            Path(args.output).write_text(output + "\n", encoding="utf-8")
        except OSError as exc:
            print(f"phishscope: could not write report: {exc}", file=sys.stderr)
            return 1
    else:
        print(output)
    if args.fail_on:
        threshold = {"benign": 0, "suspicious": 30, "malicious": 60}[args.fail_on]
        if any(report["score"] >= threshold for report in reports):
            return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

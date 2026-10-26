"""Command line interface: ``pii-guard scan --file input.txt``."""
import argparse
import json
import sys

from pii_guard.sanitizer import sanitize


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="pii-guard", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    scan = sub.add_parser("scan", help="tokenize PII in a file or stdin")
    scan.add_argument("--file", "-f", help="input file (default: read stdin)")
    scan.add_argument(
        "--json",
        action="store_true",
        help='print {"clean": ..., "audit": [...]} instead of plain text',
    )
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    if args.file:
        with open(args.file, encoding="utf-8") as fh:
            text = fh.read()
    else:
        text = sys.stdin.read()

    clean, vault = sanitize(text)
    if args.json:
        print(json.dumps({"clean": clean, "audit": vault.audit_log()}, indent=2))
    else:
        sys.stdout.write(clean)
        for rec in vault.audit_log():
            print(f"{rec['token']}  {rec['type']}  {rec['display']}", file=sys.stderr)
        print(f"{vault.count()} item(s) tokenized", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())

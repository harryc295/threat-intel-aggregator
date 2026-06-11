"""
Threat Intelligence Aggregator – CLI entry point

Usage examples:
  python cli.py --ioc 8.8.8.8
  python cli.py --ioc malicious.example.com --output-html report.html
  python cli.py --input-file iocs.json --output-json out.json --output-html out.html
"""

import argparse
import json
import logging
import sys
from datetime import datetime
from pathlib import Path

from dotenv import load_dotenv

import enricher
import dashboard

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("cli")


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="cli.py",
        description="Threat Intelligence Aggregator – enriches IPs, domains, and hashes using free APIs.",
    )
    src = p.add_mutually_exclusive_group(required=True)
    src.add_argument(
        "--ioc",
        metavar="IOC",
        help="Single IOC: IPv4 address, domain, or MD5/SHA1/SHA256 hash.",
    )
    src.add_argument(
        "--input-file",
        metavar="FILE",
        help='Path to a JSON file containing a list of IOCs: ["8.8.8.8", "example.com"]',
    )
    p.add_argument(
        "--output-json",
        metavar="FILE",
        default="",
        help="Path for the JSON report (default: report_<timestamp>.json).",
    )
    p.add_argument(
        "--output-html",
        metavar="FILE",
        default="",
        help="Path for the HTML dashboard (default: dashboard_<timestamp>.html).",
    )
    return p.parse_args()


def _load_iocs(args: argparse.Namespace) -> list[str]:
    if args.ioc:
        return [args.ioc.strip()]
    path = Path(args.input_file)
    if not path.exists():
        log.error("Input file not found: %s", path)
        sys.exit(1)
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, list):
        log.error("Input file must contain a JSON array of IOC strings.")
        sys.exit(1)
    return [str(x).strip() for x in raw if str(x).strip()]


def main() -> None:
    args = _parse_args()
    iocs = _load_iocs(args)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    json_out = args.output_json or f"report_{timestamp}.json"
    html_out = args.output_html or f"dashboard_{timestamp}.html"

    total = len(iocs)
    log.info("Enriching %d IOC(s)…", total)

    records = []
    for i, ioc in enumerate(iocs, 1):
        log.info("[%d/%d] Processing %s", i, total, ioc)
        try:
            record = enricher.enrich(ioc)
        except Exception as exc:
            log.error("Unexpected error for %s: %s", ioc, exc)
            record = {"ioc": ioc, "error": str(exc), "risk_score": 0, "enrichments": {}}
        records.append(record)

    Path(json_out).write_text(
        json.dumps(records, indent=2, default=str), encoding="utf-8"
    )
    log.info("JSON report → %s", json_out)

    dashboard.generate(json_out, html_out)
    log.info("Done. Open %s in your browser.", html_out)

    # Print a brief console summary
    high = sum(1 for r in records if r.get("risk_score", 0) >= 70)
    med = sum(1 for r in records if 30 <= r.get("risk_score", 0) < 70)
    low = total - high - med
    print(
        f"\n{'='*50}\n"
        f"  IOCs processed : {total}\n"
        f"  High risk (>=70): {high}\n"
        f"  Medium risk    : {med}\n"
        f"  Low / clean    : {low}\n"
        f"  JSON report    : {json_out}\n"
        f"  HTML dashboard : {html_out}\n"
        f"{'='*50}"
    )


if __name__ == "__main__":
    main()

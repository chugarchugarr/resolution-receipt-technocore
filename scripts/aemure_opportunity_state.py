#!/usr/bin/env python3
"""Resolve an AEMURE opportunity-state decision record from JSON."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from resolution_receipt.opportunity import OpportunityStateError, resolve_decision


def main() -> int:
    parser = argparse.ArgumentParser(description="AEMURE Opportunity-State Test v0.1")
    parser.add_argument("input", nargs="?", help="decision JSON file; omit to read stdin")
    parser.add_argument("--epsilon", type=float, default=1e-9)
    args = parser.parse_args()

    try:
        raw = Path(args.input).read_text(encoding="utf-8") if args.input else sys.stdin.read()
        decision = json.loads(raw)
        receipt = resolve_decision(decision, epsilon=args.epsilon)
    except (OSError, json.JSONDecodeError, OpportunityStateError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    json.dump(receipt, sys.stdout, indent=2, sort_keys=True, ensure_ascii=False)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

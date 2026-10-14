"""Jason Stys: read-only evaluation and policy-diff CLI; local execution never applies network changes."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# definition: main — line 34
# parameter: argv — line 34
# variable: parser — line 36
# variable: commands — line 39
# variable: replay — line 40
# variable: compare — line 50
# variable: args — line 55
# variable: _ — line 58
# variable: before — line 58
# variable: _ — line 59
# variable: after — line 59
# variable: delta — line 60
# variable: policy — line 70
# variable: sha — line 70
# variable: report — line 71
# variable: report_id — line 72
# variable: failures — line 73
# END CODE MAP

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from ztlab.analysis import difference
from ztlab.contracts import ContractError, load_policy
from ztlab.evidence import evaluate, private_file, save


def main(argv: list[str] | None = None) -> int:
    """Emit safe counts/digests and preserve old evidence; nonzero marks oracle drift or invalid input."""
    parser = argparse.ArgumentParser(
        description="Zero-trust segmentation lab — Jason Stys; no network changes"
    )
    commands = parser.add_subparsers(dest="command", required=True)
    replay = commands.add_parser("evaluate")
    replay.add_argument("--policy", type=Path, default=Path("examples/policy.json"))
    replay.add_argument("--cases", type=Path, default=Path("examples/requests.jsonl"))
    replay.add_argument(
        "--now",
        type=int,
        default=1000,
        help="Trusted synthetic clock tick, not real wall-clock expiry",
    )
    replay.add_argument("--out", type=Path, required=True)
    compare = commands.add_parser("diff")
    compare.add_argument("--before", type=Path, required=True)
    compare.add_argument("--after", type=Path, required=True)
    compare.add_argument("--now", type=int, default=1000)
    compare.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "diff":
            before, _ = load_policy(args.before)
            after, _ = load_policy(args.after)
            delta = difference(before, after, args.now)
            private_file(
                args.out, json.dumps(delta, sort_keys=True, indent=2).encode() + b"\n"
            )
            print(
                json.dumps(
                    {"added": len(delta["added"]), "removed": len(delta["removed"])}
                )
            )
            return 0
        policy, sha = load_policy(args.policy)
        report = evaluate(policy, sha, args.cases, args.now)
        report_id = save(args.out, report, policy, args.now)
        failures = report["case_count"] - report["oracle_matches"]
        print(
            json.dumps(
                {
                    "report_id": report_id,
                    "cases": report["case_count"],
                    "oracle_mismatches": failures,
                }
            )
        )
        return int(failures > 0)
    except (ContractError, OSError, ValueError) as error:
        print(
            json.dumps(
                {
                    "error": type(error).__name__,
                    "help": "See docs/usage.md; choose a new output path.",
                }
            ),
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

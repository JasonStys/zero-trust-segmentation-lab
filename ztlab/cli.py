"""Jason Stys: read-only evaluation and policy-diff CLI; local execution never applies network changes."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# definition: main — line 37
# parameter: argv — line 37
# variable: parser — line 39
# variable: commands — line 42
# variable: replay — line 43
# variable: compare — line 53
# variable: continuity — line 58
# variable: args — line 66
# variable: result — line 69
# variable: _ — line 81
# variable: before — line 81
# variable: _ — line 82
# variable: after — line 82
# variable: delta — line 83
# variable: policy — line 93
# variable: sha — line 93
# variable: report — line 94
# variable: report_id — line 95
# variable: failures — line 96
# END CODE MAP

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from ztlab.analysis import difference
from ztlab.continuity import preview, publish
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
    continuity = commands.add_parser(
        "continuity", help="Non-enforcing transport expiry and dependency review"
    )
    continuity.add_argument("--policy", type=Path, default=Path("examples/policy.json"))
    continuity.add_argument("--requirements", type=Path, required=True)
    continuity.add_argument("--start", type=int, required=True)
    continuity.add_argument("--end", type=int, required=True)
    continuity.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "continuity":
            result = preview(args.policy, args.requirements, args.start, args.end)
            publish(result, args.out)
            print(
                json.dumps(
                    {
                        "ticks": len(result["timeline"]),
                        "review_items": len(result["review_queue"]),
                    }
                )
            )
            return 0
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

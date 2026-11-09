"""Jason Stys: non-enforcing transport permission timeline and owner-authored dependency invariants."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# definition: preview — line 67
# parameter: end — line 68
# parameter: policy_path — line 68
# parameter: requirements_path — line 68
# parameter: start — line 68
# variable: path — line 73
# variable: p — line 77
# variable: policy — line 82
# variable: sha — line 82
# variable: stream — line 83
# variable: raw — line 84
# variable: data — line 85
# variable: requirements — line 93
# variable: seen_ids — line 94
# variable: seen_flows — line 95
# variable: e — line 96
# variable: known — line 96
# variable: item — line 97
# variable: row — line 98
# variable: name — line 99
# variable: owner — line 99
# variable: flow — line 100
# variable: boundaries — line 115
# variable: r — line 116
# variable: b — line 118
# variable: t — line 118
# variable: ticks — line 118
# variable: ticks — line 119
# variable: engine — line 120
# variable: timeline — line 121
# variable: previous — line 122
# variable: queue — line 123
# variable: tick — line 124
# variable: allowed — line 125
# variable: checks — line 126
# variable: item — line 127
# variable: decision — line 128
# variable: matches — line 129
# variable: check — line 130
# variable: previous — line 150
# definition: publish — line 166
# parameter: output — line 166
# parameter: result — line 166
# variable: target — line 168
# variable: p — line 169
# variable: text — line 172
# variable: page — line 174
# END CODE MAP

from __future__ import annotations

import hashlib
import html
import json
from dataclasses import asdict
from pathlib import Path
from typing import Any

from ztlab.admission import Attester, Engine
from ztlab.analysis import allowed_flows
from ztlab.contracts import Flow, fields, identifier, integer, load_policy, parse
from ztlab.evidence import private_file


def preview(
    policy_path: Path, requirements_path: Path, start: int, end: int
) -> dict[str, Any]:
    """Evaluate every effective validity/exception transition and just-before boundary; never apply or renew policy."""
    integer(start, 0, 2**31 - 1)
    integer(end, start, min(2**31 - 1, start + 3600))
    for path in (policy_path, requirements_path):
        if (
            any(
                p.is_symlink() or p.is_junction()
                for p in (path.absolute(), *path.absolute().parents)
            )
            or not path.is_file()
        ):
            raise ValueError("ordinary nonlinked policy/requirements required")
    policy, sha = load_policy(policy_path)
    with requirements_path.open("rb") as stream:
        raw = stream.read(65537)
    data = fields(parse(raw), {"schema", "requirements"})
    if (
        type(data["schema"]) is not int
        or data["schema"] != 1
        or not isinstance(data["requirements"], list)
        or not 1 <= len(data["requirements"]) <= 64
    ):
        raise ValueError("bounded continuity requirements")
    requirements = []
    seen_ids: set[str] = set()
    seen_flows: set[Flow] = set()
    known = {e.name for e in policy.endpoints}
    for item in data["requirements"]:
        row = fields(item, {"id", "owner", "flow", "expect"})
        name, owner = identifier(row["id"]), identifier(row["owner"])
        flow = Flow.from_json(row["flow"])
        if (
            flow.source not in known
            or flow.target not in known
            or flow.source == flow.target
            or row["expect"] not in ("allow", "deny")
            or name in seen_ids
            or flow in seen_flows
        ):
            raise ValueError("ambiguous requirement scope")
        seen_ids.add(name)
        seen_flows.add(flow)
        requirements.append(
            {"id": name, "owner": owner, "flow": flow, "expect": row["expect"]}
        )
    boundaries = {start, end, policy.created_at, policy.expires_at} | {
        r.until for r in policy.rules if r.until is not None
    }
    ticks = sorted(t for b in boundaries for t in (b - 1, b) if start <= t <= end)
    ticks = sorted(set(ticks))
    engine = Engine(policy, Attester())
    timeline = []
    previous: set[tuple[str, str, int]] | None = None
    queue = []
    for tick in ticks:
        allowed = allowed_flows(policy, tick)
        checks = []
        for item in requirements:
            decision = engine.transport(item["flow"], tick)
            matches = decision.allowed == (item["expect"] == "allow")
            check = {
                "id": item["id"],
                "owner": item["owner"],
                "flow": asdict(item["flow"]),
                "expected": item["expect"],
                "decision": asdict(decision),
                "matches": matches,
            }
            checks.append(check)
            if not matches:
                queue.append({"tick": tick, **check})
        timeline.append(
            {
                "tick": tick,
                "allowed": sorted(allowed),
                "added": [] if previous is None else sorted(allowed - previous),
                "removed": [] if previous is None else sorted(previous - allowed),
                "requirements": checks,
            }
        )
        previous = allowed
    return {
        "schema": 1,
        "kind": "transport_continuity_preview",
        "author": "Jason Stys",
        "policy_sha256": sha,
        "requirements_sha256": hashlib.sha256(raw).hexdigest(),
        "policy_revision": policy.revision,
        "start": start,
        "end": end,
        "timeline": timeline,
        "review_queue": queue,
        "scope": "All effective transport-policy change boundaries in the bounded synthetic-tick interval, plus just-before checks. Direct TCP/UDP invariants are authored expectations, not policy grants or workload admission/mTLS proofs. No time-varying posture, live sessions, real routes, packet enforcement or automatic renewal is simulated. Expiry can break required connectivity and must remain visible.",
    }


def publish(result: dict[str, Any], output: Path) -> None:
    """Create new inert JSON/HTML review evidence, never nftables output or a notification."""
    target = output.absolute()
    if any(p.is_symlink() or p.is_junction() for p in (target, *target.parents)):
        raise ValueError("linked preview output")
    target.mkdir(mode=0o700)
    text = json.dumps(result, sort_keys=True, indent=2)
    private_file(target / "continuity.json", text.encode())
    page = (
        '<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src \'none\'; base-uri \'none\'; form-action \'none\'"><title>Transport continuity — Jason Stys</title><main><h1>Transport continuity preview</h1><p>Created by Jason Stys. Non-enforcing; reviewed requirements do not grant access.</p><pre>'
        + html.escape(text)
        + "</pre></main></html>"
    )
    private_file(target / "continuity.html", page.encode())

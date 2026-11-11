"""Jason Stys: non-enforcing transport permission timeline and owner-authored dependency invariants."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# definition: preview — line 74
# parameter: end — line 75
# parameter: policy_path — line 75
# parameter: requirements_path — line 75
# parameter: start — line 75
# variable: path — line 80
# variable: p — line 84
# variable: policy — line 89
# variable: sha — line 89
# variable: raw — line 90
# variable: data — line 91
# variable: requirements — line 99
# variable: seen_ids — line 100
# variable: seen_flows — line 101
# variable: e — line 102
# variable: known — line 102
# variable: item — line 103
# variable: row — line 104
# variable: name — line 105
# variable: owner — line 105
# variable: flow — line 106
# variable: boundaries — line 121
# variable: r — line 122
# variable: b — line 124
# variable: t — line 124
# variable: ticks — line 124
# variable: ticks — line 125
# variable: engine — line 126
# variable: timeline — line 127
# variable: previous — line 128
# variable: queue — line 129
# variable: tick — line 130
# variable: allowed — line 131
# variable: checks — line 132
# variable: item — line 133
# variable: decision — line 134
# variable: matches — line 135
# variable: check — line 136
# variable: previous — line 156
# definition: publish — line 172
# parameter: output — line 172
# parameter: result — line 172
# variable: target — line 174
# variable: p — line 175
# variable: text — line 178
# variable: page — line 180
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
from ztlab.contracts import (
    Flow,
    fields,
    identifier,
    integer,
    load_policy,
    parse,
    read_source,
)
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
    raw = read_source(requirements_path, 65536)
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

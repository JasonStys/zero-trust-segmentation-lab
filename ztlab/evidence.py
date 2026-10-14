"""Jason Stys: bounded synthetic admission replay and exclusive metadata-only JSON/HTML/nft evidence outputs."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# variable: MODES — line 78
# definition: proof_fixture — line 91
# parameter: engine — line 91
# parameter: flow — line 91
# parameter: mode — line 91
# parameter: now — line 91
# variable: identity — line 95
# variable: claims — line 100
# variable: claims — line 104
# variable: claims — line 106
# variable: claims — line 108
# variable: claims — line 110
# variable: claims — line 112
# variable: claims — line 114
# variable: proof — line 115
# definition: evaluate — line 119
# parameter: cases_path — line 120
# parameter: now — line 120
# parameter: policy — line 120
# parameter: policy_sha — line 120
# variable: stream — line 123
# variable: raw — line 124
# variable: lines — line 125
# variable: line — line 129
# variable: engine — line 132
# variable: rows — line 133
# variable: seen — line 134
# variable: line — line 135
# variable: case — line 136
# variable: case_id — line 137
# variable: flow — line 145
# variable: decision — line 146
# variable: row — line 170
# definition: private_file — line 178
# parameter: content — line 178
# parameter: path — line 178
# variable: descriptor — line 180
# variable: stream — line 181
# definition: render — line 185
# parameter: report — line 185
# variable: rows — line 187
# variable: value — line 191
# variable: row — line 201
# variable: name — line 213
# definition: save — line 223
# parameter: directory — line 223
# parameter: now — line 223
# parameter: policy — line 223
# parameter: report — line 223
# variable: endpoint — line 232
# END CODE MAP

from __future__ import annotations

import html
import json
import os
from dataclasses import asdict, replace
from pathlib import Path
from typing import Any

from ztlab.admission import Attester, Claims, Engine, Proof
from ztlab.analysis import matrix, reachable
from ztlab.compiler import compile_rules
from ztlab.contracts import (
    ContractError,
    Flow,
    Policy,
    digest,
    fields,
    identifier,
    integer,
    parse,
)

MODES = (
    "valid",
    "missing",
    "tampered",
    "wrong-identity",
    "wrong-source",
    "unhealthy",
    "expired",
    "future",
    "old-policy",
)


def proof_fixture(engine: Engine, flow: Flow, mode: str, now: int) -> Proof | None:
    """Construct operator-owned test attestations, never authority supplied by a raw network peer."""
    if mode == "missing":
        return None
    identity = (
        engine.endpoints[flow.source].identity
        if flow.source in engine.endpoints
        else "unknown"
    )
    claims = Claims(
        flow.source, identity, "healthy", now, now + 30, engine.policy.revision
    )
    if mode == "wrong-identity":
        claims = replace(claims, identity="spiffe://lab.example/tenant-b/other")
    if mode == "wrong-source":
        claims = replace(claims, workload="other")
    if mode == "unhealthy":
        claims = replace(claims, posture="compromised")
    if mode == "expired":
        claims = replace(claims, issued_at=now - 30, expires_at=now)
    if mode == "future":
        claims = replace(claims, issued_at=now + 1, expires_at=now + 31)
    if mode == "old-policy":
        claims = replace(claims, policy_revision=engine.policy.revision - 1)
    proof = engine.attester.issue(claims)
    return replace(proof, signature="0" * 64) if mode == "tampered" else proof


def evaluate(
    policy: Policy, policy_sha: str, cases_path: Path, now: int
) -> dict[str, Any]:
    """Read bounded reviewed cases and grade actual admission decisions; oracle labels never choose policy outcomes."""
    with cases_path.open("rb") as stream:
        raw = stream.read(131073)
    lines = raw.splitlines()
    if (
        len(raw) > 131072
        or not 1 <= len(lines) <= 128
        or any(not line.strip() for line in lines)
    ):
        raise ContractError("case file limit")
    engine = Engine(policy, Attester())
    rows = []
    seen = set()
    for line in lines:
        case = fields(parse(line), {"id", "flow", "proof_mode", "expected"})
        case_id = identifier(case["id"])
        if (
            case_id in seen
            or case["proof_mode"] not in MODES
            or type(case["expected"]) is not bool
        ):
            raise ContractError("invalid case metadata")
        seen.add(case_id)
        flow = Flow.from_json(case["flow"])
        decision = engine.decide(
            flow, proof_fixture(engine, flow, case["proof_mode"], now), now
        )
        rows.append(
            {
                "id": case_id,
                "flow": asdict(flow),
                "proof_mode": case["proof_mode"],
                "expected": case["expected"],
                "decision": asdict(decision),
                "oracle_match": decision.allowed == case["expected"],
            }
        )
    import hashlib

    return {
        "author": "Jason Stys",
        "schema_version": 1,
        "mode": "synthetic-admission",
        "policy_sha256": policy_sha,
        "case_sha256": hashlib.sha256(raw).hexdigest(),
        "revision": policy.revision,
        "evaluated_at_tick": now,
        "cases": rows,
        "oracle_matches": sum(row["oracle_match"] for row in rows),
        "case_count": len(rows),
        "transport_matrix": matrix(policy, now),
        "possible_application_pivots": reachable(policy, now),
        "limits": "Offline admission and L4 projection. Demo MAC proofs are not mTLS identities. Graph paths do not grant direct connectivity. Native packet evidence is a separate hosted test.",
    }


def private_file(path: Path, content: bytes) -> None:
    """Create a new file with restrictive POSIX mode; never overwrite an existing file or follow its symlink."""
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(content)


def render(report: dict[str, Any]) -> str:
    """Render escaped decision metadata as inert browser-readable HTML with no scripts or remote assets."""
    rows = "".join(
        "<tr>"
        + "".join(
            "<td>" + html.escape(str(value), quote=True) + "</td>"
            for value in (
                row["id"],
                row["flow"]["source"],
                row["flow"]["target"],
                row["decision"]["allowed"],
                row["decision"]["reason"],
                row["oracle_match"],
            )
        )
        + "</tr>"
        for row in report["cases"]
    )
    return (
        '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">'
        '<meta http-equiv="Content-Security-Policy" content="default-src &#39;none&#39;; base-uri &#39;none&#39;; form-action &#39;none&#39;">'
        "<title>Zero-trust segmentation — Jason Stys</title></head><body><main><h1>Zero-trust segmentation lab</h1>"
        "<p>Created by Jason Stys. Offline synthetic evidence.</p><p>"
        + html.escape(report["limits"])
        + "</p>"
        "<table><caption>Admission decisions, not network-location trust</caption><thead><tr>"
        + "".join(
            '<th scope="col">' + name + "</th>"
            for name in ("Case", "Source", "Target", "Allowed", "Reason", "Oracle")
        )
        + "</tr></thead><tbody>"
        + rows
        + "</tbody></table>"
        "<h2>Help</h2><p>See docs/usage.md for interpretation and deployment limits. Do not apply exported rules to a host network namespace.</p>"
        '<p><a href="https://github.com/JasonStys" rel="noreferrer">Contact Jason Stys</a></p></main></body></html>'
    )


def save(directory: Path, report: dict[str, Any], policy: Policy, now: int) -> str:
    """Create exclusive private evidence and per-workload exports; no firewall command is invoked."""
    integer(now, 0, 2**31 - 1)
    directory.mkdir(mode=0o700, parents=True, exist_ok=False)
    private_file(
        directory / "evaluation.json",
        json.dumps(report, sort_keys=True, indent=2, allow_nan=False).encode() + b"\n",
    )
    private_file(directory / "evaluation.html", render(report).encode())
    for endpoint in policy.endpoints:
        private_file(
            directory / (endpoint.name + ".nft"),
            compile_rules(policy, endpoint.name, now).encode(),
        )
    return digest(report)

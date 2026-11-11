"""Actual offline admission, direct permission graph, policy comparison and expiry review. Jason Stys."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# variable: ROOT — line 144
# variable: PRODUCT — line 145
# variable: PROFILE — line 145
# variable: TITLE — line 146
# variable: VERSION — line 146
# variable: COLUMNS — line 147
# variable: RESOURCES — line 148
# variable: MODES — line 157
# variable: REVIEW_MODE — line 163
# variable: CHOICES — line 164
# variable: FIELDS — line 165
# variable: ACTIVE_FIELDS — line 180
# variable: SCENARIOS — line 186
# variable: HELP — line 193
# definition: scenario — line 196
# parameter: name — line 196
# variable: index — line 200
# definition: number — line 226
# parameter: maximum — line 226
# parameter: minimum — line 226
# parameter: value — line 226
# variable: text — line 228
# definition: graph — line 234
# parameter: policy — line 234
# parameter: sha — line 234
# parameter: tick — line 234
# variable: endpoint — line 246
# definition: text_bundle — line 252
# parameter: title — line 252
# parameter: value — line 252
# variable: raw — line 254
# variable: page — line 255
# definition: analyze — line 267
# parameter: parameters — line 268
# parameter: stage — line 268
# parameter: state — line 268
# variable: mode — line 271
# variable: result — line 272
# variable: end — line 274
# variable: start — line 274
# variable: policy — line 275
# variable: sha — line 275
# variable: result — line 276
# variable: output — line 281
# variable: files — line 283
# variable: p — line 283
# variable: diagram — line 284
# variable: summary — line 285
# variable: tick — line 287
# variable: before — line 288
# variable: old_sha — line 288
# variable: after — line 289
# variable: new_sha — line 289
# variable: result — line 290
# variable: files — line 297
# variable: diagram — line 298
# variable: summary — line 299
# variable: tick — line 301
# variable: policy — line 302
# variable: sha — line 302
# variable: diagram — line 303
# variable: result — line 305
# variable: output — line 306
# variable: files — line 308
# variable: p — line 308
# variable: summary — line 309
# variable: flow — line 313
# variable: engine — line 321
# variable: result — line 322
# variable: files — line 338
# variable: summary — line 339
# definition: views — line 346
# parameter: files — line 346
# variable: diagram — line 348
# variable: common — line 349
# variable: port — line 361
# variable: source — line 361
# variable: target — line 361
# variable: report — line 366
# variable: source — line 372
# variable: targets — line 372
# variable: report — line 377
# variable: report — line 383
# variable: change — line 397
# variable: port — line 398
# variable: source — line 398
# variable: target — line 398
# definition: cells — line 405
# parameter: row — line 405
# variable: flow — line 407
# variable: decision — line 408
# definition: draw_preview — line 439
# parameter: canvas — line 439
# parameter: files — line 439
# variable: value — line 450
# variable: width — line 451
# variable: height — line 452
# parameter: row — line 453
# variable: nodes — line 453
# variable: positions — line 454
# variable: index — line 459
# variable: node — line 459
# variable: peers — line 468
# variable: port — line 469
# variable: source — line 469
# variable: target — line 469
# variable: ports — line 471
# variable: source — line 471
# variable: target — line 471
# variable: x1 — line 472
# variable: y1 — line 472
# variable: x2 — line 473
# variable: y2 — line 473
# variable: distance — line 474
# variable: dx — line 475
# variable: dy — line 475
# variable: label — line 486
# variable: index — line 494
# variable: node — line 494
# variable: x — line 495
# variable: y — line 495
# END CODE MAP

from __future__ import annotations

import html
import math
import sys
from dataclasses import asdict
from pathlib import Path
from typing import Any

from .admission import Attester, Engine
from .analysis import allowed_flows, difference
from .continuity import preview, publish
from .contracts import Flow, Policy, canonical, integer, load_policy
from .desktop_io import Rejected, json_value, read_bytes
from .desktop_state import Workspace
from .evidence import MODES as PROOFS
from .evidence import evaluate, proof_fixture, save

ROOT = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parents[1]))
PRODUCT, PROFILE = "zero-trust-segmentation-lab", "ZeroTrustSegmentationLab"
TITLE, VERSION = "Zero-Trust Segmentation Workbench", "1.1.1"
COLUMNS = ("Flow / owner", "Protocol / port", "Original reason", "Permission / change")
RESOURCES = (
    "examples/policy.json",
    "examples/requests.jsonl",
    "examples/continuity-requirements.json",
    "examples/desktop/quarantined.json",
    "notices.txt",
    "app.ico",
    "python314.dll",
)
MODES = (
    "Review admission and transport matrix",
    "Compare direct policy permissions",
    "Preview dependency continuity boundaries",
    "Inspect one hypothetical admission",
)
REVIEW_MODE = None
CHOICES = {"protocol": ("tcp", "udp"), "proof": PROOFS}
FIELDS = (
    ("policy", "Authorized offline policy JSON", "file"),
    ("cases", "Labeled synthetic admission cases JSONL", "file"),
    ("now", "Explicit synthetic clock tick (not today's wall clock)", "text"),
    ("before", "Earlier offline policy JSON", "file"),
    ("after", "Candidate offline policy JSON", "file"),
    ("requirements", "Owner-authored direct allow/deny requirements JSON", "file"),
    ("start", "Continuity start tick", "text"),
    ("end", "Continuity end tick (at most 3600 after start)", "text"),
    ("source", "Source workload name", "text"),
    ("target", "Target workload name", "text"),
    ("protocol", "Hypothetical transport protocol", "choice"),
    ("port", "Hypothetical destination port", "text"),
    ("proof", "Synthetic ephemeral MAC proof fixture (not a certificate)", "choice"),
)
ACTIVE_FIELDS = {
    MODES[0]: ("policy", "cases", "now"),
    MODES[1]: ("before", "after", "now"),
    MODES[2]: ("policy", "requirements", "start", "end"),
    MODES[3]: ("policy", "now", "source", "target", "protocol", "port", "proof"),
}
SCENARIOS = (
    "Fictional default-deny admission",
    "Fictional quarantine review",
    "Fictional policy permission removal",
    "Fictional expiry continuity",
    "Fictional invalid identity proof",
)
HELP = "Select authorized offline policy/cases/requirements and an explicit synthetic clock tick. Actual original engines compute admissions, full direct TCP/UDP matrix, possible application pivots, policy differences and expiry boundaries. The graph draws direct permitted TCP edges only, never transitive grants; matrix/pivot views retain complete records. In continuity it shows the FINAL reviewed interval tick, not a live network. Admission MAC fixtures are fresh in-memory dummy proofs, not actual certificates/mTLS. Policy/clock changes can intentionally cause labeled-case mismatches: retain and review those outcomes. Owner requirements never grant access or renew policy. No network listener, host discovery, firewall/namespace command or rule enforcement exists in this app. Exported .nft files are data-only and must not be applied to a workstation. The separate privileged hosted kernel lane stays outside the GUI. Prepared fictional scenarios fill the same controls. History/exports are plaintext OS-owner data, not authentication/encryption; no automatic upload."


def scenario(name: str) -> dict[str, str]:
    """Fill actual policy/flow/clock controls with public fictional data; permission and Run remain explicit."""
    if name not in SCENARIOS:
        raise Rejected("unknown prepared scenario")
    index = SCENARIOS.index(name)
    return {
        "mode": MODES[0] if index < 2 else MODES[index - 1],
        "policy": str(
            ROOT
            / (
                "examples/desktop/quarantined.json"
                if index == 1
                else "examples/policy.json"
            )
        ),
        "cases": str(ROOT / "examples/requests.jsonl"),
        "now": "1000",
        "before": str(ROOT / "examples/policy.json"),
        "after": str(ROOT / "examples/desktop/quarantined.json"),
        "requirements": str(ROOT / "examples/continuity-requirements.json"),
        "start": "1000",
        "end": "1300",
        "source": "web",
        "target": "api",
        "protocol": "tcp",
        "port": "8080",
        "proof": "wrong-identity",
    }


def number(value: str, minimum: int = 0, maximum: int = 2**31 - 1) -> int:
    """Reject coercion, bool-like text, Unicode digits and unbounded numeric parameters before core evaluation."""
    text = value.strip()
    if len(text) > 10 or not text.isascii() or not text.isdecimal():
        raise Rejected("use a bounded base-ten integer")
    return integer(int(text), minimum, maximum)


def graph(policy: Policy, sha: str, tick: int) -> dict[str, Any]:
    """Bind a bounded direct-permission graph to exact policy bytes and actual effective transport decisions."""
    return {
        "scope": "Direct effective TCP permissions only; application pivots are not direct grants",
        "policy_sha256": sha,
        "tick": tick,
        "nodes": [
            {
                "name": endpoint.name,
                "tenant": endpoint.tenant,
                "quarantined": endpoint.name in policy.quarantined,
            }
            for endpoint in policy.endpoints
        ],
        "edges": sorted(allowed_flows(policy, tick)),
    }


def text_bundle(value: dict[str, Any], title: str) -> dict[str, bytes]:
    """Keep source fingerprints and actual outcomes as finite metadata/escaped inert HTML, never active policy commands."""
    raw = canonical(value) + b"\n"
    page = (
        '<!doctype html><html lang="en"><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="default-src &#39;none&#39;; base-uri &#39;none&#39;; form-action &#39;none&#39;"><title>'
        + html.escape(title)
        + "</title><main><h1>"
        + html.escape(title)
        + "</h1><p>Jason Stys. Offline preview only; no rules applied.</p><pre>"
        + html.escape(raw.decode())
        + "</pre></main></html>"
    )
    return {"result.json": raw, "result.html": page.encode()}


def analyze(
    state: Workspace, parameters: dict[str, str], stage: Path
) -> tuple[str, str, dict[str, bytes]]:
    """Reuse real admission/transport/continuity engines without any collector, arbitrary target or enforcement path."""
    mode = parameters["mode"]
    result: dict[str, Any]
    if mode == MODES[2]:
        start, end = number(parameters["start"]), number(parameters["end"])
        policy, sha = load_policy(Path(parameters["policy"]))
        result = preview(
            Path(parameters["policy"]), Path(parameters["requirements"]), start, end
        )
        if result["policy_sha256"] != sha:
            raise Rejected("selected policy changed during continuity evaluation")
        output = stage / "continuity"
        publish(result, output)
        files = {p.name: read_bytes(p, 32 * 1024 * 1024) for p in output.iterdir()}
        diagram = graph(policy, sha, end)
        summary = f"{len(result['timeline'])} boundary ticks; {len(result['review_queue'])} owner review items; graph at final tick {end}; no enforcement"
    elif mode == MODES[1]:
        tick = number(parameters["now"])
        before, old_sha = load_policy(Path(parameters["before"]))
        after, new_sha = load_policy(Path(parameters["after"]))
        result = {
            **difference(before, after, tick),
            "before_policy_sha256": old_sha,
            "after_policy_sha256": new_sha,
            "tick": tick,
            "scope": "Direct effective permissions, not workload authentication or actual deployment",
        }
        files = text_bundle(result, "Offline direct policy changes")
        diagram = graph(after, new_sha, tick)
        summary = f"{len(result['added'])} permissions added; {len(result['removed'])} removed; no policy applied"
    elif mode in (MODES[0], MODES[3]):
        tick = number(parameters["now"])
        policy, sha = load_policy(Path(parameters["policy"]))
        diagram = graph(policy, sha, tick)
        if mode == MODES[0]:
            result = evaluate(policy, sha, Path(parameters["cases"]), tick)
            output = stage / "admission"
            save(output, result, policy, tick)
            files = {p.name: read_bytes(p, 32 * 1024 * 1024) for p in output.iterdir()}
            summary = f"{result['oracle_matches']}/{result['case_count']} supplied admission oracles; {len(result['transport_matrix'])} transport rows; no enforcement"
        else:
            if parameters["proof"] not in PROOFS:
                raise Rejected("unsupported synthetic proof fixture")
            flow = Flow.from_json(
                {
                    "source": parameters["source"],
                    "target": parameters["target"],
                    "protocol": parameters["protocol"],
                    "port": number(parameters["port"], 1, 65535),
                }
            )
            engine = Engine(policy, Attester())
            result = {
                "flow": asdict(flow),
                "proof_fixture": parameters["proof"],
                "admission": asdict(
                    engine.decide(
                        flow,
                        proof_fixture(engine, flow, parameters["proof"], tick),
                        tick,
                    )
                ),
                "transport": asdict(engine.transport(flow, tick)),
                "policy_sha256": sha,
                "revision": policy.revision,
                "tick": tick,
                "scope": "Fresh in-memory synthetic MAC fixture, not actual workload identity/certificate or real traffic",
            }
            files = text_bundle(result, "Hypothetical admission evidence")
            summary = f"admission {'ALLOW' if result['admission']['allowed'] else 'DENY'}; transport {'ALLOW' if result['transport']['allowed'] else 'DENY'}; dummy proof only"
    else:
        raise Rejected("unsupported non-enforcing operation")
    files["graph.json"] = canonical(diagram) + b"\n"
    return mode, summary, files


def views(files: dict[str, bytes]) -> dict[str, list[dict[str, Any]]]:
    """Keep full original decisions, exact matrix/flow changes and boundary owner items beside the graph."""
    diagram = json_value(files["graph.json"])
    common = {
        "Direct permitted TCP edges": [
            {
                "flow": {
                    "source": source,
                    "target": target,
                    "protocol": "tcp",
                    "port": port,
                },
                "state": "ALLOW_DIRECT",
                "tick": diagram["tick"],
            }
            for source, target, port in diagram["edges"]
        ],
        "Workload inventory": diagram["nodes"],
    }
    if "evaluation.json" in files:
        report = json_value(files["evaluation.json"])
        return {
            "Original admission decisions": report["cases"],
            "Full direct transport matrix": report["transport_matrix"],
            "Possible application pivots — not direct grants": [
                {"source": source, "possible_targets": targets}
                for source, targets in report["possible_application_pivots"].items()
            ],
            **common,
        }
    if "continuity.json" in files:
        report = json_value(files["continuity.json"])
        return {
            "Boundary owner review queue": report["review_queue"],
            "Complete boundary timeline": report["timeline"],
            **common,
        }
    report = json_value(files["result.json"])
    if "admission" in report:
        return {"Hypothetical admission and transport": [report], **common}
    return {
        "Direct permission changes": [
            {
                "change": change,
                "flow": {
                    "source": source,
                    "target": target,
                    "protocol": "tcp",
                    "port": port,
                },
            }
            for change in ("added", "removed")
            for source, target, port in report[change]
        ],
        "Original policy comparison": [report],
        **common,
    }


def cells(row: dict[str, Any]) -> tuple[str, str, str, str]:
    """Summarize direct facts; full selected JSON retains identities, clocks, scope and original reasons."""
    flow = row.get("flow", {})
    decision = row.get("decision", row.get("admission", {}))
    return (
        str(
            flow.get(
                "source", row.get("source", row.get("id", row.get("name", "scope")))
            )
        )
        + (" → " + str(flow["target"]) if "target" in flow else ""),
        str(flow.get("protocol", row.get("owner", "tick")))
        + (
            "/" + str(flow["port"])
            if "port" in flow
            else " " + str(row.get("tick", ""))
        ),
        str(decision.get("reason", row.get("scope", "inspect exact record"))),
        str(
            row.get(
                "change",
                row.get(
                    "state",
                    "ALLOW"
                    if decision.get("allowed") is True
                    else "DENY"
                    if decision.get("allowed") is False
                    else "review",
                ),
            )
        ),
    )


def draw_preview(canvas: Any, files: dict[str, bytes]) -> None:
    """Render only bounded saved direct permissions; no routing, traffic, transitive-edge inference or host command exists."""
    canvas.delete("all")
    if not files:
        canvas.create_text(
            12,
            12,
            anchor="nw",
            text="Run an offline analysis to inspect its saved direct-permission graph.",
        )
        return
    value = json_value(files["graph.json"])
    width = max(300, canvas.winfo_width())
    height = max(250, canvas.winfo_height())
    nodes = sorted(value["nodes"], key=lambda row: row["name"])
    positions = {
        node["name"]: (
            width / 2 + (width / 2 - 130) * math.cos(index * 2 * math.pi / len(nodes)),
            height / 2 + (height / 2 - 75) * math.sin(index * 2 * math.pi / len(nodes)),
        )
        for index, node in enumerate(nodes)
    }
    canvas.create_text(
        12,
        10,
        anchor="nw",
        text=f"Direct TCP permissions at saved tick {value['tick']} · arrows are not transitive grants",
        tags="scope",
    )
    peers: dict[tuple[str, str], list[int]] = {}
    for source, target, port in value["edges"]:
        peers.setdefault((source, target), []).append(port)
    for (source, target), ports in peers.items():
        x1, y1 = positions[source]
        x2, y2 = positions[target]
        distance = math.hypot(x2 - x1, y2 - y1)
        dx, dy = (x2 - x1) / distance, (y2 - y1) / distance
        canvas.create_line(
            x1 + dx * 15,
            y1 + dy * 15,
            x2 - dx * 18,
            y2 - dy * 18,
            arrow="last",
            fill="#195b87",
            width=2,
            tags="permission",
        )
        label = (
            ",".join(map(str, ports))
            if len(ports) <= 2
            else str(len(ports)) + " ports; inspect matrix"
        )
        canvas.create_text(
            (x1 + x2) / 2, (y1 + y2) / 2 - 8, text=label, fill="#173b50", tags="port"
        )
    for index, node in enumerate(nodes):
        x, y = positions[node["name"]]
        canvas.create_oval(
            x - 12,
            y - 12,
            x + 12,
            y + 12,
            fill="#9c3434" if node["quarantined"] else "#286f78",
            outline="#ffffff",
            tags="workload",
        )
        canvas.create_text(
            x,
            y + 25,
            text=f"N{index + 1} "
            + node["name"][:20]
            + ("…" if len(node["name"]) > 20 else ""),
            tags="name",
        )

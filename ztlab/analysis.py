"""Jason Stys: finite transport matrices, bounded BFS pivot analysis and exact policy-change blast-radius deltas."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# definition: allowed_flows — line 54
# parameter: now — line 54
# parameter: policy — line 54
# variable: engine — line 56
# variable: rule — line 59
# definition: matrix — line 66
# parameter: now — line 66
# parameter: policy — line 66
# variable: declared — line 68
# variable: item — line 68
# variable: negative — line 69
# variable: port — line 69
# variable: ports — line 70
# variable: engine — line 71
# variable: rows — line 72
# variable: source — line 73
# variable: target — line 74
# variable: protocol — line 77
# variable: port — line 78
# variable: flow — line 79
# definition: reachable — line 89
# parameter: now — line 89
# parameter: policy — line 89
# variable: graph — line 91
# variable: item — line 91
# variable: _ — line 92
# variable: source — line 92
# variable: target — line 92
# variable: result — line 94
# variable: source — line 95
# variable: seen — line 96
# variable: queue — line 97
# variable: target — line 99
# definition: difference — line 107
# parameter: after — line 107
# parameter: before — line 107
# parameter: now — line 107
# variable: new — line 109
# variable: old — line 109
# END CODE MAP

from __future__ import annotations

from collections import deque
from dataclasses import asdict
from typing import Any

from ztlab.admission import Attester, Engine
from ztlab.contracts import Flow, Policy


def allowed_flows(policy: Policy, now: int) -> set[tuple[str, str, int]]:
    """Return effective directed TCP permissions after validity, tenant, quarantine and exception checks."""
    engine = Engine(policy, Attester())
    return {
        (rule.source, rule.target, rule.port)
        for rule in policy.rules
        if engine.transport(
            Flow(rule.source, rule.target, "tcp", rule.port), now
        ).allowed
    }


def matrix(policy: Policy, now: int) -> list[dict[str, Any]]:
    """Evaluate every distinct workload pair, TCP/UDP and declared ports plus a closed negative port."""
    declared = {item.port for item in policy.rules}
    negative = next(port for port in range(8081, 8090) if port not in declared)
    ports = sorted(declared | {negative})
    engine = Engine(policy, Attester())
    rows = []
    for source in sorted(engine.endpoints):
        for target in sorted(engine.endpoints):
            if source == target:
                continue
            for protocol in ("tcp", "udp"):
                for port in ports:
                    flow = Flow(source, target, protocol, port)
                    rows.append(
                        {
                            "flow": asdict(flow),
                            "decision": asdict(engine.transport(flow, now)),
                        }
                    )
    return rows


def reachable(policy: Policy, now: int) -> dict[str, list[str]]:
    """Compute possible application-pivot paths; graph transitivity never grants a direct packet permission."""
    graph: dict[str, set[str]] = {item.name: set() for item in policy.endpoints}
    for source, target, _ in allowed_flows(policy, now):
        graph[source].add(target)
    result = {}
    for source in sorted(graph):
        seen = {source}
        queue = deque([source])
        while queue:
            for target in sorted(graph[queue.popleft()]):
                if target not in seen:
                    seen.add(target)
                    queue.append(target)
        result[source] = sorted(seen - {source})
    return result


def difference(before: Policy, after: Policy, now: int) -> dict[str, Any]:
    """Describe exact permissions added/removed and pivot-reachability changes without applying either policy."""
    old, new = allowed_flows(before, now), allowed_flows(after, now)
    return {
        "before_revision": before.revision,
        "after_revision": after.revision,
        "added": sorted(new - old),
        "removed": sorted(old - new),
        "before_reachable": reachable(before, now),
        "after_reachable": reachable(after, now),
    }

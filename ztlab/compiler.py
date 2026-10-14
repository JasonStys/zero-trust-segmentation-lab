"""Jason Stys: deterministic namespace-scoped nftables projection; exports rules but never applies them."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# definition: compile_rules — line 33
# parameter: now — line 33
# parameter: policy — line 33
# parameter: workload — line 33
# variable: inventory — line 35
# variable: item — line 35
# variable: flows — line 38
# variable: lines — line 39
# variable: port — line 48
# variable: source — line 48
# variable: target — line 48
# variable: lines — line 53
# variable: port — line 60
# variable: source — line 60
# variable: target — line 60
# variable: lines — line 65
# variable: indexes — line 71
# variable: index — line 73
# variable: line — line 73
# variable: count — line 76
# variable: index — line 77
# variable: name — line 77
# END CODE MAP

from __future__ import annotations

from ztlab.analysis import allowed_flows
from ztlab.contracts import ContractError, Policy


def compile_rules(policy: Policy, workload: str, now: int) -> str:
    """Emit IPv4 TCP input/output allowlists and default-deny inet hooks; not identity/mTLS enforcement."""
    inventory = {item.name: item for item in policy.endpoints}
    if workload not in inventory:
        raise ContractError("unknown export workload")
    flows = sorted(allowed_flows(policy, now))
    lines = [
        "# Jason Stys: generated namespace-only L4 projection; never apply to a host namespace.",
        "# input/output/forward are base hooks; peer IPs are inventory data, not authenticated identities.",
        "table inet ztl {",
        "  chain input {",
        "    type filter hook input priority filter; policy drop;",
        '    iifname "lo" accept',
        "    ct state established accept",
    ]
    for source, target, port in flows:
        if target == workload:
            lines.append(
                f"    ip saddr {inventory[source].address} ip daddr {inventory[target].address} tcp dport {port} ct state new accept # {source} to {target}"
            )
    lines += [
        "  }",
        "  chain output {",
        "    type filter hook output priority filter; policy drop;",
        '    oifname "lo" accept',
        "    ct state established accept",
    ]
    for source, target, port in flows:
        if source == workload:
            lines.append(
                f"    ip saddr {inventory[source].address} ip daddr {inventory[target].address} tcp dport {port} ct state new accept # {source} to {target}"
            )
    lines += [
        "  }",
        "  chain forward { type filter hook forward priority filter; policy drop; }",
        "}",
    ]
    # Exact generated header locations for every chain; output also documents the input rule variables.
    indexes = [
        (index, line.strip().split()[1])
        for index, line in enumerate(lines, 1)
        if line.strip().startswith("chain ")
    ]
    count = len(indexes)
    lines[2:2] = [f"# chain {name} — line {index + count}" for index, name in indexes]
    return "\n".join(lines) + "\n"

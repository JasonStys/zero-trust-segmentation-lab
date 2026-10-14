"""Jason Stys: generate deterministic reviewed inventory and admission oracles from independent scenario definitions."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# variable: ROOT — line 29
# definition: policy_data — line 32
# variable: index — line 46
# variable: name — line 46
# variable: tenant — line 46
# variable: source — line 64
# variable: target — line 64
# definition: request_data — line 69
# variable: rows — line 71
# variable: allowed — line 72
# variable: source — line 73
# variable: target — line 74
# variable: protocol — line 77
# variable: port — line 78
# variable: mode — line 92
# definition: main — line 131
# variable: output — line 133
# variable: row — line 141
# END CODE MAP

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]


def policy_data() -> dict[str, Any]:
    """Return the four owned synthetic workloads and two least-privilege service dependencies."""
    return {
        "revision": 1,
        "created_at": 1000,
        "expires_at": 1300,
        "quarantined": [],
        "endpoints": [
            {
                "name": name,
                "tenant": tenant,
                "address": f"198.18.0.{index}",
                "identity": f"spiffe://lab.example/{tenant}/{name}",
            }
            for index, (name, tenant) in enumerate(
                (
                    ("web", "tenant-a"),
                    ("api", "tenant-a"),
                    ("db", "tenant-a"),
                    ("guest", "tenant-b"),
                ),
                11,
            )
        ],
        "rules": [
            {
                "source": source,
                "target": target,
                "port": 8080,
                "until": None,
                "ticket": None,
            }
            for source, target in (("web", "api"), ("api", "db"))
        ],
    }


def request_data() -> list[dict[str, Any]]:
    """Create complete pair/protocol/port controls plus missing/tampered/stale identity and posture cases."""
    rows = []
    allowed = {("web", "api", "tcp", 8080), ("api", "db", "tcp", 8080)}
    for source in ("web", "api", "db", "guest"):
        for target in ("web", "api", "db", "guest"):
            if source == target:
                continue
            for protocol in ("tcp", "udp"):
                for port in (8080, 8081):
                    rows.append(
                        {
                            "id": f"{source}-{target}-{protocol}-{port}",
                            "flow": {
                                "source": source,
                                "target": target,
                                "protocol": protocol,
                                "port": port,
                            },
                            "proof_mode": "valid",
                            "expected": (source, target, protocol, port) in allowed,
                        }
                    )
    for mode in (
        "missing",
        "tampered",
        "wrong-identity",
        "wrong-source",
        "unhealthy",
        "expired",
        "future",
        "old-policy",
    ):
        rows.append(
            {
                "id": "proof-" + mode,
                "flow": {
                    "source": "web",
                    "target": "api",
                    "protocol": "tcp",
                    "port": 8080,
                },
                "proof_mode": mode,
                "expected": False,
            }
        )
    rows.append(
        {
            "id": "unknown-workload",
            "flow": {
                "source": "unknown",
                "target": "api",
                "protocol": "tcp",
                "port": 8080,
            },
            "proof_mode": "valid",
            "expected": False,
        }
    )
    return rows


def main() -> None:
    """Regenerate authored public fixtures; no external inventory, accounts or network collection occurs."""
    output = ROOT / "examples"
    output.mkdir(exist_ok=True)
    (output / "policy.json").write_text(
        json.dumps(policy_data(), indent=2) + "\n", encoding="utf-8", newline="\n"
    )
    (output / "requests.jsonl").write_text(
        "\n".join(
            json.dumps(row, sort_keys=True, separators=(",", ":"))
            for row in request_data()
        )
        + "\n",
        encoding="utf-8",
        newline="\n",
    )
    print(f"Reviewed admission cases: {len(request_data())}")


if __name__ == "__main__":
    main()

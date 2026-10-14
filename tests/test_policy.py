"""Jason Stys: actual admission decisions, exact identity/freshness binding, quarantine, graph and exporter regression."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# definition: policy — line 63
# definition: test_invalid_clock_with_empty_graph — line 69
# parameter: now — line 69
# variable: current — line 71
# variable: operation — line 72
# definition: test_default_deny_and_attestation — line 79
# variable: engine — line 81
# variable: flow — line 82
# variable: proof — line 83
# variable: mode — line 85
# variable: changed — line 99
# variable: overlong — line 101
# definition: test_exception_quarantine_and_diff — line 126
# variable: before — line 128
# variable: data — line 129
# variable: after — line 140
# variable: delta — line 143
# variable: isolated — line 151
# variable: cycle_data — line 165
# variable: values — line 170
# definition: test_compiler_and_matrix — line 173
# variable: current — line 175
# variable: rows — line 176
# variable: row — line 177
# variable: api — line 178
# variable: database — line 178
# variable: guest — line 178
# variable: web — line 178
# variable: name — line 179
# variable: exported — line 186
# variable: line — line 188
# variable: name — line 190
# variable: number — line 190
# variable: changed — line 198
# variable: row — line 203
# definition: test_independent_exact_flow_oracle — line 214
# parameter: port — line 215
# parameter: protocol — line 215
# parameter: source — line 215
# parameter: target — line 215
# variable: engine — line 218
# variable: expected — line 219
# END CODE MAP

from __future__ import annotations

from dataclasses import replace

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from scripts.fixtures import policy_data
from ztlab.admission import Attester, Claims, Engine
from ztlab.analysis import allowed_flows, difference, matrix, reachable
from ztlab.compiler import compile_rules
from ztlab.contracts import ContractError, Flow, Policy
from ztlab.evidence import proof_fixture


def policy() -> Policy:
    """Build the reviewed immutable four-workload policy for controlled tests."""
    return Policy.from_json(policy_data())


@pytest.mark.parametrize("now", [-1, True, 2**31])
def test_invalid_clock_with_empty_graph(now: int) -> None:
    """Time validity cannot be skipped just because an inventory has no edges or distinct peer pairs."""
    current = replace(policy(), endpoints=(policy().endpoints[0],), rules=())
    for operation in (allowed_flows, matrix, reachable):
        with pytest.raises(ContractError):
            operation(current, now)
    with pytest.raises(ContractError):
        difference(current, current, now)


def test_default_deny_and_attestation() -> None:
    """Every proof dimension is checked independently for an otherwise permitted connection."""
    engine = Engine(policy(), Attester())
    flow = Flow("web", "api", "tcp", 8080)
    proof = proof_fixture(engine, flow, "valid", 1000)
    assert proof is not None and engine.decide(flow, proof, 1000).allowed
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
        assert not engine.decide(
            flow, proof_fixture(engine, flow, mode, 1000), 1000
        ).allowed
    assert not Engine(policy(), Attester()).decide(flow, proof, 1000).allowed
    changed = replace(proof, claims=replace(proof.claims, posture="healthy-other"))
    assert not engine.decide(flow, changed, 1000).allowed
    overlong = engine.attester.issue(
        Claims("web", engine.endpoints["web"].identity, "healthy", 1000, 1031, 1)
    )
    assert engine.decide(flow, overlong, 1000).reason == "stale-posture"
    assert engine.decide(flow, proof, 1030).reason == "stale-posture"
    assert engine.transport(flow, 999).reason == "policy-not-current"
    assert engine.transport(flow, 1300).reason == "policy-not-current"
    assert (
        engine.transport(Flow("unknown", "api", "tcp", 8080), 1000).reason
        == "unknown-workload"
    )
    assert (
        engine.transport(Flow("guest", "api", "tcp", 8080), 1000).reason
        == "tenant-boundary"
    )
    assert (
        engine.transport(Flow("web", "api", "udp", 8080), 1000).reason == "default-deny"
    )
    assert (
        engine.transport(Flow("web", "db", "tcp", 8080), 1000).reason == "default-deny"
    )
    with pytest.raises(ContractError):
        engine.transport(flow, -1)


def test_exception_quarantine_and_diff() -> None:
    """Expiry/deny-overrides revoke permissions; graph reachability is not direct network authorization."""
    before = policy()
    data = policy_data()
    data["revision"] = 2
    data["rules"].append(
        {
            "source": "web",
            "target": "db",
            "port": 8080,
            "until": 1020,
            "ticket": "change-1",
        }
    )
    after = Policy.from_json(data)
    assert ("web", "db", 8080) in allowed_flows(after, 1019)
    assert ("web", "db", 8080) not in allowed_flows(after, 1020)
    delta = difference(before, after, 1000)
    assert delta["added"] == [("web", "db", 8080)] and not delta["removed"]
    assert reachable(before, 1000)["web"] == ["api", "db"]
    assert (
        not Engine(before, Attester())
        .transport(Flow("web", "db", "tcp", 8080), 1000)
        .allowed
    )
    isolated = replace(after, quarantined=("api",))
    assert (
        Engine(isolated, Attester())
        .transport(Flow("web", "api", "tcp", 8080), 1000)
        .reason
        == "quarantined"
    )
    assert (
        Engine(isolated, Attester())
        .transport(Flow("api", "db", "tcp", 8080), 1000)
        .reason
        == "quarantined"
    )
    assert len(difference(before, isolated, 1000)["removed"]) == 2
    cycle_data = policy_data()
    cycle_data["rules"].append(
        {"source": "db", "target": "web", "port": 8080, "until": None, "ticket": None}
    )
    assert reachable(Policy.from_json(cycle_data), 1000)["db"] == ["api", "web"]
    assert all(not values for values in reachable(before, 1300).values())


def test_compiler_and_matrix() -> None:
    """Both source egress and target ingress get exact same permissions; expired policies export no new allows."""
    current = policy()
    rows = matrix(current, 1000)
    assert len(rows) == 48 and sum(row["decision"]["allowed"] for row in rows) == 2
    web, api, database, guest = [
        compile_rules(current, name, 1000) for name in ("web", "api", "db", "guest")
    ]
    assert "ip saddr 198.18.0.11 ip daddr 198.18.0.12 tcp dport 8080" in web
    assert "ip saddr 198.18.0.11 ip daddr 198.18.0.12 tcp dport 8080" in api
    assert "ip saddr 198.18.0.12 ip daddr 198.18.0.13 tcp dport 8080" in database
    assert "ct state new accept" not in guest
    assert "ct state new accept" not in compile_rules(current, "web", 1300)
    for exported in (web, api, database, guest):
        assert exported.count("policy drop") == 3 and "flush ruleset" not in exported
        for line in exported.splitlines():
            if line.startswith("# chain "):
                name, number = line.split(" — line ")
                assert (
                    exported.splitlines()[int(number) - 1]
                    .strip()
                    .startswith("chain " + name.split()[-1])
                )
    with pytest.raises(ContractError):
        compile_rules(current, "unknown", 1000)
    changed = policy_data()
    changed["rules"].append(
        {"source": "web", "target": "db", "port": 8081, "until": None, "ticket": None}
    )
    assert any(
        row["flow"]["port"] == 8082 for row in matrix(Policy.from_json(changed), 1000)
    )


@given(
    st.sampled_from(("web", "api", "db", "guest")),
    st.sampled_from(("web", "api", "db", "guest")),
    st.sampled_from(("tcp", "udp")),
    st.integers(1, 65535),
)
@settings(max_examples=300, deadline=None)
def test_independent_exact_flow_oracle(
    source: str, target: str, protocol: str, port: int
) -> None:
    """Compare actual transport evaluation with independent finite exact-edge logic; no transitive grants."""
    engine = Engine(policy(), Attester())
    expected = (source, target, protocol, port) in {
        ("web", "api", "tcp", 8080),
        ("api", "db", "tcp", 8080),
    }
    assert (
        engine.transport(Flow(source, target, protocol, port), 1000).allowed == expected
    )

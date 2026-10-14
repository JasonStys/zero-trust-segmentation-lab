"""Jason Stys: strict policy boundaries, ambiguous JSON rejection and bounded inventory/rule invariants."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# definition: test_json_rejects — line 83
# parameter: raw — line 83
# definition: test_parser_fuzz — line 91
# parameter: raw — line 91
# variable: value — line 94
# definition: test_bad_identifier — line 101
# parameter: value — line 101
# definition: test_port_integer — line 108
# parameter: value — line 108
# definition: test_policy_limits — line 132
# parameter: field — line 132
# parameter: value — line 132
# variable: data — line 134
# definition: test_policy_semantics — line 155
# parameter: kind — line 155
# variable: data — line 157
# variable: port — line 175
# definition: test_address_and_identity — line 185
# parameter: address — line 185
# variable: endpoint — line 187
# definition: test_rule_and_flow_contract — line 194
# parameter: tmp_path — line 194
# variable: rule — line 196
# variable: changes — line 197
# variable: path — line 204
# variable: policy — line 206
# variable: sha — line 206
# END CODE MAP

from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from scripts.fixtures import policy_data
from ztlab.contracts import (
    ContractError,
    Endpoint,
    Flow,
    Policy,
    Rule,
    canonical,
    digest,
    identifier,
    integer,
    load_policy,
    parse,
)


@pytest.mark.parametrize(
    "raw",
    [
        b'{"a":1,"a":2}',
        b"NaN",
        b"1.5",
        b"1e999",
        b"\xff",
        b"{",
        b"9" * 5000,
        b"[" * 257,
        b"x" * 65537,
    ],
    ids=[
        "duplicate",
        "nan",
        "float",
        "overflow",
        "utf8",
        "syntax",
        "integer-cap",
        "structure",
        "byte-cap",
    ],
)
def test_json_rejects(raw: bytes) -> None:
    """Reject ambiguous/noninteger/oversized payloads without reflecting their contents."""
    with pytest.raises(ContractError):
        parse(raw)


@given(st.binary(max_size=512))
@settings(max_examples=200, deadline=None)
def test_parser_fuzz(raw: bytes) -> None:
    """Exercise the real parser with arbitrary bytes; successful values round-trip exactly."""
    try:
        value = parse(raw)
    except ContractError:
        return
    assert parse(canonical(value)) == value


@pytest.mark.parametrize("value", ["A", "../web", "wеb", "", "a" * 33, 1])
def test_bad_identifier(value: Any) -> None:
    """Keep names bounded ASCII rather than commands, paths or visual lookalikes."""
    with pytest.raises(ContractError):
        identifier(value)


@pytest.mark.parametrize("value", [True, 0, 65536, 1.0, "8080"])
def test_port_integer(value: Any) -> None:
    """Reject booleans, numeric strings and out-of-range transport ports."""
    with pytest.raises(ContractError):
        integer(value, 1, 65535)


@pytest.mark.parametrize(
    "field,value",
    [
        ("revision", 0),
        ("created_at", True),
        ("expires_at", 1000),
        ("expires_at", 4601),
        ("endpoints", []),
        ("endpoints", "web"),
        ("endpoints", [{}] * 17),
        ("rules", "rule"),
        ("rules", [{}] * 65),
        ("quarantined", "web"),
        ("quarantined", ["web"] * 17),
        ("quarantined", ["unknown"]),
        ("quarantined", ["web", "web"]),
    ],
)
def test_policy_limits(field: str, value: Any) -> None:
    """Explicit limits and missing identities must be rejected during configuration load."""
    data = policy_data()
    data[field] = value
    with pytest.raises(ContractError):
        Policy.from_json(data)


@pytest.mark.parametrize(
    "kind",
    [
        "duplicate-name",
        "duplicate-ip",
        "duplicate-rule",
        "self",
        "unknown",
        "tenant",
        "exception-early",
        "exception-long",
        "ports",
        "extra",
    ],
)
def test_policy_semantics(kind: str) -> None:
    """Reject widening/ambiguous configurations before any exporter sees them."""
    data = deepcopy(policy_data())
    if kind == "duplicate-name":
        data["endpoints"].append(deepcopy(data["endpoints"][0]))
    elif kind == "duplicate-ip":
        data["endpoints"][1]["address"] = data["endpoints"][0]["address"]
    elif kind == "duplicate-rule":
        data["rules"].append(deepcopy(data["rules"][0]))
    elif kind in ("self", "unknown", "tenant"):
        data["rules"][0]["target"] = {
            "self": "web",
            "unknown": "unknown",
            "tenant": "guest",
        }[kind]
    elif kind.startswith("exception"):
        data["rules"][0].update(
            until=1000 if kind == "exception-early" else 1301, ticket="change-1"
        )
    elif kind == "ports":
        data["rules"] = [{**data["rules"][0], "port": port} for port in range(1, 10)]
    else:
        data["allow_all"] = True
    with pytest.raises(ContractError):
        Policy.from_json(data)


@pytest.mark.parametrize(
    "address", ["::1", "198.018.0.11", "invalid", 3323068427, None]
)
def test_address_and_identity(address: Any) -> None:
    """Only exact canonical IPv4 strings match the trusted inventory shape."""
    endpoint = policy_data()["endpoints"][0]
    with pytest.raises(ContractError):
        Endpoint.from_json({**endpoint, "address": address})
    with pytest.raises(ContractError):
        Endpoint.from_json({**endpoint, "identity": "spiffe://wrong/web"})


def test_rule_and_flow_contract(tmp_path: Path) -> None:
    """Incomplete exception metadata and unsupported protocols cannot become permissions."""
    rule = policy_data()["rules"][0]
    for changes in ({"until": 1020}, {"ticket": "change-1"}, {"extra": True}):
        with pytest.raises(ContractError):
            Rule.from_json({**rule, **changes})
    with pytest.raises(ContractError):
        Flow.from_json(
            {"source": "web", "target": "api", "protocol": "icmp", "port": 8080}
        )
    path = tmp_path / "policy.json"
    path.write_bytes(canonical(policy_data()))
    policy, sha = load_policy(path)
    assert len(sha) == 64 and policy.revision == 1 and sha == digest(policy_data())
    path.write_bytes(b"x" * 65537)
    with pytest.raises(ContractError):
        load_policy(path)

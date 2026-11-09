"""Jason Stys: direct dependency invariant and exact synthetic-time boundary regressions."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# definition: fixture — line 61
# parameter: tmp_path — line 61
# variable: p — line 63
# variable: r — line 63
# variable: rows — line 65
# definition: test_exact_expiry_and_direct_no_transitive_grant — line 89
# parameter: tmp_path — line 89
# variable: _ — line 91
# variable: p — line 91
# variable: r — line 91
# variable: before — line 92
# variable: result — line 93
# variable: t — line 94
# variable: t — line 95
# variable: x — line 96
# variable: x — line 97
# variable: t — line 100
# variable: c — line 101
# definition: test_exception_and_quarantine — line 109
# parameter: tmp_path — line 109
# variable: _ — line 111
# variable: p — line 111
# variable: r — line 111
# variable: data — line 112
# variable: result — line 115
# variable: t — line 116
# definition: test_closed_requirement_contract — line 139
# parameter: mode — line 139
# parameter: tmp_path — line 139
# variable: p — line 141
# variable: r — line 141
# variable: rows — line 141
# variable: data — line 142
# definition: test_invalid_bounds_output_and_actual_cli — line 166
# parameter: tmp_path — line 166
# variable: _ — line 168
# variable: p — line 168
# variable: r — line 168
# variable: a — line 169
# variable: b — line 169
# variable: out — line 172
# variable: args — line 173
# variable: before — line 187
# variable: result — line 189
# END CODE MAP

import copy
import json
from pathlib import Path
from unittest.mock import patch

import pytest

from scripts.fixtures import policy_data
from ztlab.cli import main
from ztlab.continuity import preview, publish


def fixture(tmp_path):
    """Authored availability and isolation expectations are independent of policy rules."""
    p, r = tmp_path / "policy.json", tmp_path / "requirements.json"
    p.write_text(json.dumps(policy_data()))
    rows = [
        {
            "id": "web-api",
            "owner": "app-owner",
            "flow": {"source": "web", "target": "api", "protocol": "tcp", "port": 8080},
            "expect": "allow",
        },
        {
            "id": "api-db",
            "owner": "data-owner",
            "flow": {"source": "api", "target": "db", "protocol": "tcp", "port": 8080},
            "expect": "allow",
        },
        {
            "id": "no-web-db",
            "owner": "security-owner",
            "flow": {"source": "web", "target": "db", "protocol": "tcp", "port": 8080},
            "expect": "deny",
        },
    ]
    r.write_text(json.dumps({"schema": 1, "requirements": rows}))
    return p, r, rows


def test_exact_expiry_and_direct_no_transitive_grant(tmp_path: Path):
    """Policy expiry removes two needed dependencies while required direct web→db denial remains correct."""
    p, r, _ = fixture(tmp_path)
    before = p.read_bytes(), r.read_bytes()
    result = preview(p, r, 1000, 1300)
    assert [t["tick"] for t in result["timeline"]] == [1000, 1299, 1300]
    assert [len(t["allowed"]) for t in result["timeline"]] == [2, 2, 0]
    assert {x["id"] for x in result["review_queue"]} == {"web-api", "api-db"}
    assert {x["tick"] for x in result["review_queue"]} == {1300}
    assert all(
        c["matches"]
        for t in result["timeline"]
        for c in t["requirements"]
        if c["id"] == "no-web-db"
    )
    assert (p.read_bytes(), r.read_bytes()) == before and result == preview(
        p, r, 1000, 1300
    )


def test_exception_and_quarantine(tmp_path: Path):
    """Exact exception cutoff and quarantine override cannot be undone by a required-allow declaration."""
    p, r, _ = fixture(tmp_path)
    data = policy_data()
    data["rules"][0].update(until=1120, ticket="review-42")
    p.write_text(json.dumps(data))
    result = preview(p, r, 1119, 1120)
    assert [len(t["allowed"]) for t in result["timeline"]] == [2, 1]
    assert (
        result["review_queue"][0]["id"] == "web-api"
        and result["review_queue"][0]["tick"] == 1120
    )
    data["quarantined"] = ["api"]
    p.write_text(json.dumps(data))
    assert len(preview(p, r, 1000, 1000)["review_queue"]) == 2


@pytest.mark.parametrize(
    "mode",
    [
        "duplicate",
        "contradiction",
        "unknown",
        "self",
        "empty",
        "oversize",
        "wrong-schema",
        "extra",
    ],
)
def test_closed_requirement_contract(tmp_path: Path, mode):
    """Ambiguous or out-of-inventory expectations fail instead of creating false continuity assurances."""
    p, r, rows = fixture(tmp_path)
    data = {"schema": 1, "requirements": copy.deepcopy(rows)}
    if mode == "duplicate":
        data["requirements"].append(copy.deepcopy(rows[0]))
    if mode == "contradiction":
        data["requirements"].append(
            {**copy.deepcopy(rows[0]), "id": "different", "expect": "deny"}
        )
    if mode == "unknown":
        data["requirements"][0]["flow"]["source"] = "absent"
    if mode == "self":
        data["requirements"][0]["flow"]["target"] = "web"
    if mode == "empty":
        data["requirements"] = []
    if mode == "oversize":
        data["requirements"] *= 22
    if mode == "wrong-schema":
        data["schema"] = True
    if mode == "extra":
        data["extra"] = "no"
    r.write_text(json.dumps(data))
    with pytest.raises(ValueError):
        preview(p, r, 1000, 1300)


def test_invalid_bounds_output_and_actual_cli(tmp_path: Path):
    """CLI writes new inert evidence, rejects bad horizons/linked files and preserves old reports."""
    p, r, _ = fixture(tmp_path)
    for a, b in ((-1, 1000), (1000, 999), (0, 3601), (True, 1)):
        with pytest.raises(ValueError):
            preview(p, r, a, b)
    out = tmp_path / "review"
    args = [
        "continuity",
        "--policy",
        str(p),
        "--requirements",
        str(r),
        "--start",
        "1000",
        "--end",
        "1300",
        "--out",
        str(out),
    ]
    assert main(args) == 0
    before = (out / "continuity.json").read_bytes()
    assert main(args) == 2 and (out / "continuity.json").read_bytes() == before
    result = preview(p, r, 1000, 1300)
    result["scope"] = "<script>bad</script>"
    publish(result, tmp_path / "escaped")
    assert "&lt;script&gt;" in (tmp_path / "escaped/continuity.html").read_text(
        encoding="utf-8"
    )
    with patch.object(Path, "is_symlink", return_value=True), pytest.raises(ValueError):
        preview(p, r, 1000, 1300)
    with (
        patch.object(Path, "is_junction", return_value=True),
        pytest.raises(ValueError),
    ):
        publish(result, tmp_path / "linked")

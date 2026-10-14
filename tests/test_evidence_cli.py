"""Jason Stys: real CLI outputs, exact fixture oracles, input limits, escaping, private permissions and no overwrite."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# variable: ROOT — line 53
# definition: test_cli_end_to_end — line 56
# parameter: capsys — line 56
# parameter: tmp_path — line 56
# variable: source — line 58
# variable: requests — line 59
# variable: args — line 60
# variable: report — line 70
# variable: bad — line 85
# variable: row — line 86
# variable: after — line 118
# variable: data — line 119
# variable: diff_args — line 122
# variable: result — line 137
# definition: test_case_file_limits — line 146
# parameter: kind — line 146
# parameter: tmp_path — line 146
# variable: policy — line 148
# variable: sha — line 148
# variable: row — line 149
# variable: encoded — line 156
# variable: raw — line 157
# variable: path — line 164
# definition: test_private_escaped_outputs — line 170
# parameter: tmp_path — line 170
# variable: policy — line 172
# variable: sha — line 172
# variable: report — line 173
# variable: html — line 175
# variable: output — line 177
# variable: existing — line 182
# variable: link — line 190
# END CODE MAP

from __future__ import annotations

import json
import os
import runpy
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from scripts.fixtures import policy_data, request_data
from ztlab.cli import main
from ztlab.contracts import ContractError, canonical, load_policy
from ztlab.evidence import evaluate, private_file, render, save

ROOT = Path(__file__).resolve().parents[1]


def test_cli_end_to_end(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """Evaluate real fixtures, export nft files, diff quarantine and reject old output replacement."""
    source = ROOT / "examples/policy.json"
    requests = ROOT / "examples/requests.jsonl"
    args = [
        "evaluate",
        "--policy",
        str(source),
        "--cases",
        str(requests),
        "--out",
        str(tmp_path / "evidence"),
    ]
    assert main(args) == 0
    report = json.loads((tmp_path / "evidence/evaluation.json").read_text())
    assert report["case_count"] == report["oracle_matches"] == 57
    assert main(args) == 2 and "FileExistsError" in capsys.readouterr().err
    assert (
        main(
            [
                "evaluate",
                "--policy",
                str(tmp_path / "missing"),
                "--out",
                str(tmp_path / "unused"),
            ]
        )
        == 2
    )
    bad = tmp_path / "bad.jsonl"
    row = request_data()[0]
    row["expected"] = not row["expected"]
    bad.write_bytes(canonical(row))
    assert (
        main(
            [
                "evaluate",
                "--policy",
                str(source),
                "--cases",
                str(bad),
                "--out",
                str(tmp_path / "drift"),
            ]
        )
        == 1
    )
    bad.write_bytes(b"{}")
    assert (
        main(
            [
                "evaluate",
                "--policy",
                str(source),
                "--cases",
                str(bad),
                "--out",
                str(tmp_path / "invalid"),
            ]
        )
        == 2
    )
    after = tmp_path / "after.json"
    data = policy_data()
    data["revision"], data["quarantined"] = 2, ["api"]
    after.write_bytes(canonical(data))
    diff_args = [
        "diff",
        "--before",
        str(source),
        "--after",
        str(after),
        "--out",
        str(tmp_path / "delta.json"),
    ]
    assert main(diff_args) == 0 and main(diff_args) == 2
    with (
        patch.dict(sys.modules),
        patch.object(sys, "argv", ["ztlab.cli", *args[:-1], str(tmp_path / "module")]),
    ):
        sys.modules.pop("ztlab.cli", None)
        with pytest.raises(SystemExit) as result:
            runpy.run_module("ztlab.cli", run_name="__main__")
    assert result.value.code == 0


@pytest.mark.parametrize(
    "kind",
    ["bytes", "count", "empty", "blank", "duplicate", "mode", "boolean", "extra"],
)
def test_case_file_limits(tmp_path: Path, kind: str) -> None:
    """Bound reviewed replay files and reject ambiguous or duplicate metadata before evaluation."""
    policy, sha = load_policy(ROOT / "examples/policy.json")
    row = request_data()[0]
    if kind == "mode":
        row["proof_mode"] = "self-approved"
    if kind == "boolean":
        row["expected"] = 1
    if kind == "extra":
        row["allow"] = True
    encoded = canonical(row)
    raw = {
        "bytes": b"x" * 131073,
        "count": b"{}\n" * 129,
        "empty": b"",
        "blank": b"{}\n\n",
        "duplicate": encoded + b"\n" + encoded,
    }.get(kind, encoded)
    path = tmp_path / "cases.jsonl"
    path.write_bytes(raw)
    with pytest.raises(ContractError):
        evaluate(policy, sha, path, 1000)


def test_private_escaped_outputs(tmp_path: Path) -> None:
    """Metadata is inert escaped HTML; existing files and symlinks cannot be overwritten."""
    policy, sha = load_policy(ROOT / "examples/policy.json")
    report = evaluate(policy, sha, ROOT / "examples/requests.jsonl", 1000)
    report["cases"][0]["id"] = "<script>alert('test')</script>"
    html = render(report)
    assert "<script>" not in html and "&lt;script&gt;" in html and "default-src" in html
    output = tmp_path / "export"
    assert len(save(output, report, policy, 1000)) == 64
    assert len(list(output.glob("*.nft"))) == 4
    with pytest.raises(FileExistsError):
        save(output, report, policy, 1000)
    existing = tmp_path / "existing"
    existing.write_text("preserve")
    with pytest.raises(FileExistsError):
        private_file(existing, b"replace")
    assert existing.read_text() == "preserve"
    if os.name != "nt":
        assert output.stat().st_mode & 0o777 == 0o700
        assert (output / "evaluation.json").stat().st_mode & 0o777 == 0o600
        link = tmp_path / "linked"
        link.symlink_to(existing)
        with pytest.raises(FileExistsError):
            private_file(link, b"replace")
        assert existing.read_text() == "preserve"

"""Jason Stys: privacy, exact fixture provenance, tracked-source and no-cache SHA-pinned workflow gates."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# variable: ROOT — line 34
# definition: main — line 40
# variable: names — line 42
# variable: name — line 58
# variable: path — line 59
# variable: text — line 62
# variable: target — line 67
# variable: action — line 77
# variable: word — line 81
# variable: row — line 89
# variable: codeql — line 91
# variable: value — line 94
# variable: path — line 104
# variable: word — line 107
# variable: native — line 109
# END CODE MAP

from __future__ import annotations

import json
import re
import subprocess
import sys
import tomllib
from pathlib import Path

if __package__:
    from .publication_text import public_text
else:
    from publication_text import public_text

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts.fixtures import policy_data, request_data  # noqa: E402
from ztlab.contracts import canonical  # noqa: E402


def main() -> None:
    """Check all tracked text, private-state exclusions, local links, pinning and isolated native test boundaries."""
    names = (
        subprocess.check_output(["git", "ls-files", "-z"], cwd=ROOT)
        .decode()
        .rstrip("\0")
        .split("\0")
    )
    assert {
        "ztlab/contracts.py",
        "ztlab/admission.py",
        "ztlab/analysis.py",
        "ztlab/compiler.py",
        "ztlab/evidence.py",
        "ztlab/cli.py",
        "scripts/native.sh",
        "scripts/native.py",
    }.issubset(names)
    for name in names:
        path = ROOT / name
        assert path.is_file() and not name.startswith(("out/", ".venv/", ".tools/"))
        assert not re.search(r"\.(?:pem|key|env)(?:$|[.-])", name)
        text = public_text(path, ROOT)
        assert not re.search(
            r"(?:ghp_|github_pat_)[A-Za-z0-9]{20,}|BEGIN [A-Z ]*PRIVATE KEY", text
        )
        if name.endswith(".md"):
            for target in re.findall(r"\]\(([^)]+)\)", text):
                if not target.startswith(("http:", "https:", "#", "mailto:")):
                    assert (path.parent / target.split("#")[0]).is_file(), (
                        name + ": " + target
                    )
        if name.startswith(".github/workflows/"):
            assert (
                "pull_request_target" not in text
                and "persist-credentials: false" in text
            )
            for action in re.findall(r"uses:\s*([^\s#]+)", text):
                assert re.fullmatch(r"[\w/.-]+@[a-f0-9]{40}", action)
                assert not any(
                    word in action
                    for word in (
                        "upload-artifact",
                        "download-artifact",
                        "actions/cache",
                    )
                )
    assert json.loads((ROOT / "examples/policy.json").read_text()) == policy_data()
    assert (ROOT / "examples/requests.jsonl").read_bytes() == b"\n".join(
        canonical(row) for row in request_data()
    ) + b"\n"
    codeql = (ROOT / ".github/workflows/codeql.yml").read_text()
    assert all(
        value in codeql
        for value in (
            "trap-caching: false",
            "dependency-caching: false",
            "upload-database: false",
        )
    )
    assert not tomllib.loads((ROOT / "pyproject.toml").read_text())["project"][
        "dependencies"
    ]
    assert "--hash=sha256:" in (ROOT / "requirements-dev.lock").read_text()
    for path in (ROOT / "ztlab").glob("*.py"):
        assert not any(
            word in path.read_text()
            for word in ("import subprocess", "import socket", "shell=True")
        )
    native = (ROOT / "scripts/native.sh").read_text()
    assert (
        "GITHUB_ACTIONS" in native
        and "--run-isolated-demo" in native
        and "created+=(" in native
    )
    assert "ip netns delete" in native and "netns delete -all" not in native
    assert "flush ruleset" not in (ROOT / "scripts/native.py").read_text()
    assert "listener.bind((address, port))" in (ROOT / "scripts/native.py").read_text()
    print(
        f"Privacy/pin/link/fixture/native-isolation gates: {len(names)} tracked files passed"
    )


if __name__ == "__main__":
    main()

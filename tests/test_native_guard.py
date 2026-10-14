"""Jason Stys: native test guard regressions require no privileges and make no network changes."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# definition: test_hosted_guard — line 21
# parameter: actions — line 21
# parameter: platform_name — line 21
# definition: test_invalid_namespace_and_explicit_opt_in — line 31
# END CODE MAP

from __future__ import annotations

from unittest.mock import patch

import pytest

from scripts import native


@pytest.mark.parametrize(
    "platform_name,actions", [("Windows", "true"), ("Linux", "false")]
)
def test_hosted_guard(platform_name: str, actions: str) -> None:
    """Refuse native commands on a workstation or non-hosted Linux environment before any mutation."""
    with (
        patch.object(native.platform, "system", return_value=platform_name),
        patch.dict(native.os.environ, {"GITHUB_ACTIONS": actions}),
    ):
        with pytest.raises(RuntimeError, match="hosted"):
            native.guard()


def test_invalid_namespace_and_explicit_opt_in() -> None:
    """Invalid namespace names and missing wrapper authority cannot enter native command execution."""
    with (
        patch.object(native.platform, "system", return_value="Linux"),
        patch.dict(native.os.environ, {"GITHUB_ACTIONS": "true"}),
    ):
        with pytest.raises(RuntimeError, match="name"):
            native.guard("root")
        with pytest.raises(RuntimeError, match="opt-in"):
            native.run("ztl-123", False)
        with pytest.raises(RuntimeError, match="opt-in"):
            native.run("bad-prefix", True)

"""Jason Stys: correctness-checked admission/matrix/graph timing and allocation observations, not native packet latency."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# variable: ROOT — line 27
# definition: main — line 33
# variable: policy — line 35
# variable: sha — line 35
# variable: path — line 36
# variable: samples — line 38
# variable: _ — line 39
# variable: start — line 40
# variable: report — line 41
# variable: _ — line 47
# variable: peak — line 47
# variable: result — line 49
# END CODE MAP

from __future__ import annotations

import json
import platform
import statistics
import sys
import time
import tracemalloc
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from ztlab.contracts import load_policy  # noqa: E402
from ztlab.evidence import evaluate  # noqa: E402


def main() -> None:
    """Warm up, sample twenty complete evaluations and separately measure Python peak allocation."""
    policy, sha = load_policy(ROOT / "examples/policy.json")
    path = ROOT / "examples/requests.jsonl"
    evaluate(policy, sha, path, 1000)
    samples = []
    for _ in range(20):
        start = time.perf_counter()
        report = evaluate(policy, sha, path, 1000)
        samples.append((time.perf_counter() - start) * 1000)
        if report["oracle_matches"] != report["case_count"]:
            raise RuntimeError("correctness drift; benchmark rejected")
    tracemalloc.start()
    evaluate(policy, sha, path, 1000)
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    result = {
        "author": "Jason Stys",
        "scope": "synthetic admission, matrix and graph; excludes native network/report writes",
        "python": platform.python_version(),
        "platform": platform.system(),
        "policy_sha256": sha,
        "cases": report["case_count"],
        "samples_ms": samples,
        "median_ms": statistics.median(samples),
        "max_ms": max(samples),
        "python_peak_allocated_bytes": peak,
    }
    (ROOT / "out").mkdir(exist_ok=True)
    (ROOT / "out/benchmark.json").write_text(
        json.dumps(result, indent=2) + "\n", encoding="utf-8", newline="\n"
    )
    print(json.dumps(result))


if __name__ == "__main__":
    main()

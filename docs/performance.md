# Complexity and performance methodology

Author: Jason Stys. W ≤ 16 workloads, R ≤ 64 rules, P ≤ 9 matrix ports (eight declared plus a guaranteed closed port), C ≤ 128 cases.

- Strict JSON loading/hash: O(input bytes), bounded at 64 KiB policy / 128 KiB case file.
- Inventory/rule indexing: O(W + R) time and memory.
- Admission/transport lookup: O(1) average after indexing plus O(claim bytes) MAC; fixed schema and small names.
- Matrix: O(W²P) time/output, two protocols, excluding self pairs; at most 4,320 rows.
- Pivot BFS: O(W(W + R)) time; bounded graph, cycles handled by seen sets. Graph paths are not packet grants.
- Policy diff: O(R log R) for sorted edge deltas plus two bounded reachability analyses.
- Export: O(W + R log R) per workload, deterministic joins rather than repeated large concatenations.
- Evidence: O(report bytes), metadata only.

`python scripts/benchmark.py` warms up once, times twenty complete admission/matrix/graph evaluations, checks correctness every sample, then separately measures peak Python allocations with tracemalloc. Records environment, exact input SHA, all samples and median/max in out/benchmark.json.

Includes case-file reading; excludes native packets, output serialization/disk writes and firewall application. Allocation peak is not process RSS. Observations are not latency guarantees. Native probes have bounded timeouts; benchmark has no fragile shared-runner speed gate.

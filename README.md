# Zero-Trust Segmentation Lab

Created by **Jason Stys**. A defensive portfolio lab for default-deny service dependencies, workload admission, posture freshness, quarantine, policy-change analysis and reproducible packet-level assurance.

**Segmentation is not a complete zero-trust architecture.** The offline admission engine uses ephemeral synthetic MAC proofs, not real certificates. The separate Linux kernel test enforces IPv4 TCP transport permissions, not identities. No workstation firewall, cloud account, Kubernetes cluster or Docker installation is changed.

## Quick start

Python 3.12+ from the repository root; no runtime dependencies, credentials, service or network access needed:

```console
python -m ztlab.cli evaluate --out out/first-evaluation
```

Open out/first-evaluation/evaluation.html in a browser. JSON contains 57 reviewed admission outcomes, a 48-row transport matrix and possible application-pivot paths. Four .nft files are **exports only**: never apply them to a host network namespace. Choose a new output directory each time; existing evidence is not overwritten.

The demo uses synthetic clock tick 1000, not today's timestamp. See [usage](docs/usage.md) before changing configuration.

## Features

- **Default deny:** two exact dependencies, web → api and api → db, TCP/8080. Reverse direction, unknown peers, wrong ports/protocols and cross-tenant traffic are denied.
- **Workload admission:** exact source/identity binding, MAC integrity, healthy posture, 30-tick freshness and policy revision checked per request. Sharing a subnet grants no identity trust.
- **Policy lifecycle:** immutable inventory, reviewed short-lived exception metadata, explicit policy expiry, deny-overrides quarantine and exact added/removed permission diffs.
- **Pivot analysis:** bounded BFS shows possible application compromise paths; web reaching db through api never grants direct web → db connectivity.
- **Deterministic exports:** namespace-scoped nftables input/output/forward default-drop rules, exact source/destination/port restrictions and response connection tracking.
- **Real hosted packets:** disposable isolated Linux namespaces, private bridge with no uplink/NAT/default route, instrumented IPv4/IPv6 TCP/UDP listeners, baseline checks, ingress/egress independence, invalid update preservation, live-session revocation and rollback.
- **Safe evidence:** metadata-only JSON and escaped script-free HTML; generated files stay ignored/private. POSIX modes are restrictive; Windows inherits parent ACLs. No encryption is claimed.
- **DevSecOps:** OS/Python test matrix, strict types/style, hash-locked development graph, dependency audit, Gitleaks, actionlint, shellcheck and CodeQL. No Actions artifacts/caches, including implicit CodeQL caches.

## Documentation

- [Architecture and decisions](docs/architecture.md)
- [Configuration and admission contracts](docs/contracts.md)
- [Threat model and limits](docs/security.md)
- [Usage and troubleshooting](docs/usage.md)
- [Testing and native enforcement](docs/testing.md)
- [Performance and complexity](docs/performance.md)
- [Primary-source research](docs/research.md)
- [Coding/contribution rules](docs/contributing.md)
- [Release and rollback checklist](docs/release.md)
- [Actual validation evidence](docs/validation.md)

## Development

Activate a virtual environment or use its Python executable explicitly:

```console
python -m venv .venv
python -m pip install --require-hashes -r requirements-dev.lock
python -m ruff check .
python -m ruff format --check .
python -m mypy
python -m pytest --cov=ztlab --cov-report=term-missing:skip-covered
python scripts/code_map.py --check
python scripts/file_guide.py --check
python scripts/validate_repo.py
python scripts/benchmark.py
```

The native job requires explicit hosted-runner opt-in and privileges **inside its disposable test environment**. It is intentionally unavailable on this PC. Default CLI/test commands never invoke ip/nft/conntrack.

## Author and license

Jason Stys · [GitHub / contact](https://github.com/JasonStys) · [LinkedIn](https://www.linkedin.com/in/jason-stys-31b30b351/). MIT-licensed original implementation and synthetic fixtures. No affiliation, government authorization, clearance or compliance certification is claimed.

## Validated evidence

70 tests passed with 100% combined runtime statement/branch coverage. All 57 admission oracles matched. Actual isolated kernel tests verified 96 baseline/enforced channels, live-session revocation and rollback. All seven accepted-source CI jobs passed with zero open CodeQL alerts and zero Actions artifacts/caches. [Measured reports and correction history](docs/validation.md) preserve scope and exact source/run identities; check [current Actions](https://github.com/JasonStys/zero-trust-segmentation-lab/actions) for the current commit.

## Complete file inventory

<!-- BEGIN FILE GUIDE -->

| File | Purpose |
| --- | --- |
| [.gitattributes](.gitattributes) | Consistent LF text checkouts across operating systems. |
| [.github/workflows/ci.yml](.github/workflows/ci.yml) | Jason Stys: cross-platform admission assurance, real isolated Linux packets and audited dependencies; no artifacts/caches. |
| [.github/workflows/codeql.yml](.github/workflows/codeql.yml) | Jason Stys: security-extended Python analysis; explicitly disable trap/dependency caches and database uploads. |
| [.gitignore](.gitignore) | Exclude private diagnostics, builds, environments and generated fuzz artifacts. |
| [LICENSE](LICENSE) | MIT license for Jason Stys's authored code. |
| [README.md](README.md) | Zero-Trust Segmentation Lab. |
| [docs/architecture.md](docs/architecture.md) | Architecture and decisions. |
| [docs/contracts.md](docs/contracts.md) | Configuration and admission contracts. |
| [docs/contributing.md](docs/contributing.md) | Coding and contribution rules. |
| [docs/performance.md](docs/performance.md) | Complexity and performance methodology. |
| [docs/release.md](docs/release.md) | Publication and rollback checklist. |
| [docs/reports/benchmark.json](docs/reports/benchmark.json) | Measured bounded policy/matrix analysis timing, not network latency. |
| [docs/reports/ci.json](docs/reports/ci.json) | Immutable accepted-source CI snapshot, not a future guarantee. |
| [docs/reports/evaluation.json](docs/reports/evaluation.json) | Actual admission outcomes, L4 matrix and reachability analysis. |
| [docs/reports/native.json](docs/reports/native.json) | Actual isolated namespace packet, revocation and cleanup evidence. |
| [docs/research.md](docs/research.md) | Primary-source research and mapping. |
| [docs/security.md](docs/security.md) | Threat model and limits. |
| [docs/testing.md](docs/testing.md) | Testing and native enforcement strategy. |
| [docs/usage.md](docs/usage.md) | Usage and troubleshooting. |
| [docs/validation.md](docs/validation.md) | Validation evidence. |
| [examples/policy.json](examples/policy.json) | Reviewed four-workload inventory and exact TCP segmentation rules. |
| [examples/requests.jsonl](examples/requests.jsonl) | Deterministic admission regression inputs and independent expected decisions. |
| [pyproject.toml](pyproject.toml) | Jason Stys: strict typed standard-library runtime and branch coverage across every runtime module. |
| [requirements-dev.in](requirements-dev.in) | Jason Stys: exact development-only tools; Python runtime uses only the standard library. |
| [requirements-dev.lock](requirements-dev.lock) | Universal full hash-locked Python development graph. |
| [scripts/benchmark.py](scripts/benchmark.py) | Jason Stys: correctness-checked admission/matrix/graph timing and allocation observations, not native packet latency. |
| [scripts/code\_map.py](scripts/code_map.py) | Jason Stys: exact Python AST definition/parameter/variable maps and lexical Bash/workflow line indexes. |
| [scripts/file\_guide.py](scripts/file_guide.py) | Jason Stys: exact tracked-file README purpose inventory, unknown files fail rather than receive guesses. |
| [scripts/fixtures.py](scripts/fixtures.py) | Jason Stys: generate deterministic reviewed inventory and admission oracles from independent scenario definitions. |
| [scripts/native.py](scripts/native.py) | Jason Stys: actual IPv4/IPv6 TCP/UDP and state-revocation tests inside owned hosted-runner namespaces only. |
| [scripts/native.sh](scripts/native.sh) | Jason Stys: create and clean only owned disposable CI network namespaces; never touch host interfaces/firewall. |
| [scripts/scanners.py](scripts/scanners.py) | Install only hash-pinned official Linux scanner binaries. Created by Jason Stys. |
| [scripts/validate\_repo.py](scripts/validate_repo.py) | Jason Stys: privacy, exact fixture provenance, tracked-source and no-cache SHA-pinned workflow gates. |
| [tests/test\_contracts.py](tests/test_contracts.py) | Jason Stys: strict policy boundaries, ambiguous JSON rejection and bounded inventory/rule invariants. |
| [tests/test\_evidence\_cli.py](tests/test_evidence_cli.py) | Jason Stys: real CLI outputs, exact fixture oracles, input limits, escaping, private permissions and no overwrite. |
| [tests/test\_native\_guard.py](tests/test_native_guard.py) | Jason Stys: native test guard regressions require no privileges and make no network changes. |
| [tests/test\_policy.py](tests/test_policy.py) | Jason Stys: actual admission decisions, exact identity/freshness binding, quarantine, graph and exporter regression. |
| [tools.lock.json](tools.lock.json) | Official Linux scanner versions, URLs and SHA256 digests. |
| [ztlab/\_\_init\_\_.py](ztlab/__init__.py) | Jason Stys: offline segmentation evaluation; importing this package changes no network state. |
| [ztlab/admission.py](ztlab/admission.py) | Jason Stys: caller-bound synthetic attestation and per-request policy decisions independent of network location. |
| [ztlab/analysis.py](ztlab/analysis.py) | Jason Stys: finite transport matrices, bounded BFS pivot analysis and exact policy-change blast-radius deltas. |
| [ztlab/cli.py](ztlab/cli.py) | Jason Stys: read-only evaluation and policy-diff CLI; local execution never applies network changes. |
| [ztlab/compiler.py](ztlab/compiler.py) | Jason Stys: deterministic namespace-scoped nftables projection; exports rules but never applies them. |
| [ztlab/contracts.py](ztlab/contracts.py) | Jason Stys: bounded strict inventory, flow and rule contracts; no paths or labels are interpreted as commands. |
| [ztlab/evidence.py](ztlab/evidence.py) | Jason Stys: bounded synthetic admission replay and exclusive metadata-only JSON/HTML/nft evidence outputs. |

<!-- END FILE GUIDE -->

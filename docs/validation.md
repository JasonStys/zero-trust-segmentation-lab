# Validation evidence

Author: Jason Stys. Validated 2026-10-14. Accepted implementation: [2653df861c90a87f2d282c372416915e3350e408](https://github.com/JasonStys/zero-trust-segmentation-lab/commit/2653df861c90a87f2d282c372416915e3350e408).

Windows/Python 3.14.6: 70 tests passed, 100% combined runtime statement/branch coverage (374 statements, 122 branches, all seven modules). Strict mypy and Ruff passed; locked graph audit found no known vulnerabilities. The hosted Linux/Python 3.14 log independently confirmed 70 passed and 100% runtime coverage.

Fifty-seven reviewed admission cases matched their independent expected decisions. The 48-row L4 model permits only two exact directed TCP dependencies. Parser and independent flow-oracle property tests run 200 and 300 examples respectively per suite.

The actual CLI generated JSON, escaped HTML and four export-only nft files. No host networking, Docker, cloud account, private inventory or real credentials were changed/used. Native commands explicitly refused this Windows environment.

## Completed hosted validation

- [Validate run 38600770675](https://github.com/JasonStys/zero-trust-segmentation-lab/actions/runs/38600770675): all six jobs passed (four OS/Python combinations, native packets, locked graph/secrets/workflows).
- [CodeQL run 38600770645](https://github.com/JasonStys/zero-trust-segmentation-lab/actions/runs/38600770645): Python security-extended analysis passed; zero open alerts when inspected.
- Native baseline: all 96 instrumented IPv4/IPv6 TCP/UDP channels delivered the fixed frame before filtering. Enforcement: two exact allowed channels succeeded and all other 94 failed, matching the projection.
- Invalid replacement preserved existing rules. Ingress/egress were independently necessary. Quarantine revoked an already-open connection and denied new dependency flows; reviewed rollback restored the two allowed flows.
- All owned namespace names were verified absent after cleanup. No workstation firewall, Docker, cloud or external network was touched.
- Completed workflows stored zero Actions artifacts and zero cache bytes.

## Preserved actual evidence

- [Immutable CI snapshot](reports/ci.json): accepted source, actual run/job IDs, timestamps and scoped local/browser evidence.
- [Native kernel observations](reports/native.json): all 96 observations plus positive baseline, update/revocation/rollback and observed cleanup. Tools: nftables 1.0.9, iproute2 6.1.0, conntrack 1.4.8. This is L4 enforcement, not mTLS authentication.
- [Admission/model evidence](reports/evaluation.json): 57/57 oracles matched; 48 transport rows; pivot graph. Synthetic MAC identity/posture checks are separate from kernel listeners.
- [Hosted performance observations](reports/benchmark.json): twenty measured complete admission/matrix/graph samples; median about 2.720 ms, Python allocation peak 262,898 bytes. Excludes native packets and report writes; no speed guarantee.

The generated report opened in a local browser with 57 case rows, six scoped column headers, zero scripts/external assets and a restrictive meta CSP. This is a content/structure smoke check, not a full accessibility or cross-browser audit. Temporary preview server stopped afterward.

[Testing](testing.md) and [security](security.md) explain scope. Account storage evidence remains private; coverage is not proof of security. The accepted snapshot is immutable historical evidence, not a promise that subsequent documentation or future commits pass; inspect current Actions for the current head.

## Initial hosted correction

[Initial Validate run 38599731980](https://github.com/JasonStys/zero-trust-segmentation-lab/actions/runs/38599731980) caught ShellCheck SC2015 in the cleanup helper before native tests began. An ambiguous and/or shortcut was replaced with an explicit if block; no lint suppression, test removal or policy weakening was used. The failed run and logs remain in GitHub history.

CodeQL identified wildcard listener bindings in the isolated test servers. They were changed to bind exact owned namespace addresses, rather than suppressing/dismissing the alert. Subsequent native tests passed and CodeQL automatically reported zero open alerts.

Final edge-case review added explicit clock validation for empty permission graphs. Negative, boolean and overflowing clock values cannot bypass checks just because there are no graph edges.

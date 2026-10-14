# Validation evidence

Author: Jason Stys. Initial local validation 2026-10-14; hosted results are recorded only after completion.

Windows/Python 3.14.6: 67 tests passed, 100% combined runtime statement/branch coverage (372 statements, 122 branches, all seven modules). Strict mypy and Ruff passed; locked graph audit found no known vulnerabilities.

Fifty-seven reviewed admission cases matched their independent expected decisions. The 48-row L4 model permits only two exact directed TCP dependencies. Parser and independent flow-oracle property tests run 200 and 300 examples respectively per suite.

The actual CLI generated JSON, escaped HTML and four export-only nft files. No host networking, Docker, cloud account, private inventory or real credentials were changed/used. Native commands explicitly refused this Windows environment.

Privileged kernel enforcement requires the separate hosted job. Until its actual observations are available, these local checks are not native packet results. [Testing](testing.md) and [security](security.md) explain scope. Account storage evidence remains private; coverage is not proof of security.

## Initial hosted correction

[Initial Validate run 38599731980](https://github.com/JasonStys/zero-trust-segmentation-lab/actions/runs/38599731980) caught ShellCheck SC2015 in the cleanup helper before native tests began. An ambiguous and/or shortcut was replaced with an explicit if block; no lint suppression, test removal or policy weakening was used. The failed run and logs remain in GitHub history.

CodeQL identified wildcard listener bindings in the isolated test servers. They were changed to bind exact owned namespace addresses, rather than suppressing/dismissing the alert. Subsequent kernel and security scans must confirm the change before accepted evidence is published.

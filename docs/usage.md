# Usage and troubleshooting

Author: Jason Stys.

Run from repo root using Python 3.12+. `python -m ztlab.cli evaluate --out out/first-evaluation` writes metadata JSON, script-free HTML and four ruleset exports to a new directory. It never applies networking changes.

The demo's trusted clock defaults to tick 1000, policy valid through but excluding 1300. Pass --now explicitly to explore expiry; expected fixtures may then drift and return nonzero. Do not mistake synthetic ticks for real authentication time.

## Interpret

Admission allow means demo proof/context and exact dependency passed. L4 allow means an inventory address/port permission, not proof of identity. Deny reason distinguishes identity, freshness, tenant, quarantine, scope and expiry. A web → api → db graph path does not allow web → db packets.

Exit codes: 0 all reviewed oracles match; 1 mismatch; 2 invalid input/output failure. Zero does not certify a production zero-trust deployment.

## Change review

Make a new reviewed policy file; increment revision; define exact dependencies or short ticketed exceptions. Compare:

```console
python -m ztlab.cli diff --before examples/policy.json --after out/reviewed-policy.json --now 1000 --out out/change-diff.json
```

Create out/ and the reviewed file yourself before this example; it is not supplied production configuration. Inspect added permissions, removed edges and pivot changes; test before deployment. The CLI never applies either policy.

## Hosted native tests

The privileged script requires --run-isolated-demo, a disposable GitHub Linux runner, root, fresh collision-free owned namespace names and the Bash wrapper's prefix. It intentionally refuses workstation execution. Namespace workers verify their actual namespace inode. No local Docker or OS security settings are changed.

## Troubleshoot

- Existing output: choose a new path; never discard evidence just to make a command pass.
- Invalid contract: see [contracts](contracts.md); check exact fields, integer ticks, IPs, names, duplicates and caps.
- Denied posture: expected security result, not a reason to bypass proof checks.
- Native missing baseline/readiness: test failure, not a successful denial. Check signed Ubuntu packages and runner namespace/IPv6 capability.
- Partial I/O: privately inspect existing outputs and choose a new directory.
- Windows temp limits: set shell TEMP/TMP to an explicitly created out/temp directory before environment creation/testing.
- Support: [Jason Stys](https://github.com/JasonStys). Keep real inventories/proofs private.

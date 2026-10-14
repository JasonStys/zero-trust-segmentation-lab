# Testing and native enforcement strategy

Author: Jason Stys.

## Offline layers

Unit/negative tests cover JSON duplicates/overflow/types/UTF-8/limits, unique inventory, cross-tenant/self/unknown rules, short exceptions, quarantine, exact proof binding, expired/future posture and revision mismatch. Graph cycles and direct-versus-pivot permissions are independently checked.

Property tests: 200 arbitrary byte examples through the actual parser; 300 source/target/protocol/port combinations compared with an independent exact-edge oracle. This is not exhaustive or coverage-guided native fuzzing.

Integration tests run the actual CLI, generated JSON/HTML/nft files, escaping, no-overwrite, permissions/symlinks and change diffs. POSIX-only checks run on Linux/macOS; Windows inherits parent ACLs. Native guard tests make no changes on any workstation.

Minimum 95% combined statements/branches across **all seven runtime modules**. Test/scripts coverage is not included.

## Native packet methodology

Four workload namespaces plus one private bridge namespace. Baseline: all 96 directed pair × IPv4/IPv6 × TCP/UDP × two-port channels must deliver the fixed application frame. Every server must remain alive; absent/error telemetry fails, never counts as denial.

Apply generated input/output/forward rules and clear only owned conntrack state. Expected projection: two IPv4 TCP permissions, all other 94 channels denied. Actual application frame delivery is measured, not merely connect/send success. Server TCP receives correctly handle fragmented frames.

Additional checks: invalid replacement rejected while old rules remain; source egress and target ingress are independently necessary; an already-open connection is revoked after quarantine/state cleanup; new quarantined dependencies are denied; reviewed rollback restores exact permits. Finally all owned namespace names are removed and verified absent.

This proves the **tested kernel projection**, not real workload authentication, full zero-trust architecture, all protocol behavior or a production deployment.

## CI gates

Four OS/Python jobs (Linux 3.12/3.14, Windows 3.14, macOS 3.14), a privileged disposable native job, locked dependency/secret/workflow checks and CodeQL security-extended. Native Bash also passes bash -n and shellcheck.

No artifact/cache upload; CodeQL trap/dependency caches and database upload disabled. Synthetic results are normalized into docs/reports only after actual success. Private account billing/storage evidence is never published.

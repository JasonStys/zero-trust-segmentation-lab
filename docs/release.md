# Publication and rollback checklist

Author: Jason Stys. This is a source lab, not a production deployment.

Before publication: strict contracts/types/style, all tests and coverage gate, exact source-line maps, full file inventory, local links, fixture provenance, locked dependency audit, secret scan, workflow lint, Bash checks and CodeQL. Confirm latest main matches local reviewed source and all jobs passed.

Native job must retain positive baseline, instrumented observations, unchanged-table failure check, one-sided isolation, existing-session revocation, quarantine, rollback and owned namespace cleanup. Missing evidence is failure.

Only public synthetic evidence goes into docs/reports. Keep account billing/storage private. Check live artifact/cache counters and warn about the available billing meter; ask fresh approval before deleting anything.

Do not deploy this project's firewall exports to a workstation/production environment. If an experiment fails, the CI wrapper terminates only owned namespace processes and deletes only successfully created names. Namespace resources are disposable; source/commit history and failed-run logs remain recoverable.

A production change would need authenticated workload identity, trusted posture/time, staged rollout, scoped established-session handling, monitoring, independently approved rollback and downstream policy enforcement. Those operational approvals are not supplied by this lab.

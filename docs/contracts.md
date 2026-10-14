# Configuration and admission contracts

Author: Jason Stys. Strict UTF-8 integer-only JSON, duplicate-key rejection; 64 KiB per record and conservative structural limits.

## Policy

Exactly revision, created_at, expires_at, endpoints, rules and quarantined. Validity: positive revision, nonnegative ticks, lifetime at most 3,600 ticks. Bounds: 1–16 endpoints, at most 64 exact rules and eight distinct service ports. Inventory names and IP addresses are unique; quarantine IDs are known/unique.

Endpoint: name, tenant, canonical IPv4 address and identity exactly shaped as spiffe://lab.example/tenant/name. **This string is not proof of a certificate or workload identity.**

Rule: source, target, port, until, ticket. TCP only. No wildcard/CIDR grants or self/cross-tenant rules. A temporary rule must have both ticket and deadline, after creation and within the policy's validity / 300-tick exception limit. A ticket records a reviewed change, not authenticated approval.

## Flow and proof

Flow: exactly source, target, protocol (tcp/udp) and port (integer 1–65,535, not boolean). Caller-supplied extra fields cannot mint identity/posture authority.

A trusted demo attester seals workload, identity, posture, issued_at, expires_at and policy_revision using an ephemeral random HMAC key. Admission requires exact source/identity, healthy posture, current policy revision and freshness no longer than thirty ticks. Reuse during validity is allowed; this is not a single-use authorization token. Altered or foreign-key proof fails. Key loss/restart invalidates issued proofs.

Proofs are in-process fixture objects, not a public protocol or credential store. Production must supply actual verified credentials and trusted time through a real enforcement point.

## Reviewed cases

JSONL file capped at 128 KiB / 128 nonblank records. Each has exactly id, flow, proof_mode and expected boolean. Mode: valid/missing/tampered/wrong-identity/wrong-source/unhealthy/expired/future/old-policy. IDs are unique bounded ASCII. Expected labels grade decisions; they never choose policy outcomes.

## Evidence

Schema version 1 includes input byte hashes, revision, synthetic clock, decisions/reasons/oracle matches, L4 matrix and pivot lists. Proof signatures/keys are never included. Hashes identify content, not authenticity/anonymity. Outputs are new-only JSON, inert HTML and nft exports; no command applies them.

The compiler is a **snapshot at the selected tick**. It does not schedule future expiry or update active firewalls. Deployment controllers must recompile/reconcile and handle established sessions.

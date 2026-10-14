# Architecture and decisions

Author: Jason Stys. ADRs accepted for this defensive lab, 2026-10-14.

## Separation of concerns

Trusted reviewed inventory + flow + synthetic attestation → Python admission decision. Independently: effective L4 permissions → nftables export → owned hosted namespaces → instrumented packet observations.

The layers are separately tested, **not integrated into a production proxy**. Real applications need an authenticated policy-enforcement point binding verified peer credentials to requests, plus a managed network dataplane.

## ADR-001: Python policy control plane

Standard-library dataclasses, HMAC, strict JSON, indexing and BFS fit bounded control-plane work. Immutable policy and indexed exact permissions keep decisions readable and constant-time after loading. No compiled extension, framework or provider account is needed. Strict mypy/Ruff and property tests validate it.

Alternative: only firewall scripts. That would demonstrate network filtering but miss identity, posture and revision semantics. Conversely, only Python simulation would not demonstrate actual kernel enforcement.

## ADR-002: Bash namespace lifecycle; nftables dataplane

Bash orchestrates native Linux tools and tracks successfully created namespace names. All virtual links/bridge live inside those namespaces. The host has no test interface, bridge, default-route or firewall change. Native helper commands use argument lists, never shell evaluation.

nftables projects exact IPv4 TCP permissions into both source egress and target ingress, with default drop on input/output/forward. Established replies are permitted; connection tracking must be cleared **in owned namespaces** during scoped revocation. Unsupported new IPv6/UDP channels are closed in this projection.

Alternative: provision Kubernetes/CNI or cloud networks. Those are relevant production targets but add permissions, costs and environmental assumptions. No Kubernetes support or cluster validation is claimed here.

## ADR-003: separate admission and transport evidence

Synthetic short-lived MAC claims model per-request identity/posture checks. The private key is ephemeral process memory; no signing key/token is stored. This is not mTLS, SPIRE, JWT validation or device attestation. Native listeners deliberately serve harmless fixed frames without application authentication, demonstrating the L4 layer only.

Graph transitivity reports a possible compromised-service pivot, not a routing permission or verified exploit. Diffs describe effective new connections at a selected trusted clock tick; they are never applied by the CLI.

## ADR-004: safe publication

Only synthetic source/fixtures and measured synthetic reports are public. Outputs are exclusive, local and ignored. Runtime has no network calls or subprocess imports. Privileged native routines are separate guarded CI scripts. No artifact/cache upload is permitted, including CodeQL's internal caching.

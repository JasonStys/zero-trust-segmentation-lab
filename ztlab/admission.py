"""Jason Stys: caller-bound synthetic attestation and per-request policy decisions independent of network location."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# definition: Claims — line 67
# variable: workload — line 70
# variable: identity — line 71
# variable: posture — line 72
# variable: issued_at — line 73
# variable: expires_at — line 74
# variable: policy_revision — line 75
# definition: Proof — line 79
# variable: claims — line 82
# variable: signature — line 83
# definition: Attester — line 86
# definition: __init__ — line 89
# parameter: self — line 89
# attribute: _key — line 91
# definition: sign — line 93
# parameter: claims — line 93
# parameter: self — line 93
# definition: issue — line 99
# parameter: claims — line 99
# parameter: self — line 99
# definition: verify — line 103
# parameter: proof — line 103
# parameter: self — line 103
# definition: Decision — line 111
# variable: allowed — line 114
# variable: reason — line 115
# variable: revision — line 116
# definition: Engine — line 119
# definition: __init__ — line 122
# parameter: attester — line 122
# parameter: policy — line 122
# parameter: self — line 122
# attribute: policy — line 124
# attribute: attester — line 125
# attribute: endpoints — line 126
# variable: item — line 126
# attribute: rules — line 127
# variable: item — line 128
# attribute: quarantined — line 130
# definition: transport — line 132
# parameter: flow — line 132
# parameter: now — line 132
# parameter: self — line 132
# variable: rule — line 145
# definition: decide — line 150
# parameter: flow — line 150
# parameter: now — line 150
# parameter: proof — line 150
# parameter: self — line 150
# variable: transport — line 152
# variable: claims — line 157
# END CODE MAP

from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import asdict, dataclass

from ztlab.contracts import Flow, Policy, canonical, integer


@dataclass(frozen=True)
class Claims:
    """Trusted demo attester's workload identity, posture, freshness and policy revision."""

    workload: str
    identity: str
    posture: str
    issued_at: int
    expires_at: int
    policy_revision: int


@dataclass(frozen=True)
class Proof:
    """Ephemeral HMAC-sealed claims; never logged or stored in public reports."""

    claims: Claims
    signature: str


class Attester:
    """Demo-only single-process issuer, not a certificate authority or production identity provider."""

    def __init__(self) -> None:
        """Create an ephemeral random MAC key; there are no static credentials in the repository."""
        self._key = secrets.token_bytes(32)

    def sign(self, claims: Claims) -> str:
        """Bind every claim without exposing the key to untrusted flow inputs."""
        return hmac.new(
            self._key, canonical(asdict(claims)), hashlib.sha256
        ).hexdigest()

    def issue(self, claims: Claims) -> Proof:
        """Trusted test-fixture operator operation; callers cannot issue proof through the flow contract."""
        return Proof(claims, self.sign(claims))

    def verify(self, proof: Proof | None) -> bool:
        """Validate integrity before interpreting workload authority or device posture."""
        return proof is not None and hmac.compare_digest(
            proof.signature, self.sign(proof.claims)
        )


@dataclass(frozen=True)
class Decision:
    """Safe allow/deny metadata; content, credentials and attestation signatures are excluded."""

    allowed: bool
    reason: str
    revision: int


class Engine:
    """Preindexed per-request admission plus conservative IPv4 TCP segmentation projection."""

    def __init__(self, policy: Policy, attester: Attester) -> None:
        """Index exact endpoints and permissions once; immutable policy prevents stale index mutation."""
        self.policy = policy
        self.attester = attester
        self.endpoints = {item.name: item for item in policy.endpoints}
        self.rules = {
            (item.source, item.target, item.port): item for item in policy.rules
        }
        self.quarantined = frozenset(policy.quarantined)

    def transport(self, flow: Flow, now: int) -> Decision:
        """Evaluate a new L4 flow, default deny; no trust is granted merely for sharing a network segment."""
        integer(now, 0, 2**31 - 1)
        if not self.policy.created_at <= now < self.policy.expires_at:
            return Decision(False, "policy-not-current", self.policy.revision)
        if flow.source not in self.endpoints or flow.target not in self.endpoints:
            return Decision(False, "unknown-workload", self.policy.revision)
        if flow.source in self.quarantined or flow.target in self.quarantined:
            return Decision(False, "quarantined", self.policy.revision)
        if self.endpoints[flow.source].tenant != self.endpoints[flow.target].tenant:
            return Decision(False, "tenant-boundary", self.policy.revision)
        if flow.protocol != "tcp":
            return Decision(False, "default-deny", self.policy.revision)
        rule = self.rules.get((flow.source, flow.target, flow.port))
        if rule is None or rule.until is not None and now >= rule.until:
            return Decision(False, "default-deny", self.policy.revision)
        return Decision(True, "explicit-rule", self.policy.revision)

    def decide(self, flow: Flow, proof: Proof | None, now: int) -> Decision:
        """Require proof, exact source identity, healthy fresh posture and current revision for every admission."""
        transport = self.transport(flow, now)
        if not transport.allowed:
            return transport
        if not self.attester.verify(proof) or proof is None:
            return Decision(False, "unverified-proof", self.policy.revision)
        claims = proof.claims
        if (
            claims.workload != flow.source
            or claims.identity != self.endpoints[flow.source].identity
        ):
            return Decision(False, "identity-binding", self.policy.revision)
        if not claims.issued_at <= now < claims.expires_at <= claims.issued_at + 30:
            return Decision(False, "stale-posture", self.policy.revision)
        if claims.posture != "healthy":
            return Decision(False, "unhealthy-posture", self.policy.revision)
        if claims.policy_revision != self.policy.revision:
            return Decision(False, "stale-policy-proof", self.policy.revision)
        return Decision(True, "verified-admission", self.policy.revision)

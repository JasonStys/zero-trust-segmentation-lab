"""Jason Stys: bounded strict inventory, flow and rule contracts; no paths or labels are interpreted as commands."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# definition: ContractError — line 115
# definition: pairs — line 119
# parameter: items — line 119
# variable: output — line 121
# variable: key — line 122
# variable: value — line 122
# definition: reject_number — line 129
# parameter: value — line 129
# definition: parse — line 134
# parameter: raw — line 134
# variable: text — line 139
# definition: canonical — line 152
# parameter: value — line 152
# definition: digest — line 159
# parameter: value — line 159
# definition: fields — line 164
# parameter: names — line 164
# parameter: value — line 164
# definition: identifier — line 171
# parameter: value — line 171
# definition: integer — line 178
# parameter: maximum — line 178
# parameter: minimum — line 178
# parameter: value — line 178
# definition: Endpoint — line 186
# variable: name — line 189
# variable: tenant — line 190
# variable: address — line 191
# variable: identity — line 192
# definition: from_json — line 195
# parameter: cls — line 195
# parameter: value — line 195
# variable: data — line 197
# variable: name — line 198
# variable: tenant — line 198
# variable: address — line 200
# definition: Flow — line 212
# variable: source — line 215
# variable: target — line 216
# variable: protocol — line 217
# variable: port — line 218
# definition: from_json — line 221
# parameter: cls — line 221
# parameter: value — line 221
# variable: data — line 223
# definition: Rule — line 235
# variable: source — line 238
# variable: target — line 239
# variable: port — line 240
# variable: until — line 241
# variable: ticket — line 242
# definition: from_json — line 245
# parameter: cls — line 245
# parameter: value — line 245
# variable: data — line 247
# variable: until — line 248
# variable: ticket — line 251
# definition: Policy — line 264
# variable: revision — line 267
# variable: created_at — line 268
# variable: expires_at — line 269
# variable: endpoints — line 270
# variable: rules — line 271
# variable: quarantined — line 272
# definition: from_json — line 275
# parameter: cls — line 275
# parameter: value — line 275
# variable: data — line 277
# variable: revision — line 288
# variable: created — line 289
# variable: expires — line 289
# variable: endpoints — line 304
# variable: item — line 304
# variable: item — line 305
# variable: known — line 305
# variable: item — line 307
# variable: item — line 310
# variable: rules — line 310
# variable: item — line 312
# variable: item — line 313
# variable: rule — line 316
# variable: item — line 329
# variable: quarantined — line 329
# definition: read_source — line 338
# parameter: limit — line 338
# parameter: path — line 338
# variable: absolute — line 340
# variable: item — line 343
# variable: flags — line 346
# variable: descriptor — line 352
# variable: stream — line 353
# variable: info — line 354
# variable: named — line 355
# variable: raw — line 363
# definition: load_policy — line 369
# parameter: path — line 369
# variable: raw — line 371
# END CODE MAP

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any


class ContractError(ValueError):
    """Reject invalid configuration without echoing potentially private input contents."""


def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
    """Reject duplicate JSON keys before they can silently change a policy field."""
    output: dict[str, Any] = {}
    for key, value in items:
        if key in output:
            raise ContractError("duplicate JSON key")
        output[key] = value
    return output


def reject_number(value: str) -> None:
    """Only bounded integer ticks/ports are supported; floating and nonfinite representations are rejected."""
    raise ContractError("integer-only contract")


def parse(raw: bytes) -> Any:
    """Decode at most 64 KiB with conservative structural limits and strict UTF-8/integer JSON."""
    if len(raw) > 65536:
        raise ContractError("record too large")
    try:
        text = raw.decode("utf-8")
        if text.count("{") + text.count("[") > 256:
            raise ContractError("structure budget")
        return json.loads(
            text,
            object_pairs_hook=pairs,
            parse_float=reject_number,
            parse_constant=reject_number,
        )
    except (ValueError, UnicodeError, RecursionError) as error:
        raise ContractError("invalid JSON") from error


def canonical(value: Any) -> bytes:
    """Produce stable compact ASCII JSON for content hashes and demo MAC bindings."""
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode()


def digest(value: Any) -> str:
    """Return SHA256 provenance, not proof of identity or anonymity."""
    return hashlib.sha256(canonical(value)).hexdigest()


def fields(value: Any, names: set[str]) -> dict[str, Any]:
    """Require exactly the reviewed schema; extension fields never gain implicit meaning."""
    if not isinstance(value, dict) or set(value) != names:
        raise ContractError("incorrect fields")
    return value


def identifier(value: Any) -> str:
    """Accept small lowercase ASCII identifiers only; no paths, hostnames or shell metacharacters."""
    if not isinstance(value, str) or not re.fullmatch(r"[a-z][a-z0-9-]{0,31}", value):
        raise ContractError("invalid identifier")
    return value


def integer(value: Any, minimum: int, maximum: int) -> int:
    """Require an actual bounded integer; booleans cannot masquerade as ports or timestamps."""
    if type(value) is not int or not minimum <= value <= maximum:
        raise ContractError("invalid integer")
    return value


@dataclass(frozen=True)
class Endpoint:
    """Immutable inventory identity, tenant and canonical IPv4 address; labels do not authenticate packets."""

    name: str
    tenant: str
    address: str
    identity: str

    @classmethod
    def from_json(cls, value: Any) -> Endpoint:
        """Validate the fixed lab SPIFFE-shaped naming convention without claiming certificate verification."""
        data = fields(value, {"name", "tenant", "address", "identity"})
        name, tenant = identifier(data["name"]), identifier(data["tenant"])
        try:
            address = str(ipaddress.IPv4Address(data["address"]))
        except (ValueError, TypeError) as error:
            raise ContractError("IPv4 address required") from error
        if (
            address != data["address"]
            or data["identity"] != f"spiffe://lab.example/{tenant}/{name}"
        ):
            raise ContractError("noncanonical inventory")
        return cls(name, tenant, address, data["identity"])


@dataclass(frozen=True)
class Flow:
    """A proposed new transport flow, not an already-established connection."""

    source: str
    target: str
    protocol: str
    port: int

    @classmethod
    def from_json(cls, value: Any) -> Flow:
        """Parse exact endpoints, TCP/UDP and a bounded port; unsupported protocols fail closed."""
        data = fields(value, {"source", "target", "protocol", "port"})
        if data["protocol"] not in ("tcp", "udp"):
            raise ContractError("unsupported protocol")
        return cls(
            identifier(data["source"]),
            identifier(data["target"]),
            data["protocol"],
            integer(data["port"], 1, 65535),
        )


@dataclass(frozen=True)
class Rule:
    """Exact directed TCP permission; optional exception deadline must have a reviewed ticket."""

    source: str
    target: str
    port: int
    until: int | None
    ticket: str | None

    @classmethod
    def from_json(cls, value: Any) -> Rule:
        """Require complete exact rules; wildcards, blanket CIDRs and untracked temporary access are absent."""
        data = fields(value, {"source", "target", "port", "until", "ticket"})
        until = (
            integer(data["until"], 0, 2**31 - 1) if data["until"] is not None else None
        )
        ticket = identifier(data["ticket"]) if data["ticket"] is not None else None
        if (until is None) != (ticket is None):
            raise ContractError("exception requires deadline and ticket")
        return cls(
            identifier(data["source"]),
            identifier(data["target"]),
            integer(data["port"], 1, 65535),
            until,
            ticket,
        )


@dataclass(frozen=True)
class Policy:
    """Immutable finite inventory/rules with explicit validity and deny-overrides quarantine."""

    revision: int
    created_at: int
    expires_at: int
    endpoints: tuple[Endpoint, ...]
    rules: tuple[Rule, ...]
    quarantined: tuple[str, ...]

    @classmethod
    def from_json(cls, value: Any) -> Policy:
        """Validate bounded collections, unique names/IPs/edges, tenant separation and short exceptions."""
        data = fields(
            value,
            {
                "revision",
                "created_at",
                "expires_at",
                "endpoints",
                "rules",
                "quarantined",
            },
        )
        revision = integer(data["revision"], 1, 1000000)
        created, expires = (
            integer(data["created_at"], 0, 2**31 - 1),
            integer(data["expires_at"], 0, 2**31 - 1),
        )
        if not created < expires <= created + 3600:
            raise ContractError("policy validity")
        if (
            not isinstance(data["endpoints"], list)
            or not 1 <= len(data["endpoints"]) <= 16
        ):
            raise ContractError("inventory limit")
        if not isinstance(data["rules"], list) or len(data["rules"]) > 64:
            raise ContractError("rule limit")
        if not isinstance(data["quarantined"], list) or len(data["quarantined"]) > 16:
            raise ContractError("quarantine limit")
        endpoints = tuple(Endpoint.from_json(item) for item in data["endpoints"])
        known = {item.name: item for item in endpoints}
        if len(known) != len(endpoints) or len(
            {item.address for item in endpoints}
        ) != len(endpoints):
            raise ContractError("duplicate inventory")
        rules = tuple(Rule.from_json(item) for item in data["rules"])
        if (
            len({(item.source, item.target, item.port) for item in rules}) != len(rules)
            or len({item.port for item in rules}) > 8
        ):
            raise ContractError("duplicate or excessive service rules")
        for rule in rules:
            if (
                rule.source not in known
                or rule.target not in known
                or rule.source == rule.target
            ):
                raise ContractError("unknown or self rule")
            if known[rule.source].tenant != known[rule.target].tenant:
                raise ContractError("cross-tenant rule")
            if rule.until is not None and not created < rule.until <= min(
                expires, created + 300
            ):
                raise ContractError("exception validity")
        quarantined = tuple(identifier(item) for item in data["quarantined"])
        if (
            len(set(quarantined)) != len(quarantined)
            or not set(quarantined) <= known.keys()
        ):
            raise ContractError("unknown or duplicate quarantine")
        return cls(revision, created, expires, endpoints, rules, quarantined)


def read_source(path: Path, limit: int) -> bytes:
    """Read only bounded ordinary one-link bytes from one nonblocking descriptor; refuse reparse paths and replacements."""
    absolute = path.absolute()
    if any(
        item.is_symlink() or item.is_junction()
        for item in (absolute, *absolute.parents)
    ):
        raise ContractError("linked input path")
    flags = (
        os.O_RDONLY
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    descriptor = os.open(absolute, flags)
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        named = absolute.lstat()
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or info.st_size > limit
            or (named.st_dev, named.st_ino) != (info.st_dev, info.st_ino)
        ):
            raise ContractError("bounded ordinary unchanged input required")
        raw = stream.read(limit + 1)
        if len(raw) != info.st_size or len(raw) > limit:
            raise ContractError("input changed or exceeded byte limit")
    return raw


def load_policy(path: Path) -> tuple[Policy, str]:
    """Read a bounded policy and return exact byte provenance; no network or execution occurs."""
    raw = read_source(path, 65536)
    return Policy.from_json(parse(raw)), hashlib.sha256(raw).hexdigest()

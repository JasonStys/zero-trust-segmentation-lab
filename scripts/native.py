"""Jason Stys: actual IPv4/IPv6 TCP/UDP and state-revocation tests inside owned hosted-runner namespaces only."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# variable: ROOT — line 152
# variable: NAMES — line 159
# variable: ADDRESSES — line 160
# variable: index — line 162
# variable: name — line 162
# variable: PAYLOAD — line 164
# definition: guard — line 167
# parameter: namespace — line 167
# definition: receive — line 181
# parameter: stream — line 181
# variable: content — line 183
# variable: chunk — line 185
# variable: content — line 188
# definition: listen — line 192
# parameter: family — line 192
# parameter: port — line 192
# parameter: protocol — line 192
# parameter: ready — line 192
# variable: kind — line 194
# variable: listener — line 195
# variable: _ — line 205
# variable: peer — line 205
# variable: _ — line 208
# variable: connection — line 208
# variable: thread — line 209
# definition: serve_connection — line 215
# parameter: connection — line 215
# variable: _ — line 220
# definition: server — line 228
# parameter: namespace — line 228
# variable: events — line 231
# variable: family — line 232
# variable: protocol — line 233
# variable: port — line 234
# variable: ready — line 235
# variable: event — line 240
# definition: exchange — line 246
# parameter: protocol — line 246
# parameter: stream — line 246
# definition: probe — line 252
# parameter: address — line 253
# parameter: hold — line 253
# parameter: namespace — line 253
# parameter: port — line 253
# parameter: protocol — line 253
# variable: pair — line 258
# variable: value — line 258
# variable: family — line 263
# variable: kind — line 264
# variable: stream — line 265
# variable: reachable — line 269
# variable: reachable — line 271
# variable: reachable — line 276
# variable: reachable — line 278
# definition: command — line 282
# parameter: arguments — line 283
# parameter: check — line 283
# parameter: content — line 283
# definition: namespace_command — line 296
# parameter: arguments — line 297
# parameter: namespace — line 297
# parameter: options — line 297
# definition: reset_state — line 303
# parameter: namespace — line 303
# definition: apply — line 308
# parameter: namespace — line 308
# parameter: replacing — line 308
# parameter: rules — line 308
# variable: batch — line 310
# definition: read_ready — line 315
# parameter: process — line 315
# definition: run — line 322
# parameter: opted_in — line 322
# parameter: prefix — line 322
# variable: policy — line 332
# variable: engine — line 333
# variable: name — line 334
# variable: namespaces — line 334
# variable: servers — line 335
# variable: held — line 336
# variable: observations — line 337
# variable: name — line 339
# variable: namespace — line 340
# variable: process — line 341
# variable: combinations — line 360
# variable: source — line 362
# variable: target — line 363
# variable: family — line 365
# variable: protocol — line 366
# variable: port — line 367
# definition: observed — line 370
# parameter: family — line 371
# parameter: port — line 371
# parameter: protocol — line 371
# parameter: source — line 371
# parameter: target — line 371
# variable: namespace — line 374
# variable: response — line 375
# variable: family — line 393
# variable: port — line 393
# variable: protocol — line 393
# variable: source — line 393
# variable: target — line 393
# variable: name — line 398
# variable: family — line 401
# variable: port — line 401
# variable: protocol — line 401
# variable: source — line 401
# variable: target — line 401
# variable: expected — line 402
# variable: actual — line 406
# variable: before — line 422
# variable: invalid — line 425
# variable: after — line 431
# variable: reduced — line 436
# variable: rule — line 439
# variable: name — line 441
# variable: held — line 449
# variable: quarantined — line 475
# variable: _ — line 479
# variable: output — line 479
# variable: name — line 490
# variable: process — line 496
# variable: report — line 498
# variable: row — line 506
# variable: row — line 507
# variable: process — line 526
# definition: main — line 536
# variable: parser — line 538
# variable: args — line 547
# END CODE MAP

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import select
import socket
import subprocess
import sys
import threading
from dataclasses import replace
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts.fixtures import policy_data  # noqa: E402
from ztlab.admission import Attester, Engine  # noqa: E402
from ztlab.compiler import compile_rules  # noqa: E402
from ztlab.contracts import Flow, Policy  # noqa: E402

NAMES = ("web", "api", "db", "guest")
ADDRESSES = {
    name: ("198.18.0." + str(index), "fd42:203::" + str(index))
    for index, name in enumerate(NAMES, 11)
}
PAYLOAD = b"ZTL!"


def guard(namespace: str | None = None) -> None:
    """Refuse execution outside explicit disposable CI context; workers verify their actual network namespace inode."""
    if platform.system() != "Linux" or os.environ.get("GITHUB_ACTIONS") != "true":
        raise RuntimeError("hosted isolated Linux test required")
    if namespace is not None:
        if not re.fullmatch(r"ztl-[0-9]+-(web|api|db|guest)", namespace):
            raise RuntimeError("invalid owned namespace name")
        if (
            Path("/proc/self/ns/net").stat().st_ino
            != Path("/run/netns", namespace).stat().st_ino
        ):
            raise RuntimeError("worker is not in its declared namespace")


def receive(stream: socket.socket) -> bytes:
    """Read one small TCP frame correctly even when a packet is fragmented."""
    content = b""
    while len(content) < len(PAYLOAD):
        chunk = stream.recv(len(PAYLOAD) - len(content))
        if not chunk:
            break
        content += chunk
    return content


def listen(family: int, protocol: str, port: int, ready: threading.Event) -> None:
    """Serve a fixed harmless frame on one isolated namespace socket; no incoming command or payload is executed."""
    kind = socket.SOCK_STREAM if protocol == "tcp" else socket.SOCK_DGRAM
    with socket.socket(family, kind) as listener:
        if family == socket.AF_INET6:
            listener.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("::" if family == socket.AF_INET6 else "0.0.0.0", port))
        if protocol == "tcp":
            listener.listen(32)
        ready.set()
        while True:
            if protocol == "udp":
                _, peer = listener.recvfrom(64)
                listener.sendto(PAYLOAD, peer)
            else:
                connection, _ = listener.accept()
                thread = threading.Thread(
                    target=serve_connection, args=(connection,), daemon=True
                )
                thread.start()


def serve_connection(connection: socket.socket) -> None:
    """Echo at most five fixed frames with a bounded receive timeout; close owned connections afterward."""
    with connection:
        connection.settimeout(5)
        try:
            for _ in range(5):
                if receive(connection) != PAYLOAD:
                    break
                connection.sendall(PAYLOAD)
        except OSError:
            return


def server(namespace: str) -> None:
    """Start eight instrumented TCP/UDP listeners; readiness requires every IPv4/IPv6 port to bind successfully."""
    guard(namespace)
    events = []
    for family in (socket.AF_INET, socket.AF_INET6):
        for protocol in ("tcp", "udp"):
            for port in (8080, 8081):
                ready = threading.Event()
                threading.Thread(
                    target=listen, args=(family, protocol, port, ready), daemon=True
                ).start()
                events.append(ready)
    if not all(event.wait(5) for event in events):
        raise RuntimeError("listener startup failed")
    print('{"ready":true}', flush=True)
    threading.Event().wait()


def exchange(stream: socket.socket, protocol: str) -> bool:
    """Test application payload delivery, not just a successful TCP connect or silent UDP send."""
    stream.sendall(PAYLOAD)
    return (receive(stream) if protocol == "tcp" else stream.recv(64)) == PAYLOAD


def probe(
    namespace: str, address: str, protocol: str, port: int, hold: bool = False
) -> None:
    """Probe only one of four synthetic peers/ports; no arbitrary host, scan range or external route is accepted."""
    guard(namespace)
    if (
        address not in {value for pair in ADDRESSES.values() for value in pair}
        or port not in (8080, 8081)
        or protocol not in ("tcp", "udp")
    ):
        raise RuntimeError("probe outside owned fixture")
    family = socket.AF_INET6 if ":" in address else socket.AF_INET
    kind = socket.SOCK_STREAM if protocol == "tcp" else socket.SOCK_DGRAM
    with socket.socket(family, kind) as stream:
        stream.settimeout(0.25)
        try:
            stream.connect((address, port))
            reachable = exchange(stream, protocol)
        except OSError:
            reachable = False
        print(json.dumps({"reachable": reachable}), flush=True)
        if hold and reachable:
            sys.stdin.readline()
            try:
                reachable = exchange(stream, protocol)
            except OSError:
                reachable = False
            print(json.dumps({"after_revision_reachable": reachable}), flush=True)


def command(
    arguments: list[str], *, content: str | None = None, check: bool = True
) -> subprocess.CompletedProcess[str]:
    """Run a fixed native command without a shell, bounded by ten seconds and captured output."""
    return subprocess.run(
        arguments,
        input=content,
        text=True,
        capture_output=True,
        timeout=10,
        check=check,
    )


def namespace_command(
    namespace: str, arguments: list[str], **options: Any
) -> subprocess.CompletedProcess[str]:
    """Enter an exact already-owned namespace; do not operate on the runner's root firewall."""
    return command(["ip", "netns", "exec", namespace, *arguments], **options)


def reset_state(namespace: str) -> None:
    """Clear only owned namespace connection tracking so an old established flow cannot bypass a new revision."""
    namespace_command(namespace, ["conntrack", "-F"])


def apply(namespace: str, rules: str, replacing: bool = True) -> None:
    """Check then atomically replace the owned table in one nft batch; never flush a host ruleset."""
    batch = ("delete table inet ztl\n" if replacing else "") + rules
    namespace_command(namespace, ["nft", "--check", "-f", "-"], content=batch)
    namespace_command(namespace, ["nft", "-f", "-"], content=batch)


def read_ready(process: subprocess.Popen[str]) -> dict[str, Any]:
    """Read bounded startup evidence using select; missing readiness fails the test instead of counting as denial."""
    if process.stdout is None or not select.select([process.stdout], [], [], 10)[0]:
        raise RuntimeError("missing startup evidence")
    return json.loads(process.stdout.readline(1024))


def run(prefix: str, opted_in: bool) -> None:
    """Validate all baseline/enforced channels, ingress/egress independence, rollback and existing-session revocation."""
    guard()
    if (
        not opted_in
        or not re.fullmatch(r"ztl-[0-9]+", prefix)
        or os.environ.get("ZTL_CREATED_PREFIX") != prefix
        or os.geteuid() != 0
    ):
        raise RuntimeError("owned-wrapper opt-in required")
    policy = Policy.from_json(policy_data())
    engine = Engine(policy, Attester())
    namespaces = {name: prefix + "-" + name for name in NAMES}
    servers = []
    held: subprocess.Popen[str] | None = None
    observations = []
    try:
        for name in NAMES:
            namespace = namespaces[name]
            process = subprocess.Popen(
                [
                    "ip",
                    "netns",
                    "exec",
                    namespace,
                    sys.executable,
                    str(Path(__file__).resolve()),
                    "server",
                    "--namespace",
                    namespace,
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            servers.append(process)
            if read_ready(process) != {"ready": True}:
                raise RuntimeError("server not ready")
        combinations = [
            (source, target, family, protocol, port)
            for source in NAMES
            for target in NAMES
            if source != target
            for family in (4, 6)
            for protocol in ("tcp", "udp")
            for port in (8080, 8081)
        ]

        def observed(
            source: str, target: str, family: int, protocol: str, port: int
        ) -> bool:
            """Run the instrumented peer probe; errors/empty telemetry fail rather than imply a blocked packet."""
            namespace = namespaces[source]
            response = namespace_command(
                namespace,
                [
                    sys.executable,
                    str(Path(__file__).resolve()),
                    "probe",
                    "--namespace",
                    namespace,
                    "--address",
                    ADDRESSES[target][family == 6],
                    "--protocol",
                    protocol,
                    "--port",
                    str(port),
                ],
            )
            return json.loads(response.stdout)["reachable"] is True

        for source, target, family, protocol, port in combinations:
            if not observed(source, target, family, protocol, port):
                raise RuntimeError(
                    "baseline reachability missing; denial results would be invalid"
                )
        for name in NAMES:
            apply(namespaces[name], compile_rules(policy, name, 1000), replacing=False)
            reset_state(namespaces[name])
        for source, target, family, protocol, port in combinations:
            expected = (
                family == 4
                and engine.transport(Flow(source, target, protocol, port), 1000).allowed
            )
            actual = observed(source, target, family, protocol, port)
            observations.append(
                {
                    "source": source,
                    "target": target,
                    "family": family,
                    "protocol": protocol,
                    "port": port,
                    "expected": expected,
                    "observed": actual,
                }
            )
            if expected != actual:
                raise RuntimeError("native projection mismatch")

        # Invalid replacement must leave the previous filtering table unchanged.
        before = namespace_command(
            namespaces["web"], ["nft", "-j", "list", "table", "inet", "ztl"]
        ).stdout
        invalid = namespace_command(
            namespaces["web"],
            ["nft", "-f", "-"],
            content="delete table inet ztl\nadd rule inet nonexistent nowhere drop\n",
            check=False,
        )
        after = namespace_command(
            namespaces["web"], ["nft", "-j", "list", "table", "inet", "ztl"]
        ).stdout
        if invalid.returncode == 0 or before != after:
            raise RuntimeError("invalid batch did not preserve previous rules")
        reduced = replace(
            policy,
            revision=2,
            rules=tuple(rule for rule in policy.rules if rule.source != "web"),
        )
        for name in ("web", "api"):
            apply(namespaces[name], compile_rules(reduced, name, 1000))
            reset_state(namespaces["web"])
            reset_state(namespaces["api"])
            if observed("web", "api", 4, "tcp", 8080):
                raise RuntimeError("one-sided policy did not isolate")
            apply(namespaces[name], compile_rules(policy, name, 1000))

        held = subprocess.Popen(
            [
                "ip",
                "netns",
                "exec",
                namespaces["web"],
                sys.executable,
                str(Path(__file__).resolve()),
                "probe",
                "--namespace",
                namespaces["web"],
                "--address",
                ADDRESSES["api"][0],
                "--protocol",
                "tcp",
                "--port",
                "8080",
                "--hold",
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if read_ready(held) != {"reachable": True}:
            raise RuntimeError("existing session did not start")
        quarantined = replace(policy, revision=2, quarantined=("api",))
        apply(namespaces["api"], compile_rules(quarantined, "api", 1000))
        reset_state(namespaces["web"])
        reset_state(namespaces["api"])
        output, _ = held.communicate("probe\n", timeout=5)
        if (
            held.returncode != 0
            or json.loads(output)["after_revision_reachable"] is not False
        ):
            raise RuntimeError("existing session survived scoped revocation")
        if observed("web", "api", 4, "tcp", 8080) or observed(
            "api", "db", 4, "tcp", 8080
        ):
            raise RuntimeError("quarantine allowed a new flow")
        apply(namespaces["api"], compile_rules(policy, "api", 1000))
        for name in NAMES:
            reset_state(namespaces[name])
        if not observed("web", "api", 4, "tcp", 8080) or not observed(
            "api", "db", 4, "tcp", 8080
        ):
            raise RuntimeError("reviewed rollback did not restore permitted flows")
        if any(process.poll() is not None for process in servers):
            raise RuntimeError("server died; observations invalid")
        report = {
            "author": "Jason Stys",
            "scope": "owned disposable Linux namespaces; L4 only, no mTLS",
            "policy_digest": hashlib.sha256(
                json.dumps(policy_data(), sort_keys=True).encode()
            ).hexdigest(),
            "baseline_successful_channels": len(combinations),
            "enforced_channels": len(observations),
            "allowed": sum(row["observed"] for row in observations),
            "denied": sum(not row["observed"] for row in observations),
            "invalid_batch_preserved_rules": True,
            "ingress_egress_independently_required": True,
            "existing_session_revoked": True,
            "new_quarantine_flows_denied": True,
            "reviewed_rollback_restored": True,
            "tools": {
                "nft": command(["nft", "--version"]).stdout.strip(),
                "ip": command(["ip", "-Version"]).stdout.strip(),
                "conntrack": command(["conntrack", "-V"]).stdout.strip(),
            },
            "observations": observations,
        }
        (ROOT / "out").mkdir(exist_ok=True)
        (ROOT / "out/native.json").write_text(
            json.dumps(report, indent=2) + "\n", encoding="utf-8", newline="\n"
        )
        print(json.dumps(report))
    finally:
        for process in [*servers, *([held] if held is not None else [])]:
            if process.poll() is None:
                process.terminate()
            try:
                process.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.communicate()


def main() -> None:
    """Dispatch guarded hosted-only server/probe/run commands; no credentials or host changes on import."""
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("server", "probe", "run"))
    parser.add_argument("--namespace")
    parser.add_argument("--prefix")
    parser.add_argument("--address")
    parser.add_argument("--protocol", choices=("tcp", "udp"), default="tcp")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--hold", action="store_true")
    parser.add_argument("--run-isolated-demo", action="store_true")
    args = parser.parse_args()
    if args.mode == "run":
        run(args.prefix or "", args.run_isolated_demo)
    elif args.mode == "server":
        server(args.namespace or "")
    else:
        probe(
            args.namespace or "",
            args.address or "",
            args.protocol,
            args.port,
            args.hold,
        )


if __name__ == "__main__":
    main()

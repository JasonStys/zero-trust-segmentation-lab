# Threat model and limits

Author: Jason Stys.

Trusted: reviewed policy, demo attester/process, synthetic clock, output parent directory, CI runner/tool chain. Untrusted: flow inputs, mutated proofs, malformed configuration. Test peers/services are owned synthetic workloads.

## Tested controls

Default-deny exact routes; ingress and egress permissions; tenant boundary; source/identity binding; MAC mutation; healthy/fresh posture; policy revision/expiry; exception deadline; quarantine; immutable inventory; strict input types/size bounds; safe reporting and no-overwrite.

Native tests use only four peer addresses on a private namespace bridge. No uplink, NAT, default route, external DNS, host interface or host nftables rule is configured. All addresses are fixed lab values. Namespace cleanup targets only names successfully created by this run; collisions are rejected. IPv6 is enabled only inside owned namespaces to prove baseline connectivity, then tested closed by policy.

## Important limitations

- Network addresses do not authenticate workloads. IP spoofing, malicious namespace-root processes, ARP/NDP attacks and host compromise are not prevented by this lab.
- MAC proofs are synthetic. There is no actual certificate chain, mTLS proxy, hardware posture agent, production identity provider, key vault or durable revocation store.
- Admission and kernel tests are separate. Native fixed-frame servers do not enforce the Python identity/posture decisions.
- The inet projection permits new IPv4 TCP only. New IPv6/UDP are denied in the finite tested matrix, not guaranteed safe for every protocol. ARP and loopback are outside inter-workload IP filtering. Loopback is explicitly allowed.
- Established traffic can survive a rule-only change. The native revocation workflow clears only owned namespace conntrack state after policy replacement; production needs scoped session lifecycle handling. Static exports do not automatically expire.
- Namespace isolation is not a malicious-code sandbox. CI runs trusted authored listeners/probes, not uploaded binaries or arbitrary scanning. Guard environment variables prevent accidents, not an adversary who controls the host.
- Cleanup traps handle normal failure/signals, not an uncatchable SIGKILL or runner crash; disposable-runner teardown remains the final lifecycle boundary.
- A compromised signing process can manufacture claims. Correct issuance/authentication and clocks are assumed; the demo cannot measure real device trust.
- Graph reachability describes possible application pivots, not successful exploitation or transitive packet permission.
- POSIX permissions and inherited Windows ACLs are not encryption. File-parent ancestry is caller-selected/trusted. Partial I/O failures retain already-created evidence.
- SHA256 provenance is not a signed attestation. Coverage and scanners do not prove absence of bugs or compliance.

Use only owned or explicitly authorized environments. Never apply generated rules to a workstation/production host. Contact [Jason Stys](https://github.com/JasonStys) without uploading private inventory, credentials, proofs or sensitive reports publicly.

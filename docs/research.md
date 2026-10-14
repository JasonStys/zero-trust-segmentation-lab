# Primary-source research and mapping

Author: Jason Stys. Checked 2026-10-14. Implementation/fixtures original; guidance paraphrased. Educational mapping, not certification.

- [NIST SP 800-207](https://csrc.nist.gov/pubs/sp/800/207/final): no implicit trust from location/ownership; subject/device authorization informs the separately modeled admission layer. Network segmentation alone cannot establish zero trust.
- [nftables base chains](https://wiki.nftables.org/wiki-nftables/index.php/Configuring_chains): explicit input/output hooks and default-drop policies inform the compiler. These rules are namespace-scoped, not copied workstation configuration.
- [Connection tracking](https://wiki.nftables.org/wiki-nftables/index.php/Matching_connection_tracking_stateful_metainformation): established traffic semantics motivate the explicit existing-session revocation test and namespace-only state cleanup.
- [ip-netns manual](https://man7.org/linux/man-pages/man8/ip-netns.8.html): independent namespace network stacks/routes/firewall and process lifecycle inform collision checks, owned-name tracking and cleanup.
- [Kubernetes NetworkPolicy](https://kubernetes.io/docs/concepts/services-networking/network-policies/): source egress and destination ingress must both permit a flow; standard policies are additive. Used as comparison only: no Kubernetes manifests, CNI evaluation or cluster deployment is implemented.

For government/enterprise review this demonstrates exact least-privilege dependencies, policy drift analysis and reproducible enforcement evidence. Real data classification, identity infrastructure, authorization, compliance and operational assurance require independent review.

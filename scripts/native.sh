#!/usr/bin/env bash
# Jason Stys: create and clean only owned disposable CI network namespaces; never touch host interfaces/firewall.
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# shell loop/input: tool — line 27
# shell variable: prefix — line 28
# shell variable: hub — line 30
# shell variable: created — line 31
# shell function: cleanup — line 34
# shell loop/input: namespace — line 36
# shell loop/input: pid — line 37
# shell loop/input: namespace — line 43
# shell function: create_namespace — line 50
# shell variable: namespace — line 51
# shell variable: disable_ipv6 — line 55
# shell variable: index — line 61
# shell loop/input: workload — line 62
# shell variable: namespace — line 63
# shell variable: index — line 73
# shell variable: created — line 80
# shell loop/input: workload — line 82
# END CODE MAP
set -euo pipefail

# Guard: explicit opt-in, GitHub disposable Linux runner and root are required before any namespace operation.
[[ "${1:-}" == "--run-isolated-demo" && "$#" == 1 ]] || { echo "Explicit --run-isolated-demo is required." >&2; exit 2; }
[[ "${GITHUB_ACTIONS:-}" == true && "$(uname -s)" == Linux && "$EUID" == 0 ]] || { echo "Use only the isolated GitHub Linux runner." >&2; exit 2; }
for tool in ip nft conntrack python3 sysctl; do command -v "$tool" >/dev/null; done
prefix="ztl-$BASHPID"
[[ "$prefix" =~ ^ztl-[0-9]+$ ]] || exit 2
hub="$prefix-hub"
created=()

# cleanup: stop only processes in successfully created namespace names, then delete those exact namespaces.
cleanup() {
  local namespace pid
  for namespace in "${created[@]}"; do
    while read -r pid; do
      if [[ "$pid" =~ ^[0-9]+$ ]]; then
        kill "$pid" 2>/dev/null || true
      fi
    done < <(ip netns pids "$namespace")
  done
  for namespace in "${created[@]}"; do ip netns delete "$namespace"; done
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# create_namespace: refusal on name collision; ownership list is populated only after successful creation.
create_namespace() {
  local namespace="$1"
  [[ ! -e "/run/netns/$namespace" ]] || { echo "Namespace collision; refusing to reuse it." >&2; exit 2; }
  ip netns add "$namespace"
  created+=("$namespace")
  ip netns exec "$namespace" sysctl -qw net.ipv6.conf.all.disable_ipv6=0 net.ipv6.conf.default.disable_ipv6=0
  ip -n "$namespace" link set lo up
}
create_namespace "$hub"
ip -n "$hub" link add br0 type bridge
ip -n "$hub" link set br0 up
index=0
for workload in web api db guest; do
  namespace="$prefix-$workload"
  create_namespace "$namespace"
  ip -n "$hub" link add "h$index" type veth peer name "w$index"
  ip -n "$hub" link set "w$index" netns "$namespace"
  ip -n "$hub" link set "h$index" master br0
  ip -n "$hub" link set "h$index" up
  ip -n "$namespace" link set "w$index" name eth0
  ip -n "$namespace" address add "198.18.0.$((11 + index))/24" dev eth0
  ip -n "$namespace" address add "fd42:203::$((11 + index))/64" dev eth0 nodad
  ip -n "$namespace" link set eth0 up
  index=$((index + 1))
done
# The private bridge has no host uplink, default route, NAT or external destination.
export ZTL_CREATED_PREFIX="$prefix"
python3 scripts/native.py run --prefix "$prefix" --run-isolated-demo
# Exercise cleanup now, and verify all owned names are gone; never enumerate-and-delete other namespaces.
cleanup
created=()
trap - EXIT
for workload in hub web api db guest; do [[ ! -e "/run/netns/$prefix-$workload" ]]; done
echo '{"namespace_cleanup":"verified-owned-names-absent"}'

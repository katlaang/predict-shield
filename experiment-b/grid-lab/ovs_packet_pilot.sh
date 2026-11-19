#!/usr/bin/env bash
# Isolated Linux network-namespace + real Open vSwitch packet pilot.
# Never run on an operator system. No SCADA, relay, breaker or real grid.
set -euo pipefail
if [[ "${EUID}" -ne 0 || "${PREDICT_SHIELD_ISOLATED_LAB:-}" != "1" ]]; then
  echo "REFUSED: root in explicitly authorized disposable laboratory is required" >&2
  exit 3
fi
OUT="${1:-/tmp/ps-ovs-grid-packet.json}"
BR="psgridb"
NS=(psguvpn psgctrl psgrelay)
PORTS=(psgatt0 psgctl0 psgrel0)
PEERS=(psgatt1 psgctl1 psgrel1)
IPS=(10.89.34.10 10.89.34.20 10.89.34.30)
for name in "${NS[@]}"; do
  if ip netns list | grep -Eq "^${name}([[:space:]]|$)"; then
    echo "REFUSED: pre-existing namespace ${name}" >&2
    exit 3
  fi
done
if ovs-vsctl br-exists "$BR"; then
  echo "REFUSED: bridge already exists" >&2
  exit 3
fi
cleanup() {
  ovs-vsctl --if-exists del-br "$BR" 2>/dev/null || true
  for name in "${NS[@]}"; do ip netns del "$name" 2>/dev/null || true; done
}
trap cleanup EXIT
for i in 0 1 2; do
  ip netns add "${NS[$i]}"
  ip link add "${PORTS[$i]}" type veth peer name "${PEERS[$i]}"
  ip link set "${PEERS[$i]}" netns "${NS[$i]}"
  ip netns exec "${NS[$i]}" ip link set lo up
  ip netns exec "${NS[$i]}" ip addr add "${IPS[$i]}/24" dev "${PEERS[$i]}"
  ip netns exec "${NS[$i]}" ip link set "${PEERS[$i]}" up
done
ovs-vsctl add-br "$BR" -- set bridge "$BR" protocols=OpenFlow13
for port in "${PORTS[@]}"; do
  ovs-vsctl add-port "$BR" "$port"
  ip link set "$port" up
done
ip link set "$BR" up
ovs-ofctl -O OpenFlow13 add-flow "$BR" "priority=0,actions=NORMAL"

probe() {
  local ns="$1" dest="$2" output="$3"
  if ip netns exec "$ns" ping -c 3 -W 2 "$dest" > "$output" 2>&1; then
    return 0
  fi
  return 1
}
# Retry baseline once for ARP neighbor convergence.
if ! probe psguvpn 10.89.34.30 /tmp/ps-grid-attacker-baseline.txt; then
  sleep 2
  probe psguvpn 10.89.34.30 /tmp/ps-grid-attacker-baseline.txt
fi
probe psgctrl 10.89.34.30 /tmp/ps-grid-control-baseline.txt
ovs-ofctl -O OpenFlow13 dump-flows "$BR" > /tmp/ps-grid-before.flows
# Lab approval is explicit in the caller. This rule restricts only lab source
# and destination IPv4 addresses, never any field device or control traffic.
ovs-ofctl -O OpenFlow13 add-flow "$BR" \
  "priority=250,ip,nw_src=10.89.34.10,nw_dst=10.89.34.30,actions=drop"
ovs-ofctl -O OpenFlow13 dump-flows "$BR" > /tmp/ps-grid-after.flows
blocked=0
if ! probe psguvpn 10.89.34.30 /tmp/ps-grid-attacker-after.txt; then blocked=1; fi
control_alive=0
if probe psgctrl 10.89.34.30 /tmp/ps-grid-control-after.txt; then control_alive=1; fi
ovs-ofctl -O OpenFlow13 del-flows "$BR" \
  "ip,nw_src=10.89.34.10,nw_dst=10.89.34.30"
restored=0
if probe psguvpn 10.89.34.30 /tmp/ps-grid-attacker-restored.txt; then restored=1; fi
export PS_BLOCKED="$blocked" PS_CONTROL="$control_alive" PS_RESTORED="$restored"
export PS_BEFORE="$(sha256sum /tmp/ps-grid-before.flows | cut -d ' ' -f 1)"
export PS_AFTER="$(sha256sum /tmp/ps-grid-after.flows | cut -d ' ' -f 1)"
python3 - "$OUT" <<'PY'
import json, os, pathlib, sys
report = {
    "schema": "predict-shield/real-ovs-packet-lab/1",
    "environment": "disposable Linux namespaces + real Open vSwitch",
    "attacker_to_relay_blocked_after_rule": os.environ["PS_BLOCKED"] == "1",
    "control_center_to_relay_reachable_after_rule": os.environ["PS_CONTROL"] == "1",
    "attacker_to_relay_restored_after_rollback": os.environ["PS_RESTORED"] == "1",
    "ovs_before_flow_table_sha256": os.environ["PS_BEFORE"],
    "ovs_after_flow_table_sha256": os.environ["PS_AFTER"],
    "evidence": [
        "/tmp/ps-grid-attacker-baseline.txt",
        "/tmp/ps-grid-control-baseline.txt",
        "/tmp/ps-grid-attacker-after.txt",
        "/tmp/ps-grid-control-after.txt",
        "/tmp/ps-grid-attacker-restored.txt",
        "/tmp/ps-grid-before.flows",
        "/tmp/ps-grid-after.flows",
    ],
    "test_traffic": "ICMP only; no SCADA/relay protocols",
    "model_selected_action": False,
    "real_electric_grid": False,
    "grid_power_flow_coupled": False,
    "operational_critical_infrastructure_resilience_established": False,
}
report["outcome"] = ("VERIFIED_PACKET_LAB_ONLY" if all([
    report["attacker_to_relay_blocked_after_rule"],
    report["control_center_to_relay_reachable_after_rule"],
    report["attacker_to_relay_restored_after_rollback"],
]) else "NOT_VERIFIED")
p = pathlib.Path(sys.argv[1])
p.parent.mkdir(parents=True, exist_ok=True)
p.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
print(p.read_text())
if report["outcome"] != "VERIFIED_PACKET_LAB_ONLY":
    raise SystemExit(1)
PY

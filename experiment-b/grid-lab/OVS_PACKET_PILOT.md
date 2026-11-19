# Open vSwitch packet pilot: first real network action, isolated only

**Scope:** In GitHub Actions on an Ubuntu disposable runner, install real
Open vSwitch, create Linux network namespaces, connect veth peers to an
OpenFlow 1.3 virtual switch, and run real ICMP packet probes. Do **not**
run this on a utility, ISP or other production host. No external hosts,
electric-grid equipment, SCADA or protection relays are involved.

The three simulated roles are an untrusted VPN endpoint, a control-center
endpoint and a relay-named endpoint (which is just a Linux network
namespace). It is a **simplified communication subgraph**, not an exact
rendering of the complete registered grid topology.

## Controlled response

1. Confirm both lab source roles can send packets to the destination.
2. Save a hash of the actual switch flow table.
3. Insert a real IPv4 OpenFlow DROP rule for the untrusted source to the
   simulated relay, leaving the control-center source unchanged.
4. **Independently send ICMP test packets from both namespaces.** Require
   attacker traffic to fail and legitimate-control traffic to succeed.
   Do not trust `ovs-ofctl add-flow` success as the outcome.
5. Remove the restrictive flow and require formerly blocked traffic to
   recover. Save packet command output and both flow-table dumps.
6. Delete all created network namespaces and the dedicated lab switch in
   a shell trap regardless of experiment outcome.

## Run on an approved disposable Linux VM

```bash
sudo apt-get update
sudo apt-get install -y openvswitch-switch iproute2 iputils-ping
sudo service openvswitch-switch start
sudo env PREDICT_SHIELD_ISOLATED_LAB=1 bash \
  experiment-b/grid-lab/ovs_packet_pilot.sh /tmp/ps-grid-ovs-pilot.json
```

The script refuses to overwrite pre-existing namespaces/bridge and has
deliberately fixed private test addresses. It requires explicit sandbox
opt-in. This test **does not invoke an AI model**; the rule is
pre-authorized by the test runner. There is no distributed switch, network
controller, authenticated human utility operator, active SCADA command or
electrical switching. OVS packets do **not** yet affect the separate
pandapower 33-bus load flow. A passing result demonstrates *only* bounded
virtual network packet containment and rollback, not electricity-system
safety or security at a U.S. infrastructure operator.

## Remaining coupling work

- Connect the actual read-only OVS discovery interface and reconciled
  topology evidence IDs to the grid laboratory registration.
- Replace the predetermined lab action with a pinned executed AI
  recommendation, authenticated policy approval and preserved model
  uncertainty; a model must never control OVS directly.
- Add SCADA/OT protocol simulations with legitimate packet timing,
  HELICS-mediated electrical response and independently observed service
  consequences. Preserve every failed, unsafe and UNKNOWN case.
- Add a distributed laboratory with more than one switch and test link
  churn, partial control-plane failure, safety policy, recovery and loss
  of required communication.
- Require operator authorization and expert independent review before
  any field-facing connector.

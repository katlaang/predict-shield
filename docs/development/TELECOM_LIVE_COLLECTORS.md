# Authenticated read-only telecom management collection

`python -m predict_shield.telecom_collectors` implements **live, opt-in GET operations** against **explicit localhost-only authorized labs**:

- Net-SNMP `snmpget -v3 -l authPriv` retrieves `sysName.0`. Secrets are kept outside command arguments in a transient mode-0600 Net-SNMP configuration directory. Only the read-only `snmpget` command is issued.
- gNMIc `get` retrieves `/interfaces/interface/state` over peer-verified TLS with CA and client certificate/key. The raw update count is retained, **no inferred physical links**. Real gNMI endpoint interoperability is not yet physically verified.

Example from repository root:

```bash
export PS_SNMP_AUTH='<authorized-secret>'
export PS_SNMP_PRIV='<authorized-secret>'
PYTHONPATH=engine python -m predict_shield.telecom_collectors --output /private/edge-a-snmp.json snmpv3 --device-id edge-a --port 1161 --user reader
PYTHONPATH=engine python -m predict_shield.telecom_collectors --output /private/edge-a-gnmi.json gnmi --device-id edge-a --port 57400 --ca /private/ca.pem --client-cert /private/cert.pem --client-key /private/key.pem
```

**Security limitations:** Localhost-only collectors do not support direct remote-site inventory. Approved gateways/tunnels are required for real ISP deployment. Environment variables and temporary SNMP config still require trusted-host access controls. Do not commit credentials or live inventory. A returned sysName is not a trusted physical serial identifier. The gNMI implementation currently counts updates rather than parsing device-dependent OpenConfig payloads into graph links; external LLDP adapters remain separate.

Protocol references: Net-SNMP command guidelines https://www.net-snmp.org/tutorial/tutorial-5/commands/snmpv3.html and gNMIc Get/TLS https://gnmic.openconfig.net/cmd/get/ https://gnmic.openconfig.net/user_guide/targets/targets/

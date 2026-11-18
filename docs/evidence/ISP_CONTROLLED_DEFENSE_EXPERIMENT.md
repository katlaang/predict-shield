# Telecom-style simulated access-control defense experiment

This is **a real physical execution within a disposable Docker laboratory** using an actual HTTP service: query protected route, apply an allowlisted isolate request with a distinct lab token, independently probe protected route 6 times, and check service health separately. All HTTP responses are preserved, including denial failures and unknowns. A successful POST is not accepted as verification.

**Safety:** The action target is pinned to `127.0.0.1:18310`, the exact action `isolate_access`, and an explicitly eligible lab-only policy. An AI risk score is *not* permission to execute. The experiment is not a network-router firewall, a production mitigation, or an external ISP pilot. Denying one simulated service is not proof that broader ISP availability remains intact.

GitHub workflow `isp-defense-physical-pilot.yml` launches the isolated service and retains an actual outcome artifact. Its unit tests also exercise failure when the control action acknowledges success but the protected service still allows requests.

The existing `isp-snmp-physical-lab.yml` workflow must supply the additional disposable service token after the new lab service is added. No credentials are written to source control.

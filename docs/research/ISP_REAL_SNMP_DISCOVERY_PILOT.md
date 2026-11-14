# Measured ISP-like SNMPv3 discovery pilot

Runs three **actual Net-SNMP daemons in isolated Docker virtual Ethernet containers**, with authenticated and encrypted SNMPv3 GETs against the real daemon sysName responses. A deliberately incomplete OSS fixture lists only `edge-a` and `aggregation-b`; the independently queried third agent `forgotten-c` should be reported as observed and absent from the registered inventory. No network scanning occurs outside explicitly loopback-published lab agents.

The agents **are not router operating systems** and do not reproduce BGP, OSPF, fiber or radio equipment. Docker networking alone does not verify physical router-to-router links. Results substantiate real SNMP management discovery and inventory drift in a disposable research testbed, not ISP deployment, real link recovery, or AI model superiority.

The GitHub workflow stores an actual response-derived JSON evidence artifact, or fails instead of claiming a successful trial. Secrets are fresh per run, removed after the test, and not committed to git. It tests three registered lab endpoints only; this is not an open-ended scanner.

To reproduce: `cd experiment-b/isp-lab`, export distinct `LAB_SNMP_AUTH`, `LAB_SNMP_PRIV`, run `docker compose -p psisp up -d --build`, install host Net-SNMP `snmpget`, run `PYTHONPATH=../../engine python collect_live.py --output /tmp/isp-new.json`. Shut down with `docker compose -p psisp down -v`.

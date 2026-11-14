# Real reconfigured virtual-network topology research experiment

The experiment runs **five real Net-SNMPv3 agents on Docker Linux bridge networks** and preregisters **28 unique network-membership configurations** using a fixed seed before observing results. The first **20 network configurations** provide training data and the remaining **8 different configurations** are held out. Each configuration supplies all 10 undirected pairs, giving **280 real tested pairs**, 80 held-out.

**Model input:** A bidirectional read-only, encrypted SNMPv3 GET between the two observed agents, plus constant known lab site/interface features. There is no LLDP, BGP, IS-IS, or NetFlow source in this experiment; the `bidirectional_flow_seen` model feature is a **proxy representing measured two-direction SNMP response reachability**, not a claim that NetFlow or a link-layer protocol observed a physical link.

**Independent label:** Only after the model-input management probes, a different host Docker API collects each agent's real Linux bridge-network membership and independently determines whether the two agents share an isolated network segment. The label measures virtual bridge co-membership, **not a physical port-to-port connection**. Input collection never reads the Docker truth before constructing candidate features.

The existing link learner trains logistic regression on 20 groups and evaluates once on 8 unseen group configurations. The strong comparator is the actual SNMP-reachability rule (a bidirectional management exchange); no deliberately weak baseline is used. Both methods see identical held-out pairs. The locked evaluator produces a paired topology-level bootstrap interval, retaining any worse, tie or uncertain outcome, and requires externally independent attestation before it can label a superiority claim supported.

**Limitations:** The 28 configurations repeatedly rewire the **same five Linux agents on one GitHub Actions host**. They are genuinely reconfigured virtual network experiments, not 28 independent ISP deployments, and do not demonstrate network discovery for actual routers, optical equipment or radio access networks. Labels come from Docker network attachment, not external physical topology documentation. No data should be discarded or training repeated on heldout groups to manufacture positive results.

The actual experiment report is retained as a GitHub Actions artifact only when all source collection, training, evaluation and integrity checks pass.

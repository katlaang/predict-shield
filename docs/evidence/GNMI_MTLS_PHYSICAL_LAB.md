# Real read-only gNMI over mutually authenticated TLS

This isolated laboratory uses a real Go gRPC implementation of **gNMI Get** serving a fixed OpenConfig-like interface-state update, with explicit mutual TLS. It is an intentionally minimal disposable gNMI endpoint, **not a telecommunications router OS**, a vendor management agent, or an authorized remote network device. The server inherits unimplemented Set and Subscribe RPCs and does not support configuration mutation.

The physical CI compiles the pinned OpenConfig gNMI protobuf library, generates disposable CA/server/client certificates, starts the localhost-only server, runs the actual PREDICT-SHIELD Python collector through a pinned gNMIc executable in a Docker container, and stores its observed JSON result. The reference gNMIc tool and TLS flags are documented at https://gnmic.openconfig.net/cmd/get/ and https://gnmic.openconfig.net/user_guide/targets/targets/.

The reported asset type is an intentionally broad **router surrogate**, not a claim that the process is router firmware. Independent validation with an actual gNMI-capable network OS and schema-specific payload mapping remains required. This test establishes protocol integration, not ISP topology discovery.

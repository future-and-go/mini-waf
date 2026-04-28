# waf-cluster

Multi-node clustering layer. Provides QUIC-based peer transport, leader election, health detection, and config/rule sync between WAF instances.

## Features
- **QUIC transport**: mTLS-secured client/server over `quinn` with framed messages.
- **Discovery**: peer registry and bootstrap.
- **Leader election**: coordinator selection across the cluster.
- **Health detection**: peer heartbeat + failure detection / eviction.
- **Sync**: replicates rules, config, and events between nodes (lz4-compressed).
- **Crypto / PKI**: internal CA, per-node certs, sealed token store.
- **Cluster forwarding**: forward proxied traffic to the appropriate node.
- **Wire protocol**: typed message definitions shared by client and server.

## Folder Structure
```
src/
├── lib.rs
├── node.rs                   # Node identity + lifecycle
├── protocol.rs               # Wire message types
├── discovery.rs              # Peer discovery / registry
├── cluster_forward.rs        # Inter-node request forwarding
├── transport/                # QUIC transport
│   ├── mod.rs, client.rs, server.rs, frame.rs
├── crypto/                   # Internal PKI
│   ├── mod.rs, ca.rs, node_cert.rs, store.rs, token.rs
├── election/                 # Leader election
├── health/                   # Heartbeat + detector
└── sync/                     # Replication
    ├── mod.rs, config.rs, rules.rs, events.rs

tests/                        # Integration: cluster, election, peer eviction
```

## Dependencies
Depends on `waf-common`, `waf-engine`. Stack: `quinn`, `rustls`, `rcgen`, `aes-gcm`, `hmac`, `sha2`, `lz4_flex`, `serde_json`, `parking_lot`.

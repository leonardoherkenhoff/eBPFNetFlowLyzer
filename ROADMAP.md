# 🗺️ eBPFNetFlowLyzer Development Roadmap (Extractor-Centric)

This document outlines the strategic trajectory for eBPFNetFlowLyzer, prioritizing its evolution as a world-class network feature extractor.

## 🏁 Phase 1: Foundation (v1.0) - [COMPLETED]
- [x] High-performance Data Plane (XDP/C).
- [x] Unified Dual-Stack (IPv4/IPv6) support.
- [x] Stateful flow tracking with O(1) statistical calculation (Welford's).
- [x] Support for TCP, UDP, and ICMPv6.
- [x] Automated Research Pipeline (Extraction, Labeling, ML Analysis).

---

## 🚀 Phase 2: Advanced Extraction Capabilities (v2.0) - [PLANNED]

### Milestone 1: Deep Network Visibility
*Focus: Eliminating blind spots in modern infrastructure.*
- [ ] **Tunneling Decapsulation**: In-kernel stripping of GRE, VXLAN, and IP-in-IP headers to extract inner 5-tuple features.
- [ ] **L7 SNI Extraction**: Non-intrusive TLS handshake parsing in XDP to identify domain names (HTTPS metadata).
- [ ] **QUIC/HTTP3 Feature Mapping**: Heuristic-based feature extraction for UDP-based encrypted web traffic.
- [ ] **ICMPv6 Specific Features**: Dedicated counters for RA/RS, Neighbor Solicitation, and Echo Request/Reply ratios.

### Milestone 2: Industrial Scalability & Performance
*Focus: Scaling the extractor for high-density scrubbing environments.*
- [ ] **Multi-Interface Ingestion**: Unified aggregation from multiple NICs into a single flow table.
- [ ] **Dynamic RingBuffer Tuning**: Adaptive buffer sizing based on real-time PPS to prevent packet drops during volumetric floods.
- [ ] **XDP Driver-Mode & Offload**: Optimization for hardware-level XDP offloading (NIC-level execution).

### Milestone 3: Advanced Flow Metadata (The "Lyzer" Expansion)
*Focus: Providing higher-quality data for Machine Learning models.*
- [ ] **TCP State Analytics**: Tracking retransmissions, Out-of-Order packets, and Zero-Window signals.
- [ ] **Payload Entropy Calculation**: Real-time measurement of packet payload entropy to identify encrypted vs. plain-text floods.
- [ ] **Flow Directionality (Forward/Backward)**: Enhanced logic for symmetrical flow correlation in multi-homed environments.

---

## 🛠️ Phase 4: Long-term Evolution (v3.0) - [RESEARCH]
- [ ] **Real-time Inference Integration**: Using the extractor features for immediate detection.
- [ ] **Prometheus/Grafana Export**: Standardizing the telemetry output.

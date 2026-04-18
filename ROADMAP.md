# 🗺️ eBPFNetFlowLyzer Development Roadmap

This document outlines the strategic milestones and technical trajectory for the eBPFNetFlowLyzer project.

## 🏁 Phase 1: Foundation (v1.0) - [COMPLETED]
- [x] High-performance Data Plane (XDP/C).
- [x] Unified Dual-Stack (IPv4/IPv6) support.
- [x] Stateful flow tracking with O(1) statistical calculation (Welford's).
- [x] Support for TCP, UDP, and ICMPv6.
- [x] Automated Research Pipeline (Extraction, Labeling, ML Analysis).

---

## 🚀 Phase 2: Visibility & Scalability (v2.0) - [PLANNED]

### Milestone 1: Advanced Protocol Parsing
- [ ] **Tunneling Decapsulation**: Support for GRE, VXLAN, and IP-in-IP to unmask tunneled DDoS traffic.
- [ ] **L7 HTTPS SNI Extraction**: Implementation of a non-intrusive TLS handshake parser to extract domain metadata.
- [ ] **QUIC/HTTP3 Entropy Analysis**: Statistical identification of encrypted high-layer floods.

### Milestone 2: Production-Grade Observability
- [ ] **Prometheus/Grafana Integration**: Native exporter for real-time flow metrics and PPS/BPS monitoring.
- [ ] **System Health Telemetry**: In-kernel drops and map utilization metrics.

### Milestone 3: Real-Time Mitigation Engine
- [ ] **In-Daemon Inference**: Porting the Random Forest classifier to the C-Daemon for real-time attack detection.
- [ ] **Dynamic XDP Drop**: Implementation of an eBPF map-driven blocklist for immediate mitigation of identified malicious flows.

---

## 🛠️ Phase 3: Enterprise Features (v3.0) - [RESEARCH]
- [ ] **Hardware Offload (AF_XDP)**: Transition to zero-copy data paths for Multi-100G environments.
- [ ] **Distributed Flow Correlation**: Aggregation of flows across multiple scrubbing nodes.
- [ ] **Autonomous Tuning**: ML-driven dynamic adjustment of eBPF map sizes and sampling rates.

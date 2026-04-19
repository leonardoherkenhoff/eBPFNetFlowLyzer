# 🗺️ Lynceus Project Roadmap

This document outlines the strategic evolution of the **Lynceus** eBPF engine, transitioning from a high-fidelity research extractor to a fully autonomous network security infrastructure.

---

## ✅ Phase 1: High-Performance Extraction (v1.0 - v2.0)
*Target: Research Integrity and Core Performance.*
- [x] **Shared-Nothing Architecture**: N-Core scalability via Map-in-Map.
- [x] **Partitioned I/O**: Mutex-free telemetry persistence.
- [x] **Statistical Fidelity**: Welford's Algorithm for 4th-order moments.
- [x] **IPv4/IPv6 Parity**: Full dual-stack support (TCP/UDP/ICMP/ICMPv6).
- [x] **Professional Rebranding**: Transition to the 'Lynceus' identity.

---

## 🚀 Phase 2: Intelligence & Fingerprinting (v2.x)
*Target: Advanced Feature Engineering.*
- [ ] **L7 Deep Dissection**: Native eBPF support for HTTP/2 and QUIC fingerprinting.
- [ ] **Entropy Drift Analysis**: Real-time Shannon entropy monitoring for encrypted traffic anomalies.
- [ ] **Shared-Nothing State Management**: Core-local state tracking for complex protocol transitions.
- [ ] **Agnostic Export**: Integration with Prometheus/Grafana via custom exporter.

---

## 🧠 Phase 3: Autonomous Response (v3.0)
*Target: The MAPE-K Closed-Loop.*
- [ ] **ML Inference in Kernel**: Loading quantized models (XDP-Tail-Calls) for real-time packet classification.
- [ ] **Dynamic Mitigation**: Automated `XDP_DROP` or `XDP_REDIRECT` based on ML confidence levels.
- [ ] **Feedback Loop**: Self-correcting thresholds via user-space MAPE-K orchestration.

---
**Lynceus: Precise Vision, Absolute Integrity.**

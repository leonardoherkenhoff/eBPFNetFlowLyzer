# 🛡️ eBPFNetFlowLyzer v1.1.0

**Unified, High-Performance, Stateful Network Feature Extractor Powered by C-eBPF/XDP.**

---

## 📌 Overview

**eBPFNetFlowLyzer** is a next-generation network traffic feature extractor engineered for high-throughput security environments (e.g., Scrubbing Centers). By leveraging a **100% C-native architecture**, it offloads stateful flow aggregation to the **eBPF/XDP** layer, achieving massive throughput with negligible CPU impact.

The system implements a **Unified Dual-Stack Engine**, utilizing 128-bit keying and IPv4-Mapped IPv6 addressing to process **IPv4**, **IPv6**, and **ICMP/ICMPv6** traffic through a single, numerically stable O(1) statistical pipeline.

## 🚀 Key Features (v1.1.0)

*   **Stateful XDP Ingestion**: In-kernel flow correlation using lock-free `LRU_HASH` tables for maximum throughput and DDoS resistance.
*   **Deep Packet Visibility**: Native decapsulation of **GRE** and **VXLAN** tunnels (Unmasking hidden traffic).
*   **L7 SNI Extraction**: Non-intrusive HTTPS domain identification via **TLS Handshake SNI** parsing.
*   **Industrial Scalability**: Support for **Multi-Interface Ingestion** and massive 128MB RingBuffers for zero-loss extraction at scale.
*   **O(1) Statistics (Welford's Algorithm)**: Real-time calculation of Mean, Variance, and Standard Deviation without buffering packet sequences.
*   **Research Orchestration**: Full-lifecycle benchmarking suite including traffic injection (tcpreplay), hardware monitoring, and ML-ready CSV labeling.

## 🏛️ Architecture

*   **Data Plane (Kernel Space)**: XDP-based interceptor responsible for early-stage packet parsing and atomic flow accounting.
*   **Control Plane (User Space)**: High-performance C Daemon that orchestrates the BPF RingBuffer, manages bidirectional flow state, and persists data to CSV.
*   **Analysis Suite (Python)**: Scientific pipeline for dataset preprocessing, topological labeling, and Machine Learning validation (Random Forest).

## 🛠️ Build & Execution

### Prerequisites
*   **Linux Kernel**: 5.10+ (CO-RE enabled)
*   **Toolchain**: `clang` / `llvm` (v12+), `libbpf`, `libelf`, `zlib`, `uthash`.

### Compilation
```bash
# Standard Build
make clean && make all
```

### Research Pipeline
```bash
# Automated Benchmark Execution
python3 scripts/testbed/ebpf_wrapper.py

# Dataset Labeling & ML Analysis
python3 scripts/preprocessing/ebpf_labeler.py
python3 scripts/analysis/ebpf_run_benchmark.py
```

## ⚖️ License

Distributed under the **GNU General Public License v2.0**. See `LICENSE` for more information.

---
*Developed as part of the Master's Degree in Applied Computing research, focused on Network Security for the Detection and Mitigation of DDoS attacks.*

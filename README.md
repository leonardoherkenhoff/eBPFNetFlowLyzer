# 🛡️ eBPFNetFlowLyzer v1.9.10

**High-Performance Parallel Network Telemetry & Stateful Feature Extraction.**

---

## 📌 Overview

**eBPFNetFlowLyzer** is a state-of-the-art network traffic feature extractor engineered for extreme high-throughput environments (48+ cores) and high-fidelity security research. By leveraging a **Massively Parallel Shared-Nothing Architecture**, it achieves linear scalability on multi-socket NUMA systems, making it the definitive tool for building real-time autonomous systems (**MAPE-K Loops**).

The system integrates a **Full Statistical Moments Engine** ($\mu, \sigma^2, \gamma, \kappa$) and a decentralized I/O pipeline to ensure **Absolute Capture Integrity** (zero-loss) even under multi-gigabit DDoS volumetric conditions.

---

## 🚀 Key Features (v1.9.10)

*   **Massively Parallel Shared-Nothing Core**: Eliminates lock contention via dynamic **Map-in-Map (BPF_MAP_TYPE_ARRAY_OF_MAPS)** architecture, providing independent telemetry channels per CPU core.
*   **Zero-Contention Partitioned I/O**: High-performance multi-threaded output engine where each core writes to its own isolated telemetry stream, bypasssing global filesystem locks.
*   **Scientific Statistical Suite (400+ Features)**: Numerically stable $O(1)$ calculation of 4th-order moments using Welford's Algorithm.
*   **NUMA-Aware Orchestration**: Real-time hardware topology detection and CPU affinity pinning to maximize cache locality on high-end Xeon/EPYC servers.
*   **Full IPv6 & VLAN Support**: Transparent dissection of encapsulated and multi-stack traffic without performance degradation.
*   **Entropy-Based L7 Fingerprinting**: Real-time Shannon Entropy calculation ($H(x)$) for identification of randomized/encrypted malicious payloads.

---

## 🏛️ System Architecture

### 1. Data Plane (Kernel Space)
XDP-based interceptor implementing the **Stateful Monitoring** phase. It performs:
- Atomic 5-tuple normalization.
- Bidirectional flow correlation.
- SMP-Processor ID based telemetry routing to private RingBuffers.

### 2. Control Plane (User Space)
A decentralized C-Daemon responsible for the **Analyze** phase of the MAPE-K loop:
- **Shared-Nothing Workers**: One thread per CPU core, pinned via `pthread_setaffinity_np`.
- **Stateless Aggregation**: Each worker manages its own flow table and statistical accumulators.
- **High-Velocity Persistence**: Partitioned I/O writing to `worker_telemetry/` with 2MB internal buffering.

---

## 📊 Feature Reference Matrix

The extractor exports over 400 dimensions for every detected network flow:

### 🔬 Statistical Moments (30 features per metric)
Calculated for **Payload Size**, **Header Size**, **IAT (Inter-Arrival Time)**, and **Packet-Length Deltas**.
- **Mean ($\mu$)**: Arithmetic average.
- **Variance ($\sigma^2$) / StdDev ($\sigma$)**: Dispersion analysis.
- **Skewness ($\gamma$)**: Distribution asymmetry (attack signature indicator).
- **Kurtosis ($\kappa$)**: Outlier sensitivity (burstiness detection).
- **Median / Mode**: Central tendency and frequency estimators.

### 🛡️ Protocol & Control Metadata
- **TCP States**: Complete bidirectional flag tracking (`FIN, SYN, RST, PSH, ACK, URG, ECE, CWR`).
- **L3/L4 Indicators**: TTL/Hop-Limit, ICMP Types/Codes, Port-specific volatility.
- **Payload Entropy**: Shannon entropy for protocol fingerprinting.

---

## 🛠️ Build & Performance Benchmarking

### Prerequisites
- **Linux Kernel**: 5.15+ (required for BPF RingBuffer and Array-of-Maps).
- **Toolchain**: `clang/llvm`, `libbpf`, `zstandard`.

### Deployment & Execution
```bash
# 1. Compile the parallel engine
make clean && make all

# 2. Reconstruct the experiment data tree
mkdir -p data/raw data/interim/EBPF_RAW data/processed/EBPF

# 3. Run the high-resolution extraction pipeline
sudo python3 scripts/analysis/ebpf_full_experiment.py
```

### 📉 Performance Metrics (Xeon Silver 4410Y - 48 Cores)
- **Ingestion Fidelity**: 100% (33M+ packets tested with zero drops).
- **Memory Footprint**: Linear $O(N)$ with flow table size (~3GB for 200k active flows).
- **I/O Throughput**: 2.5GB/s+ (partitioned writing to NVMe).

---

## ⚖️ License & Research Credits

Distributed under the **GNU General Public License v2.0**.
Designed for the **SBSeg 2026** Research Report and Master's Dissertation in Applied Computing.

---
**eBPFNetFlowLyzer: Absolute Integrity, Infinite Scalability.**

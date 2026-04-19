# 🛡️ eBPFNetFlowLyzer v1.9.13

**High-Performance Parallel Network Telemetry & Massive Dataset Orchestration.**

---

## 📌 Overview

**eBPFNetFlowLyzer** is a state-of-the-art network traffic feature extractor engineered for **Dynamic N-Core environments** and high-fidelity security research. By leveraging a **Massively Parallel Shared-Nothing Architecture**, it achieves linear scalability on multi-socket NUMA systems, making it the definitive tool for building real-time autonomous systems (**MAPE-K Loops**).

The system automatically probes the host hardware at runtime, instantiating independent extraction pipelines for every available CPU core. This ensures **Absolute Capture Integrity** (zero-loss) even under multi-gigabit DDoS volumetric conditions and large-scale dataset extraction (180GB+).

---

## 🚀 Key Features (v1.9.13)

*   **Elastic N-Core Scalability**: Automatically detects system topology via `sysconf` and instantiates a dynamic **Map-in-Map (BPF_MAP_TYPE_ARRAY_OF_MAPS)** structure, providing private telemetry channels per core.
*   **Zero-Contention Partitioned I/O**: High-performance multi-threaded output engine where each core writes to its own isolated telemetry stream, bypassing global filesystem locks and mutex contention.
*   **Iterative Storage Orchestration (v1.9.12+)**: Implements a rigorous **"Extract-Label-Purge"** pipeline. Telemetry is labeled and source-purged batch-by-batch, allowing 180GB+ datasets to be processed on constrained storage partitions.
*   **Scientific Statistical Suite (400+ Features)**: Numerically stable $O(1)$ calculation of 4th-order moments using Welford's Algorithm.
*   **NUMA-Aware Orchestration**: Real-time CPU affinity pinning (`pthread_setaffinity_np`) to maximize cache locality and minimize cross-socket latency.
*   **Full IPv6 & VLAN Support**: Transparent dissection of encapsulated and multi-stack traffic without performance degradation.
*   **Entropy-Based L7 Fingerprinting**: Real-time Shannon Entropy calculation ($H(x)$) for identification of randomized/encrypted malicious payloads.

---

## 🏛️ System Architecture

### 1. Data Plane (Kernel Space)
XDP-based interceptor implementing the **Stateful Monitoring** phase. It performs:
- Atomic 5-tuple normalization and bidirectional flow correlation.
- SMP-Processor ID based telemetry routing to core-specific RingBuffers.
- High-fidelity L3/L4/L7 feature extraction at line-rate.

### 2. Control Plane (User Space)
A decentralized C-Daemon responsible for the **Analyze** phase of the MAPE-K loop:
- **Shared-Nothing Workers**: One thread per CPU core, dynamically spawned based on host capacity.
- **Stateless Aggregation**: Each worker manages its own flow table and statistical accumulators.
- **High-Velocity Persistence**: Partitioned I/O writing to `worker_telemetry/` with 2MB internal buffering.

### 3. Orchestrator (Research Pipeline)
A Python-based testbed supervisor that manages the **Extract-Label-Purge** cycle:
- Automatically handles network topology (VETH pairs).
- Iterates through massive PCAP directories, performing real-time labeling.
- Purges interim raw data post-processing to maintain storage health.

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
- **Toolchain**: `clang/llvm`, `libbpf`, `python3-pandas`.

### Deployment & Execution
```bash
# 1. Compile the parallel engine
make clean && make all

# 2. Run the full iterative research pipeline (Extraction -> Labeling -> ML Benchmark)
sudo python3 scripts/analysis/ebpf_full_experiment.py
```

### 📉 Testbed Case Study (Xeon Silver 4410Y - 48 Cores)
- **Ingestion Fidelity**: 100% (33M+ packets tested with zero drops).
- **Storage Resilience**: Successfully processed 180GB CICDDoS2019 dataset using iterative cleanup.
- **Architecture Adaptability**: The system dynamically scaled to all 48 threads without manual configuration.
- **Memory Footprint**: ~3GB for 200k active flows.
- **I/O Throughput**: 2.5GB/s+ (sustained partitioned writing).

---

## ⚖️ License & Research Credits

Distributed under the **GNU General Public License v2.0**.
Designed for the **SBSeg 2026** Research Report and Master's Dissertation in Applied Computing.

---
**eBPFNetFlowLyzer: Absolute Integrity, Infinite Scalability.**

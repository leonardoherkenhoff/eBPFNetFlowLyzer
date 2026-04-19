# 🛡️ eBPFNetFlowLyzer v1.9.1

**High-Performance, Stateful Network Feature Extractor Powered by C-eBPF/XDP.**

---

## 📌 Overview

**eBPFNetFlowLyzer** is an industrial-grade network traffic feature extractor engineered for high-throughput security environments, traffic analysis, and anomaly detection. By leveraging a **100% C-native architecture**, it offloads stateful flow aggregation to the **eBPF/XDP** layer, achieving massive throughput with negligible CPU impact.

The system implements a **State-of-the-Art Statistical Engine**, providing high-resolution bidirectional telemetry through a numerically stable O(1) pipeline. It is designed to capture atomic per-packet events across **IPv4**, **IPv6**, and **ICMP** protocols, ensuring zero-loss extraction even under volumetric network conditions.

## 🚀 Key Features (v1.9.1)

*   **Massive Feature Vector (400+)**: Extraction of high-dimensional flow signatures, including 4th-order statistical moments and application-layer entropy.
*   **Stateful XDP Ingestion**: In-kernel flow correlation using lock-free hash tables for maximum throughput and resistance to network flooding.
*   **O(1) Statistical Moments**: Real-time calculation of Mean ($\mu$), Variance ($\sigma^2$), Skewness ($\gamma$), and Kurtosis ($\kappa$) using incremental update algorithms.
*   **Real-Time Metric Estimators**: Hardware-efficient estimators for **Median** and **Mode**, providing a complete statistical profile of network flows.
*   **Volatility Analysis (Deltas)**: Real-time tracking of inter-packet variations (Size/Timing) to identify jitter and burstiness signatures.
*   **Industrial I/O Optimization**: High-speed 1MB buffered output engine designed for large-scale data ingestion and Big Data pipelines.

---

## 📊 Feature Reference Matrix

The extractor generates a high-density CSV containing over 400 features. Below is the technical breakdown of the exported dimensions:

### 1. Flow Identity & Metadata
*   `flow_id`: Unique 5-tuple identifier (Bidirectional).
*   `src_ip` / `dst_ip`: Source and destination addresses (IPv4-Mapped IPv6 support).
*   `src_port` / `dst_port`: Layer 4 ports.
*   `protocol`: IANA protocol number (TCP/UDP/ICMP).
*   `timestamp`: Epoch micro-precision start time.
*   `duration`: Elapsed flow time in seconds.

### 2. Physical Aggregates (Total, Forward, Backward)
*   `PacketsCount`: Total packet volume per direction.
*   `TotalBytes`: Accumulated payload size per direction.
*   `FwdBwdPktRatio`: Ratio of forward to backward packets.
*   `FwdBwdByteRatio`: Ratio of forward to backward bytes.

### 3. Statistical Moments Suite (30 features per category)
Applied to **Payload Length**, **Header Length**, **IAT (Inter-Arrival Time)**, and **Delta-Length** (Size variation between consecutive packets).

*   `Max` / `Min`: Absolute range of the metric.
*   `Mean`: Arithmetic average calculated via Welford's algorithm.
*   `Std` / `Var`: Standard Deviation and Variance (dispersion).
*   `Median`: Estimated central tendency via Iterative SGD.
*   `Skewness`: Measure of distribution asymmetry.
*   `Kurtosis`: Measure of "tailedness" (outlier sensitivity).
*   `CoV`: Coefficient of Variation ($\sigma / \mu$).
*   `Mode`: Estimated most frequent value via bucketed histogram.

### 4. Network Control & L7 Signatures
*   **TCP Flags**: Bidirectional counts for `FIN, SYN, RST, PSH, ACK, URG, ECE, CWR`.
*   `PayloadEntropy`: Shannon Entropy ($H(X)$) of the packet payload for L7 randomized/malicious traffic detection.
*   `IcmpType` / `IcmpCode`: ICMP control plane metadata.
*   `TTL`: Hop-limit tracking for OS fingerprinting and routing analysis.

---

## 🏛️ Architecture

*   **Data Plane (Kernel Space)**: XDP-based interceptor responsible for early-stage packet parsing, 5-tuple normalization, and high-speed flow event streaming.
*   **Control Plane (User Space)**: Deeply optimized C Daemon that orchestrates the BPF RingBuffer, manages bidirectional state, and persists multi-dimensional telemetry to CSV via 1MB accelerated I/O.

## 🛠️ Build & Installation

### Prerequisites
*   **Linux Kernel**: 5.15+ (BPF RingBuffer support)
*   **Toolchain**: `clang` / `llvm` (v12+), `libbpf`, `libelf`, `zlib`.

### Compilation
```bash
make clean && make all
```

### Basic Usage
```bash
# Attach the extractor to a network interface
sudo ./build/loader eth0 > flow_features.csv
```

## ⚖️ License

Distributed under the **GNU General Public License v2.0**.

---

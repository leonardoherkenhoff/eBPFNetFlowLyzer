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
*   **Real-Time Metric Estimators**: Hardware-efficient estimators for **Median** and **Mode**, providing a complete statistical profile of network flows without offline processing.
*   **Volatility Analysis (Deltas)**: Real-time tracking of inter-packet variations (Size/Timing) to identify jitter and burstiness signatures.
*   **Industrial I/O Optimization**: High-speed 1MB buffered output engine designed for large-scale data ingestion and Big Data pipelines.

## 🏛️ Architecture

*   **Data Plane (Kernel Space)**: XDP-based interceptor responsible for early-stage packet parsing, 5-tuple normalization, and high-speed flow event streaming.
*   **Control Plane (User Space)**: Deeply optimized C Daemon that orchestrates the BPF RingBuffer, manages bidirectional state, and persists multi-dimensional telemetry to CSV.

## 🛠️ Build & Installation

### Prerequisites
*   **Linux Kernel**: 5.15+ (BPF RingBuffer support)
*   **Toolchain**: `clang` / `llvm` (v12+), `libbpf`, `libelf`, `zlib`.

### Compilation
```bash
# Compile the Kernel Program and User Daemon
make clean && make all
```

### Basic Usage
```bash
# Attach the extractor to a network interface (e.g., eth0)
sudo ./build/loader eth0 > flow_features.csv
```

## ⚖️ License

Distributed under the **GNU General Public License v2.0**. See `LICENSE` for more information.

---

<p align="center">
  <i>A professional solution for high-fidelity network telemetry and security monitoring.</i>
</p>

# 🛡️ eBPFNetFlowLyzer v1.9.1

**Unified, High-Performance, Stateful Network Feature Extractor Powered by C-eBPF/XDP.**

---

## 📌 Overview

**eBPFNetFlowLyzer** is a next-generation network traffic feature extractor engineered for high-throughput security environments and academic research. By leveraging a **100% C-native architecture**, it offloads stateful flow aggregation to the **eBPF/XDP** layer, achieving massive throughput with negligible CPU impact.

The system implements a **Unified Master Feature Matrix**, achieving 100% taxonomic parity with leading research tools (**NTLFlowLyzer** and **ALFlowLyzer**). It utilizes a single, numerically stable O(1) statistical pipeline to process **IPv4**, **IPv6**, and **ICMP/ICMPv6** traffic, capturing atomic bidirectional telemetry at line-rate.

## 🚀 Key Features (v1.9.1)

*   **Unified Taxonomic Matrix**: Consolidation of 348 (NTL) and 130 (AL) features into a single, non-redundant high-dimensional space for DDoS research.
*   **Stateful XDP Ingestion**: In-kernel flow correlation using lock-free hash tables for maximum throughput and resistance to volumetric flooding.
*   **O(1) Statistical Moments**: Real-time calculation of Mean ($\mu$), Variance ($\sigma^2$), Skewness ($\gamma$), and Kurtosis ($\kappa$) using Pébay's incremental update formulas.
*   **Advanced Metric Estimation**: Real-time $O(1)$ estimators for **Median** (Iterative SGD) and **Mode** (Histogram-based), enabling absolute parity with offline extractors.
*   **I/O Accelerated Extraction**: Optimized 1MB full-buffer output engine capable of sustaining zero-loss capture for 33M+ packet datasets.
*   **Research Orchestration**: Full-lifecycle benchmarking suite including traffic injection (tcpreplay), hardware monitoring, and ML-ready CSV labeling for SBSeg 2026 standards.

## 🏛️ Architecture

*   **Data Plane (Kernel Space)**: XDP-based interceptor responsible for early-stage packet parsing, 5-tuple normalization, and atomic flow event streaming via RingBuffer.
*   **Control Plane (User Space)**: High-performance C Daemon that orchestrates the BPF RingBuffer, implements the 10-moment statistical engine, and persists data via accelerated I/O.
*   **Analysis Suite (Python)**: Scientific pipeline for dataset preprocessing, topological ground truth labeling, and Machine Learning validation (Random Forest).

## 🛠️ Build & Execution

### Prerequisites
*   **Linux Kernel**: 5.15+ (RingBuffer support)
*   **Toolchain**: `clang` / `llvm` (v12+), `libbpf`, `libelf`, `zlib`.

### Compilation
```bash
# Standard Build
make clean && make all
```

### Research Pipeline
```bash
# Automated Benchmark Execution (PCAP Ingestion)
sudo python3 scripts/analysis/ebpf_full_experiment.py
```

## ⚖️ License

Distributed under the **GNU General Public License v2.0**. See `LICENSE` for more information.

---

<p align="center">
  <i>Developed for the Master's Thesis in Network Security and DDoS Mitigation.</i>
</p>

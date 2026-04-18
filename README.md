# 🛡️ eBPFNetFlowLyzer

**High-Performance, Dual-Stack (IPv4/IPv6), Stateful Network Feature Extractor Powered by C-eBPF.**

---

## 📌 Overview

**eBPFNetFlowLyzer** is a next-generation network traffic feature extractor built for high-throughput environments. By implementing a **100% C-based architecture** utilizing eBPF/XDP for data ingestion and a deeply optimized User-Space daemon, it achieves wire-speed processing (tested up to **480k pps**) with minimal CPU overhead.

It provides a **Unified Dual-Stack Engine** via IPv4-Mapped IPv6 address space, processing both legacy IPv4 and modern IPv6 traffic through the same O(1) statistical pipeline.

## 🚀 Key Features

* **Stateful eBPF Interception**: In-kernel flow aggregation using lock-free `LRU_HASH` tables.
* **O(1) Statistics (Welford's Algorithm)**: Iterative calculation of Standard Deviation and Mean, eliminating packet storage overhead.
* **Dual-Stack Unification**: Native 128-bit key architecture supporting **IPv4** and **IPv6** seamlessly.
* **DNS L7 Offloading**: Safe, verifier-vetted DNS metadata extraction (TTL, Query Count).

## 🏛️ Architecture

* **Data Plane (Kernel)**: XDP hook for parsing L2-L4 and performing fast-path flow accounting.
* **Control Plane (User-Space)**: C Daemon responsible for RingBuffer orchestration, bidirectional state management, and CSV export.

## 🛠️ Build Requirements

* **Linux Kernel**: 5.4+ (CO-RE enabled).
* **Compiler**: `clang` / `llvm` (v12+).
* **Libs**: `libbpf`, `libelf`, `zlib`.

```bash
# Compile
make clean && make all

# Run (Attach to Interface)
sudo ./build/loader <interface_name> > flow_results.csv
```

## ⚖️ License

Distributed under the **GNU General Public License v2.0**. See `LICENSE` for more information.

---
*Developed as part of the Master's Degree in Applied Computing research, focused on Network Security for the Detection and Mitigation of DDoS attacks.*

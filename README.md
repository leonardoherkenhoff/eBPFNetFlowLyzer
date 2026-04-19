# 🛡️ Lynceus

**High-Performance eBPF/XDP Feature Extraction Engine for Security Research and Infrastructure.**

---

## 📌 Overview

**Lynceus** is a professional-grade network telemetry engine designed for line-rate, flow-level feature extraction. Leveraging a **Massively Parallel Shared-Nothing Architecture** and eBPF/XDP, it provides a non-redundant matrix of **399 scientific features**, including advanced statistical moments and deep protocol dissection.

The project is **hardware-agnostic**, performing dynamic host CPU topology detection (SMP/NUMA) to instantiate isolated workers and core-private RingBuffers eBPF for every available physical core.

---

## 🚀 Key Features

*   **Dynamic Topology Scaling**: Automatic core detection via `sysconf` for massive parallelism, eliminating L1/L2 cache contention and global synchronization bottlenecks.
*   **High-Fidelity Protocol Dissection**:
    *   **L3/L4**: Full Dual-Stack (**IPv4/IPv6**), **TCP** (RFC 793 - Flags/Window), **UDP** (RFC 768), **ICMP/ICMPv6** (RFC 792/4443 with Echo ID granularity), **SCTP**, and **IGMP**.
    *   **Tunneling**: Native recursive decapsulation for **GRE** and **VXLAN**.
    *   **Encapsulation**: Iterative traversal for **VLAN** and **QinQ (802.1Q/802.1ad)**.
*   **Scientific Statistical Engine**:
    *   **399 Non-Redundant Features**: Unified matrix integrating NTLFlowLyzer and ALFlowLyzer specifications.
    *   **Welford Algorithm**: Numerically stable, $O(1)$ calculation of 4th-order statistical moments.
        $$\Delta = x - M_1, \quad M_1 = M_1 + \frac{\Delta}{n}$$
    *   **High-Density Histograms**: 240 bins (80 per set) with 20-byte resolution for micro-signature distribution analysis.
*   **Micro-Temporal Granularity**: Flow segmentation every **100 packets** ($N=100$) for high-fidelity time-series analysis.
*   **L7 Intelligence**: Shannon payload entropy and DNS telemetry tracking (RFC 1035).

---

## 🏛️ System Architecture

### 1. Data Plane (Kernel Space)
eBPF/XDP interceptor implementing atomic 5-tuple normalization and recursive tunnel decapsulation. Telemetry events are routed to core-private RingBuffers via **SMP Processor ID** affinity.

### 2. Control Plane (User Space)
Multithreaded C daemon with strict CPU pinning. Each worker processes its own event stream and persists data via **Partitioned I/O** (Zero-Contention CSV writing), ensuring linear scalability with core count.

---

## 🛠️ Build & Usage

### Prerequisites
- Linux Kernel 5.15+
- `clang`, `llvm`, `libbpf-dev`
- `make`

### Compilation and Execution
```bash
# Optimized parallel build
make clean && make -j$(nproc)

# Execution (Target specific interfaces)
# IMPORTANT: Adjust interface name for production server (e.g., eth0, ens3)
sudo ./build/loader <interface_name>
```
Telemetry is exported to `worker_telemetry/cpu_%d.csv`, ready for direct ingestion by **Deep Learning** pipelines.

---

## ⚖️ License

Distributed under the **GNU General Public License v2.0**.
Designed for high-fidelity network analysis and community-driven security research.

---
**Lynceus: Precise Vision, Absolute Integrity.**

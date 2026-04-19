# 🛡️ Lynceus

**High-Performance eBPF/XDP Telemetry Engine for Research and Security Infrastructure.**

---

## 📌 Overview

**Lynceus** is a professional-grade network telemetry engine designed for high-resolution flow extraction at wire-speed. Leveraging a **Shared-Nothing Parallel Architecture** and eBPF/XDP, it provides a non-redundant matrix of 399 features, including advanced statistical moments and deep protocol introspection.

The project is designed for high-throughput environments (e.g., Xeon-based clusters), providing zero-loss data ingestion and granular temporal resolution for network observability and security research.

---

## 🚀 Key Features

*   **Massively Parallel Shared-Nothing Architecture**: One isolated worker thread per CPU core with local flow tables, eliminating cache contention and mutex bottlenecks.
*   **Ultimate Protocol Dissection**:
    *   **L3/L4**: Full Dual-Stack (**IPv4/IPv6**), **TCP** (Flag/Window tracking), **UDP**, **ICMP/ICMPv6** (with Echo ID granularity), **SCTP**, and **IGMP**.
    *   **Tunneling**: Native recursive decapsulation for **GRE** and **VXLAN**.
    *   **Encapsulation**: Iterative traversal for **VLAN** and **QinQ (802.1Q/ad)**.
*   **Scientific Statistical Engine**:
    *   **399 Non-Redundant Features**: Unified matrix based on NTLFlowLyzer and ALFlowLyzer specifications.
    *   **Welford's Algorithm**: Numerically stable $O(1)$ calculation of the first four statistical moments (Mean, Variance, Skewness, Kurtosis).
    *   **192-Bin Payload Histograms**: High-resolution distribution analysis of packet sizes.
*   **Maximum Granularity**: State-driven flushing (FIN/RST) combined with **Segmented Flow Export** (100-packet micro-batches) for precise temporal analysis of floods.
*   **L7 Telemetry Hints**: Payload entropy (Shannon) and DNS query/answer tracking.

---

## 🏛️ System Architecture

### 1. Data Plane (Kernel Space)
XDP-based interceptor implementing atomic 5-tuple normalization, iterative encapsulation traversal, and recursive tunnel decapsulation. Telemetry events are routed to core-private RingBuffers via SMP affinity.

### 2. Control Plane (User Space)
Multi-threaded C daemon utilizing NUMA-aware workers. Each worker performs real-time statistical aggregation using Welford's algorithm and persists data via high-velocity **Partitioned I/O**.

---

## 🛠️ Build & Usage

### Prerequisites
- Linux Kernel 5.15+
- `clang`, `llvm`, `libbpf-dev`
- `make`

### Compilation
```bash
make clean && make -j$(nproc)
```

### Execution
```bash
sudo ./build/loader <interface_name> [additional_interfaces...]
```
Telemetry will be generated in the `worker_telemetry/` directory, partitioned by CPU core.

---

## 📜 Scientific Formalism

The engine utilizes Welford's Algorithm for online calculation of moments:

$$M_1 = \bar{x}_n = \bar{x}_{n-1} + \frac{x_n - \bar{x}_{n-1}}{n}$$
$$M_2 = M_2 + (x_n - \bar{x}_{n-1})(x_n - \bar{x}_n)$$

This ensures that the precision of 4th-order moments (Skewness and Kurtosis) is maintained even at multi-Gbps traffic levels.

---

## ⚖️ License

Distributed under the **GNU General Public License v2.0**.
Designed for high-fidelity network analysis and community-driven security research.

---
**Lynceus: Precise Vision, Absolute Integrity.**

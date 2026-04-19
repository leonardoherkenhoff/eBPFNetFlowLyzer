# 🗺️ Lynceus: Requirements Matrix, Technical Specification, and Definitive Roadmap

This document serves as the technical authority record for the **Lynceus** engine. It details every component, algorithm, and metric implemented, serving as the verification guide for the project's scientific "Totality."

---

## 🏛️ 1. Architecture and Design Philosophy
*Lynceus was built to eliminate contention bottlenecks and ensure absolute statistical fidelity.*

### 1.1. Core Parallelism: Shared-Nothing
- **Dynamic Detection**: The system utilizes `sysconf(_SC_NPROCESSORS_ONLN)` to identify the host's CPU topology.
- **Worker Isolation**: For every core, a control thread and a private **eBPF RingBuffer** are instantiated.
- **Zero-Lock Policy**: No Mutexes or Global write-maps exist in the critical path. Each core processes its own events and writes to its own CSV file (`worker_telemetry/cpu_%d.csv`).
- **NUMA Affinity**: Threads are pinned to physical cores via `pthread_setaffinity_np` to maximize L1/L2 cache locality and minimize bus latency.

---

## 🛡️ 2. Data Plane: Visibility and Dissection (eBPF/XDP)
*The capture engine operates at Layer 2 for total visibility before the kernel network stack.*

### 2.1. Normalization and Protocols
- **Native Dual-Stack**: Mapping of IPv4 addresses into the 128-bit IPv6 space for processing uniformity.
- **Recursive Tunnel Dissection**: The parser iterates over **GRE** and **VXLAN** headers, extracting features from the inner payload.
- **VLAN & QinQ**: Iterative support for multiple 802.1Q and 802.1ad headers.
- **ICMP/v6 Granularity**: Flow differentiation based not only on IP but on the `Type/Code` pair and the **Identifier (Echo ID)**, allowing tracking of individual ping sessions.

---

## 📊 3. Statistical Engine: The 399-Feature Matrix
*Rigorous unification of NTLFlowLyzer and ALFlowLyzer with 4th-order precision.*

### 3.1. Welford Algorithm (Numerical Stability)
- **Online Calculation**: Mean, Variance, Standard Deviation, Skewness, and Kurtosis calculated in $O(1)$ per packet.
- **Statistical Sets (15 Sets)**:
  - **Payload**: Total, Forward, Backward.
  - **Header**: Total, Forward, Backward.
  - **IAT (Inter-Arrival Time)**: Total, Forward, Backward.
  - **Size Deltas**: Total, Forward, Backward.
  - **Flow Dynamics**: Active Time, Idle Time, TCP Window Dynamics.

### 3.2. High-Density Histograms (240 Features)
- **Configuration**: 3 sets (Total, Fwd, Bwd) $\times$ 80 bins each.
- **Resolution**: **20-byte** step per bin, covering from 0 to 1600 bytes.
- **Function**: Captures the "image" of payload distribution, essential for detecting multimodal attacks that simple averages mask.

### 3.3. Bulk and Sub-flow Characteristics
- **Bulk Definition**: Uninterrupted sequences in one direction with $IAT < 1.0s$.
- **Metrics**: `bulk_bytes`, `bulk_packets`, `bulk_count` (For Fwd and Bwd).

---

## ⚙️ 4. Control Plane: State Management and I/O
### 4.1. Flow-Level Paradigm
- **Micro-Temporal Segmentation**: The engine flushes statistics every **100 packets** ($N=100$), allowing high-resolution time-series analysis.
- **Export Triggers**:
  - **Event-Driven**: Receipt of TCP FIN or RST flags.
  - **Volume-Driven**: Reaching the 100-packet threshold.
  - **Time-Driven**: 60-second Idle Timeout for inactive flows.

---

## 🚀 5. Strategic Evolution Roadmap

### Phase 2: Complex Feature Engineering (Upcoming)
- [ ] **L7 Deep Fingerprinting**: Extraction of specific fields from **HTTP/2** (Settings, Priority) and **QUIC** (Connection IDs) frames.
- [ ] **Temporal Drift Analysis**: Calculation of statistical variation between consecutive segments of the same flow.
- [ ] **Binary Export Backend**: Implementation of **Apache Arrow** or **ZMQ** output for direct integration with Deep Learning clusters.

### Phase 3: Autonomous Response and Inference (MAPE-K)
- [ ] **In-Kernel Inference**: Loading of quantized ML models (via XDP Tail-Calls) for real-time classification.
- [ ] **Intelligent Mitigation**: `XDP_DROP` actions based on the classifier's confidence level.
- [ ] **MAPE-K Orchestration**: Feedback loop for automatic adjustment of detection thresholds and extraction depth.

---
**Lynceus: Precise Vision, Absolute Integrity.**

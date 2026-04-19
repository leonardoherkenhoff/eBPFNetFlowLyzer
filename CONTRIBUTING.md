# Contributing to Lynceus

Thank you for your interest in contributing to **Lynceus**! As a high-performance eBPF engine, we maintain strict standards for code quality, performance, and integrity.

---

## 🛠️ Development Workflow

1.  **Fork the Repository**: Create your own fork of the project.
2.  **Branching Strategy**:
    - All new features and bug fixes must branch from **`develop`**.
    - Use descriptive branch names: `feature/your-feature` or `bugfix/issue-id`.
3.  **Implement Changes**: Follow the technical guidelines below.
4.  **Submit a Pull Request**: Targeted at the **`develop`** branch of the main repository.

---

## 📜 Technical Guidelines

### 1. eBPF Data Plane (C)
- **Style**: Follow the [Linux Kernel coding style](https://www.kernel.org/doc/html/latest/process/coding-style.html).
- **Complexity**: Ensure your BPF programs pass the verifier. Avoid complex loops or large stack allocations.
- **CO-RE**: All BPF code must be BTF-capable and CO-RE (Compile Once – Run Everywhere) compatible.

### 2. Control Plane (C/Daemon)
- **Shared-Nothing**: Maintain the Shared-Nothing architecture. Avoid global locks (mutexes) in the telemetry hot-path.
- **Memory**: Use NUMA-aware allocations where possible. Ensure zero memory leaks in the flow table logic.

### 3. Orchestration (Python)
- **Style**: Follow **PEP 8**.
- **Performance**: Use efficient data structures (e.g., `pandas`, `numpy`) for telemetry processing.

---

## 🧪 Testing Requirements

- All contributions must be tested against real or simulated network traffic using `tcpreplay` or `scapy`.
- Verify XDP loading and map integrity:
  ```bash
  sudo ./build/loader <iface>
  sudo bpftool map dump name pkt_ringbuf_map
  ```

---

## ⚖️ License & Sign-off

By contributing, you agree that your contributions will be licensed under the **GNU General Public License v2.0**. We require a **Developer Certificate of Origin (DCO)** sign-off (e.g., `git commit -s`) for all commits.

---
**Lynceus: Precise Vision, Absolute Integrity.**

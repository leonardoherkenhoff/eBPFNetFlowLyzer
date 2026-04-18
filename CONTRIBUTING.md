# 🤝 Contributing to eBPFNetFlowLyzer

Thank you for your interest in contributing to the project. To maintain high code quality and research reproducibility, please follow these guidelines.

## 🌿 Branching Strategy
We follow the **GitHub Flow** model:
1.  **main**: Stable baseline. Only merged from `develop` after full validation.
2.  **develop**: Main integration branch for the next release.
3.  **feature/<name>**: For new features (e.g., `feature/http-parsing`).
4.  **fix/<name>**: For bug fixes.
5.  **research/***: For experimental scripts and temporary benchmarks.

## 🛠️ Code Standards
- **Kernel Code (C)**: Must comply with eBPF Verifier constraints. Use `clang-format` (LLVM style).
- **Daemon Code (C)**: Modular, documented with Doxygen-style comments.
- **Scripts (Python)**: PEP8 compliant, type-hinted where possible.

## 🧪 Submission Process
1.  Create a feature branch from `develop`.
2.  Implement changes and add documentation.
3.  Verify with `scripts/analysis/ebpf_full_experiment.py`.
4.  Submit a Pull Request (PR) describing the changes and performance impact.

## 📏 Commits
Use semantic commit messages:
- `FEAT`: New feature.
- `FIX`: Bug fix.
- `DOCS`: Documentation changes.
- `CHORE`: Build system or library updates.
- `SYNC`: Synchronization across branches.

# 📝 Changelog

All notable changes to this project will be documented in this file.

## [1.0.0] - 2026-04-18
### Added
- **Core**: High-performance C-eBPF/XDP Data Plane.
- **Core**: O(1) statistical calculation via Welford's Algorithm.
- **Protocols**: Unified Dual-Stack (IPv4/IPv6) 128-bit keying.
- **Protocols**: Explicit support for TCP, UDP, and ICMPv6.
- **L7**: DNS metadata extraction (TTL, Query Count).
- **Automation**: End-to-end experiment orchestrator (`ebpf_full_experiment.py`).
- **Monitoring**: Real-time hardware resource sampler (`monitor.py`).
- **Analysis**: Topological labeler and Random Forest benchmark scripts.
- **Documentation**: Rigorous academic documentation and professional README.

### Fixed
- Packet reporting logic in the orchestrator pipeline.
- IPv6 attacker identification in the labeling phase.
- Data Plane support for ICMPv6 (Protocol 58).

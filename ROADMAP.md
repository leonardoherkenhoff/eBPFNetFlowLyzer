# 🗺️ Lynceus: Matriz de Requisitos e Roadmap Técnico

Este documento consolida todos os requisitos técnicos, arquiteturais e científicos do motor **Lynceus**, servindo como o registro definitivo da "Totalidade" exigida para a extração de características em fluxo.

---

## 🛡️ Matriz de Requisitos e Evidências (Status Atual)

### 1. Visibilidade Protocolar e Dissecção (Data Plane)
| Requisito | Status | Evidência Técnica |
| :--- | :---: | :--- |
| **Dual-Stack IPv4/v6** | [x] | `main.bpf.c:parse_l3` (Mapeamento 128-bit) |
| **Dissecção L4 (TCP/UDP)** | [x] | `main.bpf.c:xdp_prog` (Flags/Window dissecção) |
| **Diferenciação ICMP-ID** | [x] | `main.bpf.c:xdp_prog` (Echo ID Flow Separation) |
| **Túneis (GRE/VXLAN)** | [x] | `main.bpf.c:xdp_prog` (Decapsulamento Recursivo) |
| **VLAN QinQ** | [x] | `main.bpf.c:xdp_prog` (802.1Q/ad Iterative Traversal) |
| **SCTP / IGMP** | [ ] | *Planejado para Fase de Expansão* |

### 2. Engenharia de Características (399 Features)
| Requisito | Status | Evidência Técnica |
| :--- | :---: | :--- |
| **Fidelidade Welford** | [x] | `loader.c:w_update` (Momentos de 4ª ordem $O(1)$) |
| **Deltas (Time & Size)** | [x] | `loader.c:flow_state` (`t_iat` e `t_pay_delta`) |
| **Histogramas (192 Bins)** | [x] | `loader.c:w_stat.hist` (Distribuição de 64 bins x 3) |
| **Inteligência L7** | [x] | `loader.c:calculate_entropy` (Shannon Entropy) |
| **DNS Metrics** | [x] | `loader.c:handle_event` (`dns_a_count` / `dns_q_count`) |
| **Dinâmica de Janela** | [x] | `loader.c:flow_state.win_s` (Estatísticas de Window) |

### 3. Arquitetura e Performance (Control Plane)
| Requisito | Status | Evidência Técnica |
| :--- | :---: | :--- |
| **Shared-Nothing Parallel**| [x] | `loader.c:worker_t` (Isolamento por core Xeon) |
| **NUMA-Aware Affinity** | [x] | `loader.c:worker_fn` (`pthread_setaffinity_np`) |
| **I/O Particionado** | [x] | `loader.c:worker_fn` (`worker_telemetry/cpu_%d.csv`) |
| **Paradigma de Fluxo** | [x] | `loader.c:flush_flow` (Exportação orientada a eventos) |
| **Granularidade Micro** | [x] | `loader.c:handle_event` (`SEGMENT_THRESHOLD = 100`) |
| **Gatilhos de Flush** | [x] | `loader.c:handle_event` (FIN/RST + Idle Timeout) |

---

## 🚀 Evolução Estratégica (Fases Futuras)

### Fase 2: Engenharia Complexa
- [ ] **L7 Deep Fingerprinting**: Extração de features de frames **HTTP/2** e **QUIC**.
- [ ] **Temporal Drift Analysis**: Cálculo da evolução de características entre segmentos.
- [ ] **Backend de Exportação ML**: Ingestão binária direta (ZMQ/Arrow) para Deep Learning.

### Fase 3: Resposta Autônoma (MAPE-K)
- [ ] **Inferência ML no Kernel**: Classificação via modelos quantizados em XDP.
- [ ] **Mitigação em Fluxo**: Ações de drop/redirect baseadas em assinaturas estatísticas.
- [ ] **Feedback Loop**: Ajuste dinâmico da profundidade de extração.

---
**Lynceus: Extração Precisa, Integridade Absoluta.**

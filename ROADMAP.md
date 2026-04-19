# 🗺️ Lynceus Project Roadmap

Este documento define a trajetória técnica e o histórico de marcos (Milestones) do motor **Lynceus**, focado exclusivamente na evolução como motor de extração de características (Features) em fluxo de rede.

---

## 📅 Histórico de Milestones (Concluídos)

| Milestone | Marco Técnico | Descrição |
| :--- | :--- | :--- |
| **v1.0.0** | Core Research | Lançamento inicial: Extrator Unificado Dual-Stack (IPv4/v6). |
| **v1.1.0** | Protocol Expansion | Suporte total a ICMP e ICMPv6 para pesquisa de DDoS. |
| **v1.4.1** | Granular Discovery | Implementação de dissecção de **ICMP ID** e extensões IPv6 aninhadas. |
| **v1.6.0** | NTL/AL Hybrid | Fusão inicial NTL+AL com extração segmentada de fluxos. |
| **v1.8.5** | High-Res Welford | Implementação de **Welford $O(1)$** e granularidade extrema ($N=1000$). |
| **v2.0.0** | Lynceus Parallel | Arquitetura **Shared-Nothing** massivamente paralela para Xeon. |
| **v2.2.0** | Ultimate Unified | Restauração de **Túneis (GRE/VXLAN)** e **VLAN QinQ**. |
| **v2.4.0** | Flow-Level Logic | Transição definitiva para o **Paradigma de Fluxo** com $N=100$. |

---

## ✅ Fase 1: Extração de Alta Performance (Status: 100% OK)
*Objetivo: Integridade Estatística e Vazão de Extração.*

- [x] **Arquitetura Shared-Nothing**: Isolamento N-Core para extração linear.
- [x] **Matriz Científica (399 Features)**: Unificação NTLFlowLyzer + ALFlowLyzer.
- [x] **Fidelidade de 4ª Ordem**: Algoritmo de Welford em $O(1)$.
- [x] **Visibilidade Protocolar Universal**: Suporte a 11+ protocolos (incluindo GRE/VXLAN/QinQ).
- [x] **Granularidade Segmentada**: Flush de características a cada 100 pacotes.

---

## 🚀 Fase 2: Engenharia de Características Complexas
*Objetivo: Expansão da Densidade de Dados para ML.*

- [ ] **Fingerprinting L7 Nativo**: Extração de características de **HTTP/2** e **QUIC** (Stream IDs, Frame Types).
- [ ] **Análise de Drift Temporal**: Evolução da entropia e momentos entre segmentos.
- [ ] **Extração de Estados de Protocolo**: Features baseadas em transições (Latência Handshake, Retransmissão).
- [ ] **Exportação para Pipelines ML**: Backend otimizado (ZMQ/Binary) para ingestão em Deep Learning.

---

## 🧠 Fase 3: Extração Híbrida e Resposta (MAPE-K)
*Objetivo: Otimização da Extração via Inferência.*

- [ ] **Seleção de Features no Kernel**: Filtros ML quantizados (XDP) para redução de dimensionalidade.
- [ ] **Mitigação Baseada em Features**: Ações de rede acionadas por assinaturas em tempo real.
- [ ] **Loop de Feedback MAPE-K**: Ajuste dinâmico da extração via confiança do classificador.

---
**Lynceus: Extração Precisa, Integridade Absoluta.**

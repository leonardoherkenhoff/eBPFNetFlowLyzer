# 🗺️ Lynceus Project Roadmap

Este documento define a trajetória estratégica do motor **Lynceus**, evoluindo de um extrator de alta fidelidade para uma infraestrutura de segurança autônoma.

---

## ✅ Fase 1: Extração de Alta Performance (Concluída)
*Objetivo: Integridade de Pesquisa e Vazão Wire-Speed.*

- [x] **Arquitetura Shared-Nothing**: Escalabilidade N-Core linear via isolamento de memória por CPU.
- [x] **Persistência Particionada**: Escrita em CSV sem contenção de lock global.
- [x] **Matriz de 399 Características**: Paridade total (NTL+AL) com 192 bins de histograma.
- [x] **Fidelidade Estatística**: Algoritmo de Welford para momentos de 4ª ordem ($O(1)$).
- [x] **Visibilidade Protocolar Universal**: Suporte a IPv4/v6, TCP, UDP, ICMP-ID, SCTP, IGMP e decapsulamento de túneis (GRE/VXLAN) e QinQ.
- [x] **Identidade Profissional**: Consolidação da marca Lynceus para a comunidade.

---

## 🚀 Fase 2: Inteligência e Observabilidade Avançada
*Objetivo: Engenharia de Características Complexas.*

- [ ] **Dissecção L7 Profunda**: Suporte nativo eBPF para fingerprinting de **HTTP/2** e **QUIC**.
- [ ] **Análise de Drift de Entropia**: Monitoramento temporal da Entropia de Shannon para detecção de anomalias em tráfego criptografado.
- [ ] **Gestão de Estado Distribuída**: Rastreamento de transições de protocolo complexas (ex: Handshakes) em ambiente multi-core.
- [ ] **Exportação Agnóstica**: Integração com **Prometheus/Grafana** via exportador customizado de baixa latência.

---

## 🧠 Fase 3: Resposta Autônoma (MAPE-K)
*Objetivo: O Loop Fechado de Mitigação.*

- [ ] **Inferência ML no Kernel**: Execução de modelos quantizados (via XDP Tail-Calls) para classificação em tempo real.
- [ ] **Mitigação Dinâmica**: Ações automatizadas de `XDP_DROP` ou `XDP_REDIRECT` baseadas em níveis de confiança estatística.
- [ ] **Feedback Loop**: Orquestração MAPE-K em user-space para ajuste dinâmico de limiares de detecção.

---
**Lynceus: Visão Precisa, Integridade Absoluta.**

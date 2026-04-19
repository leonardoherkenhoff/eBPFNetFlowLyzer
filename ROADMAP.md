# 🗺️ Lynceus Project Roadmap

Este documento define a trajetória técnica do **Lynceus**, focado exclusivamente na evolução como motor de extração de características (Features) em fluxo de rede.

---

## ✅ Fase 1: Extração de Alta Performance (Concluída)
*Objetivo: Integridade Estatística e Vazão de Extração.*

- [x] **Arquitetura Shared-Nothing**: Isolamento N-Core para extração linear sem contenção.
- [x] **Matriz Científica (399 Features)**: Unificação NTLFlowLyzer + ALFlowLyzer (não-redundante).
- [x] **Fidelidade de 4ª Ordem**: Implementação de Welford para momentos estatísticos em $O(1)$.
- [x] **Universalidade Protocolar**: Extração em IPv4/v6, TCP, UDP, ICMP-ID, GRE, VXLAN e QinQ.
- [x] **Granularidade Segmentada**: Flush de características a cada 100 pacotes (N=100).

---

## 🚀 Fase 2: Engenharia de Características Complexas
*Objetivo: Expansão da Densidade de Dados para ML.*

- [ ] **Fingerprinting L7 Nativo**: Extração de características específicas de **HTTP/2** e **QUIC** (ex: Priority Frames, Stream IDs) para detecção de anomalias em tráfego criptografado.
- [ ] **Análise de Drift Temporal**: Cálculo da evolução da entropia e dos momentos estatísticos entre segmentos consecutivos do mesmo fluxo.
- [ ] **Extração de Estados de Protocolo**: Geração de features baseadas em transições (ex: latência de handshake, variação de janela TCP, taxas de retransmissão).
- [ ] **Exportação de Alta Velocidade para Pipelines ML**: Implementação de backend de exportação otimizado (ex: ZMQ ou buffers binários) para ingestão direta por frameworks de Deep Learning.

---

## 🧠 Fase 3: Extração Híbrida e Resposta (MAPE-K)
*Objetivo: Otimização da Extração via Inferência.*

- [ ] **Seleção de Características no Kernel**: Uso de modelos de ML quantizados (XDP) para filtrar e exportar apenas as características de maior relevância para a detecção detectada.
- [ ] **Mitigação Baseada em Features**: Ações de drop/redirect acionadas diretamente pela extração de assinaturas de ataque em tempo real.
- [ ] **Loop de Feedback MAPE-K**: Ajuste dinâmico da profundidade da extração com base no nível de confiança do classificador externo.

---
**Lynceus: Extração Precisa, Integridade Absoluta.**

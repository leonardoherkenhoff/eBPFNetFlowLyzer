# 🗺️ Lynceus: Matriz de Requisitos e Roadmap Técnico

Este documento consolida todos os requisitos técnicos, arquiteturais e científicos do motor **Lynceus**, servindo como o registro definitivo da "Totalidade" exigida para a extração de características em fluxo.

---

## 🛡️ Matriz de Requisitos do Motor (Status Atual)

### 1. Visibilidade Protocolar e Dissecção (Data Plane)
- [x] **Dual-Stack Nativo**: Suporte completo a IPv4 e IPv6 (mapeamento 128-bit).
- [x] **Dissecção L4 Granular**: Tracking detalhado de **TCP** (Flags, Window), **UDP** e **ICMP/ICMPv6**.
- [x] **Diferenciação ICMP**: Separação de fluxos baseada em `Type`, `Code` e **Identifier (Echo ID)**.
- [x] **Decapsulamento de Túneis**: Visibilidade do payload interno em fluxos **GRE** e **VXLAN**.
- [x] **Traversal de Encapsulamento**: Suporte iterativo a **VLAN** e **QinQ (802.1Q/ad)**.
- [ ] **Protocolos Adicionais**: Suporte profundo planejado para **SCTP**, **IGMP** e **SASP**.

### 2. Engenharia de Características (399 Features - NTL+AL)
- [x] **Paridade NTLFlowLyzer**: Extração de 348 características baseadas em estatísticas de rede.
- [x] **Paridade ALFlowLyzer**: Extração de 51 características L7 não-redundantes.
- [x] **Fidelidade Welford**: Cálculo estável de momentos de 4ª ordem (Média, Desvio Padrão, Variância, Assimetria, Curtose) em $O(1)$.
- [x] **Histogramas de Payload**: 192 bins (64 por set: Total, Fwd, Bwd) para análise de distribuição de tamanho.
- [x] **Inteligência L7**: Cálculo de **Entropia de Shannon** e metadados de **DNS** (Query/Answer counts).
- [x] **Dinâmica de Janela**: Suíte estatística completa aplicada à janela TCP.

### 3. Arquitetura e Performance (Control Plane)
- [x] **Paradigma de Fluxo (Flow-Level)**: Agregação em RAM com exportação orientada a eventos.
- [x] **Granularidade Extrema**: Segmentação de fluxos a cada **100 pacotes** para análise temporal de floods.
- [x] **Shared-Nothing Parallelism**: Um worker por CPU, sem contenção de Mutex ou Mapas globais.
- [x] **Afinidade NUMA**: Fixação de threads em cores físicos para maximizar cache locality.
- [x] **I/O Particionado**: Escrita em CSVs isolados por core (Zero-Contention).
- [x] **Gatilhos de Flush**: FIN/RST (Imediato), Idle Timeout (60s) e Volume (N=100).

---

## 🚀 Evolução Estratégica

### Fase de Engenharia Complexa
- [ ] **L7 Deep Fingerprinting**: Extração de features de frames **HTTP/2** e **QUIC**.
- [ ] **Temporal Drift Analysis**: Cálculo da evolução de características entre segmentos.
- [ ] **Backend de Exportação ML**: Ingestão binária direta (ZMQ/Arrow) para Deep Learning.

### Fase de Resposta Autônoma (MAPE-K)
- [ ] **Inferência ML no Kernel**: Classificação via modelos quantizados em XDP.
- [ ] **Mitigação em Fluxo**: Ações de drop/redirect baseadas em assinaturas estatísticas.
- [ ] **Feedback Loop**: Ajuste dinâmico da profundidade de extração.

---
**Lynceus: Extração Precisa, Integridade Absoluta.**

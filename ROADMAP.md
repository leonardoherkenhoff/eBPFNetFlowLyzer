# 🗺️ Lynceus: Matriz de Requisitos, Especificação Técnica e Roadmap Definitivo

Este documento é o registro de autoridade técnica do motor **Lynceus**. Ele detalha cada componente, algoritmo e métrica implementada, servindo como guia de verificação para a "Totalidade" científica do projeto.

---

## 🏛️ 1. Arquitetura e Filosofia de Design
*O Lynceus foi construído para eliminar gargalos de contenção e garantir fidelidade estatística absoluta.*

### 1.1. Core Parallelism: Shared-Nothing
- **Detecção Dinâmica**: O sistema utiliza `sysconf(_SC_NPROCESSORS_ONLN)` para identificar a topologia de CPU do host.
- **Isolamento de Workers**: Para cada núcleo, é instanciada uma thread de controle e um **RingBuffer eBPF** privado.
- **Zero-Lock Policy**: Não existem Mutexes ou Mapas Globais de escrita no caminho crítico. Cada core processa seus próprios eventos e escreve em seu próprio arquivo CSV (`worker_telemetry/cpu_%d.csv`).
- **Afinidade NUMA**: Threads são fixadas em cores físicos via `pthread_setaffinity_np` para maximizar a localidade de cache L1/L2 e minimizar latência de barramento.

---

## 🛡️ 2. Data Plane: Visibilidade e Dissecção (eBPF/XDP)
*O motor de captura opera em Layer 2 para visibilidade total antes da pilha de rede do kernel.*

### 2.1. Normalização e Protocolos
- **Dual-Stack nativo**: Mapeamento de endereços IPv4 para o espaço de 128-bit do IPv6 para uniformidade de processamento.
- **Dissecção Recursiva de Túneis**: O parser itera sobre cabeçalhos **GRE** e **VXLAN**, extraindo as características do payload interno.
- **VLAN & QinQ**: Suporte iterativo a múltiplos cabeçalhos 802.1Q e 802.1ad.
- **Granularidade ICMP/v6**: Diferenciação de fluxos baseada não apenas no IP, mas no par `Type/Code` e no **Identifier (Echo ID)**, permitindo rastrear sessões individuais de ping.

---

## 📊 3. Motor Estatístico: A Matriz de 399 Features
*Unificação rigorosa de NTLFlowLyzer e ALFlowLyzer com precisão de 4ª ordem.*

### 3.1. Algoritmo de Welford (Estabilidade Numérica)
- **Cálculo Online**: Média, Variância, Desvio Padrão, Assimetria (Skewness) e Curtose (Kurtosis) calculados em $O(1)$ por pacote.
- **Sets Estatísticos (15 Conjuntos)**:
  - **Payload**: Total, Forward, Backward.
  - **Header**: Total, Forward, Backward.
  - **IAT (Inter-Arrival Time)**: Total, Forward, Backward.
  - **Size Deltas (Variação de Tamanho)**: Total, Forward, Backward.
  - **Fluxo**: Active Time, Idle Time, TCP Window Dynamics.

### 3.2. Histogramas de Alta Densidade (240 Features)
- **Configuração**: 3 conjuntos (Total, Fwd, Bwd) $\times$ 80 bins cada.
- **Resolução**: Passo de **20 bytes** por bin, cobrindo de 0 a 1600 bytes.
- **Função**: Captura a "imagem" da distribuição de carga útil, essencial para detectar ataques multimodais que médias simples mascaram.

### 3.3. Características de Bulk e Sub-fluxo
- **Definição de Bulk**: Sequências ininterruptas em uma direção com $IAT < 1.0s$.
- **Métricas**: `bulk_bytes`, `bulk_packets`, `bulk_count` (Para Fwd e Bwd).

---

## ⚙️ 4. Control Plane: Gestão de Estado e I/O
### 4.1. Paradigma de Fluxo (Flow-Level)
- **Segmentação Micro-Temporal**: O motor realiza o flush de estatísticas a cada **100 pacotes** ($N=100$), permitindo análise de séries temporais de alta resolução.
- **Gatilhos de Exportação**:
  - **Event-Driven**: Recebimento de flags TCP FIN ou RST.
  - **Volume-Driven**: Atingimento do threshold de 100 pacotes.
  - **Time-Driven**: Idle Timeout de 60 segundos para fluxos inativos.

---

## 🚀 5. Roadmap de Evolução Estratégica

### Fase 2: Engenharia de Características Complexas (Próxima)
- [ ] **L7 Deep Fingerprinting**: Extração de campos específicos de frames **HTTP/2** (Settings, Priority) e **QUIC** (Connection IDs).
- [ ] **Análise de Drift Temporal**: Cálculo da variação das estatísticas entre segmentos consecutivos do mesmo fluxo.
- [ ] **Backend de Exportação Binária**: Implementação de output em **Apache Arrow** ou **ZMQ** para integração direta com clusters de Deep Learning.

### Fase 3: Resposta Autônoma e Inferência (MAPE-K)
- [ ] **Inferência no Kernel**: Carregamento de modelos de ML quantizados (Via XDP Tail-Calls) para classificação em tempo real.
- [ ] **Mitigação Inteligente**: Ações de `XDP_DROP` baseadas no nível de confiança do classificador estatístico.
- [ ] **Orquestração MAPE-K**: Loop de feedback para ajuste automático de limiares de detecção e profundidade de extração.

---
**Lynceus: Visão Precisa, Integridade Absoluta.**

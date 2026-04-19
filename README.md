# 🛡️ Lynceus

**Motor de Extração de Features eBPF/XDP de Alta Performance para Pesquisa e Infraestrutura de Segurança.**

---

## 📌 Visão Geral

**Lynceus** é um motor de telemetria de rede de nível profissional projetado para extração de características em fluxo (Flow-Level Feature Extraction) em velocidade de linha. Utilizando uma **Arquitetura Paralela Shared-Nothing** e eBPF/XDP, ele fornece uma matriz não-redundante de 399 características, incluindo momentos estatísticos avançados e dissecção profunda de protocolos.

O projeto é **agnóstico a hardware**, realizando a detecção dinâmica da topologia de CPU do host para instanciar workers e RingBuffers isolados para cada núcleo disponível.

---

## 🚀 Principais Características

*   **Escalabilidade Dinâmica de Topologia**: Detecção automática de cores via `sysconf` para paralelismo Massivamente Shared-Nothing, eliminando contenção de cache e gargalos de mutex.
*   **Dissecção Protocolar de Extrema Fidelidade**:
    *   **L3/L4**: Full Dual-Stack (**IPv4/IPv6**), **TCP** (Flags/Window), **UDP**, **ICMP/ICMPv6** (com granularidade de Echo ID), **SCTP** e **IGMP**.
    *   **Tunelamento**: Decapsulamento recursivo nativo para **GRE** e **VXLAN**.
    *   **Encapsulamento**: Traversal iterativo para **VLAN** e **QinQ (802.1Q/ad)**.
*   **Motor Estatístico Científico**:
    *   **399 Features Não-Redundantes**: Matriz unificada baseada nas especificações NTLFlowLyzer e ALFlowLyzer.
    *   **Algoritmo de Welford**: Cálculo numericamente estável de momentos estatísticos de 4ª ordem (Média, Variância, Assimetria, Curtose) em $O(1)$.
    *   **Histogramas de Payload**: 192 bins para análise de distribuição de tamanho.
*   **Granularidade Micro-Temporal**: Exportação orientada a eventos (FIN/RST) combinada com **Segmentação de Fluxo** a cada 100 pacotes.
*   **Inteligência L7**: Entropia de payload (Shannon) e tracking de queries/respostas DNS.

---

## 🏛️ Arquitetura do Sistema

### 1. Data Plane (Kernel Space)
Interceptor baseado em XDP que implementa normalização atômica de 5-tuple, traversal de encapsulamento e decapsulamento de túneis. Eventos de telemetria são roteados para RingBuffers privados por núcleo via SMP affinity.

### 2. Control Plane (User Space)
Daemon multithreaded em C utilizando workers isolados. Cada worker realiza agregação estatística em tempo real e persiste dados via **I/O Particionado** de alta velocidade, garantindo zero-contenção entre threads.

---

## 🛠️ Build & Uso

### Pré-requisitos
- Kernel Linux 5.15+
- `clang`, `llvm`, `libbpf-dev`
- `make`

### Compilação
```bash
make clean && make -j$(nproc)
```

### Execução
```bash
sudo ./build/loader <interface_name> [additional_interfaces...]
```
A telemetria será gerada no diretório `worker_telemetry/`, particionada por núcleo de CPU detectado.

---

## ⚖️ Licença

Distribuído sob a **GNU General Public License v2.0**.
Projetado para análise de rede de alta fidelidade e pesquisa de segurança dirigida pela comunidade.

---
**Lynceus: Visão Precisa, Integridade Absoluta.**

# 🛡️ Lynceus

**Motor de Extração de Features eBPF/XDP de Alta Performance para Pesquisa e Infraestrutura de Segurança.**

---

## 📌 Visão Geral

**Lynceus** é um motor de telemetria de rede de nível profissional projetado para extração de características em fluxo (Flow-Level Feature Extraction) em velocidade de linha. Utilizando uma **Arquitetura Paralela Shared-Nothing** e eBPF/XDP, ele fornece uma matriz não-redundante de **399 características**, incluindo momentos estatísticos avançados e dissecção profunda de protocolos.

O projeto é **totalmente agnóstico a hardware**, realizando a detecção dinâmica da topologia de CPU do host (via SMP/NUMA detection) para instanciar workers e RingBuffers eBPF isolados para cada núcleo físico disponível.

---

## 🚀 Principais Características

*   **Escalabilidade Dinâmica de Topologia**: Detecção automática de cores via `sysconf` para paralelismo massivo, eliminando contenção de cache L1/L2 e gargalos de sincronização global.
*   **Dissecção Protocolar de Alta Fidelidade**:
    *   **L3/L4**: Full Dual-Stack (**IPv4/IPv6**), **TCP** (RFC 793 - Flags/Window), **UDP** (RFC 768), **ICMP/ICMPv6** (RFC 792/4443 com granularidade de Echo ID), **SCTP** e **IGMP**.
    *   **Tunelamento**: Decapsulamento recursivo nativo para **GRE** e **VXLAN**.
    *   **Encapsulamento**: Traversal iterativo para **VLAN** e **QinQ (802.1Q/802.1ad)**.
*   **Motor Estatístico Científico**:
    *   **399 Features Não-Redundantes**: Matriz unificada integrando NTLFlowLyzer e ALFlowLyzer.
    *   **Algoritmo de Welford**: Cálculo numericamente estável de momentos estatísticos de 4ª ordem em $O(1)$.
        $$\Delta = x - M_1, \quad M_1 = M_1 + \frac{\Delta}{n}$$
    *   **Histogramas de Payload**: 240 bins (80 por conjunto) com resolução de 20 bytes para análise de micro-assinaturas.
*   **Granularidade Micro-Temporal**: Segmentação de fluxo a cada **100 pacotes** ($N=100$) para análise de séries temporais de alta fidelidade.
*   **Inteligência L7**: Entropia de Shannon para payload e metadados de DNS (RFC 1035).

---

## 🏛️ Arquitetura do Sistema

### 1. Data Plane (Kernel Space)
Interceptor eBPF/XDP que implementa normalização atômica de 5-tuple e decapsulamento recursivo. Eventos de telemetria são roteados para RingBuffers privados por núcleo via **SMP Processor ID**.

### 2. Control Plane (User Space)
Daemon C multithreaded com afinidade de CPU estrita. Cada worker processa seu próprio stream de eventos e persiste dados via **I/O Particionado** (Zero-Contention CSV writing), garantindo escalabilidade linear com o número de cores.

---

## 🛠️ Build & Uso

### Pré-requisitos
- Kernel Linux 5.15+
- `clang`, `llvm`, `libbpf-dev`
- `make`

### Compilação e Execução
```bash
# Compilação paralela otimizada
make clean && make -j$(nproc)

# Execução (Direcionada a interfaces específicas)
sudo ./build/loader <interface_name>
```
Os dados são exportados em `worker_telemetry/cpu_%d.csv`, prontos para ingestão direta por pipelines de **Deep Learning**.

---

## ⚖️ Licença

Distribuído sob a **GNU General Public License v2.0**.
Projetado para análise de rede de alta fidelidade e pesquisa de segurança dirigida pela comunidade.

---
**Lynceus: Visão Precisa, Integridade Absoluta.**

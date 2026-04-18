# 🗺️ Roadmap de Desenvolvimento (eBPFNetFlowLyzer)

Este documento descreve a trajetória evolutiva do projeto para se tornar o extrator de fluxos de referência para pesquisa acadêmica e produção industrial.

---

## 🏛️ Milestone 1: Visibilidade Profunda (Concluído - v1.1)
*Objetivo: Descortinar ataques complexos e aninhados.*
- [x] **Deep Decapsulation**: Suporte a túneis GRE e VXLAN (Unmasking de ataques).
- [x] **L7 SNI Extraction**: Identificação de domínios HTTPS via TLS Handshake.
- [x] **Multi-Protocol**: Suporte nativo a ICMP e ICMPv6.
- [x] **Stateful Aggregation**: Agregação de fluxos bidirecionais no Kernel.

## 🏛️ Milestone 2: Escalabilidade Industrial (Concluído - v1.1)
*Objetivo: Preparação para ambientes de alto tráfego (Mpps).*
- [x] **Multi-Interface Ingestion**: Agregação unificada de múltiplas NICs em um único Daemon.
- [x] **Performance Patch**: Expansão de RingBuffer (128MB) e Cache LRU (512k).
- [x] **Drop Telemetry**: Monitoramento de transbordamento de buffer via `drop_counter`.
- [x] **Atomic Flush**: Exportação atômica do cache ao receber sinais POSIX (SIGINT).

## 🚀 Milestone 3: Automação e Resiliência (Pesquisa Atual)
*Objetivo: Adaptação dinâmica a condições de rede variáveis.*
- [ ] **Dynamic Tuning**: Ajuste automático dos recursos do Kernel (buffer/cache) baseado no PPS.
- [ ] **Advanced Metadata**: Extração de TTL, Window Size e TCP Options para fingerprinting de OS.
- [ ] **Payload Entropy**: Cálculo em tempo real da entropia do payload para detectar ataques cifrados vs. texto plano.

## 🛡️ Milestone 4: Hardware Offload (SmartNICs/DPUs)
*Objetivo: Mover o plano de dados para o hardware dedicado.*
- [ ] **XDP-HW-Mode**: Suporte a offload direto em ASICs/FPGAs de placas Netronome/NVIDIA.
- [ ] **DPU Native Packaging**: Empacotamento do daemon para rodar nos núcleos ARM de DPUs BlueField.

## 🏁 Milestone 5: Ultra-Performance (The End Game)
*Objetivo: Atingir Wire-Speed (100Gbps+) com overhead zero.*
- [ ] **AF_XDP Zero-Copy Backend**: Implementação de memória compartilhada para eliminar cópias entre Kernel e User-space.
- [ ] **Lock-less User-space Table**: Otimização da tabela de fluxos para escala massiva em servidores multicore.

---

## 📈 Métricas de Sucesso
- **Throughput**: Suportar > 10 Mpps em hardware commodity (x86).
- **Integridade**: Zero pacotes perdidos em condições de pico (estatística validada via `drop_counter`).
- **Precisão**: > 99% de F1-Score em modelos de ML baseados nos atributos extraídos.

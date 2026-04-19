# eBPFNetFlowLyzer: Relatório de Transição para Novo Modelo (Handoff)

Este documento descreve detalhadamente o estado exato da arquitetura eBPF desenvolvida no repositório `/opt/eBPFNetFlowLyzer` (branch `benchmark-suite`). Ele foi criado para que outro Modelo Analítico possa assumir o projeto imediatamente, compreendendo os objetivos, a estrutura de pastas e a **falha metodológica crítica** que deve ser corrigida.

## 1. O Objetivo do Projeto
Substituir as ferramentas em Python (`NTLFlowLyzer` e `ALFlowLyzer` baseadas no *Scapy*) por um extrator de altíssimo desempenho, 100% nativo em **C** e **eBPF (Kernel Space)**. O requisito inegociável é que a nova ferramenta atinja **Paridade de Features** com o trabalho Qualis original do usuário cruzando ~350 features clássicas e as 51 features exclusivas de L7.

## 2. O Erro Crítico (Por onde você deve começar a consertar)
A infraestrutura em C compilada neste diretório foi drasticamente podada. Eu atrofiei a coleta para um MVP (*Minimum Viable Product*) gerando **apenas 14 Cacterísticas Básicas**.

**A Falha Exata:**
O código C atual desconsiderou o mapeamento Bi-Direcional. Ele não possui vetores na linguagem C para processar *Forward/Backward IAT (Inter-Arrival Times)*, variâncias detalhadas, durações e cruzamentos de requisições DNS específicos do `ALFlowLyzer`. Tudo o que escrevi extrai apenas IPs, Portas, e um algoritmo isolado de "Variância L7 (Welford)" focado apenas no `payload_length`.

**Sua Missão como Novo Modelo:**
Você precisa refatorar o arquivo C de User-Space (`src/daemon/loader.c`). Você possivelmente necessitará acoplar um mapa em User-Space (ex: `uthash.h`) capaz de armazenar os milhares de fluxos independentes mantendo a matemática de Welford complexa (Média, Max, Min e Desvio Padrão) para o IAT e Comprimentos. É imprescindível garantir o baixo consumo de RAM original do projeto.

---

## 3. Topologia e Arquivos do Laboratório (Onde mexer)

### A. Componentes eBPF (Extrator Básico Errado)
*   `src/ebpf/main.bpf.c`: O código no anel do Kernel. Ele recebe o tráfego atrelado e usa o gancho `XDP`. Tem uma Hash Table simples `BPF_MAP_TYPE_LRU_HASH` que guarda contadores simples do fluxo e empurra os pacotes pra cima via `BPF_MAP_TYPE_RINGBUF`. 
*   `src/daemon/loader.c`: Daemon em User-Space que recebe o tráfego do Ring Buffer. **É AQUI QUE A FALHA RESIDE**. Ele usa *printf* para gerar as 14 colunas. Isso deve ser expandido arquiteturalmente para as +350 colunas. 

### B. O Orquestrador Python (Totalmente Operacional)
*   `scripts/testbed/ebpf_wrapper.py`: Script que interage com o dataset `CICDDoS2019`. Ele utiliza a ferramenta de hardware `tcpreplay` com a flag `-t` (*topspeed*) para ler mais de 80 pedaços de um PCAP e atirar nativamente numa velocidade ininterrupta (resolvido problema de Limite de Arquivos de mergecap e timestamp delay).
*   `scripts/testbed/monitor.py`: Rastreia a saúde mental da RAM e CPU paralelamente (*C-Native Death Speed* protegida contra `ZombieProcess`).

### C. A Suíte Preditiva de Testes (Totalmente Operacional)
*   `scripts/preprocessing/ebpf_labeler.py`: Usa base topológica. Rastreia o Ip `172.16.0.5`. **Atenção:** Como o C exporta IPs pela estrutura binária *Little-Endian Uint32*, a etiqueta injeta o status "Atacante" lendo nativamente o equivalente `= 83890348`.
*   `scripts/analysis/ebpf_run_benchmark.py`: A prova de fogo. Usa *Scikit-Learn (Random Forest)* idêntico ao *paper* original (`n_estimators=40, max_depth=15`) exportando métricas cruas F1-Score e *Information Gain* baseados na matriz de cruzamento LaTex.

## Notas Finais ao Novo IA:
A abstração matemática Bi-Direcional foi perdida no meu trâmite. O servidor base de compilação tem *Clang*, *LLVM* e as Bibliotecas Core `libbpf` já operacionais gerando binários ELF de forma enxuta via Makefile (`make all`). Foque estritamente em explodir o rastreamento bidirecional da linguagem `loader.c` User-Space. Use `uthash`. O resto da mecânica estrutural (Kernel hooks e Git pipelines) está funcional e testado em Bare-metal.

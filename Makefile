# Makefile eBPFNetFlowLyzer (Pure C Architecture)

CLANG ?= clang
LLC ?= llc
OPT ?= opt
BPFTOOL ?= bpftool

# Diretórios
SRC_DIR = src
EBPF_DIR = $(SRC_DIR)/ebpf
DAEMON_DIR = $(SRC_DIR)/daemon
BUILD_DIR = build

# Alvos
EBPF_OBJ = $(BUILD_DIR)/main.bpf.o
DAEMON_BIN = $(BUILD_DIR)/loader

# Flags de Compilação
CFLAGS = -g -O2 -Wall -Wextra
BPF_CFLAGS = -g -O2 -target bpf -D__TARGET_ARCH_x86 -I$(EBPF_DIR) -Wall -Wextra -Werror -Wshadow
LDFLAGS = -lbpf -lelf -lz

all: $(BUILD_DIR) $(EBPF_OBJ) $(DAEMON_BIN)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

# Compilação do Data Plane Interceptador (Kernel XDP)
$(EBPF_OBJ): $(EBPF_DIR)/main.bpf.c $(EBPF_DIR)/vmlinux.h
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

# Compilação do Control Plane de CPU (Daemon libbpf)
$(DAEMON_BIN): $(DAEMON_DIR)/loader.c
	$(CLANG) $(CFLAGS) $< -o $@ $(LDFLAGS)

clean:
	rm -rf $(BUILD_DIR)

.PHONY: all clean

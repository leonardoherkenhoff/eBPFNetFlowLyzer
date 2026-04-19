# Makefile - eBPFNetFlowLyzer (Senior Research Suite)
# -----------------------------------------------------------------------------
# Research Objective: High-performance eBPF-based Network Feature Extraction.
# This Makefile orchestrates the compilation of the Kernel-Space Data Plane 
# (XDP) and the User-Space Control Plane (Daemon).
#
# Requirements:
# - Clang/LLVM 10+ (BPF Target)
# - libbpf-dev, libelf-dev, zlib1g-dev
# - Linux Kernel 5.15+ (BTF Support)
# -----------------------------------------------------------------------------

CLANG ?= clang
LLC ?= llc
BPFTOOL ?= bpftool

# --- Workspace Configuration ---
SRC_DIR = src
EBPF_DIR = $(SRC_DIR)/ebpf
DAEMON_DIR = $(SRC_DIR)/daemon
BUILD_DIR = build

# --- Output Artifacts ---
EBPF_OBJ = $(BUILD_DIR)/main.bpf.o
DAEMON_BIN = $(BUILD_DIR)/loader

# --- Compilation Flags ---
# User-Space: Standard C99/GNU11 with libbpf and math linkage
CFLAGS = -g -O2 -Wall -Wextra -std=gnu11
# Kernel-Space: BPF architecture target with BTF alignment
BPF_CFLAGS = -g -O2 -target bpf -D__TARGET_ARCH_x86 -I$(EBPF_DIR) \
             -Wall -Wno-missing-declarations -Wno-compare-distinct-pointer-types

# --- Linker Dependencies ---
LDFLAGS = -lbpf -lelf -lz -lm

# --- Build Rules ---

all: $(BUILD_DIR) $(EBPF_OBJ) $(DAEMON_BIN)

$(BUILD_DIR):
	@mkdir -p $(BUILD_DIR)

# Target: Data Plane Interceptor
# Compiles the XDP program into BPF Bytecode for kernel injection.
$(EBPF_OBJ): $(EBPF_DIR)/main.bpf.c $(EBPF_DIR)/vmlinux.h
	@echo "🔧 Compiling eBPF Data Plane: $<"
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

# Target: Control Plane Orchestrator
# Compiles the C daemon that manages RingBuffers and statistical aggregation.
$(DAEMON_BIN): $(DAEMON_DIR)/loader.c
	@echo "🚀 Compiling User-Space Control Plane: $<"
	$(CLANG) $(CFLAGS) $< -o $@ $(LDFLAGS)

clean:
	@echo "🧹 Cleaning research build artifacts..."
	rm -rf $(BUILD_DIR)

.PHONY: all clean

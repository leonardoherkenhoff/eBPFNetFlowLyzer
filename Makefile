# eBPFNetFlowLyzer: High-Performance Feature Extractor
# ----------------------------------------------------
# This Makefile orchestrates the dual-component compilation:
# 1. Data Plane (Kernel-Space): eBPF/XDP program for packet interception.
# 2. Control Plane (User-Space): C Daemon using libbpf for state management.

CLANG ?= clang
BPFTOOL ?= bpftool

# Project Structure
SRC_DIR = src
EBPF_DIR = $(SRC_DIR)/ebpf
DAEMON_DIR = $(SRC_DIR)/daemon
BUILD_DIR = build

# Compilation Targets
EBPF_OBJ = $(BUILD_DIR)/main.bpf.o
DAEMON_BIN = $(BUILD_DIR)/loader

# Optimization & Compilation Flags
# -O2 is critical for eBPF verifier pass (enables dead-code elimination)
CFLAGS = -g -O2 -Wall -Wextra
BPF_CFLAGS = -g -O2 -target bpf -D__TARGET_ARCH_x86 -I$(EBPF_DIR) \
             -Wall -Wno-missing-declarations -Wno-compare-distinct-pointer-types

# Libraries for User-Space link: libbpf (CO-RE), libelf, zlib (compression)
LDFLAGS = -lbpf -lelf -lz -lm

all: $(BUILD_DIR) $(EBPF_OBJ) $(DAEMON_BIN)

$(BUILD_DIR):
	@mkdir -p $(BUILD_DIR)

# --- Data Plane Compilation (Kernel-Space) ---
# Generates the BPF bytecode to be loaded into the XDP hook.
# Requires vmlinux.h (generated via bpftool) for CO-RE compatibility.
$(EBPF_OBJ): $(EBPF_DIR)/main.bpf.c $(EBPF_DIR)/vmlinux.h
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

# --- Control Plane Compilation (User-Space) ---
# Compiles the daemon responsible for map orchestration and CSV export.
# Leverages UTHASH for fast user-space flow tracking where applicable.
$(DAEMON_BIN): $(DAEMON_DIR)/loader.c
	$(CLANG) $(CFLAGS) $< -o $@ $(LDFLAGS)

clean:
	rm -rf $(BUILD_DIR)

deep-clean: clean
	rm -rf data/interim/*
	rm -rf data/processed/*

.PHONY: all clean deep-clean

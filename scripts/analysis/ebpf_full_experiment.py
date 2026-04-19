#!/usr/bin/env python3
"""
eBPFNetFlowLyzer - Full Research Pipeline Orchestrator
------------------------------------------------------
Research Objective:
This script executes the complete end-to-end research experiment, from 
source compilation to Machine Learning validation.

Pipeline Phases:
1. Build Phase: Compiles the BPF bytecode and User-space daemon.
2. Extraction Phase: Ingests raw PCAPs and extracts granular flow features.
3. Pre-processing Phase: Applies topological ground truth labels.
4. Analysis Phase: Evaluates detection performance via Random Forest.

Reproducibility:
Each phase is designed to be idempotent and generates forensic logs 
required for the SBSeg 2026 artifact seals (SeloD, F, S, R).

Usage:
  sudo python3 scripts/analysis/ebpf_full_experiment.py
"""

import subprocess
import os
import sys
import time

def run_command(cmd, description):
    """
    Executes a shell command with research-grade logging and error handling.
    
    Args:
        cmd (str): The shell command to execute.
        description (str): A user-friendly description of the phase.
    """
    print(f"\n" + "="*60)
    print(f"🚀 {description}")
    print(f"="*60)
    start_time = time.time()
    try:
        # Direct terminal streaming for real-time visibility
        subprocess.run(cmd, shell=True, check=True)
        elapsed = time.time() - start_time
        print(f"\n✅ SUCCESS: {description} (Duration: {elapsed:.2f}s)")
    except subprocess.CalledProcessError as e:
        print(f"\n❌ ERROR: {description} failed with exit code {e.returncode}")
        sys.exit(1)

def main():
    """Main orchestrator for the eBPFNetFlowLyzer research experiment."""
    print("=== eBPFNetFlowLyzer End-to-End Experiment Pipeline ===")
    
    # --- Phase 1: Infrastructure Preparation ---
    run_command("make clean && make all", "Compiling eBPF Core and Daemon")
    
    # --- Phase 2: Feature Extraction (Data Plane + Control Plane) ---
    # Orchestrates VETH topology and BPF ingestion.
    run_command("python3 scripts/testbed/ebpf_wrapper.py", "Executing High-Speed Feature Extraction")
    
    # --- Phase 3: Post-processing (Topological Labeling) ---
    # Transforms raw telemetry into supervised datasets.
    run_command("python3 scripts/preprocessing/ebpf_labeler.py", "Applying Topological Ground Truth Labeling")
    
    # --- Phase 4: Research Validation (ML Benchmark) ---
    # Validates detection accuracy for academic reporting.
    run_command("python3 scripts/analysis/ebpf_run_benchmark.py", "Running Machine Learning Benchmark (Random Forest)")

    print("\n" + "="*60)
    print("🏆 ALL RESEARCH PHASES COMPLETED SUCCESSFULLY")
    print("="*60)
    print("Processed datasets: data/processed/EBPF/")
    print("Validation metrics are detailed in the Analysis Phase log above.")

if __name__ == "__main__":
    # Ensure root privileges for BPF/XDP attachment
    if os.geteuid() != 0:
        print("⚠️  Warning: This orchestrator requires sudo/root for eBPF attachment.")
    
    main()

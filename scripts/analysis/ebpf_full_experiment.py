"""
eBPFNetFlowLyzer - Full Research Pipeline Orchestrator
------------------------------------------------------
This script executes the complete end-to-end experiment:
1. Build: Compiles the C-eBPF Data Plane and Control Plane.
2. Extraction: Processes all datasets in data/raw via ebpf_wrapper.py.
3. Labeling: Applies topological ground truth via ebpf_labeler.py.
4. ML Benchmark: Evaluates detection performance via ebpf_run_benchmark.py.

Usage:
  sudo python3 scripts/analysis/ebpf_full_experiment.py
"""

import subprocess
import os
import sys
import time

def run_command(cmd, description):
    print(f"\n" + "="*60)
    print(f"🚀 {description}")
    print(f"="*60)
    start_time = time.time()
    try:
        # Using subprocess.run to stream output directly to terminal
        subprocess.run(cmd, shell=True, check=True)
        elapsed = time.time() - start_time
        print(f"\n✅ SUCCESS: {description} (Time: {elapsed:.2f}s)")
    except subprocess.CalledProcessError as e:
        print(f"\n❌ ERROR: {description} failed with return code {e.returncode}")
        sys.exit(1)

def main():
    print("=== eBPFNetFlowLyzer End-to-End Experiment Pipeline ===")
    
    # 1. Build Phase
    run_command("make clean && make all", "Compiling eBPF Core and Daemon")
    
    # 2. Extraction Phase (Data Plane + Control Plane)
    run_command("python3 scripts/testbed/ebpf_wrapper.py", "Executing High-Speed Feature Extraction")
    
    # 3. Pre-processing Phase (Labeling)
    run_command("python3 scripts/preprocessing/ebpf_labeler.py", "Applying Topological Ground Truth Labeling")
    
    # 4. Analysis Phase (ML Validation)
    run_command("python3 scripts/analysis/ebpf_run_benchmark.py", "Running Machine Learning Benchmark (Random Forest)")

    print("\n" + "="*60)
    print("🏆 ALL PHASES COMPLETED SUCCESSFULLY")
    print("="*60)
    print("Final datasets are in: data/processed/EBPF/")
    print("ML results are summarized above in the Analysis Phase output.")

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("⚠️  Warning: This script should ideally be run as root/sudo to ensure XDP attachment.")
    
    main()

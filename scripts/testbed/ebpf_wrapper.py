#!/usr/bin/env python3
"""
Lynceus Research Pipeline - Extraction Wrapper & Testbed Orchestrator (v2.0-Research)
-----------------------------------------------------------
v2.0-Research Stable Milestone:
- Engine: Lynceus v2.0 (Massively Parallel eBPF Extractor).
- "Extract-Label-Purge" Strategy: Integrates labelling and cleanup into the loop.
- NOTE: Current version uses VETH pairs for simulation. For production 
  server verification, adjust the 'LOADER_BIN' attachment to the physical NIC.
"""

import subprocess
import os
import time
import glob
import json
import threading
import shutil
import re

# --- Project Paths ---
BASE_DIR = "/opt/eBPFNetFlowLyzer"
DATA_RAW = os.path.join(BASE_DIR, "data/raw")
DATA_INTERIM = os.path.join(BASE_DIR, "data/interim/EBPF_RAW")
LOADER_BIN = os.path.join(BASE_DIR, "build/loader")
WORKER_DATA_DIR = os.path.join(BASE_DIR, "worker_telemetry") 
LABELER_SCRIPT = os.path.join(BASE_DIR, "scripts/preprocessing/ebpf_labeler.py")

# --- Research Constraints ---
EXPERIMENT_ORDER = ["PCAPv6", "PCAP"]

def process_pcap_dir(pcap_dir, category):
    """
    Orchestrates the extraction of a single PCAP directory.
    """
    rel_path = os.path.relpath(pcap_dir, os.path.join(DATA_RAW, category))
    output_dir = os.path.normpath(os.path.join(DATA_INTERIM, category, rel_path))
    os.makedirs(output_dir, exist_ok=True)
    
    pcaps = glob.glob(os.path.join(pcap_dir, "*.pcap*"))
    if not pcaps:
        return
    
    metrics_csv = os.path.join(output_dir, "resource_metrics.csv")
    experiment_name = f"{category}/{rel_path}"

    print(f"\n🚀 STARTING eBPF EXTRACTION: {experiment_name}")
    
    if os.path.exists(WORKER_DATA_DIR):
        shutil.rmtree(WORKER_DATA_DIR)
    os.makedirs(WORKER_DATA_DIR, exist_ok=True)
    
    # --- Step 1: Network Topology Initialization ---
    subprocess.run(["ip", "link", "delete", "veth0"], check=False, stderr=subprocess.DEVNULL)
    subprocess.run(["ip", "link", "add", "veth0", "type", "veth", "peer", "name", "veth1"], check=True)
    subprocess.run(["ip", "link", "set", "veth0", "up"], check=True)
    subprocess.run(["ip", "link", "set", "veth1", "up"], check=True)
    
    subprocess.run(["sysctl", "-w", "net.ipv6.conf.veth0.disable_ipv6=0"], check=False)
    subprocess.run(["sysctl", "-w", "net.ipv6.conf.veth1.disable_ipv6=0"], check=False)
    subprocess.run(["sysctl", "-w", "net.ipv6.conf.all.forwarding=1"], check=False)

    try:
        # --- Step 2: Daemon Ignition ---
        loader_log_path = os.path.join(output_dir, "loader_stderr.log")
        
        proc_loader = subprocess.Popen(
            [LOADER_BIN, "veth1"], 
            stdout=subprocess.DEVNULL, 
            stderr=subprocess.PIPE,
            text=True,
            cwd=BASE_DIR
        )
        
        def stream_logs(proc, log_file_path):
            try:
                with open(log_file_path, 'w') as f_log:
                    for line in iter(proc.stderr.readline, ""):
                        if not line: break
                        f_log.write(line)
                        f_log.flush()
                        # REMOVED FILTER FOR MAXIMUM DEBUG
                        print(f"   [Loader] {line.strip()}")
            except Exception as e:
                print(f"   [Wrapper] Log Thread Error: {e}")
        
        log_thread = threading.Thread(target=stream_logs, args=(proc_loader, loader_log_path), daemon=True)
        log_thread.start()
        
        time.sleep(5) 
        
        # --- Step 3: Resource Monitoring ---
        monitor_script = "scripts/testbed/monitor.py"
        proc_mon = None
        if os.path.exists(monitor_script):
            proc_mon = subprocess.Popen(["python3", monitor_script, str(proc_loader.pid), metrics_csv])
        
        # --- Step 4: Traffic Injection ---
        total_packets = 0
        start_time = time.time()
        
        for p in pcaps:
            print(f"   Streaming: {os.path.basename(p)}")
            cmd = f"tcpreplay -i veth0 -t {p} 2>&1"
            try:
                res = subprocess.run(cmd, shell=True, capture_output=True, text=True, check=True)
                matches = re.findall(r"(\d+)\s+packets", res.stdout)
                if matches:
                    total_packets += int(matches[0])
            except subprocess.CalledProcessError as e:
                print(f"   ❌ Replay Error: {e.stderr}")

        elapsed = time.time() - start_time
        pps = total_packets / elapsed if elapsed > 0 else 0
        
        # --- Step 5: Termination & Synchronization ---
        print("   🛑 Terminating Loader (Syncing Buffers)...")
        if proc_mon:
            proc_mon.terminate()
            proc_mon.wait()
        
        subprocess.run(["kill", "-INT", str(proc_loader.pid)], check=False)
        try:
            proc_loader.wait(timeout=300)
        except subprocess.TimeoutExpired:
            print("   ⚠️ Loader timed out. Force killing...")
            subprocess.run(["kill", "-9", str(proc_loader.pid)], check=False)
            
        log_thread.join(timeout=10)

        # --- Step 6: Telemetry Collection ---
        print("   📂 Collecting partitioned telemetry...")
        worker_files = glob.glob(os.path.join(WORKER_DATA_DIR, "*.csv"))
        for wf in worker_files:
            try:
                shutil.move(wf, output_dir)
            except Exception as e:
                print(f"   ⚠️ Failed to move {os.path.basename(wf)}: {e}")
        
        # --- Labeling and Purging ---
        print(f"   🏷️  Running Iterative Labeling for {experiment_name}...")
        label_cmd = f"python3 {LABELER_SCRIPT} --path {output_dir} --cleanup"
        subprocess.run(label_cmd, shell=True, check=False)
            
    finally:
        subprocess.run(["ip", "link", "delete", "veth0"], check=False, stderr=subprocess.DEVNULL)
    
    summary = {
        "experiment": experiment_name, "packets_sent": total_packets,
        "time_seconds": elapsed, "pps": pps, "timestamp": time.ctime(),
        "iterative_cleanup": True
    }
    with open(os.path.join(output_dir, "summary.json"), 'w') as f:
        json.dump(summary, f, indent=4)
        
    print(f"✅ DONE: {total_packets} packets | {elapsed:.2f}s | {pps:.2f} pps [Lynceus Engine]")

def main():
    """Entry point for the Extraction Wrapper."""
    print("=== Lynceus Research Pipeline (v2.0-Research Iterative) ===")
    if not os.path.exists(LOADER_BIN):
        print(f"❌ Error: {LOADER_BIN} not found. Run 'make all' first.")
        return

    for category in EXPERIMENT_ORDER:
        category_path = os.path.join(DATA_RAW, category)
        if not os.path.exists(category_path): continue
        pcap_files = glob.glob(os.path.join(category_path, "**", "*.pcap*"), recursive=True)
        pcap_dirs = sorted(list(set(os.path.dirname(p) for p in pcap_files)))
        if not pcap_dirs and (glob.glob(os.path.join(category_path, "*.pcap*"))):
             pcap_dirs = [category_path]
        for pcap_dir in pcap_dirs:
            process_pcap_dir(pcap_dir, category)

if __name__ == "__main__":
    try: main()
    except KeyboardInterrupt: print("\n⚠️  Interrupted.")

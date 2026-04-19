#!/usr/bin/env python3
"""
eBPFNetFlowLyzer - Extraction Wrapper & Testbed Orchestrator
-----------------------------------------------------------
Research Methodology:
This script provides a high-level Python abstraction for executing the 
eBPF feature extraction pipeline on captured network traffic (PCAPs).

Functional Workflow:
1. Topology Setup: Initializes a VETH pair (veth0 <-> veth1).
2. Daemon Ignition: Spawns the C-based BPF loader on veth1.
3. Traffic Injection: Replays PCAP data into veth0 using tcpreplay.
4. Telemetry Collection: Aggregates real-time diagnostic logs and metrics.
5. Cleanup: Tears down the virtual topology and flushes CSV artifacts.

Usage:
  This script is intended to be called by ebpf_full_experiment.py or 
  manually for targeted dataset extraction.
"""

import subprocess
import os
import time
import glob
import json
import threading

# --- Project Paths ---
BASE_DIR = "/opt/eBPFNetFlowLyzer"
DATA_RAW = os.path.join(BASE_DIR, "data/raw")
DATA_INTERIM = os.path.join(BASE_DIR, "data/interim/EBPF_RAW")
LOADER_BIN = os.path.join(BASE_DIR, "build/loader")

# --- Research Constraints ---
EXPERIMENT_ORDER = ["PCAPv6", "PCAP"]

def process_pcap_dir(pcap_dir, category):
    """
    Orchestrates the extraction of a single PCAP directory.
    
    Args:
        pcap_dir (str): Path to directory containing .pcap/.pcapng files.
        category (str): Dataset category (e.g., PCAPv6).
    """
    rel_path = os.path.relpath(pcap_dir, os.path.join(DATA_RAW, category))
    output_dir = os.path.join(DATA_INTERIM, category, rel_path)
    os.makedirs(output_dir, exist_ok=True)
    
    pcaps = glob.glob(os.path.join(pcap_dir, "*.pcap*"))
    if not pcaps:
        return

    csv_output = os.path.join(output_dir, "extraction_PCAP.csv" if category == "PCAP" else "extraction_PCAPv6.csv")
    metrics_csv = os.path.join(output_dir, "resource_metrics.csv")
    experiment_name = f"{category}/{rel_path}"

    print(f"\n🚀 STARTING eBPF EXTRACTION: {experiment_name}")
    
    # --- Step 1: Network Topology Initialization ---
    # We use a virtual ethernet pair to simulate physical network link injection.
    print("   🔧 Resetting VETH topology (veth0 <-> veth1)")
    subprocess.run(["sudo", "ip", "link", "delete", "veth0"], check=False, stderr=subprocess.DEVNULL)
    subprocess.run(["sudo", "ip", "link", "add", "veth0", "type", "veth", "peer", "name", "veth1"], check=True)
    subprocess.run(["sudo", "ip", "link", "set", "veth0", "up"], check=True)
    subprocess.run(["sudo", "ip", "link", "set", "veth1", "up"], check=True)
    
    # Kernel sysctl tuning for IPv6 Milestone 3 visibility
    subprocess.run(["sudo", "sysctl", "-w", "net.ipv6.conf.veth0.disable_ipv6=0"], check=False)
    subprocess.run(["sudo", "sysctl", "-w", "net.ipv6.conf.veth1.disable_ipv6=0"], check=False)
    subprocess.run(["sudo", "sysctl", "-w", "net.ipv6.conf.all.forwarding=1"], check=False)

    try:
        # --- Step 2: Daemon Ignition ---
        loader_log_path = os.path.join(output_dir, "loader_stderr.log")
        
        with open(csv_output, 'w') as f_out:
            proc_loader = subprocess.Popen(
                ["sudo", LOADER_BIN, "veth1"], 
                stdout=f_out, 
                stderr=subprocess.PIPE,
                text=True
            )
            
            # Real-time Forensic Log Streamer
            def stream_logs(proc, log_file_path):
                with open(log_file_path, 'w') as f_log:
                    for line in iter(proc.stderr.readline, ""):
                        if not line: break
                        f_log.write(line)
                        f_log.flush()
                        # Advanced Diagnostic Filter
                        if any(x in line for x in ["📊", "⚠️", "❌", "System", "Error", "Fatal", "└─", "[Diagnostic]", "[Parser Errors]", "-"]):
                            print(f"   [Loader] {line.strip()}")
            
            log_thread = threading.Thread(target=stream_logs, args=(proc_loader, loader_log_path), daemon=True)
            log_thread.start()
            
            time.sleep(2) # Grace period for BPF loading
            
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
                # Tcpreplay at maximum speed (Top-speed injection)
                cmd = f"sudo tcpreplay -i veth0 -t {p} 2>&1"
                try:
                    res = subprocess.run(cmd, shell=True, capture_output=True, text=True, check=True)
                    # Extract packet count from tcpreplay output
                    for line in res.stdout.split('\n'):
                        if "packets" in line and "sent" in line:
                            try: total_packets += int(line.split()[0])
                            except: pass
                except subprocess.CalledProcessError as e:
                    print(f"   ❌ Replay Error: {e.stderr}")

            elapsed = time.time() - start_time
            pps = total_packets / elapsed if elapsed > 0 else 0
            
            # --- Step 5: Termination & Synchronization ---
            time.sleep(1) # Ensure buffer flush
            if proc_mon:
                proc_mon.terminate()
                proc_mon.wait()
            
            # Graceful shutdown of the BPF Data Plane
            subprocess.run(["sudo", "kill", "-INT", str(proc_loader.pid)], check=False)
            proc_loader.wait()
            log_thread.join(timeout=2)

    finally:
        # Cleanup virtual topology to prevent system interface pollution
        print("   🧹 Cleaning up VETH topology")
        subprocess.run(["sudo", "ip", "link", "delete", "veth0"], check=False, stderr=subprocess.DEVNULL)
    
    # Persistent metadata for research reproducibility
    summary = {
        "experiment": experiment_name, "packets_sent": total_packets,
        "time_seconds": elapsed, "pps": pps, "timestamp": time.ctime()
    }
    with open(os.path.join(output_dir, "summary.json"), 'w') as f:
        json.dump(summary, f, indent=4)
        
    print(f"✅ DONE: {total_packets} packets | {elapsed:.2f}s | {pps:.2f} pps")

def main():
    """Entry point for the Extraction Wrapper."""
    print("=== eBPFNetFlowLyzer Research Pipeline ===")
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

"""
eBPFNetFlowLyzer Research Orchestrator
--------------------------------------
This script automates the performance benchmarking of the eBPF-based feature extractor.
It manages the lifecycle of the C-daemon (loader), resource monitoring (monitor.py),
and high-speed traffic injection via tcpreplay.

Research Context:
- O(1) Feature Extraction: Features are calculated iteratively in the C-daemon.
- Dual-Stack Support: Prioritizes IPv6 (PCAPv6) for dissertation validation.
- Wire-speed Benchmarking: Uses tcpreplay in top-speed mode to stress the XDP hook.

Developed as part of the Master's Degree in Applied Computing research.
"""

import os
import re
import subprocess
import time
import json
import signal
import glob

# --- CONFIGURATION ---
# Base directory for raw datasets (PCAP/PCAPNG)
DATA_RAW = "data/raw"
# Output directory for interim extraction results (CSVs and JSONs)
OUTPUT_BASE = "data/interim/EBPF_RAW"
# Path to the compiled C-native loader
LOADER_BIN = "./build/loader"
# Processing priority: IPv6 is the primary research focus
EXPERIMENT_ORDER = ["PCAPv6", "PCAP"]

def get_tcpreplay_stats(stderr_text):
    """
    Parses tcpreplay's stderr to extract the actual number of packets injected.
    Critical for accurate PPS (Packets Per Second) and throughput metrics.
    """
    match = re.search(r"Actual: (\d+) packets", stderr_text)
    if match:
        return int(match.group(1))
    return 0

def process_pcap_dir(pcap_dir, category_tag):
    """
    Orchestrates the extraction pipeline for a specific dataset directory.
    1. Initializes C-daemon (loader) and attaches to the loopback interface.
    2. Spawns monitor.py to track hardware utilization (CPU/RAM).
    3. Injects traffic using a transparent tcpdump | tcpreplay pipeline.
    4. Triggers an orderly shutdown to dump BPF Hash Maps to CSV.
    """
    rel_path = os.path.relpath(pcap_dir, os.path.join(DATA_RAW, category_tag))
    experiment_name = category_tag if rel_path == "." else f"{category_tag}_{rel_path.replace(os.path.sep, '_')}"
    
    # Setup structured output paths
    output_dir = os.path.join(OUTPUT_BASE, category_tag, rel_path if rel_path != "." else "")
    os.makedirs(output_dir, exist_ok=True)
    
    csv_output = os.path.join(output_dir, f"extraction_{category_tag}.csv")
    metrics_csv = os.path.join(output_dir, "resource_metrics.csv")
    
    print(f"\n🚀 STARTING eBPF EXTRACTION: {experiment_name}")
    
    # Locate all supported pcap formats
    pcaps = glob.glob(os.path.join(pcap_dir, "*.pcap")) + glob.glob(os.path.join(pcap_dir, "*.pcapng"))
    if not pcaps:
        print(f"   ⚠️  No pcap files found in {pcap_dir}")
        return

    # 1. Start eBPF Loader (C-Daemon)
    # The output is redirected to the extraction CSV.
    with open(csv_output, 'w') as f:
        proc_loader = subprocess.Popen(["sudo", LOADER_BIN, "lo"], stdout=f, stderr=subprocess.DEVNULL)
    
    # Grace period for XDP program attachment and map initialization
    time.sleep(2)
    
    # 2. Start Hardware Resource Monitor
    monitor_script = "scripts/testbed/monitor.py"
    proc_mon = None
    if os.path.exists(monitor_script):
        proc_mon = subprocess.Popen(["python3", monitor_script, str(proc_loader.pid), metrics_csv])
    
    # 3. Traffic Injection Pipeline
    total_packets = 0
    start_time = time.time()
    
    for p in pcaps:
        print(f"   Streaming: {os.path.basename(p)}")
        # Universal streaming pipeline: 
        # tcpdump handles pcap/pcapng -> raw stream -> tcpreplay (top speed)
        cmd = f"sudo tcpdump -r {p} -w - 2>/dev/null | sudo tcpreplay -i lo -t -"
        try:
            # We capture stderr to parse 'Actual packets' while letting it flow to the terminal
            process = subprocess.Popen(cmd, shell=True, stderr=subprocess.PIPE, text=True)
            _, stderr_content = process.communicate()
            
            # Display tcpreplay statistics (PPS, Mbps) to the user
            print(stderr_content)
            
            packets = get_tcpreplay_stats(stderr_content)
            total_packets += packets
        except Exception as e:
            print(f"   ❌ ERROR during traffic injection: {e}")

    elapsed = time.time() - start_time
    pps = (total_packets / elapsed) if elapsed > 0 else 0

    # 4. Orderly Shutdown
    # First, terminate the monitor
    if proc_mon:
        os.kill(proc_mon.pid, signal.SIGTERM)
        proc_mon.wait()
    
    # Send SIGINT (Ctrl+C) to the loader.
    # The C code is programmed to catch this signal and dump its LRU_HASH maps to stdout.
    subprocess.run(["sudo", "kill", "-INT", str(proc_loader.pid)], check=False)
    proc_loader.wait()
    
    # Consolidate benchmark metadata
    summary = {
        "experiment": experiment_name,
        "packets_sent": total_packets,
        "time_seconds": elapsed,
        "pps": pps,
        "timestamp": time.ctime()
    }
    with open(os.path.join(output_dir, "summary.json"), 'w') as f:
        json.dump(summary, f, indent=4)
        
    print(f"✅ DONE: {total_packets} packets | {elapsed:.2f}s | {pps:.2f} pps")

def main():
    print("=== eBPFNetFlowLyzer Research Pipeline ===")
    
    # Sanity check for binary existence
    if not os.path.exists(LOADER_BIN):
        print(f"❌ Error: {LOADER_BIN} not found. Run 'make all' first.")
        return

    # Scan directories following research priority (IPv6 first)
    for category in EXPERIMENT_ORDER:
        category_path = os.path.join(DATA_RAW, category)
        if not os.path.exists(category_path):
            continue
            
        pcap_files = glob.glob(os.path.join(category_path, "**", "*.pcap*"), recursive=True)
        pcap_dirs = sorted(list(set(os.path.dirname(p) for p in pcap_files)))
        
        # Fallback if pcaps are in the category root
        if not pcap_dirs and (glob.glob(os.path.join(category_path, "*.pcap*"))):
             pcap_dirs = [category_path]

        for pcap_dir in pcap_dirs:
            process_pcap_dir(pcap_dir, category)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n⚠️  Interrupted by user. Cleaning up processes...")

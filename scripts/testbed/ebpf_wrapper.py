"""
eBPFNetFlowLyzer Research Orchestrator
--------------------------------------
This Python-based orchestrator manages the automated benchmarking lifecycle of the 
eBPF/XDP feature extractor. It bridges the gap between high-speed kernel-space 
interception and user-space data analysis.

Key Architectural Pillars:
1. Lifecycle Management: Synchronized orchestration of the C-native daemon (loader), 
   hardware resource monitoring (monitor.py), and deterministic traffic injection.
2. High-Fidelity Traffic Injection: Leverages a transparent tcpdump-to-tcpreplay 
   pipeline to ensure 100% compatibility with both PCAP and PCAPNG formats while 
   maintaining top-speed injection (O(1) streaming).
3. Deterministic Feature Offloading: Utilizes POSIX signals (SIGINT) to trigger 
   atomic Hash Map dumps from the C-daemon, ensuring zero data loss at shutdown.
4. Scientific Traceability: Generates structured metadata (JSON) for PPS, throughput, 
   and resource utilization metrics.

Research Context:
Developed as part of the Master's Degree in Applied Computing research, 
focused on Network Security for the Detection and Mitigation of DDoS attacks.
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
# Processing priority: IPv6 (PCAPv6) is the primary research validator
EXPERIMENT_ORDER = ["PCAPv6", "PCAP"]

def get_tcpreplay_stats(stderr_text):
    """
    Parses tcpreplay's stderr stream to extract the precise number of packets 
    successfully injected into the interface. This value is critical for 
    calculating the real Packets Per Second (PPS) and validating data integrity.
    """
    match = re.search(r"Actual: (\d+) packets", stderr_text)
    if match:
        return int(match.group(1))
    return 0

def process_pcap_dir(pcap_dir, category_tag):
    """
    Execution pipeline for a specific dataset subdirectory.
    1. Spawns the C-daemon (loader) attached to the 'lo' interface.
    2. Spawns the resource monitor (monitor.py) targeting the loader's PID.
    3. Injects PCAP/PCAPNG traffic via a high-throughput pipe.
    4. Triggers an orderly SIGINT shutdown to finalize the CSV feature matrix.
    """
    rel_path = os.path.relpath(pcap_dir, os.path.join(DATA_RAW, category_tag))
    experiment_name = category_tag if rel_path == "." else f"{category_tag}_{rel_path.replace(os.path.sep, '_')}"
    
    # Structured output paths following the extraction hierarchy
    output_dir = os.path.join(OUTPUT_BASE, category_tag, rel_path if rel_path != "." else "")
    os.makedirs(output_dir, exist_ok=True)
    
    csv_output = os.path.join(output_dir, f"extraction_{category_tag}.csv")
    metrics_csv = os.path.join(output_dir, "resource_metrics.csv")
    
    print(f"\n🚀 STARTING eBPF EXTRACTION: {experiment_name}")
    
    # Universal support for legacy and modern pcap formats
    pcaps = glob.glob(os.path.join(pcap_dir, "*.pcap")) + glob.glob(os.path.join(pcap_dir, "*.pcapng"))
    if not pcaps:
        print(f"   ⚠️  No pcap files found in {pcap_dir}")
        return

    # 1. Initialize eBPF Loader (Control Plane)
    # The extraction CSV is populated directly from the daemon's stdout dump.
    with open(csv_output, 'w') as f:
        proc_loader = subprocess.Popen(["sudo", LOADER_BIN, "lo"], stdout=f, stderr=subprocess.DEVNULL)
    
    # Mandatory grace period for XDP hook stabilization and BPF map allocation
    time.sleep(2)
    
    # 2. Spawn Resource Monitor
    monitor_script = "scripts/testbed/monitor.py"
    proc_mon = None
    if os.path.exists(monitor_script):
        proc_mon = subprocess.Popen(["python3", monitor_script, str(proc_loader.pid), metrics_csv])
    
    # 3. Traffic Ingestion (Data Plane stress)
    total_packets = 0
    start_time = time.time()
    
    for p in pcaps:
        print(f"   Streaming: {os.path.basename(p)}")
        # Transparent pipe: tcpdump (decoder) | tcpreplay (injector).
        # Ensures that pcapng files are correctly streamed to the 'lo' interface at top speed.
        cmd = f"sudo tcpdump -r {p} -w - 2>/dev/null | sudo tcpreplay -i lo -t -"
        try:
            # We use Popen and communicate() to capture stats while allowing terminal output
            process = subprocess.Popen(cmd, shell=True, stderr=subprocess.PIPE, text=True)
            _, stderr_content = process.communicate()
            
            # Print tcpreplay injection report (Rated PPS, Mbps)
            print(stderr_content)
            
            packets = get_tcpreplay_stats(stderr_content)
            total_packets += packets
        except Exception as e:
            print(f"   ❌ ERROR during traffic injection: {e}")

    elapsed = time.time() - start_time
    pps = (total_packets / elapsed) if elapsed > 0 else 0

    # 4. Graceful Shutdown & Map Dump
    # First, terminate the monitor to capture the final resource snapshot
    if proc_mon:
        os.kill(proc_mon.pid, signal.SIGTERM)
        proc_mon.wait()
    
    # Trigger SIGINT in the loader. 
    # This is a critical research requirement to ensure all flows in the LRU_HASH maps 
    # are flushed to the CSV file before process exit.
    subprocess.run(["sudo", "kill", "-INT", str(proc_loader.pid)], check=False)
    proc_loader.wait()
    
    # Consolidate benchmark metadata for scientific reproducibility
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
    
    # Binary existence check before initiating resource-heavy tasks
    if not os.path.exists(LOADER_BIN):
        print(f"❌ Error: {LOADER_BIN} not found. Run 'make all' first.")
        return

    # Process datasets following academic prioritization (IPv6 -> IPv4)
    for category in EXPERIMENT_ORDER:
        category_path = os.path.join(DATA_RAW, category)
        if not os.path.exists(category_path):
            continue
            
        pcap_files = glob.glob(os.path.join(category_path, "**", "*.pcap*"), recursive=True)
        pcap_dirs = sorted(list(set(os.path.dirname(p) for p in pcap_files)))
        
        # Root fallback for flat dataset structures
        if not pcap_dirs and (glob.glob(os.path.join(category_path, "*.pcap*"))):
             pcap_dirs = [category_path]

        for pcap_dir in pcap_dirs:
            process_pcap_dir(pcap_dir, category)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n⚠️  Execution interrupted by user. Cleaning up background processes...")

import os
import re
import subprocess
import time
import json
import signal
import glob

# --- CONFIGURATION ---
# Base directory for datasets (relative to project root)
DATA_RAW = "data/raw"
# Base directory for output
OUTPUT_BASE = "data/interim/EBPF_RAW"
# Path to the compiled loader
LOADER_BIN = "./build/loader"
# Priority order for scanning (explicitly list the categories)
EXPERIMENT_ORDER = ["PCAPv6", "PCAP"]

def get_tcpreplay_stats(output):
    """Extracts the real packet count from tcpreplay output."""
    match = re.search(r"Actual: (\d+) packets", output)
    if match:
        return int(match.group(1))
    return 0

def process_pcap_dir(pcap_dir, category_tag):
    """Runs the eBPF extraction for all PCAP/PCAPNG files in a directory."""
    # Clean up the name for the experiment
    rel_path = os.path.relpath(pcap_dir, os.path.join(DATA_RAW, category_tag))
    if rel_path == ".":
        experiment_name = category_tag
    else:
        experiment_name = f"{category_tag}_{rel_path.replace(os.path.sep, '_')}"
    
    output_dir = os.path.join(OUTPUT_BASE, category_tag, rel_path if rel_path != "." else "")
    os.makedirs(output_dir, exist_ok=True)
    
    csv_output = os.path.join(output_dir, f"extraction_{category_tag}.csv")
    metrics_csv = os.path.join(output_dir, "resource_metrics.csv")
    
    print(f"\n🚀 STARTING eBPF EXTRACTION: {experiment_name}")
    
    pcaps = glob.glob(os.path.join(pcap_dir, "*.pcap")) + glob.glob(os.path.join(pcap_dir, "*.pcapng"))
    if not pcaps:
        print(f"   ⚠️  No pcap files found in {pcap_dir}")
        return

    # 1. Start the eBPF Loader
    with open(csv_output, 'w') as f:
        proc_loader = subprocess.Popen(["sudo", LOADER_BIN, "lo"], stdout=f, stderr=subprocess.DEVNULL)
    
    time.sleep(2)
    
    # 2. Start the Resource Monitor
    monitor_script = "scripts/testbed/monitor.py"
    proc_mon = None
    if os.path.exists(monitor_script):
        proc_mon = subprocess.Popen(["python3", monitor_script, str(proc_loader.pid), metrics_csv])
    
    # 3. Inject Traffic
    total_packets = 0
    start_time = time.time()
    
    for p in pcaps:
        print(f"   Streaming: {os.path.basename(p)}")
        # Remove 2>/dev/null to allow capturing the output
        cmd = f"sudo tcpdump -r {p} -w - 2>/dev/null | sudo tcpreplay -i lo -t -"
        try:
            # Capture stderr because tcpreplay writes stats there
            res = subprocess.run(cmd, shell=True, capture_output=True, text=True, check=True)
            packets = get_tcpreplay_stats(res.stderr)
            total_packets += packets
            print(f"   -> {packets} packets injected.")
        except subprocess.CalledProcessError as e:
            print(f"   ❌ ERROR during injection of {p}: {e.stderr}")

    elapsed = time.time() - start_time
    pps = (total_packets / elapsed) if elapsed > 0 else 0

    # 4. Graceful Shutdown
    if proc_mon:
        os.kill(proc_mon.pid, signal.SIGTERM)
        proc_mon.wait()
    
    # Send SIGINT to loader to trigger map dump
    subprocess.run(["sudo", "kill", "-INT", str(proc_loader.pid)], check=False)
    proc_loader.wait()
    
    # Save metadata
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
    
    if not os.path.exists(LOADER_BIN):
        print(f"❌ Error: {LOADER_BIN} not found. Run 'make all' first.")
        return

    for category in EXPERIMENT_ORDER:
        category_path = os.path.join(DATA_RAW, category)
        if not os.path.exists(category_path):
            continue
            
        print(f"\n📂 Scanning Category: {category}")
        
        # Find all subdirectories containing pcaps, or the category root itself
        pcap_files = glob.glob(os.path.join(category_path, "**", "*.pcap*"), recursive=True)
        pcap_dirs = sorted(list(set(os.path.dirname(p) for p in pcap_files)))
        
        if not pcap_dirs and (glob.glob(os.path.join(category_path, "*.pcap*"))):
             pcap_dirs = [category_path]

        for pcap_dir in pcap_dirs:
            process_pcap_dir(pcap_dir, category)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠️  Interrupted. Cleaning up...")

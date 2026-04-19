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
DATA_RAW = "data/raw"
OUTPUT_BASE = "data/interim/EBPF_RAW"
LOADER_BIN = "./build/loader"
EXPERIMENT_ORDER = ["PCAPv6", "PCAP"]

def get_tcpreplay_stats(text):
    """
    Parses tcpreplay output to extract the precise number of packets injected.
    Works on both stdout and stderr since tcpreplay behavior varies across versions.
    """
    if not text:
        return 0
    # Match "Actual: 33547574 packets" or similar with flexible whitespace
    match = re.search(r"Actual:\s*(\d+)\s*packets", text)
    if match:
        return int(match.group(1))
    
    # Fallback: look for "Successful packets: 33547574"
    match = re.search(r"Successful packets:\s*(\d+)", text)
    if match:
        return int(match.group(1))
        
    return 0

def process_pcap_dir(pcap_dir, category_tag):
    rel_path = os.path.relpath(pcap_dir, os.path.join(DATA_RAW, category_tag))
    experiment_name = category_tag if rel_path == "." else f"{category_tag}_{rel_path.replace(os.path.sep, '_')}"
    
    output_dir = os.path.join(OUTPUT_BASE, category_tag, rel_path if rel_path != "." else "")
    os.makedirs(output_dir, exist_ok=True)
    
    csv_output = os.path.join(output_dir, f"extraction_{category_tag}.csv")
    metrics_csv = os.path.join(output_dir, "resource_metrics.csv")
    
    print(f"\n🚀 STARTING eBPF EXTRACTION: {experiment_name}")
    
    pcaps = glob.glob(os.path.join(pcap_dir, "*.pcap")) + glob.glob(os.path.join(pcap_dir, "*.pcapng"))
    if not pcaps:
        print(f"   ⚠️  No pcap files found in {pcap_dir}")
        return

    # 0. Setup VETH Topology (Ensures XDP visibility for replayed traffic)
    print("   🔧 Resetting VETH topology (veth0 <-> veth1)")
    subprocess.run(["sudo", "ip", "link", "delete", "veth0"], check=False, stderr=subprocess.DEVNULL)
    subprocess.run(["sudo", "ip", "link", "add", "veth0", "type", "veth", "peer", "name", "veth1"], check=True)
    subprocess.run(["sudo", "ip", "link", "set", "veth0", "up"], check=True)
    subprocess.run(["sudo", "ip", "link", "set", "veth1", "up"], check=True)
    # Ensure IPv6 is enabled to support ICMPv6 and Milestone 3 metrics
    subprocess.run(["sudo", "sysctl", "-w", "net.ipv6.conf.veth0.disable_ipv6=0"], check=False)
    subprocess.run(["sudo", "sysctl", "-w", "net.ipv6.conf.veth1.disable_ipv6=0"], check=False)
    # Enable forwarding to ensure packet flow between veth pair
    subprocess.run(["sudo", "sysctl", "-w", "net.ipv6.conf.all.forwarding=1"], check=False)

    try:
        # 1. Start eBPF Loader on veth1 with real-time log streaming
        loader_log_path = os.path.join(output_dir, "loader_stderr.log")
        
        with open(csv_output, 'w') as f_out:
            proc_loader = subprocess.Popen(
                ["sudo", LOADER_BIN, "veth1"], 
                stdout=f_out, 
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1
            )
            
            # Helper to stream loader logs to both file and console
            def stream_logs(proc, log_file_path):
                with open(log_file_path, 'w') as f_log:
                    for line in iter(proc.stderr.readline, ""):
                        if not line: break
                        f_log.write(line)
                        f_log.flush()
                        # Only print important lines (Stats, Errors, System messages) to console
                        if any(x in line for x in ["📊", "⚠️", "❌", "System", "Error", "Fatal", "└─", "[Diagnostic]", "[Parser Errors]", "-"]):
                            print(f"   [Loader] {line.strip()}")
            
            import threading
            log_thread = threading.Thread(target=stream_logs, args=(proc_loader, loader_log_path), daemon=True)
            log_thread.start()
            
            time.sleep(2)
            
            # 2. Spawn Resource Monitor
            monitor_script = "scripts/testbed/monitor.py"
            proc_mon = None
            if os.path.exists(monitor_script):
                proc_mon = subprocess.Popen(["python3", monitor_script, str(proc_loader.pid), metrics_csv])
            
            # 3. Traffic Injection on veth0
            total_packets = 0
            start_time = time.time()
            
            for p in pcaps:
                print(f"   Streaming: {os.path.basename(p)}")
                cmd = f"sudo tcpreplay -i veth0 -t {p} 2>&1"
                try:
                    res = subprocess.run(cmd, shell=True, capture_output=True, text=True, check=True)
                    output_content = res.stdout
                    print(output_content)
                    packets = get_tcpreplay_stats(output_content)
                    total_packets += packets
                except Exception as e:
                    print(f"   ❌ ERROR during traffic injection: {e}")

            elapsed = time.time() - start_time
            pps = (total_packets / elapsed) if elapsed > 0 else 0

            # 4. Shutdown
            if proc_mon:
                os.kill(proc_mon.pid, signal.SIGTERM)
                proc_mon.wait()
            
            subprocess.run(["sudo", "kill", "-INT", str(proc_loader.pid)], check=False)
            proc_loader.wait()
            log_thread.join(timeout=2)
    finally:
        print("   🧹 Cleaning up VETH topology")
        subprocess.run(["sudo", "ip", "link", "delete", "veth0"], check=False)
    
    summary = {
        "experiment": experiment_name, "packets_sent": total_packets,
        "time_seconds": elapsed, "pps": pps, "timestamp": time.ctime()
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

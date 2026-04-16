import os
import glob
import subprocess
import json
import time

"""
eBPFNetFlowLyzer Orchestrator (C-Native Benchmark Wrapper)
Replaces NTLFlowLyzer chunking strategy with direct O(1) ingestion via tcpreplay.
Calculates hardware-metrics synchronously with monitor.py.
"""

# --- CONFIGURATION ---
INPUT_DIR = "./data/raw/PCAP"
OUTPUT_DIR = "./data/interim/EBPF_RAW"

def get_packet_count(pcap_files):
    import struct
    PCAP_MAGIC_LE, PCAP_MAGIC_BE = b'\xd4\xc3\xb2\xa1', b'\xa1\xb2\xc3\xd4'
    total = 0
    for pcap in pcap_files:
        try:
            with open(pcap, 'rb') as f:
                magic = f.read(4)
                if magic not in (PCAP_MAGIC_LE, PCAP_MAGIC_BE): continue
                little_endian = (magic == PCAP_MAGIC_LE)
                f.read(20)
                count = 0
                while True:
                    hdr = f.read(16)
                    if len(hdr) < 16: break
                    endian = '<' if little_endian else '>'
                    incl_len = struct.unpack(endian + 'I', hdr[8:12])[0]
                    f.seek(incl_len, 1)
                    count += 1
                total += count
        except Exception: pass
    return total

def run_cmd(cmd):
    subprocess.run(cmd, shell=True, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)

def process_attack(input_pcap_dir, output_csv_dir, attack_name):
    final_csv = os.path.join(output_csv_dir, f"{attack_name}.csv")
    work_dir = os.path.join(output_csv_dir, f"temp_{attack_name}")
    
    print(f"\n🚀 STARTING eBPF EXTRACTION: {attack_name}...")
    os.makedirs(work_dir, exist_ok=True)
    os.makedirs(output_csv_dir, exist_ok=True)

    pcaps = glob.glob(os.path.join(input_pcap_dir, "*.pcap"))
    if not pcaps: return
    total_packets = get_packet_count(pcaps)

    # 2. Invoke eBPF Loader on loopback and hook the Monitor
    loader_cmd = ["sudo", "./build/loader", "lo"]
    with open(final_csv, 'w') as csv_out:
        loader_proc = subprocess.Popen(loader_cmd, stdout=csv_out, stderr=subprocess.DEVNULL)
    
    # Let XDP attach properly
    time.sleep(1)

    monitor_csv = os.path.join(output_csv_dir, f"monitor_{attack_name}.csv")
    monitor_script = os.path.join(os.path.dirname(os.path.abspath(__file__)), "monitor.py")
    import sys
    monitor_proc = subprocess.Popen([sys.executable, monitor_script, str(loader_proc.pid), monitor_csv])

    # 3. Stream data via Hardware (tcpreplay sequentially sends raw to Interface loopback)
    print(f"   Streaming {total_packets} packets sequentially via tcpreplay directly to BPF Map (Top-Speed)...")
    start_time = time.time()
    
    for p in pcaps:
        try:
            subprocess.run(["sudo", "tcpreplay", "-i", "lo", "-t", p], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except subprocess.CalledProcessError:
            pass

    end_time = time.time()
    elapsed = end_time - start_time
    pps = total_packets / elapsed if elapsed > 0 else 0

    # 4. Clean shutdown
    monitor_proc.terminate()
    try: monitor_proc.wait(timeout=2)
    except: monitor_proc.kill()
    
    # We must kill the daemon specifically via sudo since we started it as root
    subprocess.run(["sudo", "kill", "-INT", str(loader_proc.pid)], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    
    benchmark_log = os.path.join(output_csv_dir, f"benchmark_{attack_name}.json")
    with open(benchmark_log, 'w') as f:
        json.dump({
            "attack": attack_name, "tool": "eBPFNetFlowLyzer_C",
            "total_packets": total_packets, "time_seconds": elapsed, 
            "pps": pps, "monitor_file": monitor_csv
        }, f, indent=4)

    print(f"✅ DONE: {total_packets} packets | {elapsed:.2f}s | {pps:.2f} pps")

def run_extraction():
    print(f"=== eBPFNetFlowLyzer Pipeline ===")
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    pcap_dirs = set(os.path.dirname(p) for p in glob.glob(os.path.join(INPUT_DIR, "**", "*.pcap"), recursive=True))
    for pcap_dir in sorted(pcap_dirs):
        rel_path = os.path.relpath(pcap_dir, INPUT_DIR)
        process_attack(pcap_dir, os.path.join(OUTPUT_DIR, rel_path), rel_path.replace(os.path.sep, "_"))

if __name__ == "__main__":
    run_extraction()

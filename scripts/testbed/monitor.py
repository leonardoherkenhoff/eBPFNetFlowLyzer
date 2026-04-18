"""
Hardware Resource Monitor for eBPFNetFlowLyzer
----------------------------------------------
This script performs high-frequency sampling of CPU and Memory (RAM) utilization
during the network feature extraction benchmarks.

Research Goals:
1. Overhead Quantification: Measure the computational cost of the C-daemon 
   and the eBPF Data Plane.
2. Stability Validation: Monitor RAM usage over time to ensure no leaks 
   occur in the User-Space flow table (LRU policy validation).
3. Scalability metrics: Provide raw data (CSV) for plotting PPS vs. CPU usage.

Sampling Logic:
- Uses psutil to poll the target PID and its child processes recursively.
- Normalizes CPU usage across all cores (0-100% scale).
- Aggregates RSS (Resident Set Size) for accurate memory footprint measurement.

Developed as part of the Master's Degree in Applied Computing research.
"""

import time
import psutil
import csv
import argparse
import sys
import signal

def monitor_process(pid, output_csv, interval=1.0):
    """
    Monitors hardware metrics for a specific PID and its subtree.
    
    Args:
        pid (int): Target process ID (usually the C-loader).
        output_csv (str): Destination for the raw time-series metrics.
        interval (float): Sampling frequency in seconds (default 1.0s).
    """
    def signal_handler(signum, frame):
        print(f"\n📢 Resource Monitor: Received signal {signum}. Finalizing snapshots...")
        sys.exit(0)

    # Handle graceful termination from the orchestrator (ebpf_wrapper.py)
    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)

    try:
        parent = psutil.Process(pid)
    except psutil.NoSuchProcess:
        print(f"❌ Error: Target PID {pid} not found. Monitor exiting.")
        sys.exit(1)

    try:
        cmdline = ' '.join(parent.cmdline()[:2])
        print(f"🔍 Monitoring PID {pid} (Command: {cmdline})...")
    except Exception:
        print(f"🔍 Monitoring PID {pid} (Process state: Transient)...")
    
    metrics = []
    # Cache for child process objects to reduce syscall overhead
    proc_cache = {} 
    
    try:
        with open(output_csv, 'w', newline='') as csvfile:
            fieldnames = ['timestamp', 'cpu_percent', 'ram_mb']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()

            # Initialize psutil CPU baseline (first call is discarded by library design)
            psutil.cpu_percent(interval=None)
            try:
                proc_cache[parent.pid] = parent
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

            while True:
                try:
                    # Check if the process is still viable
                    if not parent.is_running() or parent.status() == psutil.STATUS_ZOMBIE: 
                        break
                except Exception:
                    break
                
                time.sleep(interval)

                # Capture System-wide normalized CPU impact
                total_cpu = psutil.cpu_percent(interval=None)

                # Identify and aggregate memory usage for the entire process tree
                try:
                    current_children = parent.children(recursive=True)
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    break

                for p in current_children:
                    if p.pid not in proc_cache:
                        proc_cache[p.pid] = p

                total_ram_mb = 0.0
                dead_pids = []
                for pid_key, p in proc_cache.items():
                    try:
                        # Memory RSS conversion: Bytes -> MB
                        total_ram_mb += p.memory_info().rss / (1024 * 1024)
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        dead_pids.append(pid_key)
                
                # Prune cache to keep polling performance O(n_processes)
                for pid_key in dead_pids:
                    del proc_cache[pid_key]

                row = {
                    'timestamp': time.time(),
                    'cpu_percent': round(total_cpu, 2),
                    'ram_mb': round(total_ram_mb, 2)
                }
                writer.writerow(row)
                csvfile.flush() # Ensure durability for long experiments
                metrics.append(row)
                
    except KeyboardInterrupt:
        print("\n🛑 Resource Monitor: Interrupted by user.")
    finally:
        if not metrics:
            print("⚠️ Monitor: No metrics were collected before shutdown.")
            return

        # Statistical summary calculation for dissertation tables
        max_cpu = max(m['cpu_percent'] for m in metrics)
        avg_cpu = sum(m['cpu_percent'] for m in metrics) / len(metrics)
        max_ram = max(m['ram_mb'] for m in metrics)
        avg_ram = sum(m['ram_mb'] for m in metrics) / len(metrics)
        
        print("\n" + "="*40)
        print("📊 MONITORING SUMMARY")
        print("="*40)
        print(f"Max CPU Usage: {max_cpu:>6}%")
        print(f"Avg CPU Usage: {avg_cpu:>6.2f}%")
        print(f"Max RAM Usage: {max_ram:>6} MB")
        print(f"Avg RAM Usage: {avg_ram:>6.2f} MB")
        print(f"Data saved to: {output_csv}")
        print("="*40)

        # Persistence of summary metrics for automated parsing
        summary_file = output_csv.replace('.csv', '_summary.txt')
        with open(summary_file, 'w') as f:
            f.write(f"Max_CPU_Percent={max_cpu}\n")
            f.write(f"Avg_CPU_Percent={avg_cpu:.2f}\n")
            f.write(f"Max_RAM_MB={max_ram}\n")
            f.write(f"Avg_RAM_MB={avg_ram:.2f}\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="eBPFNetFlowLyzer Resource Monitor")
    parser.add_argument("pid", type=int, help="Target PID (C-daemon)")
    parser.add_argument("output", type=str, help="Output CSV path")
    parser.add_argument("--interval", type=float, default=1.0, help="Sampling interval (sec)")
    
    args = parser.parse_args()
    monitor_process(args.pid, args.output, args.interval)

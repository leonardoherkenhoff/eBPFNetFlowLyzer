import time
import psutil
import csv
import argparse
import sys
import signal

def monitor_process(pid, output_csv, interval=1.0):
    """
    Monitors CPU and Memory usage of a process and its children.
    Saves the data and reports the max/avg usage.
    """
    def signal_handler(signum, frame):
        print(f"\n📢 Received signal {signum}. Finalizing monitoring...")
        sys.exit(0)

    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)

    try:
        parent = psutil.Process(pid)
    except psutil.NoSuchProcess:
        print(f"❌ Process {pid} not found.")
        sys.exit(1)

    try:
        cmdline = ' '.join(parent.cmdline()[:2])
        print(f"🔍 Monitoring PID {pid} (Command: {cmdline})...")
    except Exception:
        print(f"🔍 Monitoring PID {pid} (Terminating / Zombie)...")
    
    metrics = []
    proc_cache = {}  # {pid: psutil.Process} — used for per-process RAM tracking
    
    try:
        with open(output_csv, 'w', newline='') as csvfile:
            fieldnames = ['timestamp', 'cpu_percent', 'ram_mb']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()

            # Seed system-wide cpu_percent baseline (first call always returns 0.0)
            psutil.cpu_percent(interval=None)
            try:
                proc_cache[parent.pid] = parent
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

            while True:
                try:
                    if not parent.is_running() or parent.status() == psutil.STATUS_ZOMBIE: break
                except Exception:
                    break
                time.sleep(interval)

                # System-wide CPU: already normalized to 0-100% on any core count
                total_cpu = psutil.cpu_percent(interval=None)

                # Per-process RAM: discover children and sum RSS
                try:
                    current_children = parent.children(recursive=True)
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    break

                for p in current_children:
                    if p.pid not in proc_cache:
                        proc_cache[p.pid] = p

                total_ram_mb = 0.0
                dead_pids = []
                for pid, p in proc_cache.items():
                    try:
                        total_ram_mb += p.memory_info().rss / (1024 * 1024)
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        dead_pids.append(pid)
                for pid in dead_pids:
                    del proc_cache[pid]

                row = {
                    'timestamp': time.time(),
                    'cpu_percent': round(total_cpu, 2),
                    'ram_mb': round(total_ram_mb, 2)
                }
                writer.writerow(row)
                csvfile.flush()
                metrics.append(row)
                
    except KeyboardInterrupt:
        print("\n🛑 Monitoring interrupted.")
    finally:
        if not metrics:
            print("⚠️ No metrics collected.")
            return

        max_cpu = max(m['cpu_percent'] for m in metrics)
        avg_cpu = sum(m['cpu_percent'] for m in metrics) / len(metrics)
        max_ram = max(m['ram_mb'] for m in metrics)
        avg_ram = sum(m['ram_mb'] for m in metrics) / len(metrics)
        
        print("\n📊 --- Monitoring Summary ---")
        print(f"Max CPU Usage: {max_cpu}%")
        print(f"Avg CPU Usage: {avg_cpu:.2f}%")
        print(f"Max RAM Usage: {max_ram} MB")
        print(f"Avg RAM Usage: {avg_ram:.2f} MB")
        print(f"Data saved to {output_csv}")

        # Summary file beside CSV
        summary_file = output_csv.replace('.csv', '_summary.txt')
        with open(summary_file, 'w') as f:
            f.write(f"Max_CPU_Percent={max_cpu}\n")
            f.write(f"Avg_CPU_Percent={avg_cpu:.2f}\n")
            f.write(f"Max_RAM_MB={max_ram}\n")
            f.write(f"Avg_RAM_MB={avg_ram:.2f}\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Monitor process CPU/RAM over time")
    parser.add_argument("pid", type=int, help="PID of the process to monitor")
    parser.add_argument("output", type=str, help="Output CSV file path")
    parser.add_argument("--interval", type=float, default=1.0, help="Monitoring interval in seconds")
    
    args = parser.parse_args()
    monitor_process(args.pid, args.output, args.interval)

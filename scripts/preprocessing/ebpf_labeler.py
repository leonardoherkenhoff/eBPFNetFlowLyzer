import pandas as pd
import numpy as np
import os
import glob

"""
eBPFNetFlowLyzer Topological Labeler
Applies Ground Truth based entirely on the attacker's Source IP.
NOTE: eBPF outputs IP addresses as Little-Endian unsigned 32-bit integers!
Topological Rule: 172.16.0.5 -> 83890348
"""

INPUT_DIR = "./data/interim/EBPF_RAW"
OUTPUT_DIR = "./data/processed/EBPF"
ATTACKER_IP_INT = 83890348
CHUNK_SIZE = 500_000 

def process_file_auto(file_path):
    try:
        filename = os.path.basename(file_path)
        attack_name = os.path.basename(os.path.dirname(file_path))
        rel_path = os.path.relpath(os.path.dirname(file_path), INPUT_DIR)
        output_dir = os.path.join(OUTPUT_DIR, rel_path)
        os.makedirs(output_dir, exist_ok=True)
        
        output_file = os.path.join(output_dir, f"{attack_name}.csv")
        if os.path.exists(output_file): os.remove(output_file)
        
        first = True
        reader = pd.read_csv(file_path, chunksize=CHUNK_SIZE, low_memory=False)
        for chunk in reader:
            data = chunk.copy()
            # Apply rule: Flow originates from attacker gateway = Attack
            src_ips = data['src_ip']
            labels = np.where(src_ips == ATTACKER_IP_INT, attack_name, 'BENIGN')
            data['Label'] = labels
            
            data.to_csv(output_file, mode='a', header=first, index=False)
            first = False
        return True
    except Exception as e:
        print(f"Error on {file_path}: {e}")
        return False

def main():
    print("=== eBPFNetFlowLyzer Topological Labeling ===")
    files = glob.glob(os.path.join(INPUT_DIR, "**", "*.csv"), recursive=True)
    for f in files:
        if os.path.basename(f).startswith("monitor_"): continue
        if process_file_auto(f):
            print(f"    ✅ Labeled: {os.path.basename(f)}")

if __name__ == "__main__":
    main()

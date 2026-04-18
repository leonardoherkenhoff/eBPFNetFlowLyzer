"""
eBPFNetFlowLyzer Topological Labeler
-----------------------------------
This script performs post-processing on the extracted network features by applying 
Ground Truth labels based on the network topology of the testbed.

Labeling Logic:
- Topological Attribution: Identifies flows as 'ATTACK' or 'BENIGN' based on 
  the source IP address of the attacker nodes in the research testbed.
- Supervised Learning Readiness: Produces the final dataset required for 
  training and evaluating Machine Learning models (e.g., Random Forest, SVM).

Implementation Details:
- Memory Efficiency: Uses pandas chunking (CHUNK_SIZE) to handle large 
  extraction files (5GB+) without exceeding RAM limits.
- Hierarchical Output: Maintains the same directory structure as the 
  extraction phase for easier dataset management.

Developed as part of the Master's Degree in Applied Computing research.
"""

import pandas as pd
import numpy as np
import os
import glob

# --- CONFIGURATION ---
INPUT_DIR = "./data/interim/EBPF_RAW"
OUTPUT_DIR = "./data/processed/EBPF"
# Target Attacker IPs (Support for both IPv4 and IPv6)
# Update these based on your specific testbed topology
ATTACKER_IPS = ["172.16.0.5", "2001:db8:acad:10::5", "fe80::215:5dff:fe00:5"] 
CHUNK_SIZE = 500_000 

def process_file_auto(file_path):
    """
    Applies the labeling rule to a single CSV file.
    """
    try:
        filename = os.path.basename(file_path)
        attack_category = os.path.basename(os.path.dirname(file_path))
        
        rel_path = os.path.relpath(os.path.dirname(file_path), INPUT_DIR)
        output_dir = os.path.join(OUTPUT_DIR, rel_path)
        os.makedirs(output_dir, exist_ok=True)
        
        output_file = os.path.join(output_dir, f"labeled_{attack_category}.csv")
        
        if os.path.exists(output_file): 
            os.remove(output_file)
        
        first_chunk = True
        reader = pd.read_csv(file_path, chunksize=CHUNK_SIZE, low_memory=False)
        
        total_attack = 0
        total_benign = 0
        unique_ips = set()

        for chunk in reader:
            data = chunk.copy()
            
            # Record unique IPs for debugging if needed
            if len(unique_ips) < 20:
                unique_ips.update(data['src_ip'].unique()[:20])

            # Labeling Logic:
            # Matches against the list of known attacker IPs
            src_ips = data['src_ip'].astype(str)
            is_attack = src_ips.isin(ATTACKER_IPS)
            
            labels = np.where(is_attack, attack_category, 'BENIGN')
            data['Label'] = labels
            
            total_attack += np.sum(is_attack)
            total_benign += np.sum(~is_attack)
            
            data.to_csv(output_file, mode='a', header=first_chunk, index=False)
            first_chunk = False
            
        print(f"    ✅ Created: {os.path.basename(output_file)}")
        print(f"       -> Attack: {total_attack} | Benign: {total_benign}")
        if total_attack == 0:
            print(f"       ⚠️  WARNING: Zero attack flows found. Check ATTACKER_IPS.")
            print(f"       Sample IPs found: {list(unique_ips)[:5]}")

        return True
    except Exception as e:
        print(f"   ❌ Error processing {file_path}: {e}")
        return False

def main():
    print("=== eBPFNetFlowLyzer Research Pre-processing (Labeling) ===")
    files = glob.glob(os.path.join(INPUT_DIR, "**", "*.csv"), recursive=True)
    
    if not files:
        print(f"⚠️  No extraction results found in {INPUT_DIR}.")
        return

    for f in files:
        if os.path.basename(f).startswith("resource_metrics"): continue
        process_file_auto(f)

if __name__ == "__main__":
    main()

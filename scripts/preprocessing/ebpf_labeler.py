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
# Base directory for the raw eBPF extraction results
INPUT_DIR = "./data/interim/EBPF_RAW"
# Destination for the final labeled datasets
OUTPUT_DIR = "./data/processed/EBPF"
# Target Attacker Gateway IP (Used for topological labeling)
# In this environment, any flow originating from this IP is labeled as the attack.
ATTACKER_IP = "172.16.0.5" 
# Processing chunk size (adjust based on hardware RAM limits)
CHUNK_SIZE = 500_000 

def process_file_auto(file_path):
    """
    Applies the labeling rule to a single CSV file.
    """
    try:
        filename = os.path.basename(file_path)
        # Identify the attack category from the parent directory name
        attack_category = os.path.basename(os.path.dirname(file_path))
        
        # Determine the relative output path
        rel_path = os.path.relpath(os.path.dirname(file_path), INPUT_DIR)
        output_dir = os.path.join(OUTPUT_DIR, rel_path)
        os.makedirs(output_dir, exist_ok=True)
        
        output_file = os.path.join(output_dir, f"labeled_{attack_category}.csv")
        
        # Cleanup existing output to prevent appending to stale data
        if os.path.exists(output_file): 
            os.remove(output_file)
        
        first_chunk = True
        # Chunked reader for massive dataset handling
        reader = pd.read_csv(file_path, chunksize=CHUNK_SIZE, low_memory=False)
        
        for chunk in reader:
            data = chunk.copy()
            
            # Labeling Logic:
            # If src_ip matches the known Attacker Gateway, label it with the attack type.
            # Otherwise, label it as BENIGN.
            src_ips = data['src_ip']
            labels = np.where(src_ips == ATTACKER_IP, attack_category, 'BENIGN')
            data['Label'] = labels
            
            # Persistent append to the final labeled CSV
            data.to_csv(output_file, mode='a', header=first_chunk, index=False)
            first_chunk = False
            
        return True
    except Exception as e:
        print(f"   ❌ Error processing {file_path}: {e}")
        return False

def main():
    print("=== eBPFNetFlowLyzer Research Pre-processing (Labeling) ===")
    
    # Discovery of all CSV files in the interim extraction folder
    files = glob.glob(os.path.join(INPUT_DIR, "**", "*.csv"), recursive=True)
    
    if not files:
        print(f"⚠️  No extraction results found in {INPUT_DIR}. Run benchmarks first.")
        return

    for f in files:
        # Skip resource monitor files during feature labeling
        if os.path.basename(f).startswith("resource_metrics"): 
            continue
            
        if process_file_auto(f):
            print(f"    ✅ Labeled Dataset Created: {os.path.basename(f)}")

if __name__ == "__main__":
    main()

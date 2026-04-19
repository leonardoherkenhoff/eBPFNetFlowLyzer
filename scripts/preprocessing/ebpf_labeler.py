#!/usr/bin/env python3
"""
ebpf_labeler.py - Lynceus Research Pipeline - Dataset Labeling Utility (v2.0-Research)
---------------------------------------------------------------------------
v2.0-Research Stable Milestone:
- Context: Post-extraction labeling for Lynceus telemetry.
- Feature: Atomic category-based labeling and recursive discovery.
- Multi-Worker Aggregation: Handles partitioned worker CSVs natively.
- Automated Data Purge: Post-labeling cleanup to maintain partition integrity.
"""

import pandas as pd
import numpy as np
import os
import glob
import argparse
import shutil

# --- Research Configuration ---
# IMPORTANT: Adjust ATTACKER_IPS to match the production server topology
BASE_DIR = "/opt/eBPFNetFlowLyzer"
INPUT_DIR = os.path.join(BASE_DIR, "data/interim/EBPF_RAW")
OUTPUT_DIR = os.path.join(BASE_DIR, "data/processed/EBPF")

ATTACKER_IPS = ["172.16.0.5", "2001:db8:acad:10::5", "fe80::215:5dff:fe00:5"] 
CHUNK_SIZE = 500000 

def process_file_auto(file_path):
    """
    Applies the topological labeling rule to a single extraction result.
    """
    try:
        # Category is the first directory component after INPUT_DIR
        rel_from_input = os.path.relpath(file_path, INPUT_DIR)
        category = rel_from_input.split(os.sep)[0]
        
        rel_path = os.path.relpath(os.path.dirname(file_path), INPUT_DIR)
        output_folder = os.path.join(OUTPUT_DIR, rel_path)
        os.makedirs(output_folder, exist_ok=True)
        
        # If it's a worker file, we append to a single category file in 'processed'
        output_file = os.path.join(output_folder, f"labeled_{category}.csv")
        
        first_chunk = not os.path.exists(output_file)
        reader = pd.read_csv(file_path, chunksize=CHUNK_SIZE, low_memory=False)
        
        total_attack = 0
        total_benign = 0

        for chunk in reader:
            data = chunk.copy()
            if 'src_ip' in data.columns:
                src_ips = data['src_ip'].astype(str)
                is_attack = src_ips.isin(ATTACKER_IPS)
                data['Label'] = np.where(is_attack, category, 'BENIGN')
                total_attack += np.sum(is_attack)
                total_benign += np.sum(~is_attack)
            
            data.to_csv(output_file, mode='a', header=first_chunk, index=False)
            first_chunk = False
            
        return True, total_attack, total_benign
    except Exception as e:
        print(f"   ❌ Error processing {file_path}: {e}")
        return False, 0, 0

def main():
    parser = argparse.ArgumentParser(description="eBPFNetFlowLyzer Labeler v2.0-Research")
    parser.add_argument("--path", type=str, help="Specific interim directory to label")
    parser.add_argument("--cleanup", action="store_true", help="Delete interim files after labeling")
    args = parser.parse_args()

    print("=== eBPFNetFlowLyzer Research Pre-processing (Ground Truth Attribution) ===")
    
    if args.path:
        target_dir = os.path.abspath(args.path)
        files = glob.glob(os.path.join(target_dir, "*.csv"))
    else:
        files = glob.glob(os.path.join(INPUT_DIR, "**", "*.csv"), recursive=True)
    
    files = [f for f in files if not os.path.basename(f).startswith("resource_metrics")]

    if not files:
        print(f"⚠️  No extraction results found.")
        return

    processed_count = 0
    for f in files:
        success, atk, bng = process_file_auto(f)
        if success:
            processed_count += 1
            if args.cleanup:
                os.remove(f)
    
    print(f"✅ Labeling Complete: {processed_count} files processed.")
    if args.cleanup:
        print("   🧹 Interim source files purged to preserve storage.")

if __name__ == "__main__":
    main()

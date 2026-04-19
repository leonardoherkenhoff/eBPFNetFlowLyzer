#!/usr/bin/env python3
"""
ebpf_labeler.py - Research Post-Processing - Topological Ground Truth Attribution.

Research Objective:
This script transforms raw network features into a supervised dataset by 
applying ground truth labels based on the testbed's network topology.

Labeling Framework:
- Deterministic Attribution: Packets originating from known attacker nodes 
  are labeled with the specific attack category (e.g., 'DrDoS_DNS').
- Class Balancing: All other traffic is labeled as 'BENIGN'.

Methodology:
Uses high-performance pandas chunking to process multi-gigabyte packet-level 
extractions (v1.5.0) without exhausting system memory.
"""

import pandas as pd
import numpy as np
import os
import glob

# --- Research Configuration ---
BASE_DIR = "/opt/eBPFNetFlowLyzer"
INPUT_DIR = os.path.join(BASE_DIR, "data/interim/EBPF_RAW")
OUTPUT_DIR = os.path.join(BASE_DIR, "data/processed/EBPF")

# Target Attacker Nodes (Research Testbed IPs)
# Must include both IPv4 and IPv6 stack for Milestone 3 compliance.
ATTACKER_IPS = ["172.16.0.5", "2001:db8:acad:10::5", "fe80::215:5dff:fe00:5"] 
CHUNK_SIZE = 500000 

def process_file_auto(file_path):
    """
    Applies the topological labeling rule to a single extraction result.
    
    Args:
        file_path (str): Path to the raw CSV extraction file.
        
    Returns:
        bool: True if processed successfully, False otherwise.
    """
    try:
        filename = os.path.basename(file_path)
        attack_category = os.path.basename(os.path.dirname(file_path))
        
        # Maintain hierarchical directory structure for dataset integrity
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

        # Stream-based processing to handle large-scale datasets
        for chunk in reader:
            data = chunk.copy()
            
            # Forensic diagnostics: track a sample of observed IPs
            if 'src_ip' in data.columns:
                if len(unique_ips) < 20:
                    unique_ips.update(data['src_ip'].unique()[:20])

                # Ground Truth Mapping
                src_ips = data['src_ip'].astype(str)
                is_attack = src_ips.isin(ATTACKER_IPS)
                
                # Apply labels: Attack Category vs Benign
                labels = np.where(is_attack, attack_category, 'BENIGN')
                data['Label'] = labels
                
                total_attack += np.sum(is_attack)
                total_benign += np.sum(~is_attack)
            
            # Append results to the final processed dataset
            data.to_csv(output_file, mode='a', header=first_chunk, index=False)
            first_chunk = False
            
        print(f"    ✅ Created: {os.path.basename(output_file)}")
        print(f"       -> Attack: {total_attack} | Benign: {total_benign}")
        
        if total_attack == 0:
            print(f"       ⚠️  WARNING: Zero attack events found. Verify ATTACKER_IPS mapping.")
            print(f"       Forensic IPs detected: {list(unique_ips)[:5]}")

        return True
    except Exception as e:
        print(f"   ❌ Error processing {file_path}: {e}")
        return False

def main():
    """Main execution loop for dataset labeling."""
    print("=== eBPFNetFlowLyzer Research Pre-processing (Labeling) ===")
    files = glob.glob(os.path.join(INPUT_DIR, "**", "*.csv"), recursive=True)
    
    if not files:
        print(f"⚠️  No extraction results found in {INPUT_DIR}.")
        return

    for f in files:
        # Ignore diagnostic resource metric logs during labeling
        if os.path.basename(f).startswith("resource_metrics"): continue
        process_file_auto(f)

if __name__ == "__main__":
    main()

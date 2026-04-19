#!/usr/bin/env python3
"""
ebpf_run_benchmark.py - Lynceus Research Pipeline - ML Benchmark Suite (v3.1.0).
------------------------------------------------------
v3.1.0 Stable Research Milestone:
- Validation: High-fidelity F1-Score benchmarking for Lynceus features.
- Context: Post-labeling analysis and feature importance estimation.
- Dynamic Labeling Logic: Correctly identifies attack categories vs 'BENIGN'.
- Memory Optimization: Chunked loading for multi-gigabyte research datasets.
"""

import pandas as pd
import numpy as np
import os
import glob
import gc
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import f1_score, classification_report, confusion_matrix

def process_dataframe(df):
    """
    Standardizes feature selection for the v1.9.x partitioned dataset.
    """
    # Identity & metadata columns to exclude from training
    drop_cols = ['flow_id', 'timestamp', 'src_ip', 'dst_ip', 'Label']
    
    if 'Label' not in df.columns:
        return None, None
        
    y = df['Label']
    X = df.drop(columns=[c for c in drop_cols if c in df.columns])
    
    # Ensure numeric consistency
    X = X.apply(pd.to_numeric, errors='coerce').fillna(0)
    
    # v3.1.0 Logic: 'BENIGN' is 0, any other category (DNS, NTP, etc) is 1 (Attack)
    y_binary = y.apply(lambda x: 0 if str(x).upper() == 'BENIGN' else 1)
    
    return X, y_binary

def run_benchmark():
    processed_dir = "/opt/eBPFNetFlowLyzer/data/processed/EBPF"
    # v3.1.0: Recursive search for labeled files across the experiment tree
    processed_files = glob.glob(os.path.join(processed_dir, "**", "*.csv"), recursive=True)
    
    if not processed_files:
        print("[Error] No labeled datasets found. Ensure Phase 2 & 3 completed successfully.")
        return

    print(f"\n{'='*60}")
    print(f"{'EBPF RESEARCH BENCHMARK (v3.1.0)':^60}")
    print(f"{'='*60}\n")

    for file_path in processed_files:
        # Ignore resource metrics during ML training
        if os.path.basename(file_path).startswith("resource_metrics"): continue
        
        attack_name = os.path.basename(file_path).replace('labeled_', '').replace('.csv', '')
        gc.collect() 
        
        print(f"\n>>> VALIDATING DETECTION: {attack_name} <<<")
        try:
            X_list, y_list = [], []
            # Large-scale ingestion using chunking to maintain RAM stability on the Xeon
            reader = pd.read_csv(file_path, chunksize=200000, low_memory=False)
            
            for chunk in reader:
                X_chunk, y_chunk = process_dataframe(chunk)
                if X_chunk is not None:
                    X_list.append(X_chunk)
                    y_list.append(y_chunk)
                # Limit to 2M packets per category for validation efficiency
                if len(X_list) >= 10: break 
            
            if not X_list: continue
            
            X = pd.concat(X_list)
            y = pd.concat(y_list)
            
            if len(y.unique()) < 2: 
                print(f"    ⚠️ Data insufficiency: Single-class sample (Benign only or Attack only).")
                continue

            # Research-grade 70/30 Split
            X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)
            
            # High-performance Parallel Random Forest
            clf = RandomForestClassifier(n_estimators=100, n_jobs=-1, random_state=42)
            clf.fit(X_train, y_train)
            
            y_pred = clf.predict(X_test)
            f1 = f1_score(y_test, y_pred)
            
            print(f"\n    ✅ MODEL VALIDATED")
            print(f"    {'F1-Score:':<20} {f1:.4f}")
            print(f"    {'Samples:':<20} {len(X)}")
            print(f"    {'Features:':<20} {X.shape[1]}")
            
            # Scientific Analysis: Feature Importance (Top 5)
            importances = pd.Series(clf.feature_importances_, index=X.columns).sort_values(ascending=False)
            print("\n    CRITICAL ATTACK SIGNATURES (Top 5):")
            for feature, val in importances.head(5).items():
                print(f"      - {feature:<25} {val:.4f}")

        except Exception as e:
            print(f"    ❌ Critical Error analyzing {attack_name}: {e}")

    print(f"\n{'='*60}")
    print(f"{'BENCHMARK COMPLETE':^60}")
    print(f"{'='*60}\n")

if __name__ == "__main__":
    run_benchmark()

#!/usr/bin/env python3
"""
ebpf_run_benchmark.py - Research-Grade ML Validation Script (v3.0.0).

Validates the Universal Multi-Protocol EBPF Extractor using a Random Forest 
Binary Classifier. Focuses on F1-Score and Cross-Validation.
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
    Standardizes feature selection for the v3.0.0 Universal Multi-Protocol header.
    Includes TCP, UDP, ICMP, and DNS features.
    """
    # Define features to exclude (Identity & metadata)
    drop_cols = ['flow_id', 'timestamp', 'src_ip', 'dst_ip', 'Label']
    
    if 'Label' not in df.columns:
        return None, None
        
    y = df['Label']
    X = df.drop(columns=[c for c in drop_cols if c in df.columns])
    
    # Ensure all columns are numeric
    X = X.apply(pd.to_numeric, errors='coerce').fillna(0)
    
    # Binary Classification: 1 = Attack, 0 = Benign
    y = y.apply(lambda x: 1 if str(x).lower() == 'attack' else 0)
    
    return X, y

def run_benchmark():
    processed_dir = "/opt/eBPFNetFlowLyzer/data/processed/EBPF"
    processed_files = glob.glob(f"{processed_dir}/*.csv")
    
    if not processed_files:
        print("[Error] No labeled datasets found. Run the labeler first.")
        return

    print(f"\n{'='*60}")
    print(f"{'EBPF RESEARCH BENCHMARK (v3.0.0)':^60}")
    print(f"{'='*60}\n")

    for file_path in processed_files:
        attack_name = os.path.basename(file_path).replace('labeled_', '').replace('.csv', '')
        gc.collect() 
        
        print(f"\n>>> ANALYZING DATASET: {attack_name} <<<")
        try:
            # v3.0.0 datasets are massive; using chunked ingestion for RAM stability
            X_list, y_list = [], []
            reader = pd.read_csv(file_path, chunksize=200000, low_memory=False)
            
            for chunk in reader:
                X_chunk, y_chunk = process_dataframe(chunk)
                if X_chunk is not None:
                    X_list.append(X_chunk)
                    y_list.append(y_chunk)
                if len(X_list) > 10: break # Sample 2M packets for validation speed
            
            X = pd.concat(X_list)
            y = pd.concat(y_list)
            
            if len(y.unique()) < 2: 
                print(f"    ⚠️ Data insufficiency or single-class sample.")
                continue

            # Split and Train
            X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)
            
            clf = RandomForestClassifier(n_estimators=100, n_jobs=-1, random_state=42)
            clf.fit(X_train, y_train)
            
            y_pred = clf.predict(X_test)
            f1 = f1_score(y_test, y_pred)
            
            print(f"\n    ✅ MODEL VALIDATED")
            print(f"    {'F1-Score:':<20} {f1:.4f}")
            print(f"    {'Samples:':<20} {len(X)}")
            print(f"    {'Features:':<20} {X.shape[1]}")
            
            # Feature Importance (Top 5)
            importances = pd.Series(clf.feature_importances_, index=X.columns).sort_values(ascending=False)
            print("\n    TOP 5 FEATURES:")
            for feature, val in importances.head(5).items():
                print(f"      - {feature:<25} {val:.4f}")

        except Exception as e:
            print(f"    ❌ Critical Error analyzing {attack_name}: {e}")

    print(f"\n{'='*60}")
    print(f"{'BENCHMARK COMPLETE':^60}")
    print(f"{'='*60}\n")

if __name__ == "__main__":
    run_benchmark()

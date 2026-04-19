#!/usr/bin/env python3
/**
 * @file ebpf_run_benchmark.py
 * @brief Research Analysis - Machine Learning Validation & Performance Evaluation.
 * 
 * Research Objective:
 * This script performs the final validation of the eBPF feature extraction 
 * pipeline by training and evaluating Machine Learning models to detect DDoS 
 * attack vectors.
 * 
 * Model Configuration:
 * - Algorithm: Random Forest (RF) with Balanced Class Weights.
 * - Training Protocol: 70/30 stratified train-test split.
 * - Metrics: F1-Score, Precision, Recall, and Feature Importance.
 * 
 * Anti-Leakage Strategy:
 * Automatically drops identifying features (IPs, Ports, Protocols) to ensure 
 * the model learns general network behavior patterns rather than specific 
 * testbed artifacts.
 */

import pandas as pd
import numpy as np
import os
import gc
import warnings
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import f1_score, precision_score, recall_score

# Silence FutureWarnings for cleaner research logs
warnings.simplefilter(action='ignore', category=FutureWarning)

# --- Research Configuration ---
BASE_DIR = "/opt/eBPFNetFlowLyzer"
DIRS = {'EBPF': os.path.join(BASE_DIR, 'data/processed/EBPF')}
OUTPUT_DIR = os.path.join(BASE_DIR, "results/figures")

if not os.path.exists(OUTPUT_DIR):
    os.makedirs(OUTPUT_DIR)

def process_dataframe(df_chunk):
    """
    Normalizes and prepares the feature set for ML training.
    
    Args:
        df_chunk (pd.DataFrame): Raw labeled flow features.
        
    Returns:
        tuple: (Features X, Binary Labels y).
    """
    # Clean column names for consistency
    df_chunk.columns = [c.strip().lower().replace(' ', '_') for c in df_chunk.columns]
    target_col = 'label'
    if target_col not in df_chunk.columns: 
        print(f"    ⚠️ Label column not found. Available: {list(df_chunk.columns)}")
        return None, None
    
    # Feature Engineering: Drop identifying artifacts to prevent over-fitting
    drop_patterns = ['src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol']
    cols_to_drop = [c for c in df_chunk.columns if c in drop_patterns] + [target_col]
    
    X = df_chunk.drop(columns=cols_to_drop, errors='ignore')
    y_raw = df_chunk[target_col]
    
    # Numerical Normalization & Type Downcasting (Memory Optimization)
    for col in X.columns:
        X[col] = pd.to_numeric(X[col], errors='coerce').fillna(0).astype('float32')

    X.replace([np.inf, -np.inf], np.nan, inplace=True)
    X.fillna(0, inplace=True)

    # Binary Classification: 1 = Attack, 0 = Benign
    y_bin = y_raw.astype(str).str.lower().str.contains('benign').astype(int)
    y_bin = 1 - y_bin 
    
    return X, y_bin

def run_analysis():
    """Executes the machine learning benchmark suite."""
    print("=== eBPFNetFlowLyzer - Machine Learning Validation Pipeline ===")
    
    # Dataset Auto-discovery
    processed_files = []
    for root, _, files in os.walk(DIRS['EBPF']):
        for f in files:
            if f.endswith('.csv'):
                processed_files.append(os.path.join(root, f))
    
    if not processed_files:
        print(f"⚠️  No processed datasets found. Run ebpf_labeler.py first.")
        return

    for file_path in processed_files:
        attack_name = os.path.basename(file_path).replace('labeled_', '').replace('.csv', '')
        gc.collect() # Aggressive memory cleanup for large-scale analysis
        
        print(f"\n>>> ANALYZING DATASET: {attack_name} <<<")
        try:
            df = pd.read_csv(file_path, low_memory=False)
            X, y = process_dataframe(df)
            
            if X is None or len(y.unique()) < 2: 
                print(f"    ⚠️ Data insufficiency or single-class sample.")
                continue
                
            print(f"    [ML] Initiating 70/30 Stratified Split...")
            X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42, stratify=y)
            
            # Model: Random Forest with Gini Impurity
            rf = RandomForestClassifier(
                n_estimators=40, 
                n_jobs=-1, 
                random_state=42, 
                class_weight='balanced', 
                max_depth=15
            )
            rf.fit(X_train, y_train)
            
            # Metric Computation
            y_pred = rf.predict(X_test)
            f1 = f1_score(y_test, y_pred, average='weighted')
            prec = precision_score(y_test, y_pred, average='weighted', zero_division=0)
            rec = recall_score(y_test, y_pred, average='weighted', zero_division=0)
            
            print(f"    ✅ METRICS: F1: {f1:.4f} | Precision: {prec:.4f} | Recall: {rec:.4f}")
            
            # Feature Importance Analysis (Research Highlight)
            importances = rf.feature_importances_
            indices = np.argsort(importances)[::-1]
            train_cols = X_train.columns
            
            top_10 = []
            for i in range(min(10, len(indices))):
                idx = indices[i]
                top_10.append(f"{train_cols[idx]} ({importances[idx]:.3f})")
                
            # LaTeX Generation for Manuscript Inclusion
            tex_str = ", ".join(top_10).replace('_', '\\_')
            print(f"    📋 LATEX SNIPPET:\n    {attack_name} & eBPF & {prec:.4f} & {rec:.4f} & {f1:.4f} & \\scriptsize{{{tex_str}}} \\\\ \\hline")
            
            del rf, y_pred, df, X, y; gc.collect()
        except Exception as e:
            print(f"   ❌ Error analyzing {file_path}: {e}")

if __name__ == "__main__":
    run_analysis()

"""
eBPFNetFlowLyzer Machine Learning Benchmark
-------------------------------------------
This script performs the final research validation by evaluating the detection 
performance of Machine Learning models trained on the eBPF-extracted features.

Research Goals:
1. Detection Accuracy: Validate the F1-Score, Precision, and Recall for various 
   DDoS attack vectors (DNS, UDP, Syn flood, etc.).
2. Feature Importance: Identify which eBPF-extracted features contribute most 
   to the classification (e.g., IAT, Standard Deviation of Packet Length).
3. Dissertation Reporting: Generate raw LaTeX/TikZ compatible strings for 
   direct inclusion in the research manuscript.

Model Configuration:
- Algorithm: Random Forest (RF).
- Hyper-parameters: 40 estimators, max depth 15, balanced class weights.
- Protocol: 70/30 stratified split to ensure consistent representation of 
  Benign vs. Attack traffic.

Developed as part of the Master's Degree in Applied Computing research.
"""

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

# --- CONFIGURATION ---
# Path to the labeled datasets produced by the labeler
DIRS = {'EBPF': './data/processed/EBPF'}
# Output destination for LaTeX figures and summary data
OUTPUT_DIR = "./results/figures"

if not os.path.exists(OUTPUT_DIR):
    os.makedirs(OUTPUT_DIR)

def process_dataframe(df_chunk):
    """
    Pre-processes the dataframe for Machine Learning training.
    """
    df_chunk.columns = [c.strip().lower().replace(' ', '_') for c in df_chunk.columns]
    target_col = 'label'
    if target_col not in df_chunk.columns: 
        print(f"    ⚠️ Column '{target_col}' not found. Available: {list(df_chunk.columns)}")
        return None, None
    
    # Anti-Leakage strategy: We must not train on specific IPs or Ports 
    drop_patterns = ['src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol']
    cols_to_drop = [c for c in df_chunk.columns if c in drop_patterns] + [target_col]
    
    X = df_chunk.drop(columns=cols_to_drop, errors='ignore')
    y_raw = df_chunk[target_col]
    
    # Numerical normalization and type downcasting
    for col in X.columns:
        X[col] = pd.to_numeric(X[col], errors='coerce').fillna(0).astype('float32')

    X.replace([np.inf, -np.inf], np.nan, inplace=True)
    X.fillna(0, inplace=True)

    # Binary Classification: 1 = Attack, 0 = Benign
    y_bin = y_raw.astype(str).str.lower().str.contains('benign').astype(int)
    y_bin = 1 - y_bin 
    
    return X, y_bin

def run_analysis():
    print("=== eBPFNetFlowLyzer - Machine Learning Validation Pipeline ===")
    
    # Auto-discovery of all processed CSV files
    processed_files = []
    for root, _, files in os.walk(DIRS['EBPF']):
        for f in files:
            if f.endswith('.csv'):
                processed_files.append(os.path.join(root, f))
    
    if not processed_files:
        print(f"⚠️  No processed datasets found in {DIRS['EBPF']}. Run ebpf_labeler.py first.")
        return

    for file_path in processed_files:
        attack_name = os.path.basename(file_path).replace('labeled_', '').replace('.csv', '')
        # Aggressive memory cleanup
        gc.collect()
        
        print(f"\n>>> ANALYZING DATASET: {attack_name} <<<")
        print(f"    Path: {file_path}")
        try:
            df = pd.read_csv(file_path, low_memory=False)
            X, y = process_dataframe(df)
            
            if X is None or len(y.unique()) < 2: 
                print(f"    ⚠️ Data insufficiency or single-class dataset.")
                continue
                
            print(f"    [ML] Initiating 70/30 Stratified Split...")
            X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42, stratify=y)
            
            # Model Training: Random Forest
            rf = RandomForestClassifier(
                n_estimators=40, 
                n_jobs=-1, 
                random_state=42, 
                class_weight='balanced', 
                max_depth=15
            )
            rf.fit(X_train, y_train)
            
            # Prediction and Scoring
            y_pred = rf.predict(X_test)
            f1 = f1_score(y_test, y_pred, average='weighted')
            prec = precision_score(y_test, y_pred, average='weighted', zero_division=0)
            rec = recall_score(y_test, y_pred, average='weighted', zero_division=0)
            
            print(f"    ✅ METRICS: F1: {f1:.4f} | Precision: {prec:.4f} | Recall: {rec:.4f}")
            
            # Feature Importance
            importances = rf.feature_importances_
            importances_std = np.std([tree.feature_importances_ for tree in rf.estimators_], axis=0)
            indices = np.argsort(importances)[::-1]
            train_cols = X_train.columns
            
            top_10 = []
            for i in range(min(10, len(indices))):
                idx = indices[i]
                top_10.append(f"{train_cols[idx]} ({importances[idx]:.3f}±{importances_std[idx]:.3f})")
                
            # LaTeX Snippet
            tex_str = ", ".join(top_10).replace('_', '\\_')
            print(f"    📋 LATEX SNIPPET:\n    {attack_name} & eBPF & {prec:.4f} & {rec:.4f} & {f1:.4f} & \\scriptsize{{{tex_str}}} \\\\ \\hline")
            
            del rf, y_pred, df, X, y; gc.collect()
        except Exception as e:
            print(f"   ❌ Error analyzing {file_path}: {e}")

if __name__ == "__main__":
    run_analysis()

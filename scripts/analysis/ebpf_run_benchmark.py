import pandas as pd
import numpy as np
import os
import gc
import warnings
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import f1_score, precision_score, recall_score
warnings.simplefilter(action='ignore', category=FutureWarning)

"""
eBPFNetFlowLyzer ML Benchmark (Random Forest)
O(1) Memory Footprint testing with strict LaTex PGFPlots compatibility matching CICDDoS2019 topology.
"""

DIRS = {'EBPF': './data/processed/EBPF'}
OUTPUT_DIR = "./results/figures"
ATTACK_KEYWORDS = ['DNS', 'LDAP', 'MSSQL', 'NetBIOS', 'NTP', 'SNMP', 'SSDP', 'UDP', 'Syn', 'TFTP', 'UDPLag', 'Portmap'] 

if not os.path.exists(OUTPUT_DIR):
    os.makedirs(OUTPUT_DIR)

def process_chunk(df_chunk):
    df_chunk.columns = [c.strip().lower().replace(' ', '_') for c in df_chunk.columns]
    target_col = 'label'
    if target_col not in df_chunk.columns: return None, None
    
    # Drop identifiers to prevent Machine Learning data leakage
    drop_patterns = ['src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol']
    cols_to_drop = [c for c in df_chunk.columns if c in drop_patterns] + [target_col]
    
    X = df_chunk.drop(columns=cols_to_drop, errors='ignore')
    y_raw = df_chunk[target_col]
    
    # Downcast memory directly (eBPF uses integers intrinsically)
    for col in X.columns:
        X[col] = pd.to_numeric(X[col], errors='coerce').fillna(0).astype('float32')

    X.replace([np.inf, -np.inf], np.nan, inplace=True)
    X.fillna(0, inplace=True)

    y_bin = y_raw.astype(str).str.lower().str.contains('benign').astype(int)
    y_bin = 1 - y_bin # 1 = Attack, 0 = Benign
    
    return X, y_bin

def find_file(base_dir, keyword):
    keyword = keyword.lower().replace('drdos_', '')
    for root, _, files in os.walk(base_dir):
        for f in files:
            if not f.endswith('.csv'): continue
            if keyword == 'udp' and 'lag' in f.lower(): continue
            if keyword in f.lower(): return os.path.join(root, f)
    return None

def run_analysis():
    ml_results_db = []
    print("=== ANÁLISE RANDOM FOREST - eBPFNetFlowLyzer ===")
    
    for attack in ATTACK_KEYWORDS:
        gc.collect()
        file_path = find_file(DIRS['EBPF'], attack)
        if not file_path: continue
        
        print(f"\n>>> CENÁRIO: {attack} <<<")
        try:
            df = pd.read_csv(file_path, low_memory=False)
            X, y = process_chunk(df)
            if X is None or len(y.unique()) < 2: 
                print(f"    ⚠️ Dados insuficientes.")
                continue
                
            print(f"    [EBPF] Validando Matriz SPLIT 70/30...")
            X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42, stratify=y)
            
            # Matched exactly to Paper 1 hyper-parameters
            rf = RandomForestClassifier(n_estimators=40, n_jobs=-1, random_state=42, class_weight='balanced', max_depth=15)
            rf.fit(X_train, y_train)
            y_pred = rf.predict(X_test)
            
            f1 = f1_score(y_test, y_pred, average='weighted')
            prec = precision_score(y_test, y_pred, average='weighted', zero_division=0)
            rec = recall_score(y_test, y_pred, average='weighted', zero_division=0)
            print(f"    ✅ F1-Score: {f1:.4f} | Precision: {prec:.4f} | Recall: {rec:.4f}")
            
            importances = rf.feature_importances_
            importances_std = np.std([tree.feature_importances_ for tree in rf.estimators_], axis=0)
            indices = np.argsort(importances)[::-1]
            train_cols = X_train.columns
            
            top_10 = []
            for i in range(min(10, len(indices))):
                idx = indices[i]
                top_10.append(f"{train_cols[idx]} ({importances[idx]:.3f}±{importances_std[idx]:.3f})")
                
            tex_str = ", ".join(top_10).replace('_', '\\_')
            print(f"    📋 LINHA LATEX:\n    {attack} & eBPF & Split & {prec:.4f} & {rec:.4f} & {f1:.4f} & \\scriptsize{{{tex_str}}} \\\\ \\hline")
            
            del rf, y_pred, df, X, y; gc.collect()
        except Exception as e:
            print(f"Erro em {attack}: {e}")

if __name__ == "__main__":
    run_analysis()

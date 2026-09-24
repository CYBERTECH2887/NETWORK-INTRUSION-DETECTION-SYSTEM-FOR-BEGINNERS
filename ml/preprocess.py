# ==========================================
# BLOCK 1: Imports
# ==========================================
import os
import joblib
import numpy as np
import pandas as pd
from sklearn.preprocessing import LabelEncoder, StandardScaler


# ==========================================
# BLOCK 2: Directory Setup
# ==========================================
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
DATA_DIR = os.path.join(BASE_DIR, 'data')
MODELS_DIR = os.path.join(BASE_DIR, 'models')

os.makedirs(MODELS_DIR, exist_ok=True)
os.makedirs(DATA_DIR, exist_ok=True)


# ==========================================
# BLOCK 3: Attack Categories Definition
# ==========================================
DOS_ATTACKS = ['apache2', 'back', 'land', 'neptune', 'mailbomb', 'pod', 'processtable', 'smurf', 'teardrop', 'udpstorm', 'worm']
PROBE_ATTACKS = ['ipsweep', 'mscan', 'nmap', 'portsweep', 'saint', 'satan']
U2R_ATTACKS = ['buffer_overflow', 'loadmodule', 'perl', 'ps', 'rootkit', 'sqlattack', 'xterm']
R2L_ATTACKS = ['ftp_write', 'guess_passwd', 'http_tunnel', 'imap', 'multihop', 'named', 'phf', 'sendmail', 'snmpgetattack', 'snmpguess', 'spy', 'warezclient', 'warezmaster', 'xclock', 'xsnoop']


# ==========================================
# BLOCK 4: Label Mapping Function
# ==========================================
def map_attack_category(attack_name):
    attack = attack_name.lower().strip()
    if attack == 'normal':
        return 0
    elif attack in DOS_ATTACKS:
        return 1
    elif attack in PROBE_ATTACKS:
        return 2
    elif attack in U2R_ATTACKS:
        return 3
    elif attack in R2L_ATTACKS:
        return 4
    else:
        return 0


# ==========================================
# BLOCK 5: Main Preprocessing Function
# ==========================================
def preprocess_data():
    
    # Load raw datasets
    train_path = os.path.join(DATA_DIR, 'KDDTrain+.csv')
    test_path = os.path.join(DATA_DIR, 'KDDTest+.csv')
    
    print(f"Loading data from:\n  - {train_path}\n  - {test_path}")
    
    train_df = pd.read_csv(train_path)
    test_df = pd.read_csv(test_path)
    
    # ==========================================
    # BLOCK 6: Target Encoding & Feature Cleanup
    # ==========================================
    train_df['target'] = train_df['attack'].apply(map_attack_category)
    test_df['target'] = test_df['attack'].apply(map_attack_category)
    
    train_df.drop(columns=['attack', 'level'], inplace=True)
    test_df.drop(columns=['attack', 'level'], inplace=True)
    
    # ==========================================
    # BLOCK 7: Categorical Feature Encoding
    # ==========================================
    categorical_cols = ['protocol_type', 'service', 'flag']
    label_encoders = {}
    
    for col in categorical_cols:
        le = LabelEncoder()
        
        all_unique_values = pd.concat([train_df[col], test_df[col]]).astype(str).unique()
        le.fit(all_unique_values)
        
        train_df[col] = le.transform(train_df[col].astype(str))
        test_df[col] = le.transform(test_df[col].astype(str))
        label_encoders[col] = le
        
    encoder_path = os.path.join(MODELS_DIR, 'label_encoders.pkl')
    joblib.dump(label_encoders, encoder_path)
    print(f"Saved label encoders to: {encoder_path}")
    
    # ==========================================
    # BLOCK 8: Feature (X) and Target (y) Split
    # ==========================================
    X_train = train_df.drop('target', axis=1).values
    y_train = train_df['target'].values
    
    X_test = test_df.drop('target', axis=1).values
    y_test = test_df['target'].values
    
    # ==========================================
    # BLOCK 9: Feature Scaling
    # ==========================================
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    
    scaler_path = os.path.join(MODELS_DIR, 'scaler.pkl')
    joblib.dump(scaler, scaler_path)
    print(f"Saved scaler to: {scaler_path}")
    
    # ==========================================
    # BLOCK 10: Save Processed Arrays
    # ==========================================
    np.save(os.path.join(DATA_DIR, 'X_train.npy'), X_train_scaled)
    np.save(os.path.join(DATA_DIR, 'y_train.npy'), y_train)
    np.save(os.path.join(DATA_DIR, 'X_test.npy'), X_test_scaled)
    np.save(os.path.join(DATA_DIR, 'y_test.npy'), y_test)
    
    print("Preprocessing completed successfully!")


# ==========================================
# BLOCK 11: Script Execution
# ==========================================
if __name__ == '__main__':
    preprocess_data()
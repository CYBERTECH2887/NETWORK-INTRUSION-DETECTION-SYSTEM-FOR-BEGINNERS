# ==========================================
# preprocess.py - NSL-KDD dataset ko clean, encode aur scale karne ke liye
# Command to run: python training/preprocess.py
# ==========================================
import os
import json
import joblib
import numpy as np
import pandas as pd
from sklearn.preprocessing import LabelEncoder, StandardScaler

# Directories set kar rahe hain jahan data store hoga aur models save honge
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
DATA_DIR = os.path.join(BASE_DIR, 'data')
MODELS_DIR = os.path.join(BASE_DIR, 'models')
os.makedirs(MODELS_DIR, exist_ok=True)
os.makedirs(DATA_DIR, exist_ok=True)

# NSL-KDD dataset ke alag-alag specific attacks ko 4 main categories me divide kiya gaya hai
# FIX: 'httptunnel' aur 'xlock' ki correct spelling use ki hai
DOS_ATTACKS = ['apache2', 'back', 'land', 'neptune', 'mailbomb', 'pod', 'processtable', 'smurf', 'teardrop', 'udpstorm', 'worm']
PROBE_ATTACKS = ['ipsweep', 'mscan', 'nmap', 'portsweep', 'saint', 'satan']
U2R_ATTACKS = ['buffer_overflow', 'loadmodule', 'perl', 'ps', 'rootkit', 'sqlattack', 'xterm']
R2L_ATTACKS = ['ftp_write', 'guess_passwd', 'httptunnel', 'http_tunnel', 'imap', 'multihop', 'named', 'phf',
               'sendmail', 'snmpgetattack', 'snmpguess', 'spy', 'warezclient', 'warezmaster', 'xlock', 'xclock', 'xsnoop']

UNKNOWN_ATTACKS = set()

# Yeh function raw attack string ko numerical label me convert karta hai (Normal=0, DoS=1, Probe=2, U2R=3, R2L=4)
def map_attack_category(attack_name):
    attack = str(attack_name).lower().strip()
    if attack == 'normal': return 0
    if attack in DOS_ATTACKS: return 1
    if attack in PROBE_ATTACKS: return 2
    if attack in U2R_ATTACKS: return 3
    if attack in R2L_ATTACKS: return 4
    UNKNOWN_ATTACKS.add(attack)      # Agar koi unknown attack milta hai, toh use log karne ke liye store karte hain
    return -1

# Main preprocessing function jo raw CSV read karke ML-ready arrays banata hai
def preprocess_data():
    train_path = os.path.join(DATA_DIR, 'KDDTrain+.csv')
    test_path = os.path.join(DATA_DIR, 'KDDTest+.csv')
    print(f"Loading data from:\n  - {train_path}\n  - {test_path}")
    
    # Pandas se CSV read kar rahe hain
    train_df = pd.read_csv(train_path)
    test_df = pd.read_csv(test_path)

    # 'attack' column ko numerical target categories me map kar rahe hain
    train_df['target'] = train_df['attack'].apply(map_attack_category)
    test_df['target'] = test_df['attack'].apply(map_attack_category)

    # Unknown attacks ko drop kar dete hain taaki model galat train na ho
    if UNKNOWN_ATTACKS:
        print(f"WARNING: unknown attack names dropped: {sorted(UNKNOWN_ATTACKS)}")
        train_df = train_df[train_df['target'] >= 0]
        test_df = test_df[test_df['target'] >= 0]

    # Purane labels ('attack', 'level') columns drop kar rahe hain
    train_df = train_df.drop(columns=['attack', 'level'])
    test_df = test_df.drop(columns=['attack', 'level'])

    # Categorical text features ko numbers me convert karne ke liye LabelEncoder use kar rahe hain
    categorical_cols = ['protocol_type', 'service', 'flag']
    label_encoders = {}
    for col in categorical_cols:
        le = LabelEncoder()
        # Train aur Test dono ka data milakar fit karte hain taaki koi missing category error na aaye
        le.fit(pd.concat([train_df[col], test_df[col]]).astype(str).unique())
        train_df[col] = le.transform(train_df[col].astype(str))
        test_df[col] = le.transform(test_df[col].astype(str))
        label_encoders[col] = le
    
    # Encoders save kar rahe hain taaki live prediction me wapas text ko encode kiya ja sake
    joblib.dump(label_encoders, os.path.join(MODELS_DIR, 'label_encoders.pkl'))

    # Features ke naam save kar rahe hain (batch CSV upload validation ke liye)
    feature_cols = [c for c in train_df.columns if c != 'target']
    with open(os.path.join(MODELS_DIR, 'feature_names.json'), 'w') as f:
        json.dump(feature_cols, f)          

    # DataFrames se Numpy Arrays extract kar rahe hain
    X_train, y_train = train_df[feature_cols].values, train_df['target'].values
    X_test, y_test = test_df[feature_cols].values, test_df['target'].values

    # StandardScaler se data ko normalize/scale karte hain taaki Neural Network theek se train ho sake
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    
    # Scaler ko save kar rahe hain aage use karne ke liye
    joblib.dump(scaler, os.path.join(MODELS_DIR, 'scaler.pkl'))

    # Final preprocessed matrices ko Numpy format (.npy) me save kar rahe hain fast loading ke liye
    np.save(os.path.join(DATA_DIR, 'X_train.npy'), X_train_scaled)
    np.save(os.path.join(DATA_DIR, 'y_train.npy'), y_train)
    np.save(os.path.join(DATA_DIR, 'X_test.npy'), X_test_scaled)
    np.save(os.path.join(DATA_DIR, 'y_test.npy'), y_test)
    print(f"Preprocessing completed: {len(y_train)} train rows, {len(y_test)} test rows, {len(feature_cols)} features.")

if __name__ == '__main__':
    preprocess_data()
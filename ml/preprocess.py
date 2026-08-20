import os
import joblib
import numpy as np
import pandas as pd
from sklearn.preprocessing import LabelEncoder, StandardScaler

# Resolve dynamic paths relative to the project root
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
DATA_DIR = os.path.join(BASE_DIR, 'data')
MODELS_DIR = os.path.join(BASE_DIR, 'models')

os.makedirs(MODELS_DIR, exist_ok=True)
os.makedirs(DATA_DIR, exist_ok=True)

# 41 features + label + difficulty level
COLUMNS = [
    'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes', 
    'land', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins', 'logged_in', 
    'num_compromised', 'root_shell', 'su_attempted', 'num_root', 'num_file_creations', 
    'num_shells', 'num_access_files', 'num_outbound_cmds', 'is_host_login', 
    'is_guest_login', 'count', 'srv_count', 'serror_rate', 'srv_serror_rate', 
    'rerror_rate', 'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate', 
    'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count', 
    'dst_host_same_srv_rate', 'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate', 
    'dst_host_srv_diff_host_rate', 'dst_host_serror_rate', 'dst_host_srv_serror_rate', 
    'dst_host_rerror_rate', 'dst_host_srv_rerror_rate', 'attack', 'level'
]

# NSL-KDD 5-Class Attack Categories
DOS_ATTACKS = ['apache2', 'back', 'land', 'neptune', 'mailbomb', 'pod', 'processtable', 'smurf', 'teardrop', 'udpstorm', 'worm']
PROBE_ATTACKS = ['ipsweep', 'mscan', 'nmap', 'portsweep', 'saint', 'satan']
PRIVILEGE_ATTACKS = ['buffer_overflow', 'loadmodule', 'perl', 'ps', 'rootkit', 'sqlattack', 'xterm'] # U2R
ACCESS_ATTACKS = ['ftp_write', 'guess_passwd', 'http_tunnel', 'imap', 'multihop', 'named', 'phf', 'sendmail', 'snmpgetattack', 'snmpguess', 'spy', 'warezclient', 'warezmaster', 'xclock', 'xsnoop'] # R2L

def map_attack_category(attack_name):
    """Maps specific attack strings to 5 main classes: 0=Normal, 1=DoS, 2=Probe, 3=U2R, 4=R2L"""
    attack = attack_name.lower().strip()
    if attack == 'normal':
        return 0
    elif attack in DOS_ATTACKS:
        return 1
    elif attack in PROBE_ATTACKS:
        return 2
    elif attack in PRIVILEGE_ATTACKS:
        return 3
    elif attack in ACCESS_ATTACKS:
        return 4
    else:
        return 0  # Default fallback for unseen test-set attacks

def preprocess_data():
    train_path = os.path.join(DATA_DIR, 'KDDTrain+.txt')
    test_path = os.path.join(DATA_DIR, 'KDDTest+.txt')
    
    print(f"Loading data from:\n  - {train_path}\n  - {test_path}")
    train_df = pd.read_csv(train_path, names=COLUMNS)
    test_df = pd.read_csv(test_path, names=COLUMNS)
    
    # 1. Map target labels to 5 classes
    train_df['target'] = train_df['attack'].apply(map_attack_category)
    test_df['target'] = test_df['attack'].apply(map_attack_category)
    
    # Drop raw attack name and difficulty level
    train_df.drop(columns=['attack', 'level'], inplace=True)
    test_df.drop(columns=['attack', 'level'], inplace=True)
    
    # 2. Encode Categorical Features
    categorical_cols = ['protocol_type', 'service', 'flag']
    label_encoders = {}
    
    for col in categorical_cols:
        le = LabelEncoder()
        # Fit encoder on the combination of both sets to handle all unseen labels
        all_unique_values = pd.concat([train_df[col], test_df[col]]).astype(str).unique()
        le.fit(all_unique_values)
        
        train_df[col] = le.transform(train_df[col].astype(str))
        test_df[col] = le.transform(test_df[col].astype(str))
        label_encoders[col] = le
        
    # Save encoders for Flask backend
    encoder_path = os.path.join(MODELS_DIR, 'label_encoders.pkl')
    joblib.dump(label_encoders, encoder_path)
    print(f"Saved label encoders to: {encoder_path}")
    
    # 3. Split Features and Target
    X_train = train_df.drop('target', axis=1).values
    y_train = train_df['target'].values
    
    X_test = test_df.drop('target', axis=1).values
    y_test = test_df['target'].values
    
    # 4. Standard Scaling
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    
    # Save scaler for Flask backend
    scaler_path = os.path.join(MODELS_DIR, 'scaler.pkl')
    joblib.dump(scaler, scaler_path)
    print(f"Saved scaler to: {scaler_path}")
    
    # 5. Save intermediate numpy arrays in data/
    np.save(os.path.join(DATA_DIR, 'X_train.npy'), X_train_scaled)
    np.save(os.path.join(DATA_DIR, 'y_train.npy'), y_train)
    np.save(os.path.join(DATA_DIR, 'X_test.npy'), X_test_scaled)
    np.save(os.path.join(DATA_DIR, 'y_test.npy'), y_test)
    
    print("Preprocessing completed successfully!")

if __name__ == '__main__':
    preprocess_data()
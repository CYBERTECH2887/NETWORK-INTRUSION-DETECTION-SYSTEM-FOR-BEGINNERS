import os  # OS module import kiya folder aur file paths manage karne ke liye
import joblib  # ML models aur scalers ko file mein save/load karne ke liye
import numpy as np  # Numerical data aur matrix arrays handle karne ke liye
import pandas as pd  # Dataframes banane aur tabular data handle karne ke liye
from sklearn.preprocessing import LabelEncoder, StandardScaler  # Data ko numbers mein badalne aur scale karne ke tools

# Project ke root folder ka dynamic path nikal rahe hain
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..')) 
DATA_DIR = os.path.join(BASE_DIR, 'data')  # Data folder ka path set kiya
MODELS_DIR = os.path.join(BASE_DIR, 'models')  # Models folder ka path set kiya

# Agar models aur data folders nahi bane hain, toh unhe create kar do
os.makedirs(MODELS_DIR, exist_ok=True) 
os.makedirs(DATA_DIR, exist_ok=True)

# NSL-KDD dataset ke attacks ko unki 4 main categories mein divide kar rahe hain
DOS_ATTACKS = ['apache2', 'back', 'land', 'neptune', 'mailbomb', 'pod', 'processtable', 'smurf', 'teardrop', 'udpstorm', 'worm']# Denial of Service(DOS)
PROBE_ATTACKS = ['ipsweep', 'mscan', 'nmap', 'portsweep', 'saint', 'satan']# PROBE
U2R_ATTACKS = ['buffer_overflow', 'loadmodule', 'perl', 'ps', 'rootkit', 'sqlattack', 'xterm'] # User to Root (U2R)
R2L_ATTACKS = ['ftp_write', 'guess_passwd', 'http_tunnel', 'imap', 'multihop', 'named', 'phf', 'sendmail', 'snmpgetattack', 'snmpguess', 'spy', 'warezclient', 'warezmaster', 'xclock', 'xsnoop'] # Remote to Local (R2L)

def map_attack_category(attack_name):
    """Specific attack strings ko 5 classes mein map karta hai: 0=Normal, 1=DoS, 2=Probe, 3=U2R, 4=R2L"""
    attack = attack_name.lower().strip()  # Text ko lowercase karke extra spaces hata diye
    if attack == 'normal':
        return 0  # Normal traffic ke liye 0 return karo
    elif attack in DOS_ATTACKS:
        return 1  # DoS attack ke liye 1 return karo
    elif attack in PROBE_ATTACKS:
        return 2  # Probe attack ke liye 2 return karo
    elif attack in U2R_ATTACKS:
        return 3  # U2R attack ke liye 3 return karo
    elif attack in R2L_ATTACKS:
        return 4  # R2L attack ke liye 4 return karo
    else:
        return 0  # Agar koi naya/unknown attack test-set mein aata hai toh default 0 (Normal) maan lo

def preprocess_data():
    # Train aur Test files ka path set kar rahe hain
    train_path = os.path.join(DATA_DIR, 'KDDTrain+.csv')
    test_path = os.path.join(DATA_DIR, 'KDDTest+.csv')
    
    print(f"Loading data from:\n  - {train_path}\n  - {test_path}")
    
    # Text files ko Pandas DataFrame mein read kar rahe hain, columns ke naam ke saath
    train_df = pd.read_csv(train_path)
    test_df = pd.read_csv(test_path)
    
    # 1. Labels ko 0-4 integers mein convert karke naya 'target' column bana rahe hain
    train_df['target'] = train_df['attack'].apply(map_attack_category)
    test_df['target'] = test_df['attack'].apply(map_attack_category)
    
    # Purane text wale 'attack' aur 'level' columns ko drop (delete) kar rahe hain
    train_df.drop(columns=['attack', 'level'], inplace=True)
    test_df.drop(columns=['attack', 'level'], inplace=True)
    
    # 2. Text/Categorical columns ko numbers (Label Encoding) mein badal rahe hain
    categorical_cols = ['protocol_type', 'service', 'flag']
    label_encoders = {}  # Encoders save karne ke liye khali dictionary
    
    for col in categorical_cols:  # Har text wale column ke liye loop chalao
        le = LabelEncoder()
        # Train aur test ka data mila kar fit kar rahe hain taaki koi naya word miss na ho
        all_unique_values = pd.concat([train_df[col], test_df[col]]).astype(str).unique()
        le.fit(all_unique_values)
        
        # Ab words ko numbers mein transform kar do
        train_df[col] = le.transform(train_df[col].astype(str))
        test_df[col] = le.transform(test_df[col].astype(str))
        label_encoders[col] = le  # Encoder ko dictionary mein save kar lo
        
    # Flask backend ya prediction ke liye in encoders ko .pkl file mein save kar rahe hain
    encoder_path = os.path.join(MODELS_DIR, 'label_encoders.pkl')
    joblib.dump(label_encoders, encoder_path)
    print(f"Saved label encoders to: {encoder_path}")
    
    # 3. Data ko Features (X) aur Target (y) mein alag alag tod rahe hain
    X_train = train_df.drop('target', axis=1).values  # Target ko chhod kar sab X mein
    y_train = train_df['target'].values  # Sirf target column y mein
    
    X_test = test_df.drop('target', axis=1).values
    y_test = test_df['target'].values
    
    # 4. Data Scaling: Values ko normalize kar rahe hain taaki sabka range same ho (Mean=0, Variance=1)
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)  # Train data se pattern seekho aur scale karo
    X_test_scaled = scaler.transform(X_test)  # Same pattern test data par apply karo
    
    # ML prediction ke time use karne ke liye scaler ko bhi save kar rahe hain
    scaler_path = os.path.join(MODELS_DIR, 'scaler.pkl')
    joblib.dump(scaler, scaler_path)
    print(f"Saved scaler to: {scaler_path}")
    
    # 5. Final processed NumPy arrays ko aage ML training ke liye data/ folder mein save kar do
    np.save(os.path.join(DATA_DIR, 'X_train.npy'), X_train_scaled)
    np.save(os.path.join(DATA_DIR, 'y_train.npy'), y_train)
    np.save(os.path.join(DATA_DIR, 'X_test.npy'), X_test_scaled)
    np.save(os.path.join(DATA_DIR, 'y_test.npy'), y_test)
    
    print("Preprocessing completed successfully!") # Sab successfully ho gaya!

# Ye check karta hai ki script direct run ho rahi hai (import nahi ki gayi)
if __name__ == '__main__':
    preprocess_data()  # Main function call karo
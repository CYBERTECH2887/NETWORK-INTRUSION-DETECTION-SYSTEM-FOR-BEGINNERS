"""
Shared model loading + ensemble decision logic.
app.py (manual / batch) aur packet_sniff.py (live) dono is file ko use karte hain, 
taaki project ke har hisse me same traffic ke liye same prediction result mile.
"""
import os
import json
import joblib
import numpy as np
from tensorflow.keras.models import load_model

# Directories set kar rahe hain taaki saved models ko load kiya ja sake
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODELS_DIR = os.path.join(BASE_DIR, "models")

# Classes ka order same hona chahiye jisme model train hua tha
CLASS_NAMES = ["Normal", "DoS", "Probe", "U2R", "R2L"]   

# Agar sabhi attacks ki milakar probability 40% (0.40) se upar hai, toh use attack maanenge
ATTACK_THRESHOLD = 0.40                                  

# Memory me pre-trained Machine Learning models aur scalers ko load kar rahe hain
rf_model = joblib.load(os.path.join(MODELS_DIR, "random_forest.pkl"))
dnn_model = load_model(os.path.join(MODELS_DIR, "dnn_model.keras"))
scaler = joblib.load(os.path.join(MODELS_DIR, "scaler.pkl"))
encoders = joblib.load(os.path.join(MODELS_DIR, "label_encoders.pkl"))

# Model me use hone wale features ke names load kar rahe hain taaki CSV batch upload aadi me columns match ho sake
try:
    with open(os.path.join(MODELS_DIR, "feature_names.json")) as f:
        FEATURE_NAMES = json.load(f)
except (OSError, ValueError):
    FEATURE_NAMES = None          # Agar purani training thi jisme JSON nahi tha, toh order file ke hisab se maanenge

# Yeh function raw categorical text input (jaise "tcp", "http") ko encode karke number me badalta hai.
# Agar live traffic me koi aisa naya text aata hai jo training me nahi tha, toh use ek `default` safe value de deta hai.
def encode_value(column, value, default):
    """LabelEncode one categorical value, falling back to `default` if it was never seen in training."""
    classes = set(encoders[column].classes_)
    value = str(value)
    if value not in classes:
        value = default if default in classes else encoders[column].classes_[0]
    return int(encoders[column].transform([value])[0])

# Dono models ke average prediction probability vector ke base par final decision leta hai.
def decide(probs):
    """Turn one averaged probability vector into (class_index, confidence)."""
    # Index 1 se end tak saari attack probabilities (DoS, Probe, U2R, R2L) ka sum karta hai
    attack_prob = float(np.sum(probs[1:]))
    
    # Agar total attack ki probability ATTACK_THRESHOLD (0.40) se zyada hai, 
    # toh jo attack class sabse zyada likely hai uska index aur probability return karta hai.
    if attack_prob > ATTACK_THRESHOLD:
        return int(np.argmax(probs[1:]) + 1), attack_prob
    
    # Warna ise "Normal" (index 0) declare kar deta hai
    return 0, float(probs[0])

# Soft Voting Logic: Yeh function scaled input data (2D array) leta hai, 
# uspar Random Forest aur DNN dono models chalata hai aur unki class probabilities ka average (mean) nikal kar return karta hai.
def ensemble_probs(scaled):
    """Soft voting: average Random Forest and DNN probabilities. `scaled` is a 2-D array."""
    rf = rf_model.predict_proba(scaled)
    dnn = dnn_model.predict(scaled, verbose=0)
    return (rf + dnn) / 2.0
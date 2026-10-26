# ==========================================
# train_models.py - Random Forest aur DNN ko train karne ke liye, aur results save karne ke liye
# Ise preprocess.py ke baad run karna hota hai
# ==========================================
import os

# TensorFlow import hone se pehle uske extra debugging logs hide karne ki settings
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'     
os.environ['TF_ENABLE_ONEDNN_OPTS'] = '0'    

import json
import warnings
import logging
import joblib
import numpy as np
import matplotlib
matplotlib.use('Agg') # GUI window nahi kholega, direct disk pe plot save karega
import matplotlib.pyplot as plt
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, ConfusionMatrixDisplay

import tensorflow as tf
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Input, Dense, Dropout
from tensorflow.keras.utils import to_categorical

warnings.filterwarnings('ignore')
tf.get_logger().setLevel(logging.ERROR)

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
DATA_DIR = os.path.join(BASE_DIR, 'data')
MODELS_DIR = os.path.join(BASE_DIR, 'models')
IMAGES_DIR = os.path.join(BASE_DIR, 'static', 'images')
os.makedirs(MODELS_DIR, exist_ok=True)
os.makedirs(IMAGES_DIR, exist_ok=True)

CLASS_NAMES = ['Normal', 'DoS', 'Probe', 'U2R', 'R2L']
ATTACK_THRESHOLD = 0.40          # Ensemble ke liye minimum attack probability
np.random.seed(42)
tf.random.set_seed(42)

# Confusion Matrix plot karke /static/images/ folder me PNG ke form me save karne ka function
def plot_and_save_cm(y_true, y_pred, model_name, filename):
    cm = confusion_matrix(y_true, y_pred, labels=range(5))
    fig, ax = plt.subplots(figsize=(7, 6))
    ConfusionMatrixDisplay(confusion_matrix=cm, display_labels=CLASS_NAMES).plot(cmap='Blues', ax=ax, values_format='d')
    plt.title(f'{model_name} Confusion Matrix')
    plt.tight_layout()
    path = os.path.join(IMAGES_DIR, filename)
    plt.savefig(path, dpi=200)
    plt.close()
    print(f"Saved plot: {path}")

# Soft voting prediction decide karne ka rule. Agar attack probability threshold se zyada hai, tabhi alert generate hoga
def ensemble_decide(probs):
    attack = probs[:, 1:].sum(axis=1)
    return np.where(attack > ATTACK_THRESHOLD, probs[:, 1:].argmax(axis=1) + 1, 0)

# Main training and evaluation logic
def train_and_evaluate():
    # Preprocessed data load kar rahe hain
    X_train = np.load(os.path.join(DATA_DIR, 'X_train.npy'))
    y_train = np.load(os.path.join(DATA_DIR, 'y_train.npy'))
    X_test = np.load(os.path.join(DATA_DIR, 'X_test.npy'))
    y_test = np.load(os.path.join(DATA_DIR, 'y_test.npy'))

    # 1. RANDOM FOREST CLASSIFIER train karna aur accuracy nikalna
    print("\n[1/3] Training Random Forest...")
    rf = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1, class_weight='balanced')
    rf.fit(X_train, y_train)
    rf_probs = rf.predict_proba(X_test)
    rf_preds = rf_probs.argmax(axis=1)
    rf_acc = accuracy_score(y_test, rf_preds)
    print(f"-> Random Forest accuracy: {rf_acc * 100:.2f}%")
    joblib.dump(rf, os.path.join(MODELS_DIR, 'random_forest.pkl'))
    plot_and_save_cm(y_test, rf_preds, 'Random Forest', 'random_forest_cm.png')

    # 2. DEEP NEURAL NETWORK (DNN) train karna
    print("\n[2/3] Training DNN...")
    dnn = Sequential([
        Input(shape=(X_train.shape[1],)),
        Dense(128, activation='relu'), Dropout(0.3),
        Dense(64, activation='relu'), Dropout(0.2),
        Dense(32, activation='relu'),
        Dense(5, activation='softmax'), # 5 output classes ke liye Softmax
    ])
    dnn.compile(optimizer='adam', loss='categorical_crossentropy', metrics=['accuracy'])
    dnn.fit(X_train, to_categorical(y_train, 5), epochs=15, batch_size=64,
            validation_data=(X_test, to_categorical(y_test, 5)), verbose=1)
    dnn_probs = dnn.predict(X_test, verbose=0)
    dnn_preds = dnn_probs.argmax(axis=1)
    dnn_acc = accuracy_score(y_test, dnn_preds)
    print(f"-> DNN accuracy: {dnn_acc * 100:.2f}%")
    dnn.save(os.path.join(MODELS_DIR, 'dnn_model.keras'))
    plot_and_save_cm(y_test, dnn_preds, 'Deep Neural Network', 'dnn_cm.png')

    # 3. ENSEMBLE EVALUATION (Dono models ka soft voting)
    print("\n[3/3] Evaluating ensemble (soft voting)...")
    ens_preds = ensemble_decide((rf_probs + dnn_probs) / 2.0)
    ens_acc = accuracy_score(y_test, ens_preds)
    print(f"-> Ensemble accuracy: {ens_acc * 100:.2f}%")
    print(classification_report(y_test, ens_preds, labels=range(5), target_names=CLASS_NAMES, zero_division=0))
    plot_and_save_cm(y_test, ens_preds, 'Ensemble (RF + DNN)', 'ensemble_cm.png')

    # Accuracy numbers ko ek JSON me write kar rahe hain jise Flask app frontend "Model Architecture" page pe read karta hai
    with open(os.path.join(MODELS_DIR, 'metrics.json'), 'w') as f:
        json.dump({'rf_acc': round(rf_acc * 100, 2), 'dnn_acc': round(dnn_acc * 100, 2),
                   'ens_acc': round(ens_acc * 100, 2), 'train_size': int(len(y_train)),
                   'test_size': int(len(y_test))}, f)
    print("Saved models/metrics.json")

if __name__ == '__main__':
    train_and_evaluate()
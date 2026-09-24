# ==========================================
# BLOCK 1: Imports
# ==========================================
import os
import joblib
import numpy as np
import matplotlib.pyplot as plt
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, ConfusionMatrixDisplay


# ==========================================
# BLOCK 2: Directory Configurations
# ==========================================
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
DATA_DIR = os.path.join(BASE_DIR, 'data')
MODELS_DIR = os.path.join(BASE_DIR, 'models')
IMAGES_DIR = os.path.join(BASE_DIR, 'static', 'images')

os.makedirs(MODELS_DIR, exist_ok=True)
os.makedirs(IMAGES_DIR, exist_ok=True)


# ==========================================
# BLOCK 3: Global Constants
# ==========================================
CLASS_NAMES = ['Normal', 'DoS', 'Probe', 'U2R', 'R2L']


# ==========================================
# BLOCK 4: Evaluation Metrics & Plotting
# ==========================================
def plot_and_save_cm(y_true, y_pred, model_name, filename):
    """
    Generates and saves confusion matrix plots.
    """
    cm = confusion_matrix(y_true, y_pred)
    disp = ConfusionMatrixDisplay(confusion_matrix=cm, display_labels=CLASS_NAMES)
    
    fig, ax = plt.subplots(figsize=(7, 6))
    disp.plot(cmap='Blues', ax=ax, values_format='d')
    
    plt.title(f'{model_name} Confusion Matrix')
    plt.tight_layout()
    
    save_path = os.path.join(IMAGES_DIR, filename)
    plt.savefig(save_path, dpi=300)
    plt.close()
    
    print(f"Saved evaluation plot to: {save_path}")


# ==========================================
# BLOCK 5: Model Training and Evaluation
# ==========================================
def train_and_evaluate():
    
    # ----------------------------------------
    # 5.1: Load Preprocessed Data
    # ----------------------------------------
    print("Loading preprocessed arrays from data/...")
    
    X_train = np.load(os.path.join(DATA_DIR, 'X_train.npy'))
    y_train = np.load(os.path.join(DATA_DIR, 'y_train.npy'))
    X_test = np.load(os.path.join(DATA_DIR, 'X_test.npy'))
    y_test = np.load(os.path.join(DATA_DIR, 'y_test.npy'))
        
    # ----------------------------------------
    # 5.2: Train Random Forest Classifier
    # ----------------------------------------
    print("\n[1/1] Training Random Forest Classifier...")
    
    rf_model = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1, class_weight='balanced')
    rf_model.fit(X_train, y_train)
    rf_preds = rf_model.predict(X_test)
    
    # ----------------------------------------
    # 5.3: Calculate Accuracy & Save Model
    # ----------------------------------------
    rf_acc = accuracy_score(y_test, rf_preds)
    print(f"-> Random Forest Test Accuracy: {rf_acc * 100:.2f}%")
    
    rf_path = os.path.join(MODELS_DIR, 'random_forest.pkl')
    joblib.dump(rf_model, rf_path)
    print(f"Saved model to: {rf_path}")
    
    # ----------------------------------------
    # 5.4: Generate Reports and Plots
    # ----------------------------------------
    plot_and_save_cm(y_test, rf_preds, 'Random Forest', 'random_forest_cm.png')
    
    print("\n" + "="*50)
    print("Random Forest Classification Report:")
    print("="*50)
    print(classification_report(y_test, rf_preds, target_names=CLASS_NAMES, zero_division=0))


# ==========================================
# BLOCK 6: Script Execution
# ==========================================
if __name__ == '__main__':
    train_and_evaluate()
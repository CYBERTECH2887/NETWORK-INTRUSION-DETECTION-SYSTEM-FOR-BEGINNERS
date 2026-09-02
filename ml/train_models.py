import os  # OS module import kiya taaki folder aur file paths ko easily manage kiya ja sake
import joblib  # joblib module import kiya ML models (.pkl files) ko save aur load karne ke liye 
import numpy as np  # NumPy import kiya numerical data aur matrix arrays (jaise X_train) handle karne ke liye 
import matplotlib.pyplot as plt  # Matplotlib ka pyplot import kiya graphs aur charts (jaise confusion matrix) draw karne ke liye 
from sklearn.tree import DecisionTreeClassifier  # Scikit-learn se Decision Tree algorithm ka tool import kiya 
from sklearn.ensemble import RandomForestClassifier  # Scikit-learn se Random Forest algorithm import kiya 
# sklearn.metrics se models ki accuracy, classification report aur confusion matrix check karne ke tools import kiye 
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, ConfusionMatrixDisplay

# Project ke root folder ka dynamic path nikal rahe hain taaki kisi bhi computer par chal sake
# __file__ current script ka path deta hai, aur '..' usko ek folder peeche (root par) le jata hai
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
DATA_DIR = os.path.join(BASE_DIR, 'data')  # Clean data arrays (.npy) save/load karne ke liye 'data' folder ka rasta 
MODELS_DIR = os.path.join(BASE_DIR, 'models')  # Trained models (.pkl) save karne ke liye 'models' folder ka rasta 
IMAGES_DIR = os.path.join(BASE_DIR, 'static', 'images')  # UI ke liye graph images save karne ka rasta 

# Agar models aur images folders nahi bane hain, toh unhe create kar do (exist_ok=True error se bachata hai agar folder pehle se ho)
os.makedirs(MODELS_DIR, exist_ok=True)
os.makedirs(IMAGES_DIR, exist_ok=True)

# Dataset ki 5 main classes ke naam define kiye (0=Normal, 1=DoS, 2=Probe, 3=U2R, 4=R2L) 
CLASS_NAMES = ['Normal', 'DoS', 'Probe', 'U2R', 'R2L']

# def keyword ek naya function banata hai. Ye function Confusion Matrix plot karke image save karega .
def plot_and_save_cm(y_true, y_pred, model_name, filename):
    """Generates and saves confusion matrix plots to static/images/"""
    
    # confusion_matrix() true answers aur predicted answers ko compare karke ek matrix banata hai 
    cm = confusion_matrix(y_true, y_pred)
    
    # ConfusionMatrixDisplay is matrix ko ek visual format (graph) mein convert karta hai 
    disp = ConfusionMatrixDisplay(confusion_matrix=cm, display_labels=CLASS_NAMES)
    
    # plt.subplots() ek naya canvas (fig) aur plot area (ax) banata hai jiska size 7x6 inches hoga 
    fig, ax = plt.subplots(figsize=(7, 6))
    
    # disp.plot() matrix ko draw karta hai. cmap='Blues' color scheme hai aur values_format='d' numbers ko integer format mein rakhta hai 
    disp.plot(cmap='Blues', ax=ax, values_format='d')
    
    # plt.title() graph ke upar model ka naam as a title set karta hai 
    plt.title(f'{model_name} Confusion Matrix')
    
    # plt.tight_layout() extra spaces hata kar graph ko neatly arrange karta hai 
    plt.tight_layout()
    
    # Image ko save karne ka poora rasta (path) banaya
    save_path = os.path.join(IMAGES_DIR, filename)
    
    # plt.savefig() graph ko us raste par ek image file (jaise .png) ki tarah save kar deta hai (dpi=300 high quality ke liye) 
    plt.savefig(save_path, dpi=300)
    
    # plt.close() memory free karne ke liye graph figure ko close kar deta hai 
    plt.close()
    
    # print() terminal par success message dikhata hai ki graph kahan save hua
    print(f"Saved evaluation plot to: {save_path}")

# Ye hamara main function hai jo ML models ko train aur test karega 
def train_and_evaluate():
    # 1. Load Preprocessed Data
    print("Loading preprocessed arrays from data/...")
    
    # np.load() preprocessed data (.npy files) ko folder se wapas code (memory) mein Numpy arrays ke form mein lata hai 
    X_train = np.load(os.path.join(DATA_DIR, 'X_train.npy'))  # Training questions (Features)
    y_train = np.load(os.path.join(DATA_DIR, 'y_train.npy'))  # Training answers (Target Labels)
    X_test = np.load(os.path.join(DATA_DIR, 'X_test.npy'))    # Testing questions
    y_test = np.load(os.path.join(DATA_DIR, 'y_test.npy'))    # Testing answers
    
    # ---------------------------------------------------------
    # 2. Train Decision Tree
    # ---------------------------------------------------------
    print("\n[1/2] Training Decision Tree Classifier...")
    
    # DecisionTreeClassifier() algorithm ka ek khali object (model) banata hai. 
    # class_weight='balanced' rare attacks (U2R, R2L) ko extra dhyan dene ko kehta hai taaki model unhe ignore na kare 
    dt_model = DecisionTreeClassifier(random_state=42, class_weight='balanced')
    
    # .fit() model ko X_train aur y_train data dekar usme patterns seekhne (train hone) ko kehta hai 
    dt_model.fit(X_train, y_train)
    
    # .predict() trained model ko test data (X_test) deta hai taaki wo apne answers guess (predict) kare 
    dt_preds = dt_model.predict(X_test)
    
    # accuracy_score() check karta hai ki model ke guess (dt_preds) asli answers (y_test) se kitne match hote hain 
    dt_acc = accuracy_score(y_test, dt_preds)
    
    # Test accuracy ko percentage mein print kiya (.2f matlab decimal ke baad 2 digits)
    print(f"-> Decision Tree Test Accuracy: {dt_acc * 100:.2f}%")
    
    # Trained Decision Tree Model ko .pkl file mein save karne ka path banaya 
    dt_path = os.path.join(MODELS_DIR, 'decision_tree.pkl')
    
    # joblib.dump() model ki memory/learning ko hard drive par file mein physically save kar deta hai 
    joblib.dump(dt_model, dt_path)
    print(f"Saved model to: {dt_path}")
    
    # Upar banaya gaya graph wala function call kiya taaki is model ka Confusion Matrix save ho jaye 
    plot_and_save_cm(y_test, dt_preds, 'Decision Tree', 'decision_tree_cm.png')
    
    # ---------------------------------------------------------
    # 3. Train Random Forest
    # ---------------------------------------------------------
    print("\n[2/2] Training Random Forest Classifier...")
    
    # RandomForestClassifier() algorithm ka object banata hai. n_estimators=100 matlab 100 trees banenge. n_jobs=-1 PC ke saare cores use karta hai speed ke liye 
    rf_model = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1, class_weight='balanced')
    
    # .fit() se Random Forest ko data dekar train kar rahe hain 
    rf_model.fit(X_train, y_train)
    
    # .predict() se test data par predictions nikal rahe hain 
    rf_preds = rf_model.predict(X_test)
    
    # Random forest ki accuracy calculate ki 
    rf_acc = accuracy_score(y_test, rf_preds)
    print(f"-> Random Forest Test Accuracy: {rf_acc * 100:.2f}%")
    
    # Random Forest Model ko .pkl file mein save kar rahe hain taaki Flask backend ise use kar sake 
    rf_path = os.path.join(MODELS_DIR, 'random_forest.pkl')
    joblib.dump(rf_model, rf_path)
    print(f"Saved model to: {rf_path}")
    
    # Random Forest ka Confusion Matrix graph draw aur save kiya 
    plot_and_save_cm(y_test, rf_preds, 'Random Forest', 'random_forest_cm.png')
    
    # ---------------------------------------------------------
    # Summary Report
    # ---------------------------------------------------------
    print("\n" + "="*50)
    print("Random Forest Classification Report:")
    print("="*50)
    
    # classification_report() Precision, Recall, aur F1-Score ki ek detailed report generate karke print karta hai 
    print(classification_report(y_test, rf_preds, target_names=CLASS_NAMES, zero_division=0))

# Ye if condition check karti hai ki kya file direct run ki ja rahi hai (terminal se python script.py ki tarah). 
# Agar haan, toh uske andar likha function (train_and_evaluate) run hoga.
if __name__ == '__main__':
    train_and_evaluate()
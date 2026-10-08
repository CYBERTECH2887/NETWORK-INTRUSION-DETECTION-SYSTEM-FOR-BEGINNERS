```markdown
# 🛡️ CRACKA NIDS ⚡
**Advanced Network Intrusion Detection System**

CRACKA NIDS is a modern, machine learning-powered web application designed to detect and classify network intrusions in real-time. By bridging the gap between data science and network security, the system utilizes a trained Random Forest model to analyze network traffic and identify anomalies such as DoS, Probe, U2R, and R2L attacks at wire speed.

---

## ✨ Key Features

* **🧠 Machine Learning Engine:** Powered by a Random Forest classifier trained on the NSL-KDD dataset using a 41-feature extraction pipeline (StandardScaler & LabelEncoder).
* **📡 Live Packet Sniffing:** Intercepts live TCP/UDP/ICMP packets via `scapy`, extracts session parameters dynamically, and provides sub-second threat predictions.
* **🗂️ Batch CSV Processing:** Upload enterprise-scale traffic logs to automatically parse, standardize, encode, and score thousands of packets instantly.
* **⌨️ Manual Prediction Interface:** Input raw traffic metrics via a structured form to test the model's accuracy on the fly.
* **🔊 Dynamic Audio-Visual Alerts:** Features pulsing status orbs and triggers an MP3 audio beep whenever an active anomaly/threat is detected.
* **🔐 Secure Authentication:** Includes user registration, login, and a "Forgot Password" flow with industry-standard Werkzeug password hashing.
* **💾 History Management:** Securely logs live prediction sessions, packet metrics, timestamps, and threat levels into a MySQL database.
* **🌗 Modern UI/UX:** Responsive Glassmorphism design featuring seamless Dark (Deep Violet/Cyber Blue) and Light (Vibrant Orange/Indigo) theme toggling with `localStorage` persistence.

---

## 🛠️ Technology Stack

* **Backend:** Python 3, Flask, Werkzeug (Security)
* **Machine Learning:** Scikit-Learn, Pandas, NumPy, Joblib
* **Network Analysis:** Scapy (Requires Npcap on Windows)
* **Database:** MySQL, `mysql-connector-python`
* **Frontend:** HTML5, CSS3 (Glassmorphism), Vanilla JavaScript, Jinja2

---

## ⚙️ Prerequisites

Before you begin, ensure you have the following installed on your machine:
1. **Python 3.8+**
2. **MySQL Server** (Running locally on port 3306)
3. **Npcap** (Required for Windows users to allow `scapy` to sniff packets. Download from [nmap.org/npcap](https://nmap.org/npcap/))

---

## 🚀 Installation & Setup

**1. Clone the repository**
```bash
git clone [https://github.com/yourusername/cracka-nids.git](https://github.com/yourusername/cracka-nids.git)
cd cracka-nids

```

**2. Install dependencies**

```bash
pip install -r requirements.txt

```

**3. Configure the Database**
Ensure your local MySQL server is running. If your MySQL root password is not `mysql`, update the `DB_CONFIG` dictionary in `create_db_2.py`.
Initialize the database, create tables, and generate the default admin account:

```bash
python create_db_2.py

```

*(Default Admin Credentials - Username: `admin`, Password: `admin123`)*

**4. Preprocess Data & Train the Model**
Ensure your `KDDTest+.csv` and `KDDTrain+.csv` datasets are placed in the `data/` directory.

```bash
python preprocess.py
python train_models.py

```

*This will generate the required `.pkl` files (Random Forest model, Scaler, and Encoders) inside the `models/` directory.*

**5. Start the Application**

```bash
python app.py

```

*The Flask server will start, and a new browser tab will automatically open to `http://127.0.0.1:5000/`.*

---

## 📂 Project Structure

```text
CRACKA_NIDS/
│
├── app.py                   # Main Flask application and routing engine
├── create_db_2.py           # MySQL database initialization and schema setup
├── preprocess.py            # NSL-KDD dataset cleaning, encoding, and scaling script
├── train_models.py          # Random Forest training and evaluation script
├── requirements.txt         # Project dependencies
│
├── data/                    # Directory for raw datasets and numpy arrays
│   ├── KDDTrain+.csv
│   └── KDDTest+.csv
│
├── models/                  # Directory for saved ML artifacts
│   ├── random_forest.pkl
│   ├── scaler.pkl
│   └── label_encoders.pkl
│
├── utils/
│   └── packet_sniff_2.py    # Scapy live packet capture and 41-feature extraction logic
│
├── static/
│   ├── css/
│   │   └── style.css        # Main glassmorphism stylesheet with theme variables
│   ├── js/
│   │   ├── main.js          # Theme toggling and local storage logic
│   │   └── manual_predict.js# Manual prediction AJAX logic
│   ├── images/              # Evaluation plots and architecture diagrams
│   └── audio/
│       └── beep.mp3         # Threat detection alert sound
│
└── templates/               # Jinja2 HTML templates
    ├── base.html            # Base layout with sidebar and navbar
    ├── index.html           # Advanced landing page with terminal animation
    ├── login.html           # Secure login portal
    ├── register.html        # Account creation portal
    ├── forgot_password.html # Password reset flow
    ├── dashboard.html       # Analytics and charts
    ├── overview.html        # Project documentation and architecture
    ├── live_prediction.html # CSV batch upload and live Scapy sniffing UI
    ├── manual_prediction.html # Form-based traffic testing UI
    ├── model_description.html # ML evaluation metrics and matrices
    └── history_logs.html    # User-specific prediction history tables

```

---

## ⚠️ Important Notes

* **Administrator Privileges:** Live packet sniffing with `scapy` requires elevated privileges. On Windows, ensure you run your command prompt or IDE as **Administrator**. On Linux/macOS, run the app using `sudo python app.py`.
* **Testing Offline:** For demonstration purposes without internet traffic, use the **Manual Prediction** or **Batch CSV** modules to verify model accuracy.

```

```

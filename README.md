# NETWORK-INTRUSION-DETECTION-SYSTEM-FOR-BEGINNERS
# 🛡️NIDS: AI-Powered Network Intrusion Detection System

NIDS is a robust, Machine Learning-based Network Intrusion Detection System designed to monitor, classify, and mitigate cyber threats in real-time. Built using the NSL-KDD benchmark dataset, this system identifies complex anomalies and zero-day attacks that traditional firewalls often miss. 

It features an interactive dark-themed web dashboard for manual inspections, batch CSV processing, and live network packet sniffing.

---

## 🚀 Features
* **Multi-Class Threat Detection:** Categorizes traffic into Normal, DoS, Probe, U2R, and R2L.
* **Live Packet Sniffing:** Intercepts real-time network traffic using `Scapy`.
* **Machine Learning Core:** Powered by Random Forest and Decision Tree classifiers.
* **Interactive Dashboard:** Offers manual prediction forms, drag-and-drop CSV uploads, and global threat analytics.
* **Completely Offline UI:** No external CSS/JS dependencies (fully independent architecture).

---

## 🛠️ Installation & Setup Guide

Follow these step-by-step instructions to get the project running on your local machine.

### Prerequisites
* Python 3.8 or higher installed.
* Administrative / Root privileges (Strictly required for live network sniffing).

### Step 1: Clone the Repository
```bash
git clone(https://github.com/CYBERTECH2887/NETWORK-INTRUSION-DETECTION-SYSTEM-FOR-BEGINNERS.git)

```

### Step 2: Install Dependencies

It is recommended to use a virtual environment. Install the required Python libraries using:

```bash
pip install -r requirements.txt

```

### Step 3: Train the Models (Initial Setup)

Before running the server, you must train the machine learning models and generate the preprocessors.

```bash
cd ml
python preprocess_data.py
python train_models.py
cd ..

```

*(This will generate `.pkl` files and confusion matrix images in the `models/` and `static/images/` folders).*

### Step 4: Start the Flask Server

**Crucial Note:** To use the Live Packet Sniffing feature, you MUST run your terminal or IDE (like VS Code) as an **Administrator** (Windows) or use `sudo` (Linux/Mac).

```bash
python app.py

```

*The server will start on `http://127.0.0.1:5000`.*

---

## 🖥️ Webpage Navigation & Usage Guide

Once the server is running, open your browser and navigate to `http://127.0.0.1:5000`. Here is how to use each module of the CRACKA NIDS suite:

### 1. Project Overview (`/overview`)

* **What it is:** The landing page of the application.
* **How to use:** Read through the objective, scope, and the 4 core modules (Data Preprocessing, Model Training, Backend API, Frontend Interface) to understand the system's architecture.

### 2. Dashboard Analytics (`/dashboard`)

* **What it is:** A visual representation of global cyber threats and the impact of the NIDS.
* **How to use:** Review the static charts (Line, Bar, Doughnut, and GeoMap) to understand the distribution of network traffic and the severity of the 4 major attack types (DoS, Probe, U2R, R2L).

### 3. Manual Prediction (`/manual_prediction`)

* **What it is:** A tool for security analysts to manually input packet features and test the model's response.
* **How to use:**
1. Fill in the network parameters (Duration, Protocol, Service, Flag, Bytes, etc.).
2. Click the **"Analyze Traffic"** button.
3. The *Resultboard* on the right will instantly update, showing whether the traffic is "NORMAL" or an "ALERT" (Malicious), along with a confidence percentage and a glowing status orb.



### 4. Upload CSV / Live Sniffing (`/live_prediction`)

* **What it is:** The core functional page for bulk analysis and real-time monitoring.
* **Action A: Batch CSV Analysis**
1. Drag and drop a `.csv` or `.txt` file containing network logs into the upload zone, or click "Browse Files".
2. The UI will update to show the selected file with a "Remove File" option.
3. Click **"Run Batch Analysis"**.
4. The system will process the entire file and populate the table below with Record IDs, Protocols, Predicted Status, and Confidence scores. Red text indicates an attack.


* **Action B: Live Network Traffic Sniffing**
1. Scroll down to the "Live Network Traffic Sniffing" panel.
2. Click the blue **"▶️ Start Live Sniffing"** button.
3. The button will turn red ("🛑 Stop Live Sniffing"). The system will now query the backend every 3 seconds to fetch packets intercepted by your network card.
4. Watch real-time packets populate the table dynamically. Click the button again to halt sniffing. *(Requires Admin rights)*.



### 5. Model Architecture (`/model_description`)

* **What it is:** A technical breakdown of the deployed Machine Learning models.
* **How to use:** Review the test accuracy scores of the Random Forest and Decision Tree classifiers. Analyze the dynamically generated Confusion Matrices to see how well the model separates Normal traffic from Stealth attacks.

---

## 📁 Project Structure

```text
├── data/                  # NSL-KDD Datasets 
├── ml/                    # Data preprocessing and model training scripts
├── models/                # Serialized .pkl files (Encoders, Scalers, Models)
├── static/                # CSS, JS, and dynamically generated images
├── templates/             # HTML dashboard pages
├── utils/                 # Scapy packet sniffing logic
├── app.py                 # Main Flask server
└── requirements.txt       # Python dependencies

```

---

**Developed with ❤️ for enhanced Network Security.**

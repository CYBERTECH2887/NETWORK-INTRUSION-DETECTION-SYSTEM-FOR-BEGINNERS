# 🛡️ CRACKA NIDS — AI-Powered Network Intrusion Detection System

CRACKA NIDS is a Machine Learning-based Network Intrusion Detection System built on the **NSL-KDD** benchmark dataset. It classifies network traffic into five categories — **Normal, DoS, Probe, U2R, and R2L** — using a trained Random Forest classifier, and ships with a full authenticated web dashboard for manual inspection, batch CSV analysis, and real-time packet sniffing.

---

## 🚀 Features

* **Multi-Class Threat Detection** — Classifies traffic into Normal, DoS, Probe, U2R, and R2L.


* **Live Packet Sniffing** — Captures real-time network traffic using `Scapy`.


* **Batch CSV Analysis** — Upload a CSV of network records and get predictions for every row in one go.


* **Manual Prediction** — Enter individual traffic parameters and get an instant NORMAL / ALERT verdict with a confidence score.


* **Secure Authentication** — Session-based login & registration, with user accounts and prediction histories safely stored in a **MySQL** database.


* **Per-User History Logs** — Every sniffing session is saved and viewable per user, with a one-click "Clear History" option.


* **Model Insights** — Dedicated page showing accuracy, per-class precision/recall, and the confusion matrix.


* **Dark / Light Theme** — Glassmorphic dashboard UI with a persistent theme toggle.


* **Fully Offline Frontend** — No external CSS/JS CDN dependencies.

---

## 🛠️ Installation & Setup Guide

### Prerequisites

* Python 3.8 or higher
* **MySQL Server** (running locally or remotely)


* Administrative / Root privileges (required for live packet sniffing)
* **Windows users:** install [Npcap](https://npcap.com/?utm_source=gemini) separately for `Scapy` to work



### Step 1: Clone the Repository

```bash
git clone https://github.com/<your-username>/CRACKA-NIDS.git
cd CRACKA-NIDS

```

### Step 2: Install Dependencies

It's recommended to use a virtual environment.

```bash
pip install -r requirements.txt

```

### Step 3: Initialize the MySQL Database

Ensure your MySQL server is running. Update the `DB_CONFIG` credentials in `create_db.py` if your local setup uses a different username or password, then run the initialization script to create the `nids_database` and required tables:

```bash
python create_db.py

```

### Step 4: Train the Models

This processes the dataset, standardizes the features, and generates the `.pkl` files (model, scaler, encoders) alongside the confusion matrix image.

```bash
python ml/preprocess.py
python ml/train_models.py

```

### Step 5: Start the Flask Server

```bash
python app.py

```

The server starts at `[http://127.0.0.1:5000](http://127.0.0.1:5000)` and opens automatically in your browser.

> **Default login:** On the first database initialization, an admin account is auto-created — `admin` / `admin123`. Change this before deploying anywhere public.
> 
> 

**Live Packet Sniffing note:** Run your terminal/IDE as **Administrator** (Windows) or with `sudo` (Linux/Mac) so `Scapy` is allowed to capture packets.

---

## 🖥️ Webpage Navigation & Usage Guide

### 1. Login / Register (`/login`, `/register`)

Create an account or sign in — every other page requires an active session.

### 2. Project Overview (`/overview`)

Landing page explaining the objective, scope, and the four core modules — Data Preprocessing, Model Training, Backend API, and Frontend Interface.

### 3. Dashboard Analytics (`/dashboard`)

High-level cards on the problem, global impact, and the four attack types, alongside illustrative charts (Line, Bar, Pie, Map) and a working flowchart.

### 4. Manual Prediction (`/manual_prediction`)

1. Fill in the traffic parameters (Duration, Protocol, Service, Flag, Bytes, Failed Logins).


2. Click **Analyze Traffic**.


3. The Resultboard updates instantly with NORMAL / ALERT, a confidence %, and a glowing status orb.



### 5. Upload CSV / Live Sniffing (`/live_prediction`)

**Batch CSV Analysis**

1. Drag & drop (or browse) a `.csv` file formatted like the NSL-KDD feature set.


2. Click **Run Batch Analysis**.


3. Results populate the table below — Record ID, Protocol, Predicted Status, Confidence.



**Live Network Traffic Sniffing**

1. Click **▶️ Start Live Sniffing**.


2. The app polls the backend roughly every 1.5 seconds and streams intercepted packets into the table in real time.


3. Click **🛑 Stop Live Sniffing** to end the session — captured packets are saved directly to your MySQL database session history.



### 6. Model Architecture (`/model_description`)

Technical breakdown of the deployed Random Forest model — 75.49% test accuracy, the 41-feature preprocessing pipeline (LabelEncoder + StandardScaler), UML models, the full classification report, and the confusion matrix.

### 7. History Logs (`/history_logs`)

Every completed live-sniffing session, grouped by Session ID and scoped to the logged-in user, with a **Clear History** button to wipe your own logs from the database.

---

## 📊 Model Performance

Random Forest classifier, evaluated on the KDDTest+ set (22,544 records):

| Class | Precision | Recall | F1-Score | Support |
| --- | --- | --- | --- | --- |
| Normal | 0.66 | 0.97 | 0.78 | 9,853 |
| DoS | 0.96 | 0.78 | 0.86 | 7,460 |
| Probe | 0.85 | 0.68 | 0.76 | 2,421 |
| U2R | 0.60 | 0.09 | 0.16 | 67 |
| R2L | 0.81 | 0.01 | 0.02 | 2,743 |

**Overall test accuracy: 75.49%**

---

## 📁 Project Structure

```text
├── data/                  # NSL-KDD datasets (KDDTrain+.csv, KDDTest+.csv)
├── ml/                    # preprocess.py, train_models.py
├── models/                # Serialized .pkl files (model, scaler, label encoders)
├── static/                # CSS, JS, and images (charts + confusion matrix)
├── templates/             # HTML dashboard pages
├── utils/                 # Scapy packet sniffing logic (packet_sniff.py)
├── app.py                 # Main Flask server
├── create_db.py           # MySQL database and table initialization script
└── requirements.txt       # Python dependencies

```

---

**Developed with ❤️ for enhanced Network Security by Team CRACKA.**

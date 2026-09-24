# ==========================================
# BLOCK 1: Imports and Application Initialization
# ==========================================
import os
import io
import joblib
import webbrowser
import numpy as np
import pandas as pd
from threading import Timer
from flask import Flask, render_template, request, jsonify, redirect, url_for, session
from scapy.all import sniff
from utils.packet_sniff import predict 
import sqlite3

app = Flask(__name__)
app.secret_key = 'cracka_nids_secret_key_2026'

# ==========================================
# BLOCK 1.2: Database Initialization
# ==========================================
def init_db():
    conn = sqlite3.connect('nids_history.db')
    c = conn.cursor()
    
    # History Logs Table (Added 'session_id' column)
    c.execute('''CREATE TABLE IF NOT EXISTS packet_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT,
                    session_id INTEGER,
                    packet_id INTEGER,
                    ip_address TEXT,
                    protocol TEXT,
                    prediction TEXT,
                    confidence TEXT,
                    date TEXT,
                    time TEXT
                )''')
                
    # User Authentication Table (Updated with new fields)
    c.execute('''CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    fullname TEXT,
                    username TEXT UNIQUE NOT NULL,
                    email TEXT,
                    phone TEXT,
                    dob TEXT,
                    profession TEXT,
                    gender TEXT,
                    password TEXT NOT NULL
                )''')
    
    # Default Admin account add karein agar database khali hai
    c.execute('SELECT COUNT(*) FROM users')
    if c.fetchone()[0] == 0:
        c.execute('''INSERT INTO users 
                     (fullname, username, email, phone, dob, profession, gender, password) 
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?)''', 
                  ("System Administrator", "admin", "admin@crackanids.local", "0000000000", "2000-01-01", "IT Admin", "Other", "admin123"))
    conn.commit()
    conn.close()

init_db()

# Global list to hold packets during the active sniffing session
current_session_packets = []
# ==========================================
# BLOCK 2: Directory Configuration & Model Loading
# ==========================================
BASE_DIR = os.path.abspath(os.getcwd())
MODELS_DIR = os.path.join(BASE_DIR, 'models')

rf_model = joblib.load(os.path.join(MODELS_DIR, 'random_forest.pkl'))
scaler = joblib.load(os.path.join(MODELS_DIR, 'scaler.pkl'))
encoders = joblib.load(os.path.join(MODELS_DIR, 'label_encoders.pkl'))

CLASS_NAMES = ['Normal', 'DoS', 'Probe', 'U2R', 'R2L']
# ==========================================
# BLOCK 3: Authentication Routes (Login & Register)
# ==========================================
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        conn = sqlite3.connect('nids_history.db')
        c = conn.cursor()
        c.execute('SELECT * FROM users WHERE username = ? AND password = ?', (username, password))
        user = c.fetchone()
        conn.close()
        
        if user:
            session['user'] = username
            # Database columns ke index ke hisaab se baaki details session mein store kar rahe hain
            # (0:id, 1:fullname, 2:username, 3:email, 4:phone, 5:dob, 6:profession, 7:gender, 8:password)
            session['user_details'] = {
                'fullname': user[1],
                'email': user[3],
                'phone': user[4],
                'dob': user[5],
                'profession': user[6],
                'gender': user[7]
            }
            return redirect(url_for('dashboard'))
        else:
            return render_template('login.html', error="Invalid username or password!")
            
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        fullname = request.form.get('fullname')
        username = request.form.get('username')
        email = request.form.get('email')
        phone = request.form.get('phone')
        dob = request.form.get('dob')
        profession = request.form.get('profession')
        gender = request.form.get('gender')
        password = request.form.get('password')
        
        conn = sqlite3.connect('nids_history.db')
        c = conn.cursor()
        
        # Check if username already exists
        c.execute('SELECT * FROM users WHERE username = ?', (username,))
        existing_user = c.fetchone()
        
        if existing_user:
            conn.close()
            return render_template('register.html', error="Username already exists!")
        
        # Insert all data into database
        c.execute('''INSERT INTO users 
                     (fullname, username, email, phone, dob, profession, gender, password) 
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?)''', 
                  (fullname, username, email, phone, dob, profession, gender, password))
        conn.commit()
        conn.close()
        
        return redirect(url_for('login'))
        
    return render_template('register.html')

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('login'))
# ==========================================
# BLOCK 4: Page Rendering Routes (Protected)
# ==========================================
@app.before_request
def require_login():
    allowed_routes = ['login', 'register', 'static']
    if request.endpoint and request.endpoint not in allowed_routes and 'user' not in session:
        return redirect(url_for('login'))

@app.route('/')
@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html', username=session.get('user'))

@app.route('/overview')
def overview():
    return render_template('overview.html')

@app.route('/manual_prediction')
def manual_prediction():
    return render_template('manual_prediction.html')

@app.route('/live_prediction')
def live_prediction():
    return render_template('live_prediction.html')

@app.route('/model_description')
def model_description():
    return render_template('model_description.html')


# ==========================================
# BLOCK 5: Manual Prediction API Endpoint
# ==========================================
@app.route('/api/predict_manual', methods=['POST'])
def predict_manual():
    try:
        data = request.json
        duration = float(data.get('duration', 0))
        protocol = data.get('protocol_type', 'tcp').lower()
        service = data.get('service', 'http').lower()
        flag = data.get('flag', 'SF').upper()
        src_bytes = float(data.get('src_bytes', 0))
        dst_bytes = float(data.get('dst_bytes', 0))
        failed_logins = float(data.get('num_failed_logins', 0))

        try:
            proto_encoded = encoders['protocol_type'].transform([protocol])[0]
        except Exception:
            proto_encoded = 0

        try:
            service_encoded = encoders['service'].transform([service])[0]
        except Exception:
            service_encoded = 0

        try:
            flag_encoded = encoders['flag'].transform([flag])[0]
        except Exception:
            flag_encoded = 0

        count, srv_count = 1, 1
        serror_rate, rerror_rate, diff_srv_rate, dst_host_diff_srv_rate = 0.0, 0.0, 0.0, 0.0
        is_guest_login, num_compromised, hot = 0, 0, 0
        dst_host_count, dst_host_srv_count = 255, 255
        root_shell, su_attempted, num_root, num_file_creations = 0, 0, 0, 0

        if 900 <= duration <= 1000:
            root_shell, su_attempted, num_root, num_file_creations = 1, 1, 10, 5
            num_compromised, hot, dst_host_count, dst_host_srv_count = 5, 10, 1, 1

        if flag == 'S0':
            count, srv_count, serror_rate = 250, 250, 1.0
        elif flag == 'REJ':
            count, srv_count, rerror_rate, diff_srv_rate, dst_host_diff_srv_rate = 20, 1, 1.0, 1.0, 1.0
            
        if failed_logins > 0:
            is_guest_login, num_compromised, hot, count, srv_count, dst_host_count, dst_host_srv_count = 1, 1, 5, 5, 5, 1, 1

        logged_in = 1 if failed_logins == 0 and flag == 'SF' else 0

        features = [
            duration, proto_encoded, service_encoded, flag_encoded, src_bytes, dst_bytes,
            0, 0, 0, hot, failed_logins, logged_in,
            num_compromised, root_shell, su_attempted, num_root, num_file_creations, 0, 0, 0, 0, is_guest_login,
            count, srv_count, serror_rate, serror_rate, rerror_rate, rerror_rate, 
            1.0 if diff_srv_rate == 0.0 else 0.0, diff_srv_rate, 0.0,
            dst_host_count, dst_host_srv_count, 1.0 if dst_host_diff_srv_rate == 0.0 else 0.0, dst_host_diff_srv_rate, 
            0.0, 0.0, serror_rate, serror_rate, rerror_rate, rerror_rate
        ]
        
        features_array = np.array(features, dtype=float).reshape(1, -1)
        scaled_features = scaler.transform(features_array)

        probabilities = rf_model.predict_proba(scaled_features)[0]
        normal_prob = probabilities[0]
        attack_prob = sum(probabilities[1:]) 

        if attack_prob > 0.40:
            attack_probs_only = probabilities[1:]
            prediction_idx = int(np.argmax(attack_probs_only) + 1)
            final_confidence = attack_prob
        else:
            prediction_idx = 0
            final_confidence = normal_prob

        result = {
            'prediction': CLASS_NAMES[prediction_idx],
            'confidence': f"{float(final_confidence * 100):.2f}%",
            'probabilities': {CLASS_NAMES[i]: f"{float(prob * 100):.2f}%" for i, prob in enumerate(probabilities)}
        }
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ==========================================
# BLOCK 6: Packet Sniffing, Saving & History
# ==========================================
@app.route('/api/sniff_packet', methods=['GET'])
def sniff_packet():
    global current_session_packets
    try:
        packets = sniff(timeout=1, store=True)
        result = predict(packets)
        
        if result:
            # Naya ID list ki current length ke hisaab se banayenge
            # Taaki list clear hone par ye wapas 1 se start ho jaye
            current_id = len(current_session_packets) + 1
            
            packet_data = {
                'id': current_id,           # result[0] ki jagah current_id use kiya
                'ip_address': result[1],
                'protocol': result[2],
                'prediction': result[3],
                'confidence': f"{result[4]}%",
                'date': result[5],
                'time': result[6]
            }
            current_session_packets.append(packet_data)
            return jsonify(packet_data)
        else:
            return jsonify({'error': 'No valid IP packets captured.'}), 404
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ==========================================
# BLOCK 6: Packet Sniffing, Saving & History
# ==========================================
@app.route('/api/stop_sniffing', methods=['POST'])
def stop_sniffing():
    global current_session_packets
    if not current_session_packets:
        return jsonify({'message': 'No packets to save.'})
    
    current_user = session.get('user', 'unknown_user')
    
    try:
        conn = sqlite3.connect('nids_history.db')
        c = conn.cursor()
        
        # User ka pichla max session_id nikalna
        c.execute('SELECT MAX(session_id) FROM packet_logs WHERE username = ?', (current_user,))
        max_session = c.fetchone()[0]
        # Agar user ka ye pehla session hai toh 1, warna pichle max mein +1
        new_session_id = 1 if max_session is None else max_session + 1
        
        for p in current_session_packets:
            c.execute('''INSERT INTO packet_logs (username, session_id, packet_id, ip_address, protocol, prediction, confidence, date, time)
                         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                      (current_user, new_session_id, p['id'], p['ip_address'], p['protocol'], p['prediction'], p['confidence'], p['date'], p['time']))
        conn.commit()
        conn.close()
        
        saved_count = len(current_session_packets)
        current_session_packets.clear() 
        
        return jsonify({'message': f'Saved {saved_count} packets in Session #{new_session_id}.'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/history_logs')
def history_logs():
    current_user = session.get('user')
    if not current_user:
        return redirect(url_for('login'))
        
    conn = sqlite3.connect('nids_history.db')
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    # Sirf current user ke logs fetch karein
    c.execute('SELECT * FROM packet_logs WHERE username = ? ORDER BY id DESC LIMIT 1000', (current_user,)) 
    logs = c.fetchall()
    conn.close()
    return render_template('history_logs.html', logs=logs)

# ==========================================
# BLOCK 6.1: Clear History API
# ==========================================
@app.route('/api/clear_history', methods=['POST'])
def clear_history():
    current_user = session.get('user')
    if not current_user:
        return jsonify({'error': 'Unauthorized'}), 401
        
    try:
        conn = sqlite3.connect('nids_history.db')
        c = conn.cursor()
        # Sirf current user ka data delete karein
        c.execute('DELETE FROM packet_logs WHERE username = ?', (current_user,))
        conn.commit()
        conn.close()
        
        return jsonify({'message': 'Your history logs cleared successfully.'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    
@app.route('/api/predict_batch', methods=['POST'])
def predict_batch():
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400

    try:
        df = pd.read_csv(file)
        raw_protocols = df['protocol_type'].copy() if 'protocol_type' in df.columns else ['TCP']*len(df)
        
        categorical_cols = ['protocol_type', 'service', 'flag']
        for col in categorical_cols:
            if col in df.columns:
                df[col] = df[col].apply(lambda x: encoders[col].transform([x])[0] if x in encoders[col].classes_ else 0)
        
        scaled_features = scaler.transform(df.values)
        probabilities = rf_model.predict_proba(scaled_features)
        
        results = []
        for i, prob in enumerate(probabilities):
            normal_prob = prob[0]
            attack_prob = sum(prob[1:])
            
            if attack_prob > 0.40:
                pred_idx = int(np.argmax(prob[1:]) + 1)
                pred_name = CLASS_NAMES[pred_idx]
                conf = attack_prob
            else:
                pred_name = 'Normal'
                conf = normal_prob
                
            results.append({
                'id': i + 1,
                'protocol': raw_protocols[i].upper() if isinstance(raw_protocols[i], str) else 'N/A',
                'prediction': pred_name,
                'confidence': f"{float(conf * 100):.2f}%"
            })
            
        return jsonify({'results': results})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ==========================================
# BLOCK 7: Application Execution & Auto-Launch
# ==========================================
def open_browser():
    webbrowser.open_new('http://127.0.0.1:5000/')

if __name__ == '__main__':
    Timer(1.5, open_browser).start()
    app.run(host='0.0.0.0', port=5000, debug=False)
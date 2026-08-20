import os
import joblib
import numpy as np
from flask import Flask, render_template, request, jsonify
from utils.packrt_sniffer import capture_single_packet
import pandas as pd
import io

app = Flask(__name__)

# Paths
BASE_DIR = os.path.abspath(os.getcwd())
MODELS_DIR = os.path.join(BASE_DIR, 'models')

# Load ML Artifacts
rf_model = joblib.load(os.path.join(MODELS_DIR, 'random_forest.pkl'))
dt_model = joblib.load(os.path.join(MODELS_DIR, 'decision_tree.pkl'))
scaler = joblib.load(os.path.join(MODELS_DIR, 'scaler.pkl'))
encoders = joblib.load(os.path.join(MODELS_DIR, 'label_encoders.pkl'))

CLASS_NAMES = ['Normal', 'DoS', 'Probe', 'U2R', 'R2L']

# ----------------- PAGE ROUTES ----------------- #

@app.route('/')
@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

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


# ------------------ API ROUTES ------------------ #

@app.route('/api/predict_manual', methods=['POST'])
def predict_manual():
    try:
        data = request.json
        model_choice = data.get('model', 'rf')
        
        # 1. Frontend se values lein
        duration = float(data.get('duration', 0))
        protocol = data.get('protocol_type', 'tcp').lower()
        service = data.get('service', 'http').lower()
        flag = data.get('flag', 'SF').upper()
        src_bytes = float(data.get('src_bytes', 0))
        dst_bytes = float(data.get('dst_bytes', 0))
        failed_logins = float(data.get('num_failed_logins', 0))

        # 2. Categorical inputs ko ML model ke encoders se encode karein
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

        # Base variables for connection counts and error rates
        count = 1
        srv_count = 1
        serror_rate = 0.0
        rerror_rate = 0.0
        diff_srv_rate = 0.0
        dst_host_diff_srv_rate = 0.0
        is_guest_login = 0
        num_compromised = 0
        hot = 0
        dst_host_count = 255
        dst_host_srv_count = 255
        
        # U2R variables
        root_shell = 0
        su_attempted = 0
        num_root = 0
        num_file_creations = 0

        # DYNAMIC THREAT SIMULATION
        if 900 <= duration <= 1000:
            # Secret Trigger for U2R (Privilege Escalation)
            root_shell = 1
            su_attempted = 1
            num_root = 10               # Root commands badha diye
            num_file_creations = 5      # Hacker ne files banayi hain
            num_compromised = 5         # System compromise dikhayein
            hot = 10                    # Suspicious activity level max
            dst_host_count = 1          # Trusted server ka tag hata dein
            dst_host_srv_count = 1      # Trusted server ka tag hata dein

        if flag == 'S0':
            # SYN Flood (DoS)
            count = 250         
            srv_count = 250
            serror_rate = 1.0   
        elif flag == 'REJ':
            # Port Scan (Probe)
            count = 20
            srv_count = 1
            rerror_rate = 1.0   
            diff_srv_rate = 1.0
            dst_host_diff_srv_rate = 1.0
            
        if failed_logins > 0:
            # Password Guessing (R2L)
            is_guest_login = 1
            num_compromised = 1
            hot = 5
            count = 5
            srv_count = 5
            dst_host_count = 1
            dst_host_srv_count = 1

        # Agar failed logins hain, toh logically user logged_in nahi hai
        logged_in = 1 if failed_logins == 0 and flag == 'SF' else 0

        # 3. 41-Feature array dynamically banayein
        features = [
            duration, proto_encoded, service_encoded, flag_encoded, src_bytes, dst_bytes,
            0, 0, 0, hot, failed_logins, logged_in,
            num_compromised, root_shell, su_attempted, num_root, num_file_creations, 0, 0, 0, 0, is_guest_login,
            count, srv_count, serror_rate, serror_rate, rerror_rate, rerror_rate, 
            1.0 if diff_srv_rate == 0.0 else 0.0, diff_srv_rate, 0.0,
            dst_host_count, dst_host_srv_count, 1.0 if dst_host_diff_srv_rate == 0.0 else 0.0, dst_host_diff_srv_rate, 
            0.0, 0.0, serror_rate, serror_rate, rerror_rate, rerror_rate
        ]
        # Data scale karke prediction probabilities nikaalein
        features_array = np.array(features, dtype=float).reshape(1, -1)
        scaled_features = scaler.transform(features_array)

        selected_model = rf_model if model_choice == 'rf' else dt_model
        
        # Sirf highest single probability uthane ke bajaye, saari probabilities lein
        probabilities = selected_model.predict_proba(scaled_features)[0]

        # Normal aur Total Attack probabilities ko alag karein
        normal_prob = probabilities[0]
        attack_prob = sum(probabilities[1:]) # Class 1 se 4 tak ka sum (DoS, Probe, U2R, R2L)

        # Custom Threshold Logic for strict security
        if attack_prob > 0.40:
            # Agar attack chances 40% se zyada hain, toh ALERT trigger karein
            attack_probs_only = probabilities[1:]
            prediction_idx = int(np.argmax(attack_probs_only) + 1) # Sabse high attack class dhundein
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


@app.route('/api/sniff_packet', methods=['GET'])
def sniff_packet():
    try:
        result = capture_single_packet()
        return jsonify(result)
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
        # 1. CSV read karein
        df = pd.read_csv(file)
        raw_protocols = df['protocol_type'].copy() if 'protocol_type' in df.columns else ['TCP']*len(df)
        
        # 2. Categorical columns ko encode karein
        categorical_cols = ['protocol_type', 'service', 'flag']
        for col in categorical_cols:
            if col in df.columns:
                # Agar label naya hai toh 0 assign karein, warna encode karein
                df[col] = df[col].apply(lambda x: encoders[col].transform([x])[0] if x in encoders[col].classes_ else 0)
        
        # 3. Scale aur Predict karein
        scaled_features = scaler.transform(df.values)
        probabilities = rf_model.predict_proba(scaled_features)
        
        results = []
        for i, prob in enumerate(probabilities):
            normal_prob = prob[0]
            attack_prob = sum(prob[1:])
            
            # Wahi strict 40% threshold logic
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


if __name__ == '__main__':
    # Set debug=True for development in VS Code
    app.run(host='0.0.0.0', port=5000, debug=True)
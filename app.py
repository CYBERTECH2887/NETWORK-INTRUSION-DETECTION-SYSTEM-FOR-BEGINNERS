# ==========================================
# BLOCK 1: IMPORTS & FLASK INITIALIZATION
# ==========================================
import os,joblib,webbrowser,numpy as np,pandas as pd
from threading import Timer
from flask import Flask,render_template,request,jsonify,redirect,url_for,session
from scapy.all import sniff
from utils.packet_sniff import predict
from create_db import get_connection,initialize_database
app=Flask(__name__)
app.secret_key='cracka_nids_secret_key_2026'
initialize_database()
# ==========================================
# BLOCK 2: GLOBAL VARIABLES & MODEL LOADING
# ==========================================
current_session_packets=[]
BASE_DIR=os.path.abspath(os.getcwd())
MODELS_DIR=os.path.join(BASE_DIR,'models')
rf_model=joblib.load(os.path.join(MODELS_DIR,'random_forest.pkl'))
scaler=joblib.load(os.path.join(MODELS_DIR,'scaler.pkl'))
encoders=joblib.load(os.path.join(MODELS_DIR,'label_encoders.pkl'))
CLASS_NAMES=['Normal','DoS','Probe','U2R','R2L']
# ==========================================
# BLOCK 3: USER LOGIN
# ==========================================
@app.route('/login',methods=['GET','POST'])
def login():
    if request.method=='POST':
        username=request.form.get('username')
        password=request.form.get('password')
        conn=cursor=None
        try:
            conn=get_connection()
            cursor=conn.cursor()
            cursor.execute('SELECT * FROM users WHERE username=%s AND password=%s',(username,password))
            user=cursor.fetchone()
            if user:
                session['user']=username
                session['user_details']={'fullname':user[1],'email':user[3],'phone':user[4],'dob':user[5],'profession':user[6],'gender':user[7]}
                return redirect(url_for('dashboard'))
            return render_template('login.html',error='Invalid username or password!')
        except Exception as e:
            return render_template('login.html',error=f'Database error: {e}')
        finally:
            if cursor: cursor.close()
            if conn: conn.close()
    return render_template('login.html')
# ==========================================
# BLOCK 4: USER REGISTRATION
# ==========================================
@app.route('/register',methods=['GET','POST'])
def register():
    if request.method=='POST':
        fullname=request.form.get('fullname')
        username=request.form.get('username')
        email=request.form.get('email')
        phone=request.form.get('phone')
        dob=request.form.get('dob')
        profession=request.form.get('profession')
        gender=request.form.get('gender')
        password=request.form.get('password')
        conn=cursor=None
        try:
            conn=get_connection()
            cursor=conn.cursor()
            cursor.execute('SELECT id FROM users WHERE username=%s',(username,))
            if cursor.fetchone():
                return render_template('register.html',error='Username already exists!')
            cursor.execute('''INSERT INTO users(fullname,username,email,phone,dob,profession,gender,password)
                              VALUES(%s,%s,%s,%s,%s,%s,%s,%s)''',(fullname,username,email,phone,dob,profession,gender,password))
            conn.commit()
            return redirect(url_for('login'))
        except Exception as e:
            if conn: conn.rollback()
            return render_template('register.html',error=f'Database error: {e}')
        finally:
            if cursor: cursor.close()
            if conn: conn.close()
    return render_template('register.html')
# ==========================================
# BLOCK 5: USER LOGOUT
# ==========================================
@app.route('/logout')
def logout():
    session.pop('user',None)
    session.pop('user_details',None)
    return redirect(url_for('login'))
# ==========================================
# BLOCK 6: LOGIN PROTECTION
# ==========================================
@app.before_request
def require_login():
    if request.endpoint and request.endpoint not in ['login','register','static'] and 'user' not in session:
        return redirect(url_for('login'))
# ==========================================
# BLOCK 7: APPLICATION PAGE ROUTES
# ==========================================
@app.route('/')
@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html',username=session.get('user'))
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
# BLOCK 8: MANUAL PREDICTION
# ==========================================
@app.route('/api/predict_manual',methods=['POST'])
def predict_manual():
    try:
        data=request.json
        duration=float(data.get('duration',0))
        protocol=data.get('protocol_type','tcp').lower()
        service=data.get('service','http').lower()
        flag=data.get('flag','SF').upper()
        src_bytes=float(data.get('src_bytes',0))
        dst_bytes=float(data.get('dst_bytes',0))
        failed_logins=float(data.get('num_failed_logins',0))
        try: proto_encoded=encoders['protocol_type'].transform([protocol])[0]
        except: proto_encoded=0
        try: service_encoded=encoders['service'].transform([service])[0]
        except: service_encoded=0
        try: flag_encoded=encoders['flag'].transform([flag])[0]
        except: flag_encoded=0
        count=srv_count=1
        serror_rate=rerror_rate=diff_srv_rate=dst_host_diff_srv_rate=0.0
        is_guest_login=num_compromised=hot=0
        dst_host_count=dst_host_srv_count=255
        root_shell=su_attempted=num_root=num_file_creations=0
        if 900<=duration<=1000:
            root_shell=su_attempted=1
            num_root=10
            num_file_creations=5
            num_compromised=5
            hot=10
            dst_host_count=dst_host_srv_count=1
        if flag=='S0':
            count=srv_count=250
            serror_rate=1.0
        elif flag=='REJ':
            count=20
            srv_count=1
            rerror_rate=diff_srv_rate=dst_host_diff_srv_rate=1.0
        if failed_logins>0:
            is_guest_login=num_compromised=1
            hot=count=srv_count=5
            dst_host_count=dst_host_srv_count=1
        logged_in=1 if failed_logins==0 and flag=='SF' else 0
        features=[duration,proto_encoded,service_encoded,flag_encoded,src_bytes,dst_bytes,0,0,0,hot,failed_logins,logged_in,num_compromised,root_shell,su_attempted,num_root,num_file_creations,0,0,0,0,is_guest_login,count,srv_count,serror_rate,serror_rate,rerror_rate,rerror_rate,1.0 if diff_srv_rate==0.0 else 0.0,diff_srv_rate,0.0,dst_host_count,dst_host_srv_count,1.0 if dst_host_diff_srv_rate==0.0 else 0.0,dst_host_diff_srv_rate,0.0,0.0,serror_rate,serror_rate,rerror_rate,rerror_rate]
        scaled_features=scaler.transform(np.array(features,dtype=float).reshape(1,-1))
        probabilities=rf_model.predict_proba(scaled_features)[0]
        normal_prob=probabilities[0]
        attack_prob=sum(probabilities[1:])
        if attack_prob>0.40:
            prediction_idx=int(np.argmax(probabilities[1:])+1)
            confidence=attack_prob
        else:
            prediction_idx=0
            confidence=normal_prob
        return jsonify({'prediction':CLASS_NAMES[prediction_idx],'confidence':f'{confidence*100:.2f}%','probabilities':{CLASS_NAMES[i]:f'{prob*100:.2f}%' for i,prob in enumerate(probabilities)}})
    except Exception as e:
        return jsonify({'error':str(e)}),500
# ==========================================
# BLOCK 9: LIVE PACKET SNIFFING
# ==========================================
@app.route('/api/sniff_packet',methods=['GET'])
def sniff_packet():
    global current_session_packets
    try:
        packets=sniff(timeout=1,store=True)
        result=predict(packets)
        if result:
            current_id=len(current_session_packets)+1
            packet_data={'id':current_id,'ip_address':result[1],'protocol':result[2],'prediction':result[3],'confidence':f'{result[4]}%','date':result[5],'time':result[6]}
            current_session_packets.append(packet_data)
            return jsonify(packet_data)
        return jsonify({'error':'No valid IP packets captured.'}),404
    except Exception as e:
        return jsonify({'error':str(e)}),500
# ==========================================
# BLOCK 10: STOP SNIFFING & SAVE HISTORY
# ==========================================
@app.route('/api/stop_sniffing',methods=['POST'])
def stop_sniffing():
    global current_session_packets
    if not current_session_packets:
        return jsonify({'message':'No packets to save.'})
    current_user=session.get('user','unknown_user')
    conn=cursor=None
    try:
        conn=get_connection()
        cursor=conn.cursor()
        cursor.execute('SELECT MAX(session_id) FROM packet_logs WHERE username=%s',(current_user,))
        max_session=cursor.fetchone()[0]
        new_session_id=1 if max_session is None else max_session+1
        for p in current_session_packets:
            cursor.execute('''INSERT INTO packet_logs(username,session_id,packet_id,ip_address,protocol,prediction,confidence,date,time)
                              VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s)''',(current_user,new_session_id,p['id'],p['ip_address'],p['protocol'],p['prediction'],p['confidence'],p['date'],p['time']))
        conn.commit()
        saved_count=len(current_session_packets)
        current_session_packets.clear()
        return jsonify({'message':f'Saved {saved_count} packets in Session #{new_session_id}.'})
    except Exception as e:
        if conn: conn.rollback()
        return jsonify({'error':str(e)}),500
    finally:
        if cursor: cursor.close()
        if conn: conn.close()
# ==========================================
# BLOCK 11: HISTORY LOGS
# ==========================================
@app.route('/history_logs')
def history_logs():
    current_user=session.get('user')
    if not current_user:
        return redirect(url_for('login'))
    conn=cursor=None
    try:
        conn=get_connection()
        cursor=conn.cursor(dictionary=True)
        cursor.execute('SELECT * FROM packet_logs WHERE username=%s ORDER BY id DESC LIMIT 1000',(current_user,))
        logs=cursor.fetchall()
        return render_template('history_logs.html',logs=logs)
    except Exception as e:
        return render_template('history_logs.html',logs=[],error=f'Database error: {e}')
    finally:
        if cursor: cursor.close()
        if conn: conn.close()
# ==========================================
# BLOCK 12: CLEAR HISTORY
# ==========================================
@app.route('/api/clear_history',methods=['POST'])
def clear_history():
    current_user=session.get('user')
    if not current_user:
        return jsonify({'error':'Unauthorized'}),401
    conn=cursor=None
    try:
        conn=get_connection()
        cursor=conn.cursor()
        cursor.execute('DELETE FROM packet_logs WHERE username=%s',(current_user,))
        conn.commit()
        return jsonify({'message':'Your history logs cleared successfully.'})
    except Exception as e:
        if conn: conn.rollback()
        return jsonify({'error':str(e)}),500
    finally:
        if cursor: cursor.close()
        if conn: conn.close()
# ==========================================
# BLOCK 13: BATCH PREDICTION
# ==========================================
@app.route('/api/predict_batch',methods=['POST'])
def predict_batch():
    if 'file' not in request.files:
        return jsonify({'error':'No file uploaded'}),400
    file=request.files['file']
    if file.filename=='':
        return jsonify({'error':'No file selected'}),400
    try:
        df=pd.read_csv(file)
        raw_protocols=df['protocol_type'].copy() if 'protocol_type' in df.columns else ['TCP']*len(df)
        for col in ['protocol_type','service','flag']:
            if col in df.columns:
                df[col]=df[col].apply(lambda x:encoders[col].transform([x])[0] if x in encoders[col].classes_ else 0)
        scaled_features=scaler.transform(df.values)
        probabilities=rf_model.predict_proba(scaled_features)
        results=[]
        for i,prob in enumerate(probabilities):
            normal_prob=prob[0]
            attack_prob=sum(prob[1:])
            if attack_prob>0.40:
                pred_idx=int(np.argmax(prob[1:])+1)
                pred_name=CLASS_NAMES[pred_idx]
                confidence=attack_prob
            else:
                pred_name='Normal'
                confidence=normal_prob
            results.append({'id':i+1,'protocol':raw_protocols[i].upper() if isinstance(raw_protocols[i],str) else 'N/A','prediction':pred_name,'confidence':f'{confidence*100:.2f}%'})
        return jsonify({'results':results})
    except Exception as e:
        return jsonify({'error':str(e)}),500
# ==========================================
# BLOCK 14: APPLICATION STARTUP
# ==========================================
def open_browser():
    webbrowser.open_new('http://127.0.0.1:5000/')
if __name__=='__main__':
    Timer(1.5,open_browser).start()
    app.run(host='0.0.0.0',port=5000,debug=False)
import os
import joblib
import numpy as np
from scapy.all import sniff, IP, TCP, UDP, ICMP

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
MODELS_DIR = os.path.join(BASE_DIR, 'models')

# Load encoders, scaler, and model
encoders = joblib.load(os.path.join(MODELS_DIR, 'label_encoders.pkl'))
scaler = joblib.load(os.path.join(MODELS_DIR, 'scaler.pkl'))
model = joblib.load(os.path.join(MODELS_DIR, 'random_forest.pkl'))

CLASS_MAP = {0: 'Normal', 1: 'DoS', 2: 'Probe', 3: 'U2R', 4: 'R2L'}

# Common Port-to-Service Mapping for NSL-KDD
PORT_SERVICE_MAP = {
    80: 'http', 443: 'http', 21: 'ftp', 20: 'ftp_data', 
    22: 'ssh', 23: 'telnet', 25: 'smtp', 53: 'domain_u', 
    110: 'pop_3', 143: 'imap4', 3306: 'sqlnet'
}

def extract_features(packet):
    """
    Extracts and maps live packet attributes to the 41 NSL-KDD features.
    """
    if not packet.haslayer(IP):
        return None

    ip_layer = packet.getlayer(IP)
    
    # 1. Protocol Mapping
    if packet.haslayer(TCP):
        protocol = 'tcp'
        layer = packet.getlayer(TCP)
        src_port = layer.sport
        dst_port = layer.dport
        flags = str(layer.flags)
        flag = 'SF' if flags == 'SA' or flags == 'PA' or flags == 'A' else 'OTH'
    elif packet.haslayer(UDP):
        protocol = 'udp'
        layer = packet.getlayer(UDP)
        src_port = layer.sport
        dst_port = layer.dport
        flag = 'SF'
    elif packet.haslayer(ICMP):
        protocol = 'icmp'
        src_port = 0
        dst_port = 0
        flag = 'SF'
    else:
        protocol = 'tcp'
        src_port = 0
        dst_port = 0
        flag = 'OTH'

    # 2. Service Mapping
    service = PORT_SERVICE_MAP.get(dst_port, PORT_SERVICE_MAP.get(src_port, 'other'))
    
    # Basic Feature Estimations
    duration = 0
    src_bytes = len(packet)
    dst_bytes = 0
    land = 1 if ip_layer.src == ip_layer.dst else 0
    wrong_fragment = 0
    urgent = 1 if packet.haslayer(TCP) and layer.urgptr > 0 else 0
    
    # Encode categorical fields
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

    # Build 41-feature array (defaulting unobservable flow-window metrics to baseline averages)
    features = [
        duration, proto_encoded, service_encoded, flag_encoded, src_bytes, dst_bytes,
        land, wrong_fragment, urgent, 0, 0, 1 if flag == 'SF' else 0, # hot, failed logins, logged_in
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0,                                 # host/admin indicators
        1, 1, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0,                      # count & rates
        1, 1, 1.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0                  # dst_host stats
    ]
    
    return np.array(features).reshape(1, -1), ip_layer.src, ip_layer.dst, protocol

def capture_single_packet():
    """Captures 1 live packet, extracts features, and runs ML inference."""
    packets = sniff(count=1, timeout=3)
    if not packets:
        return {"error": "No packet captured during timeout window."}
    
    pkt = packets[0]
    res = extract_features(pkt)
    if res is None:
        return {"error": "Non-IP packet captured. Skipping."}
    
    feature_vector, src_ip, dst_ip, protocol = res
    scaled_vector = scaler.transform(feature_vector)
    
    pred_idx = model.predict(scaled_vector)[0]
    prediction = CLASS_MAP.get(pred_idx, 'Unknown')
    probabilities = model.predict_proba(scaled_vector)[0]
    confidence = float(np.max(probabilities) * 100)
    
    return {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "protocol": protocol.upper(),
        "packet_size": len(pkt),
        "prediction": prediction,
        "confidence": f"{confidence:.2f}%"
    }
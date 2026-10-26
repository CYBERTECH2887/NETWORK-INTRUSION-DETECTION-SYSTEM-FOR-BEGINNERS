"""
Live packet -> 41 NSL-KDD style features -> Random Forest prediction.

NOTE: Scapy ka use karke live packets capture karta hai. 1-second capture window se
connection approx. banta hai (real NSL-KDD features poore connections pe base hote hain).
Standalone command: python -m utils.packet_sniff (needs admin/root)
"""
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP, ICMP

try:
    from utils import ensemble as E
except ImportError:                    
    import ensemble as E

packet_id = 0

# Port numbers ko service names me map karne ke liye dictionary
SERVICES = {20: "ftp_data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "domain_u", 69: "tftp_u",
            80: "http", 110: "pop_3", 111: "sunrpc", 119: "nntp", 143: "imap4", 443: "http_443",
            514: "shell", 587: "smtp", 631: "printer", 993: "imap4", 995: "pop_3"}

# Packet ke layers inspect karke batata hai ki Protocol konsa hai
def protocol(p):
    if p.haslayer(TCP): return "tcp"
    if p.haslayer(UDP): return "udp"
    if p.haslayer(ICMP): return "icmp"
    return "other"

# Destination port identify karke uski corresponding service (jaise http) laata hai
def service(p):
    port = p[TCP].dport if p.haslayer(TCP) else p[UDP].dport if p.haslayer(UDP) else 0
    return SERVICES.get(port, "other")

# Same connection ke forward/backward packets ko ek key se associate karne ka helper
def flow_key(p):
    layer = p[TCP] if p.haslayer(TCP) else p.getlayer(UDP) if p.haslayer(UDP) else None
    sp, dp = (layer.sport, layer.dport) if layer else (0, 0)
    ends = sorted([(p[IP].src, sp), (p[IP].dst, dp)])        
    return (ends[0], ends[1], protocol(p))

# TCP flags ka series analyze karke connection flag string (SF, REJ, S0) predict karta hai
def flow_flag(pkts):
    """Approximate the NSL-KDD connection flag from all TCP flags seen in a flow."""
    joined = "".join(str(x[TCP].flags) for x in pkts if x.haslayer(TCP))
    if not joined: return "OTH"
    if "R" in joined: return "RSTO" if "A" in joined else "REJ"
    if "S" in joined and "A" not in joined: return "S0"
    if "F" in joined: return "SF"
    if "S" in joined: return "S1"
    return "SF"                                             

# Scapy packets ke array ko 41-feature array me transform karta hai jo ML models me feed ho sake
def build_features(packets):
    ps = [p for p in packets if p.haslayer(IP)]
    if not ps:
        return None, "0.0.0.0", "OTHER"

    first = ps[0]
    src, dst = first[IP].src, first[IP].dst
    pr, sv = protocol(first), service(first)

    flows = {}
    for p in ps:
        flows.setdefault(flow_key(p), []).append(p)
    first_flow = flows[flow_key(first)]

    # Connection rules aur error rates generate kar rahe hain based on captured window
    count = sum(1 for v in flows.values() if v[0][IP].dst == dst) or 1
    srv_count = sum(1 for v in flows.values() if service(v[0]) == sv) or 1
    same_srv = min(srv_count / count, 1.0)

    tcp_pkts = [p for p in ps if p.haslayer(TCP)]
    t = len(tcp_pkts) or 1
    serror = sum(1 for p in tcp_pkts if str(p[TCP].flags) == "S") / t
    rerror = sum(1 for p in tcp_pkts if "R" in str(p[TCP].flags)) / t

    duration = int(max(0.0, float(first_flow[-1].time - first_flow[0].time)))
    dst_hosts = min(len({p[IP].dst for p in ps}), 255)
    dst_srv = min(len({(p[IP].dst, service(p)) for p in ps}), 255)

    # 41 NSL-KDD attributes array structure
    f = [
        duration,
        E.encode_value("protocol_type", pr, "tcp"),
        E.encode_value("service", sv, "other"),
        E.encode_value("flag", flow_flag(first_flow), "OTH"),
        sum(len(x) for x in ps if x[IP].src == src),              # src_bytes
        sum(len(x) for x in ps if x[IP].dst == src),              # dst_bytes
        int(any(x[IP].src == x[IP].dst for x in ps)),             # land
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,               # content features (15 zeros dummy)
        count, srv_count,
        serror, serror, rerror, rerror,
        same_srv, 1.0 - same_srv, 0.0,
        dst_hosts, dst_srv,
        same_srv, 1.0 - same_srv, 0.0, 0.0,
        serror, serror, rerror, rerror,
    ]
    return f, src, pr.upper()

# Main function jo live packet ko features banakar Random Forest model se predict karta hai
def predict(packets):
    """Returns (id, ip, protocol, label, confidence_percent, date, time) or None."""
    global packet_id
    f, ip, pr = build_features(packets)
    if not f:
        return None
    if len(f) != 41:
        print(f"Feature error: {len(f)} features generated")
        return None
    try:
        # Standard scale karke sirf Random Forest model se attack category nikalna
        X = E.scaler.transform([f])
        probs = E.rf_model.predict_proba(X)[0]
        idx, conf = E.decide(probs)
        packet_id += 1
        now = datetime.now()
        # Frontend web dashboard / terminal ke liye result return karna
        return packet_id, ip, pr, E.CLASS_NAMES[idx], round(conf * 100, 2), now.strftime("%Y-%m-%d"), now.strftime("%H:%M:%S")
    except Exception as e:
        print("Prediction error:", e)
        return None

# Terminal app command-line entry. Infinite loop lagakar har 1 second packets sniff aur print karta hai
def start():
    print("=" * 62)
    print("INTRUSION DETECTION PACKET SNIFFER (Random Forest)")
    print("=" * 62)
    print("Prediction interval: 1 second | Press CTRL+C to stop\n")
    print(f"{'ID':<5}{'IP Address':<18}{'Protocol':<10}{'Prediction':<12}{'Confidence':<12}{'Date':<12}Time")
    print("-" * 82)
    try:
        while True:
            # Har sec 1 prediction result terminal me print
            r = predict(sniff(timeout=1, store=True))
            if r:
                print(f"{r[0]:<5}{r[1]:<18}{r[2]:<10}{r[3]:<12}{str(r[4]) + '%':<12}{r[5]:<12}{r[6]}")
    except KeyboardInterrupt:
        print("\nPacket capture stopped")

if __name__ == "__main__":
    start()
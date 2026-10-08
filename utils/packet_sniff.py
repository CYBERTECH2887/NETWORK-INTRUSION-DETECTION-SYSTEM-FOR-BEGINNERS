import os,joblib
from datetime import datetime
from scapy.all import sniff,IP,TCP,UDP,ICMP

# ==================== LOAD FILES ====================
BASE=os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
model=joblib.load(os.path.join(BASE,"models","random_forest.pkl"))
scaler=joblib.load(os.path.join(BASE,"models","scaler.pkl"))
encoders=joblib.load(os.path.join(BASE,"models","label_encoders.pkl"))

# ==================== SETTINGS ====================
packet_id=0
LABELS={0:"Normal",1:"DOS",2:"PROB",3:"R2L",4:"U2R"}

# ==================== PACKET INFORMATION ====================
def protocol(p):
    if p.haslayer(TCP): return "tcp"
    if p.haslayer(UDP): return "udp"
    if p.haslayer(ICMP): return "icmp"
    return "other"

def service(p):
    port=p[TCP].dport if p.haslayer(TCP) else p[UDP].dport if p.haslayer(UDP) else 0
    return {20:"ftp_data",21:"ftp",22:"ssh",23:"telnet",25:"smtp",53:"domain_u",69:"tftp_u",80:"http",110:"pop_3",111:"sunrpc",119:"nntp",143:"imap4",443:"http_443",514:"shell",587:"smtp",631:"printer",993:"imap4",995:"pop_3"}.get(port,"other")

def flag(p):
    if not p.haslayer(TCP): return "OTH"
    f=str(p[TCP].flags)
    return {"S":"S0","SA":"S1","A":"SF","R":"REJ"}.get(f,"SF" if "F" in f else "OTH")

# ==================== CREATE 41 FEATURES ====================
def features(packets):
    ps=[p for p in packets if p.haslayer(IP)]
    if not ps:return None,"0.0.0.0","OTHER"
    p=ps[0]
    ip=p[IP].src
    pr=protocol(p)
    sv=service(p)
    n=len(ps)
    sc=sum(service(x)==sv for x in ps)

    def enc(k,v,d):
        try:return encoders[k].transform([v])[0]
        except:return encoders[k].transform([d])[0]

    pe=enc("protocol_type",pr,"tcp")
    se=enc("service",sv,"other")
    fe=enc("flag",flag(p),"OTH")

    f=[
        1.0,pe,se,fe,
        sum(len(x) for x in ps if x[IP].src==ip),
        sum(len(x) for x in ps if x[IP].dst==ip),
        int(any(x[IP].src==x[IP].dst for x in ps)),
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,n,sc,0.0,0.0,0.0,0.0,
        sc/n if n else 0.0,
        1-sc/n if n else 0.0,0.0,
        len(set(x[IP].dst for x in ps)),
        len(set((x[IP].dst,service(x)) for x in ps)),
        1.0,0.0,1.0,0.0,0.0,0.0,0.0,0.0
    ]
    return f,ip,pr.upper()

# ==================== PREDICTION ====================
def predict(packets):
    global packet_id
    f,ip,pr=features(packets)
    if not f:return None
    if len(f)!=41:
        print(f"Feature error: {len(f)} features generated")
        return None
    try:
        X=scaler.transform([f])
        pred=int(model.predict(X)[0])
        conf=max(model.predict_proba(X)[0])*100
        packet_id+=1
        now=datetime.now()
        return packet_id,ip,pr,LABELS.get(pred,str(pred)),round(conf,2),now.strftime("%Y-%m-%d"),now.strftime("%H:%M:%S")
    except Exception as e:
        print("Prediction error:",e)
        return None

# ==================== SNIFFER ====================
def start():
    print("==============================================")
    print("INTRUSION DETECTION PACKET SNIFFER")
    print("==============================================")
    print("Prediction interval: 1 second")
    print("Press CTRL+C to stop\n")
    print(f"{'ID':<5}{'IP Address':<18}{'Protocol':<10}{'Prediction':<15}{'Confidence':<12}{'Date':<12}Time")
    print("-"*90)
    try:
        while True:
            r=predict(sniff(timeout=1,store=True))
            if r:
                print(f"{r[0]:<5}{r[1]:<18}{r[2]:<10}{r[3]:<15}{str(r[4])+'%':<12}{r[5]:<12}{r[6]}")
    except KeyboardInterrupt:
        print("\nPacket capture stopped")

# ==================== MAIN ====================
if __name__=="__main__":
    start()
import time
import joblib
import numpy as np
from collections import defaultdict, deque
import warnings
from scapy.all import sniff, IP, TCP, UDP, ICMP

# Suppress the specific scikit-learn warning about missing feature names
warnings.filterwarnings("ignore", message="X does not have valid feature names")

#Configuration & Thresholds 
WINDOW_SECONDS = 10
PORTSCAN_UNIQUE_PORTS_THRESHOLD = 25
DOS_PPS_THRESHOLD = 500
ALERT_COOLDOWN_SECONDS = 30
LOG_FILE = "ids_alerts.log"

#ML Model Setup 
MODEL_FILE = "rf_ids_model.pkl"
try:
    print(f"[*] Loading Random Forest model from {MODEL_FILE}...")
    # Loading the pre-trained scikit-learn model
    rf_model = joblib.load(MODEL_FILE)
    print("[+] Model loaded successfully!")
except FileNotFoundError:
    print(f"[!] Warning: {MODEL_FILE} not found. Running in rule-only mode.")
    rf_model = None

# Tracking State
last_alert_ts = {} 
recent_conn_attempts = defaultdict(deque)
recent_packets_to_dst = defaultdict(deque)

def now():
    return time.time()

def purge_old_conn(dq, cutoff):
    while dq and dq[0][0] < cutoff:
        dq.popleft()

def purge_old_ts(dq, cutoff):
    while dq and dq[0] < cutoff:
        dq.popleft()

def get_dst_port(pkt):
    if pkt.haslayer(TCP):
        return pkt[TCP].dport
    if pkt.haslayer(UDP):
        return pkt[UDP].dport
    return 0

#Feature Extraction for ML 
def extract_features(pkt):
    """
    Translates a Scapy packet into a numeric array for the Random Forest model.
    Features MUST match the training script: [dport, length, syn_flag, ack_flag, fin_flag]
    """
    #Destination Port
    dport = get_dst_port(pkt)
    
    #Packet Length
    length = len(pkt)
    
    # 3, 4, 5. TCP Flags
    syn_flag = 0
    ack_flag = 0
    fin_flag = 0
    
    if pkt.haslayer(TCP):
        flags = pkt[TCP].flags
        if 'S' in flags: syn_flag = 1
        if 'A' in flags: ack_flag = 1
        if 'F' in flags: fin_flag = 1

    return np.array([[dport, length, syn_flag, ack_flag, fin_flag]])

def alert(key, msg):
    t = now()
    last = last_alert_ts.get(key, 0)

    if t - last < ALERT_COOLDOWN_SECONDS:
        return
    
    last_alert_ts[key] = t
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    line = f"{ts} | {msg}"
    print("⚠️  " + line)

    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(line + "\n")

def on_packet(pkt):
    if not pkt.haslayer(IP):
        return

    t = now()
    cutoff = t - WINDOW_SECONDS
    src = pkt[IP].src
    dst = pkt[IP].dst
    dport = get_dst_port(pkt)

    #ML Detection Engine (Random Forest)
    if rf_model:
        # Ignore local broadcast and multicast noise (prevents false positives)
        if dst.startswith("224.") or dst.startswith("239.") or dst == "255.255.255.255":
            pass # Skip ML check
        else:
            features = extract_features(pkt)
            
            # Predict probability: returns an array [prob_benign, prob_malicious]
            probabilities = rf_model.predict_proba(features)[0]
            malicious_prob = probabilities[1] 
            
            # ONLY alert if the model is > 85% confident
            if malicious_prob > 0.85:
                alert(
                    ("ml_alert", src, dst), 
                    f"ML ANOMALY detected | src={src} -> dst={dst} | Confidence: {malicious_prob*100:.1f}%"
                )

    #Rule-Based Engine (Portscan & DoS)
    dq = recent_conn_attempts[src]
    dq.append((t, dst, dport))
    purge_old_conn(dq, cutoff)

    ports_by_dst = defaultdict(set)
    for (_, dst_ip, port) in dq:
        if port != 0:
            ports_by_dst[dst_ip].add(port)
    
    most_scanned_dst = None
    most_ports = 0
    for dst_ip, ports in ports_by_dst.items():
        if len(ports) > most_ports:
            most_ports = len(ports)
            most_scanned_dst = dst_ip

    if most_ports >= PORTSCAN_UNIQUE_PORTS_THRESHOLD:
        alert(
            ("portscan", src, most_scanned_dst),
            f"PORTSCAN suspected | src={src} -> dst={most_scanned_dst} | unique_ports={most_ports} | window={WINDOW_SECONDS}s"
        )
        dq.clear() 

    dq2 = recent_packets_to_dst[dst]
    dq2.append(t)
    purge_old_ts(dq2, cutoff)

    pps = len(dq2) / WINDOW_SECONDS

    if pps >= DOS_PPS_THRESHOLD:
        alert(
            ("dos", dst),
            f"DOS/BURST suspected | dst={dst} | pps≈{pps:.1f} | window={WINDOW_SECONDS}s"
        )
        dq2.clear()

def main():
    print("[*] IDS v2 running (Hybrid ML + Rules). Ctrl+C to stop.")
    sniff(prn=on_packet, store=False)

if __name__ == "__main__":
    main()
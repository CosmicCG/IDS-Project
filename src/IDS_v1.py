import time
from collections import defaultdict, deque
from scapy.all import sniff, IP, TCP, UDP

#Time window for recent history
WINDOW_SECONDS = 10

# How many unique destination ports allowed in the window
PORTSCAN_UNIQUE_PORTS_THRESHOLD = 25

#How many packets/sec to a destination over that window
DOS_PPS_THRESHOLD = 500

#Only alert once per 30s for the same threat
ALERT_COOLDOWN_SECONDS = 30

#File for alert log
LOG_FILE = "ids_alerts.log"
last_alert_ts = {}  #stores the last time you allerted for a specfic key


#Tracks what ports did a source try to hit and on which destination
recent_conn_attempts = defaultdict(deque)

#Tracks how many packets hit a destination in the time window
recent_packets_to_dst = defaultdict(deque)

def now():
    return time.time()

#Removes events older than the window
def purge_old_conn(dq, cutoff):
    # dq items: (timestamp, dst_ip, port)
     #While dq[0] is the oldest event and the timestamp is older than the cutoff
    while dq and dq[0][0] < cutoff:
        dq.popleft()

#Removes timestamps older than the window
def purge_old_ts(dq, cutoff):
    # dq items: timestamp
    while dq and dq[0] < cutoff:
        dq.popleft()

#Returns port numbers of packets
def get_dst_port(pkt):
    if pkt.haslayer(TCP):
        return pkt[TCP].dport
    if pkt.haslayer(UDP):
        return pkt[UDP].dport
    return 0

def alert(key, msg):
    #Gets current time
    t = now()
    #Time of last alert
    last = last_alert_ts.get(key, 0)

    #If the time since the last alert is less than cooldown
    if t - last < ALERT_COOLDOWN_SECONDS:
        return
    
    #Placing alert in last_alert_ts
    last_alert_ts[key] = t

    #Printing and logging the alert
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    line = f"{ts} | {msg}"
    print("⚠️  " + line)

    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(line + "\n")



def on_packet(pkt):
    #If the packet is non IP ignore it
    if not pkt.haslayer(IP):
        return

    #Setting Time Window
    t = now()
    cutoff = t - WINDOW_SECONDS

    #Pulling the src and dst IP along with the port
    src = pkt[IP].src
    dst = pkt[IP].dst
    dport = get_dst_port(pkt)

    #Records connection attempts within the last 10 seconds
    dq = recent_conn_attempts[src]
    dq.append((t, dst, dport))
    purge_old_conn(dq, cutoff)

    #Groups ports by the destination IP
    i = 0
    ports_by_dst = defaultdict(set)
    for (_, dst_ip, port) in dq:
        if port != 0:
            ports_by_dst[dst_ip].add(port)
    

    #Finds the destination IP with the most scanned ports
    most_scanned_dst = None
    most_ports = 0
    for dst_ip, ports in ports_by_dst.items():
        if len(ports) > most_ports:
            most_ports = len(ports)
            most_scanned_dst = dst_ip

    #Creats alert if the dst with the most ports is over the port threshold
    if most_ports >= PORTSCAN_UNIQUE_PORTS_THRESHOLD:
        alert(
            ("portscan", src, most_scanned_dst),
            f"PORTSCAN suspected | src={src} -> dst={most_scanned_dst} | unique_ports={most_ports} | window={WINDOW_SECONDS}s"
        )
        dq.clear()  # reset so it doesn't immediately re-trigger

    #dq2 tracks the timestamps of packets to a destination
    dq2 = recent_packets_to_dst[dst]
    dq2.append(t)
    purge_old_ts(dq2, cutoff)

    #Computes packets per second from dst IP within time window
    pps = len(dq2) / WINDOW_SECONDS

    #If the pps is > the threashold it sends an alert
    if pps >= DOS_PPS_THRESHOLD:
        alert(
            ("dos", dst),
            f"DOS/BURST suspected | dst={dst} | pps≈{pps:.1f} | window={WINDOW_SECONDS}s"
        )
        dq2.clear()

def main():
    print("[*] IDS v1 running (rule-based). Ctrl+C to stop.")
    #Calls on_packet for every packet and doesnt store packets in RAM
    sniff(prn=on_packet, store=False)

if __name__ == "__main__":
    main()
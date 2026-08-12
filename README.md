# Hybrid ML & Rule-Based Intrusion Detection System (IDS)

A lightweight, real-time Intrusion Detection System built in Python using Scapy for deep packet inspection and Scikit-Learn for machine learning anomaly detection. 

This project uses a **hybrid architecture**, combining deterministic threshold-based rules to catch volumetric attacks with a Random Forest machine learning classifier to detect subtle, behavioral anomalies.

## 🧠 Architecture Overview

### 1. Rule-Based Engine (Deterministic)
Handles high-volume, noisy network attacks with zero processing latency.
* **DoS / DDoS Detection:** Calculates Packets Per Second (PPS) targeting a single destination IP over a sliding 10-second time window.
* **Aggressive Port Scans:** Groups connection attempts by source IP and flags anomalous volumes of unique port hits.
* **Memory Management:** Utilizes Python's `collections.deque` to create strict sliding time windows, automatically purging old network flows to prevent memory leaks during prolonged sniffing.

### 2. Machine Learning Engine (Random Forest)
Trained on the **CIC-IDS-2017** cybersecurity dataset to catch attacks that evade strict threshold rules (e.g., SSH/FTP Brute Force, Stealth Nmap scans).
* **Live Feature Extraction:** Strips 5 specific features from live packets in real-time: `Destination Port`, `Packet Length`, `SYN Flag`, `ACK Flag`, and `FIN Flag`.
* **Noise Filtering:** Hardcoded bypasses for local multicast/broadcast traffic (mDNS, SSDP) to eliminate the "out-of-distribution" false positives common in lab-trained ML models.
* **Confidence Thresholds:** Evaluates probability matrices (`predict_proba`) rather than binary outputs, only triggering alerts when the ensemble model is >85% confident of malicious intent.

## 📂 Project Structure

```text
├── README.md                # Project documentation
├── requirements.txt         # Python dependencies
├── ids.py                   # Main IDS sniffer (Hybrid Engine)
├── train_ids_model.py       # ML Data preprocessing and training script
└── rf_ids_model.pkl         # Pre-trained Random Forest model

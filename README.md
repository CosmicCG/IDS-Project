# Real-Time Network Intrusion Detection System

A Python-based real-time IDS that monitors live network traffic and detects suspicious behavior such as port scanning and traffic bursts using sliding-window analysis.

## Features

* Live packet capture using Scapy

* Sliding time-window traffic analysis

* Port scan detection (unique destination ports)

* DoS burst detection (packets per second threshold)

* Alert cooldown system

* Persistent logging

## Technologies

* Python

* Scapy

* Real-time stream processing

* Network security concepts

## How to Run 
pip install -r requirements.txt

python src/ids.py  

## Example Alert Output

PORTSCAN suspected | src=192.168.1.15 -> dst=192.168.1.2

## Future Improvements

* Machine Learning Classification

* Dashboard Visualization

* Packet Payload Inspection

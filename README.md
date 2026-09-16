# DNS Tunneling Detection System

A real-time DNS traffic monitoring and detection system designed to identify possible suspicious DNS tunneling behaviour using Python, Wireshark, and Splunk.

## 📌 Abstract

DNS is mainly used for domain name resolution, but attackers can misuse DNS traffic for hidden communication and data transfer. This project monitors DNS traffic and identifies possible suspicious DNS behaviour based on different traffic characteristics.

## 🎯 Objectives

- Monitor DNS traffic in real time
- Capture and analyse DNS packets
- Identify suspicious DNS query patterns
- Calculate a risk score for DNS queries
- Generate Windows desktop notifications
- Send security logs to Splunk
- Monitor and generate alerts for suspicious activity

## 🛠️ Technologies Used

- **Python** – Detection and risk-score calculation
- **Scapy** – DNS packet processing
- **Wireshark** – DNS packet capture and analysis
- **Splunk** – Log monitoring, dashboard and alerts
- **PowerShell / BurntToast** – Windows desktop notifications
- **Windows** – Project environment

## 🔍 Detection Logic

The system analyses DNS queries using:

- Query length
- Entropy / randomness
- Digit ratio
- Query frequency

### Risk Score

```text
Risk Score =
Length Score
+ Entropy Score
+ Digit Ratio Score
+ Frequency Score

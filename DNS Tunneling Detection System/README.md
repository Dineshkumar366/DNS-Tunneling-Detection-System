# DNS Tunneling and Malicious DNS Behaviour Detection System Using Python, Wireshark and Splunk

## Project Type
Networking + Cybersecurity / SOC Academic Project

## What this project does
This project monitors DNS queries in a controlled lab, extracts behavioural features,
assigns a heuristic risk score, writes suspicious events to a log, sends the events
to Splunk, displays a dashboard, records real-time alerts, and shows a Windows desktop
notification.

**Important:** A high score means "possible suspicious DNS behaviour"; it is not proof
that a query is malicious. Testing uses synthetic DNS names under `example.com`.

## Folder structure

```text
DNS_Tunneling_Malicious_DNS_Behaviour_Detection_System/
├── data/
│   ├── sample_dns_events.csv
│   └── sample_dns_events.log
├── docs/
│   ├── Project_Report.docx
│   ├── Project_Presentation.pptx
│   ├── VIVA_QA.md
│   └── DEMO_STEPS.md
├── logs/
│   └── dns_security_live.log
├── scripts/
│   ├── dns_detector.py
│   ├── launcher.py
│   └── generate_test_traffic.bat
├── splunk/
│   ├── inputs.conf
│   ├── dashboard.xml
│   └── spl_queries.txt
├── requirements.txt
├── run_project.bat
├── run_project.ps1
└── README.md
```

## Requirements

- Windows 10/11
- Python 3.10+ (tested project environment: Python 3.14.7)
- Wireshark
- Npcap (installed with Wireshark)
- Splunk Enterprise / local Splunk installation
- Administrator privileges may be required for packet capture and Splunk configuration
- Python packages listed in `requirements.txt`

## Install

Open CMD in this folder:

```cmd
python --version
python -m pip install -r requirements.txt
```

Install BurntToast in PowerShell if it is not already installed:

```powershell
Install-Module -Name BurntToast -Scope CurrentUser -Force
```

## Run

### Option 1 — one-click batch launcher

Double-click:

```text
run_project.bat
```

or run:

```cmd
run_project.bat
```

### Option 2 — manual

```cmd
cd /d C:\Users\acer\Desktop\DNS_Security_Project
python scripts\dns_detector.py
```

The detector must remain running.

## Generate safe synthetic test DNS traffic

Open a second CMD:

```cmd
for /L %i in (1,1,30) do nslookup x9k7m2p8q4s6d1.example.com
```

You can also run:

```cmd
scripts\generate_test_traffic.bat
```

## Splunk

The project uses:

- Index: `dns_security`
- Sourcetype: `dns_security_live`

The live log is:

```text
logs\dns_security_live.log
```

Recommended search:

```text
index=dns_security sourcetype=dns_security_live
```

Dashboard panels:

1. Total Suspicious DNS Events
2. Risk Score Over Time
3. Top Suspicious DNS Queries
4. DNS Events by Source IP

## Wireshark

Useful display filter:

```text
dns.flags.response == 0 && dns.qry.name contains "example.com"
```

Check the selected packet for:

- Source / Destination
- UDP
- Destination Port: 53
- DNS query name

## Detection logic

The detector scores:

- subdomain length
- entropy
- digit ratio
- repeated-query frequency

A score >= 50 is classified as:

```text
POSSIBLE_SUSPICIOUS_DNS
```

## Project evidence

The report contains screenshot spaces for:

1. Python live detection
2. Windows desktop notification
3. Splunk live events
4. Splunk triggered alert
5. Splunk dashboard
6. Wireshark DNS packet

## Safety

This package is intended for an authorized academic lab. It does not include real
malicious DNS infrastructure, credential theft, data exfiltration, or unauthorized
access tooling.

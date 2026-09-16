# Demo Steps — DNS Tunneling and Malicious DNS Behaviour Detection System Using Python, Wireshark and Splunk

## 1. Start Splunk
Open the local Splunk web interface:
`http://localhost:8000`

Make sure the `dns_security` index exists.

## 2. Configure live input
Copy the contents of `splunk/inputs.conf` into the appropriate Splunk local inputs configuration.

Restart Splunk if required.

## 3. Start Python detector

```cmd
cd /d C:\Users\acer\Desktop\DNS_Security_Project
python scripts\dns_detector.py
```

## 4. Generate safe DNS traffic

Open a second CMD:

```cmd
for /L %i in (1,1,30) do nslookup x9k7m2p8q4s6d1.example.com
```

## 5. Expected Python result

The detector should display:
- DNS Query
- Source IP
- Destination IP
- Query Type
- Length
- Entropy
- Frequency
- Risk Score
- Possible suspicious classification

A Windows notification should appear when the score reaches the threshold.

## 6. Verify Splunk

Search:

```text
index=dns_security sourcetype=dns_security_live
```

## 7. Verify alert

Open the configured `Suspicious DNS High Risk Alert` and check Triggered Alerts.

## 8. Verify dashboard

Open the DNS Security Monitoring Dashboard and refresh it after generating new events.

## 9. Verify Wireshark

Use:

```text
dns.flags.response == 0 && dns.qry.name contains "example.com"
```

Select a packet and show:
- IPv4/IPv6 source and destination
- UDP
- Destination Port 53
- DNS query name

## 10. Screenshot order for report

1. Python live detector
2. Windows notification
3. Splunk live events
4. Triggered alert
5. Dashboard
6. Wireshark packet

from scapy.all import sniff, DNS, DNSQR, IP, IPv6
from datetime import datetime
from collections import defaultdict
import math
import os
import subprocess
import time

LIVE_LOG_FILE = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "logs", "dns_security_live.log")
)
BASE_DOMAIN = "example.com"
query_frequency = defaultdict(int)
last_notification_time = {}
NOTIFICATION_COOLDOWN = 10

os.makedirs(os.path.dirname(LIVE_LOG_FILE), exist_ok=True)

def calculate_entropy(text):
    if not text:
        return 0.0
    counts = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    entropy = 0.0
    for count in counts.values():
        p = count / len(text)
        entropy -= p * math.log2(p)
    return entropy

def get_subdomain(full_domain):
    parts = full_domain.lower().split(".")
    if len(parts) > 2:
        return ".".join(parts[:-2])
    return ""

def calculate_risk(subdomain):
    score = 0
    length = len(subdomain)
    entropy = calculate_entropy(subdomain)
    digit_count = sum(ch.isdigit() for ch in subdomain)
    digit_ratio = digit_count / length if length else 0.0
    frequency = query_frequency[subdomain]

    if length >= 15:
        score += 25
    if length >= 25:
        score += 10
    if entropy >= 3.2:
        score += 25
    if digit_ratio >= 0.25 and length >= 8:
        score += 15
    if frequency >= 10:
        score += 25
    elif frequency >= 5:
        score += 10

    return min(score, 100)

def show_notification(dns_query, risk_score):
    now = time.time()
    if dns_query in last_notification_time:
        if now - last_notification_time[dns_query] < NOTIFICATION_COOLDOWN:
            return
    last_notification_time[dns_query] = now

    safe_query = dns_query.replace("'", "''")
    command = (
        "Import-Module BurntToast; "
        f"New-BurntToastNotification "
        f"-Text 'DNS Security Alert',"
        f"'Suspicious DNS detected!`nQuery: {safe_query}`nRisk Score: {risk_score}/100'"
    )
    try:
        subprocess.Popen(
            ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass",
             "-Command", command],
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0)
        )
        print("[WINDOWS NOTIFICATION SENT]")
    except Exception as error:
        print(f"[Notification Error] {error}")

def write_log(timestamp, source_ip, destination_ip, dns_query, query_type,
              subdomain, length, entropy, frequency, risk_score, status):
    line = (
        f"timestamp={timestamp} source_ip={source_ip} "
        f"destination_ip={destination_ip} dns_query={dns_query} "
        f"query_type={query_type} subdomain={subdomain} "
        f"length={length} entropy={entropy:.3f} "
        f"frequency={frequency} risk_score={risk_score} status={status}\n"
    )
    with open(LIVE_LOG_FILE, "a", encoding="utf-8") as f:
        f.write(line)

def process_packet(packet):
    try:
        if not packet.haslayer(DNSQR):
            return
        if packet.haslayer(DNS) and packet[DNS].qr != 0:
            return

        dns_query = packet[DNSQR].qname.decode(errors="ignore").rstrip(".")
        if not dns_query.lower().endswith(BASE_DOMAIN):
            return

        source_ip = "Unknown"
        destination_ip = "Unknown"
        if packet.haslayer(IP):
            source_ip = packet[IP].src
            destination_ip = packet[IP].dst
        elif packet.haslayer(IPv6):
            source_ip = packet[IPv6].src
            destination_ip = packet[IPv6].dst

        subdomain = get_subdomain(dns_query)
        if not subdomain:
            return

        query_frequency[subdomain] += 1
        frequency = query_frequency[subdomain]
        length = len(subdomain)
        entropy = calculate_entropy(subdomain)

        qtype = packet[DNSQR].qtype
        query_type = {1: "A", 28: "AAAA", 5: "CNAME"}.get(qtype, str(qtype))

        risk_score = calculate_risk(subdomain)
        status = "POSSIBLE_SUSPICIOUS_DNS" if risk_score >= 50 else "NORMAL_OR_LOW_RISK"

        print("-" * 65)
        print(f"DNS Query: {dns_query}")
        print(f"Source IP: {source_ip}")
        print(f"Destination IP: {destination_ip}")
        print(f"Query Type: {query_type}")
        print(f"Length: {length}")
        print(f"Entropy: {entropy:.3f}")
        print(f"Frequency: {frequency}")
        print(f"Risk Score: {risk_score}/100")
        print(f"Status: {status}")

        if risk_score >= 50:
            write_log(
                datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                source_ip, destination_ip, dns_query, query_type,
                subdomain, length, entropy, frequency, risk_score, status
            )
            print("POSSIBLE SUSPICIOUS DNS ACTIVITY DETECTED!")
            show_notification(dns_query, risk_score)

    except Exception as error:
        print(f"[Packet Processing Error] {error}")

print("=" * 65)
print("DNS SECURITY LIVE MONITOR")
print("=" * 65)
print(f"Lab Domain: {BASE_DOMAIN}")
print(f"Log File: {LIVE_LOG_FILE}")
print("Monitoring live DNS traffic...")
print("Press CTRL+C to stop.")

try:
    sniff(filter="udp port 53", prn=process_packet, store=False)
except KeyboardInterrupt:
    print("DNS monitoring stopped.")
except Exception as error:
    print(f"[Sniffing Error] {error}")

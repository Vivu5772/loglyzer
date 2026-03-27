import os
import re
import pandas as pd


# -----------------------------------------------------
# 📂 Load Log File
# -----------------------------------------------------
def load_log_file(filepath):
    if not os.path.exists(filepath):
        print("❌ File not found!")
        return None

    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        lines = f.readlines()

    print(f"✅ Loaded {len(lines)} lines.")
    return lines


# -----------------------------------------------------
# 🧹 Clean Logs
# -----------------------------------------------------
def clean_logs(lines):
    cleaned = [line.strip() for line in lines if line.strip()]
    print(f"🧹 Cleaned logs — {len(cleaned)} valid lines")
    return cleaned


# -----------------------------------------------------
# 👀 Show Sample
# -----------------------------------------------------
def show_sample(lines, n=10):
    print("\n🔍 Sample Log Lines:")
    for idx, line in enumerate(lines[:n]):
        print(f"{idx+1}. {line}")


# -----------------------------------------------------
# 🌐 Detect Network Log Type
# -----------------------------------------------------
def detect_network_server(lines):
    patterns = {
        "nginx": [r"nginx", r"\"(GET|POST|HEAD|OPTIONS)\s"],
        "apache": [r"Apache", r"\"(GET|POST|HEAD|PUT|DELETE)\s"],
        "firewall": [r"SRC=", r"DST=", r"PROTO=", r"DPT=", r"DROP", r"ACCEPT", r"DENY"],
        "ids_ips": [r"Snort", r"Suricata", r"\[Classification", r"\[Priority"],
        "vpn": [r"OpenVPN", r"Peer Connection", r"CLIENT_LIST", r"AUTH_FAILED"],
"dns": [
    r"\b53\b",
    r"\bNXDOMAIN\b",
    r"\bNOERROR\b",
    r"\bC_INTERNET\b",
    r"\bPTR\b",
    r"\bAAAA\b"
]
,

        "router": [r"%SEC-", r"Interface", r"ethernet", r"ACL", r"ip access-list"]
    }

    counts = {key: 0 for key in patterns}

    for line in lines[:400]:
        for server, regex_list in patterns.items():
            for regex in regex_list:
                if re.search(regex, line, re.IGNORECASE):
                    counts[server] += 1

    detected = max(counts, key=counts.get)
    if all(v == 0 for v in counts.values()):
        detected = "unknown"

    print(f"\n🌐 Detected Network Log: {detected.upper()}")
    print("Confidence:", counts)
    return detected


# -----------------------------------------------------
# 🅰️ Apache Parser
# -----------------------------------------------------
def parse_apache_logs(lines):
    pattern = r'(?P<ip>\d+\.\d+\.\d+\.\d+).*?\[(?P<timestamp>.*?)\]\s+"(?P<method>\w+)\s+(?P<path>\S+).*?"\s+(?P<status>\d+)\s+(?P<size>\d+)'
    records = [m.groupdict() for l in lines if (m := re.search(pattern, l))]
    df = pd.DataFrame(records)
    print(f"🅰️ Apache entries: {len(df)}")
    return df


# -----------------------------------------------------
# 🌀 Nginx Parser
# -----------------------------------------------------
def parse_nginx_logs(lines):
    pattern = r'(?P<ip>\d+\.\d+\.\d+\.\d+).*\[(?P<timestamp>.*?)\]\s+"(?P<method>\w+)\s+(?P<path>\S+).*?"\s+(?P<status>\d+)'
    records = [m.groupdict() for l in lines if (m := re.search(pattern, l))]
    df = pd.DataFrame(records)
    print(f"🌀 Nginx entries: {len(df)}")
    return df


# -----------------------------------------------------
# 🔥 Firewall Logs (iptables / UFW / router)
# -----------------------------------------------------
def parse_firewall_logs(lines):
    pattern = r'SRC=(?P<src_ip>\d+\.\d+\.\d+\.\d+).*DST=(?P<dst_ip>\d+\.\d+\.\d+\.\d+).*PROTO=(?P<proto>\w+).*DPT=(?P<port>\d+)'
    records = [m.groupdict() for l in lines if (m := re.search(pattern, l))]
    df = pd.DataFrame(records)
    print(f"🔥 Firewall entries: {len(df)}")
    return df


# -----------------------------------------------------
# 🛡 IDS/IPS (Snort / Suricata)
# -----------------------------------------------------
def parse_ids_logs(lines):
    pattern = r'\[(?P<event_id>\d+:\d+:\d+)\].*Classification:\s*(?P<class>.*?)]\s*\[Priority:\s*(?P<priority>\d+)].*?\{(?P<proto>\w+)}\s*(?P<src_ip>[0-9\.]+).*?(?P<dst_ip>[0-9\.]+)'
    records = [m.groupdict() for l in lines if (m := re.search(pattern, l))]
    df = pd.DataFrame(records)
    print(f"🛡 IDS/IPS entries: {len(df)}")
    return df


# -----------------------------------------------------
# 🔑 VPN Logs (OpenVPN)
# -----------------------------------------------------
def parse_vpn_logs(lines):
    pattern = r'(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+).*?(Peer Connection|CLIENT_LIST).*?(?P<ip>\d+\.\d+\.\d+\.\d+)'
    records = [m.groupdict() for l in lines if (m := re.search(pattern, l))]
    df = pd.DataFrame(records)
    print(f"🔑 VPN entries: {len(df)}")
    return df


# -----------------------------------------------------
# 🧠 DNS Logs (ZEEK / dnsmasq)
# -----------------------------------------------------
def parse_dns_logs(lines):
    records = []

    for line in lines:
        parts = re.split(r"\s+", line.strip())

        if len(parts) < 13:
            continue

        try:
            record = {
                "timestamp": parts[0],
                "uid": parts[1],
                "src_ip": parts[2],
                "src_port": parts[3],
                "dst_ip": parts[4],
                "dst_port": parts[5],
                "proto": parts[6],
                "query": parts[8],
                "qtype": parts[11],   # A, AAAA, PTR
                "rcode": parts[12]    # NOERROR, NXDOMAIN, -
            }
            records.append(record)
        except Exception:
            continue

    df = pd.DataFrame(records)
    print(f"🧠 Parsed DNS entries: {len(df)}")
    return df



# -----------------------------------------------------
# 📡 Router Logs (Cisco style)
# -----------------------------------------------------
def parse_router_logs(lines):
    pattern = r'(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+).*%SEC.*?from\s(?P<src_ip>\d+\.\d+\.\d+\.\d+)'
    records = [m.groupdict() for l in lines if (m := re.search(pattern, l))]
    df = pd.DataFrame(records)
    print(f"📡 Router entries: {len(df)}")
    return df


# -----------------------------------------------------
# 🛠 Dispatcher
# -----------------------------------------------------
def route_network_parser(lines):
    t = detect_network_server(lines)

    return {
        "apache": parse_apache_logs,
        "nginx": parse_nginx_logs,
        "firewall": parse_firewall_logs,
        "ids_ips": parse_ids_logs,
        "vpn": parse_vpn_logs,
        "dns": parse_dns_logs,
        "router": parse_router_logs
    }.get(t, lambda x: pd.DataFrame())(lines)


# -----------------------------------------------------
# 📊 Summary
# -----------------------------------------------------
def generate_summary(df):
    if df.empty:
        print("⚠️ No structured entries detected.")
        return
    
    print("\n📊 Summary:")
    print(df.head())

    if "src_ip" in df.columns:
        print("\nTop Source IPs:")
        print(df["src_ip"].value_counts().head())

    if "query" in df.columns:
        print("\nTop DNS Queries:")
        print(df["query"].value_counts().head())

    if "qtype" in df.columns:
        print("\nQuery Types:")
        print(df["qtype"].value_counts().head())

    if "rcode" in df.columns:
        print("\nResponse Codes:")
        print(df["rcode"].value_counts().head())


def analyze_log(file_path, verbose=False):
    logs = load_log_file(file_path)
    if logs:
        logs = clean_logs(logs)
        df = route_network_parser(lines=logs)

        if verbose:
            generate_summary(df)  # only for CLI

        return df
    return None


# -----------------------------------------------------
# 🚀 MAIN
# -----------------------------------------------------
if __name__ == "__main__":
    path = input("Enter log file path: ")
    df = analyze_log(path)
    if df is not None:
        print(df.head())

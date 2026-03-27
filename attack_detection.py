import pandas as pd
import requests
import ipaddress
# ------------------------------------
# 🚨 Attack Detection Rules
# ------------------------------------
import re
import math




def geo_lookup(ip):
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}", timeout=3)
        data = r.json()

        if data.get("status") == "success":
            return {
                "country": data.get("country"),
                "city": data.get("city"),
                "lat": data.get("lat"),
                "lon": data.get("lon")
            }
    except:
        pass

    return {
        "country": "Unknown",
        "city": "Unknown",
        "lat": None,
        "lon": None
    }


def is_private_ip(ip):
    try:
        return ipaddress.ip_address(ip).is_private
    except:
        return False


def shannon_entropy(s):
    if not s:
        return 0
    freq = {c: s.count(c) for c in set(s)}
    return -sum((f/len(s)) * math.log2(f/len(s)) for f in freq.values())


def detect_attacks(df):
    alerts = []

    if df.empty or "src_ip" not in df.columns or "query" not in df.columns:
        return alerts

    total_rows = len(df)

    # -------------------------------
    # 🧠 DNS TUNNELING (REALISTIC)
    # -------------------------------
    df["query_len"] = df["query"].astype(str).apply(len)
    df["entropy"] = df["query"].astype(str).apply(shannon_entropy)

    for ip, group in df.groupby("src_ip"):
        total = len(group)
        unique_domains = group["query"].nunique()

        long_domains = group[group["query_len"] > 40]
        high_entropy = group[group["entropy"] > 3.8]

        # 🚨 REALISTIC CONDITIONS (MULTI-SIGNAL)
        if (
            total > 50 and
            unique_domains / total > 0.6 and
            len(long_domains) > 10 and
            len(high_entropy) > 10
        ):
            alerts.append({
                "attack": "DNS Tunneling (Behavior-Based)",
                "source_ip": ip,
                "details": (
                    f"{unique_domains} unique queries out of {total}, "
                    f"{len(long_domains)} long, {len(high_entropy)} high-entropy"
                )
            })

    # -------------------------------
    # ⚠️ DNS FAILURE FLOOD
    # -------------------------------
    if "rcode" in df.columns:
        failures = df[df["rcode"].isin(["NXDOMAIN", "-", "1"])]

        for ip, count in failures["src_ip"].value_counts().items():
            total = df[df["src_ip"] == ip].shape[0]

            if total > 30 and count / total > 0.4:
                alerts.append({
                    "attack": "DNS Failure Flood",
                    "source_ip": ip,
                    "details": f"{count}/{total} failed DNS responses"
                })

    # -------------------------------
    # ⚠️ EXCESSIVE DNS REQUESTS (RATE-BASED)
    # -------------------------------
    threshold = max(100, int(total_rows * 0.3))

    for ip, count in df["src_ip"].value_counts().items():
        if count > threshold:
            alerts.append({
                "attack": "Abnormal DNS Request Rate",
                "source_ip": ip,
                "details": f"{count} DNS requests (threshold={threshold})"
            })

# 🌍 ADD LOCATION TO EACH ALERT (THIS WAS MISSING)
    for alert in alerts:
        ip = alert.get("source_ip")

        if is_private_ip(ip):
            alert["location"] = {
                "country": "Internal Network",
                "city": "Private IP",
                "lat": 20.0,
                "lon": 0.0
            }
        else:
            alert["location"] = geo_lookup(ip)

    return alerts

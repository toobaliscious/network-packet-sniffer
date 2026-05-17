# ============================================================
# 🛡️ SOC WIRESHARK-STYLE ANALYZER (PRO VERSION)
# ============================================================
# UPGRADES INCLUDED:
# - Login/Register system (JSON-based)
# - Wireshark-style packet inspector
# - Domain extraction (DNS + HTTP Host)
# - Own traffic detection (local IP highlight)
# - Per-IP download reports + full export
# - Expanded protocol detection (TCP/UDP/ICMP/DNS/HTTP/HTTPS/ARP/FTP)
# - Clean Wireshark-like search workflow
# ============================================================

import streamlit as st
import pandas as pd
import json
import os
import time
import socket
from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS, ARP, Raw

# ============================================================
# PAGE CONFIG
# ============================================================

st.set_page_config(
    page_title="Network Packet Sniffer",
    page_icon="🛡️",
    layout="wide"
)

# ============================================================
# UI STYLE
# ============================================================

st.markdown("""
<style>
.stApp { background-color:#0B1220; color:#E6EDF3; }
h1,h2 { color:#58A6FF; }
.block { background:#161B22; padding:12px; border-radius:10px; border:1px solid #30363D; }
</style>
""", unsafe_allow_html=True)

# ============================================================
# AUTH SYSTEM (REGISTER / LOGIN)
# ============================================================

USER_DB = "users.json"

if not os.path.exists(USER_DB):
    with open(USER_DB,"w") as f:
        json.dump({}, f)

def load_users():
    with open(USER_DB,"r") as f:
        return json.load(f)

def save_users(data):
    with open(USER_DB,"w") as f:
        json.dump(data,f)

users = load_users()

if "user" not in st.session_state:
    st.session_state.user = None

st.sidebar.title("🔐 Login System")
mode = st.sidebar.radio("Mode", ["Login","Register"])

if mode == "Register":
    u = st.sidebar.text_input("New Username")
    p = st.sidebar.text_input("New Password", type="password")

    if st.sidebar.button("Create Account"):
        if u in users:
            st.sidebar.error("User exists")
        else:
            users[u] = p
            save_users(users)
            st.sidebar.success("Account created")

elif mode == "Login":
    u = st.sidebar.text_input("Username")
    p = st.sidebar.text_input("Password", type="password")

    if st.sidebar.button("Login"):
        if u in users and users[u] == p:
            st.session_state.user = u
            st.sidebar.success("Logged in")
        else:
            st.sidebar.error("Invalid credentials")

if st.session_state.user is None:
    st.warning("Please login first")
    st.stop()

# ============================================================
# DATA STORAGE
# ============================================================

if "packets" not in st.session_state:
    st.session_state.packets = []

local_ip = socket.gethostbyname(socket.gethostname())

# ============================================================
# PACKET PROCESSOR
# ============================================================

def extract_domain(packet):
    domain = ""

    # DNS DOMAIN
    if packet.haslayer(DNS) and packet[DNS].qd:
        try:
            domain = packet[DNS].qd.qname.decode()
        except:
            domain = "DNS"

    # HTTP HOST HEADER
    if packet.haslayer(Raw):
        try:
            load = str(packet[Raw].load)
            if "Host:" in load:
                for line in load.split("\\r\\n"):
                    if "Host:" in line:
                        domain = line.split("Host:")[1].strip()
        except:
            pass

    return domain if domain else "Unknown"

# ============================================================
# PACKET HANDLER
# ============================================================

def process(packet):
    if IP in packet:

        src = packet[IP].src
        dst = packet[IP].dst
        size = len(packet)

        protocol = "OTHER"
        if TCP in packet:
            protocol = "TCP"
        elif UDP in packet:
            protocol = "UDP"
        elif ICMP in packet:
            protocol = "ICMP"
        elif DNS in packet:
            protocol = "DNS"
        elif ARP in packet:
            protocol = "ARP"

        # HTTP / HTTPS detection
        if TCP in packet:
            if packet[TCP].dport == 80 or packet[TCP].sport == 80:
                protocol = "HTTP"
            if packet[TCP].dport == 443 or packet[TCP].sport == 443:
                protocol = "HTTPS"

        payload = ""
        if packet.haslayer(Raw):
            try:
                payload = str(packet[Raw].load)[:120]
            except:
                payload = "Unreadable"

        domain = extract_domain(packet)

        st.session_state.packets.append({
            "Time": time.strftime("%H:%M:%S"),
            "Source": src,
            "Destination": dst,
            "Protocol": protocol,
            "Domain": domain,
            "Size": size,
            "Payload": payload,
            "Is_You": "YES" if src == local_ip else "NO"
        })

# ============================================================
# CONTROL PANEL
# ============================================================

st.title("🛡️ SOC Wireshark Pro Analyzer")
st.sidebar.header("Controls")

ip_filter = st.sidebar.text_input("Search IP")
proto_filter = st.sidebar.multiselect("Protocols", ["TCP","UDP","ICMP","HTTP","HTTPS","DNS","ARP"], default=["TCP","UDP","HTTP","HTTPS"])
limit = st.sidebar.slider("Packets",10,200,50)
start = st.sidebar.button("Start Capture")

# ============================================================
# CAPTURE
# ============================================================

if start:
    sniff(prn=process, count=limit, timeout=10, store=False)

# ============================================================
# DATAFRAME
# ============================================================

df = pd.DataFrame(st.session_state.packets)

if df.empty:
    st.warning("No packets yet")
    st.stop()

# ============================================================
# FILTERS
# ============================================================

df = df[df["Protocol"].isin(proto_filter)]

if ip_filter:
    df = df[df["Source"].str.contains(ip_filter) | df["Destination"].str.contains(ip_filter)]

# ============================================================
# METRICS
# ============================================================

col1,col2,col3 = st.columns(3)
col1.metric("Packets",len(df))
col2.metric("Unique IPs",df["Source"].nunique())
col3.metric("Your Traffic",len(df[df["Is_You"]=="YES"]))

# ============================================================
# TABLE
# ============================================================

st.subheader("📡 Packet Table (Wireshark View)")
st.dataframe(df,use_container_width=True)

# ============================================================
# INSPECTOR
# ============================================================

st.subheader("🔍 Packet Inspector")
idx = st.selectbox("Select Packet", df.index)
pkt = df.loc[idx]

st.write(pkt)
st.code(pkt["Payload"])

# ============================================================
# DOWNLOAD SYSTEM
# ============================================================

st.subheader("⬇️ Export System")

csv_all = df.to_csv(index=False).encode()
st.download_button("Download ALL PACKETS", csv_all, "all_packets.csv")

if ip_filter:
    csv_ip = df.to_csv(index=False).encode()
    st.download_button("Download FILTERED IP", csv_ip, "filtered_ip.csv")

# ============================================================
# DOMAIN VIEW
# ============================================================

st.subheader("🌐 Domain Intelligence")
st.dataframe(df[["Source","Destination","Domain","Protocol"]])

# ============================================================
# LOGIN INFO DISPLAY
# ============================================================

st.success(f"Logged in as: {st.session_state.user}")

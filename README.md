# 🛡️ SOC Wireshark Analyzer (Streamlit + Scapy)

## 📌 Overview

The **SOC Wireshark Analyzer** is a cybersecurity network monitoring tool inspired by Wireshark and SOC (Security Operations Center) workflows.

It enables real-time packet capture, inspection, and analysis of network traffic using Python, Streamlit, and Scapy.

This project simulates how SOC analysts investigate network traffic, analyze packets, and detect suspicious activity.

---

## 🎥 Demo

👉 View the working demonstration:

- 📁 Local file: `demo.mp4`
- 📌 Click below:

👉 **[Watch Demo Video](demo.mp4)**

> ⚠️ If video does not open in GitHub, download and play locally.

---

## 🚀 Features

### 📡 Network Packet Capture
- Real-time packet sniffing using Scapy
- Extracts IP addresses, protocols, and payloads
- Captures live network traffic

---

### 🔍 Wireshark-Style Analysis
- Packet-by-packet inspection
- Select and analyze individual packets
- View raw payload data

---

### 🌐 Domain Intelligence
- DNS query detection
- HTTP Host header extraction
- Maps IP traffic to real domains

---

### 🔐 Authentication System
- User registration system
- Login authentication
- Session-based access control

---

### 🔎 SOC Investigation Tools
- IP search filtering
- Protocol filtering (TCP, UDP, ICMP, DNS, HTTP, HTTPS, ARP)
- Own device traffic detection
- SOC-style investigation workflow

---

### 📥 Export System
- Download full packet logs (CSV)
- Export filtered reports for investigation
- Evidence collection for SOC analysis

---

## 🧠 How It Works

1. Captures live network packets using Scapy  
2. Extracts:
   - Source IP / Destination IP  
   - Protocol type  
   - Payload data  
   - Domain information (DNS / HTTP)  
3. Displays structured traffic in Streamlit UI  
4. Allows filtering, searching, and inspection  
5. Enables export of reports for SOC analysis  

---

## 🛠️ Tech Stack

- Python 🐍  
- Streamlit 📊  
- Scapy 📡  
- Pandas 🧮  

---

## ⚙️ Setup Instructions

### 1️⃣ Run the application

```bash
streamlit run app.py

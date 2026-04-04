# FTP Honeypot - Network Attack Monitoring & Credential Logging System

**A professional threat detection and analysis platform for SOC training and research.**

![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)
![SOC](https://img.shields.io/badge/Use%20Case-SOC%20Training-red.svg)

---

## Overview

A SOC-grade FTP honeypot designed to simulate real-world attack scenarios, detect malicious activity, and map threats to MITRE ATT&CK techniques for security analysis and incident response training.

---

## 🔥 Project Highlights

- Built a multi-threaded FTP honeypot to capture real attacker behavior and interactions  
- Implemented brute-force detection with MITRE ATT&CK mapping (T1110, T1003)  
- Designed structured logging system (JSON/CSV) for SOC analysis and threat investigation  
- Simulated real-world attacks using Hydra and Telnet in a controlled lab environment  
- Developed session tracking and threat scoring system for attacker profiling  

---

## Features

### Core Capabilities
- **FTP Server Emulation** - Full FTP protocol support (USER, PASS, LIST, RETR, STOR, etc.)
- **HTTP Server** - Captures browser fingerprinting data
- **Session Tracking** - Unique session IDs with full command history
- **Threat Scoring** - Quantified threat levels per session

### Security Analysis
- **MITRE ATT&CK Mapping** - Automatic technique identification
  - T1110 - Brute Force
  - T1059 - Command and Scripting Interpreter
  - T1070.004 - File Deletion
  - T1018 - Remote System Discovery
  - And more...

- **Attack Detection**
  - Brute force attempts (configurable threshold)
  - Reconnaissance behavior
  - Suspicious commands (DELETE, WGET, NMAP, etc.)
  - Credential harvesting attempts

### Logging & Export
- **Structured JSON Logging** - IP, timestamp, session, username, password, command
- **CSV Export** - For SIEM integration
- **Session Replay** - Review complete attack chains

### Dashboard
- Real-time statistics
- Top attackers by threat score
- Recent alerts with MITRE mapping
- Rich terminal UI (optional)

---

# Installation
## Clone or navigate to the directory
```
cd Honeypot
```
## Install dependencies
```
pip install rich
```
## Run
```
python main.py
```

# Usage
Start Server
```
python main.py
```

CLI Commands
```
python main.py cli sessions
python main.py cli alerts
python main.py cli summary
python main.py cli export
python main.py cli replay:SESSION_ID
```

# Architecture
FTP Server → Attack Detection Engine → MITRE Mapping → Logging → SOC Dashboard

# Use Cases
SOC training and simulation

Threat intelligence and attacker behavior analysis

SIEM log testing and integration

Cybersecurity research and experimentation

# Ethical Considerations

This project is intended for:
Authorized security testing
Educational purposes
Research environments
Do NOT deploy on unauthorized systems.

# 👨‍💻 Author

Kishan N
Aspiring Penetration Tester | Cybersecurity Enthusiast
Focused on Offensive Security, Threat Detection & SOC Engineering

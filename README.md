# SOC-Grade FTP Honeypot System v2.0

**A professional threat detection and analysis platform for SOC training and research.**

![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)
![SOC](https://img.shields.io/badge/Use%20Case-SOC%20Training-red.svg)

---

## Overview

This is a production-ready FTP honeypot designed to simulate a vulnerable FTP server while capturing and analyzing attacker behavior. It provides SOC analysts with real-world attack data for training and research purposes.

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

## Installation

```bash
# Clone or navigate to the directory
cd Honeypot

# Install dependencies
pip install rich

# Run
python main.py
```

---

## Configuration

Edit `config.json` to customize:

```json
{
    "ftp": {
        "host": "0.0.0.0",
        "port": 21
    },
    "detection": {
        "brute_force_threshold": 5,
        "brute_force_window_seconds": 300
    },
    "logging": {
        "log_dir": "honeypot_logs",
        "export_on_exit": true
    }
}
```

### Configuration Options

| Parameter | Description | Default |
|-----------|-------------|---------|
| `ftp.port` | FTP server port | 21 |
| `detection.brute_force_threshold` | Failed logins before alert | 5 |
| `detection.brute_force_window_seconds` | Time window for brute force detection | 300 |
| `logging.log_dir` | Log output directory | honeypot_logs |
| `honeypot.valid_usernames` | Accepted usernames | ["admin", ...] |
| `honeypot.valid_passwords` | Accepted passwords | ["admin", ...] |

---

## Usage

### Start Server
```bash
python main.py
```

### CLI Commands
```bash
# Show all sessions
python main.py cli sessions

# Show all alerts
python main.py cli alerts

# Show incident summary
python main.py cli summary

# Export logs
python main.py cli export

# Replay a session
python main.py cli replay:SESSION_ID
```

### Custom Config
```bash
python main.py custom_config.json
```

---

## Log Output

### Event Log (events.jsonl)
```json
{
  "event_type": "login_failed",
  "ip": "192.168.1.100",
  "timestamp": "2026-04-04T12:00:00.000000",
  "session_id": "A1B2C3D4",
  "username": "admin",
  "password": "wrongpass",
  "command": ""
}
```

### Alert Log (alerts.jsonl)
```json
{
  "timestamp": "2026-04-04T12:00:00.000000",
  "level": "HIGH",
  "category": "BRUTE_FORCE",
  "source_ip": "192.168.1.100",
  "session_id": "A1B2C3D4",
  "description": "Brute force attack detected from 192.168.1.100",
  "mitre": {
    "id": "T1110",
    "name": "Brute Force",
    "tactic": "Credential Access"
  },
  "details": {"attempts": 5}
}
```

### Session Data (sessions.json)
```json
{
  "session_id": "A1B2C3D4",
  "ip_address": "192.168.1.100",
  "username": "admin",
  "start_time": "2026-04-04T12:00:00",
  "commands": [
    {
      "command": "DELE secret.txt",
      "timestamp": "2026-04-04T12:05:00",
      "threat_level": "HIGH",
      "mitre_id": "T1070.004",
      "mitre_name": "File Deletion"
    }
  ],
  "threat_score": 10
}
```

---

## Threat Levels

| Level | Score | Examples |
|-------|-------|----------|
| LOW | 1 | LIST, PWD, CD |
| MEDIUM | 5 | RENAME, RECON behavior |
| HIGH | 10 | DELETE, WGET, CREDENTIALS |
| CRITICAL | 25 | SHUTDOWN, EXEC, KILL |

---

## MITRE ATT&CK Techniques

| Technique | ID | Tactic |
|-----------|-----|--------|
| Brute Force | T1110 | Credential Access |
| Command and Scripting Interpreter | T1059 | Execution |
| Remote System Discovery | T1018 | Discovery |
| File Deletion | T1070.004 | Defense Evasion |
| File and Directory Discovery | T1083 | Discovery |
| Data Staged | T1074 | Collection |
| OS Credential Dumping | T1003 | Credential Access |

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    FTP Honeypot                         │
├─────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐    │
│  │ FTP Server  │  │HTTP Server  │  │  Dashboard  │    │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘    │
│         │                │                │           │
│         └────────────────┼────────────────┘           │
│                          ▼                            │
│              ┌─────────────────────┐                  │
│              │   Attack Detector    │                  │
│              │  - Brute Force      │                  │
│              │  - Recon Behavior    │                  │
│              │  - Suspicious Cmds  │                  │
│              └──────────┬──────────┘                  │
│                         ▼                             │
│              ┌─────────────────────┐                  │
│              │     SOC Logger       │                  │
│              │  - JSON Logging      │                  │
│              │  - Session Tracking  │                  │
│              │  - Alert Generation │                  │
│              └──────────┬──────────┘                  │
│                         ▼                             │
│              ┌─────────────────────┐                  │
│              │   honeypot_logs/     │                  │
│              │  - events.jsonl      │                  │
│              │  - alerts.jsonl      │                  │
│              │  - sessions.json     │                  │
│              └─────────────────────┘                  │
└─────────────────────────────────────────────────────────┘
```

---

## Use Cases

### 1. SOC Training
- Real attack simulation
- Incident response practice
- Alert analysis training

### 2. Threat Research
- Attack pattern analysis
- Attacker methodology study
- IOC collection

### 3. SIEM Testing
- Log format validation
- Alert rule testing
- Integration verification

### 4. Honeypot Deployment
- Early threat detection
- Attacker's tools analysis
- Network defense testing

---

## Ethical Considerations

This honeypot is designed for:
- **Authorized security testing**
- **Educational purposes**
- **Research environments**

Do NOT deploy on networks without proper authorization.

---

## Sample Session Output

```
╔══════════════════════════════════════════════════════════╗
║     [SOC] FTP Honeypot System v2.0                         ║
║     Threat Detection & Analysis Platform                  ║
╠══════════════════════════════════════════════════════════╣
║  [+] FTP Server: 192.168.1.100:21                        ║
║  [+] MITRE ATT&CK Mapping: ENABLED                        ║
║  [+] Logging: JSON + CSV                                   ║
║  [+] Attack Detection: ENABLED                             ║
╚══════════════════════════════════════════════════════════╝

[AUTH SUCCESS] 192.168.1.50 - admin:admin123
    [MITRE] T1003 - OS Credential Dumping
[ALERT] HIGH: Brute force attack detected from 192.168.1.100
    [MITRE] T1110 - Brute Force

============================================================
INCIDENT RESPONSE SUMMARY
============================================================
  Total Attacks:        25
  Unique Attackers:     3
  Total Alerts:         12
  High/Critical:        5
  Top Attacker IP:      192.168.1.100
  MITRE ATT&CK Tactics Detected:
    - Credential Access
    - Execution
    - Discovery
```

---

## Files Structure

```
Honeypot/
├── main.py           # Main application
├── config.json       # Configuration
├── requirements.txt  # Dependencies
├── README.md        # Documentation
└── honeypot_logs/   # Log output (created on run)
    ├── events.jsonl
    ├── alerts.jsonl
    ├── sessions.json
    └── export_*.json/csv
```

---

## License

MIT License - Free for educational and research use.

---

## Author

Built for SOC training and cybersecurity research.

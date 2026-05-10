# 🍯 FTP Honeypot

![Python](https://img.shields.io/badge/python-3.8+-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Status](https://img.shields.io/badge/status-active-brightgreen)
![MITRE](https://img.shields.io/badge/MITRE-ATT%26CK-red)
![Use Case](https://img.shields.io/badge/use--case-SOC%20Training-orange)

> Multi-threaded FTP honeypot with real-time MITRE ATT&CK mapping, threat scoring, session replay, and SOC dashboard — built for threat intelligence and attacker behavior analysis.

---

## ⚠️ Disclaimer

This tool is intended **ONLY** for:

- Authorized security research and threat intelligence
- SOC training and blue team exercises
- Controlled lab environments
- Educational and cybersecurity training purposes

**Do NOT deploy on unauthorized systems or public infrastructure without explicit permission.**

---

## Overview

FTP Honeypot is a SOC-grade deception platform that simulates a vulnerable FTP server to capture, classify, and analyze real attacker behavior. Every interaction is automatically mapped to MITRE ATT&CK techniques, scored by threat level, and logged in structured JSON/CSV format for SIEM integration and incident response training.

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                   FTP HONEYPOT                          │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  ┌───────────────────────────────────────────────────┐  │
│  │           FTP SERVER (port 21)                   │  │
│  │  Multi-threaded, full protocol emulation         │  │
│  │  USER, PASS, LIST, RETR, STOR, DELE, MKD...      │  │
│  └───────────────────────────────────────────────────┘  │
│                          │                              │
│                          ▼                              │
│  ┌───────────────────────────────────────────────────┐  │
│  │           ATTACK DETECTOR                        │  │
│  │  Brute force detection (sliding window)          │  │
│  │  Suspicious command classification               │  │
│  │  Reconnaissance behavior analysis               │  │
│  └───────────────────────────────────────────────────┘  │
│                          │                              │
│                          ▼                              │
│  ┌───────────────────────────────────────────────────┐  │
│  │           MITRE ATT&CK MAPPER                    │  │
│  │  T1110 Brute Force → Credential Access           │  │
│  │  T1059 Scripting → Execution                     │  │
│  │  T1070.004 File Deletion → Defense Evasion       │  │
│  │  T1048 Exfiltration → Exfiltration               │  │
│  │  T1083 Dir Discovery → Discovery                 │  │
│  └───────────────────────────────────────────────────┘  │
│                          │                              │
│                          ▼                              │
│  ┌───────────────────────────────────────────────────┐  │
│  │           SOC LOGGER                             │  │
│  │  events.jsonl → structured event log            │  │
│  │  alerts.jsonl → alert stream with MITRE refs    │  │
│  │  sessions.json → full session tracking          │  │
│  │  export_*.csv → SIEM-ready CSV exports          │  │
│  └───────────────────────────────────────────────────┘  │
│                          │                              │
│                          ▼                              │
│  ┌───────────────────────────────────────────────────┐  │
│  │           SOC DASHBOARD (Rich terminal UI)       │  │
│  │  Live stats, top attackers, recent alerts        │  │
│  │  Refreshes every 5 seconds                      │  │
│  └───────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────┘
```

---

## Features

### 🖧 FTP Server Emulation
- Full FTP protocol support — `USER`, `PASS`, `LIST`, `RETR`, `STOR`, `DELE`, `MKD`, `CWD`, `PWD`, `QUIT`, `RNFR`, `RNTO`, `PORT`
- Multi-threaded — handles multiple simultaneous attacker connections
- Randomized fake filesystem (8-12 files, 3-5 directories per session) — looks realistic to attackers
- Fake file content served on `RETR` — keeps attacker engaged longer
- Configurable credentials via `config.json`

### 🎯 MITRE ATT&CK Mapping

Every command and behavior is automatically mapped:

| Command / Behavior | MITRE ID | Technique | Tactic |
|-------------------|----------|-----------|--------|
| Brute force login | T1110 | Brute Force | Credential Access |
| DELE / DELETE / RM | T1070.004 | File Deletion | Defense Evasion |
| WGET / CURL / RETR | T1048 | Exfiltration Over Alt Protocol | Exfiltration |
| STOR / PUT | T1074 | Data Staged | Collection |
| LIST / DIR / LS | T1083 | File and Directory Discovery | Discovery |
| RNFR / RNTO | T1074 | Data Staged | Collection |
| MKD / MKDIR | T1083 | File and Directory Discovery | Discovery |
| Suspicious commands | T1059 | Command and Scripting Interpreter | Execution |
| Credential success | T1003 | OS Credential Dumping | Credential Access |
| Recon pattern | T1018 | Remote System Discovery | Discovery |

### 🚨 Attack Detection
- **Brute force detection** — sliding window counter (configurable threshold + time window)
- **Suspicious command detection** — `DELETE`, `WGET`, `CURL`, `NMAP`, `SQL`, `EXEC`, `SHUTDOWN`, `KILL` etc.
- **Reconnaissance behavior** — detects repeated enumeration patterns from same IP
- **Threat scoring** — LOW(+1), MEDIUM(+5), HIGH(+10), CRITICAL(+25) per session

### 📊 SOC Logging & Export
- `events.jsonl` — every connection, login attempt, command logged with IP + timestamp + session ID
- `alerts.jsonl` — alert stream with full MITRE ATT&CK references
- `sessions.json` — complete session state including full command history
- `export_*.csv` — SIEM-ready CSV export on demand or auto-export on shutdown
- `export_*.json` — full JSON export for investigation

### 🖥️ SOC Dashboard (Rich Terminal UI)
- Live statistics — active sessions, unique attackers, total alerts
- Top attackers table — ranked by threat score
- Recent alerts table — with MITRE IDs, threat levels, source IPs
- Auto-refreshes every 5 seconds
- Graceful fallback to plain text if Rich not installed

### 🔄 Session Replay
- Replay any attack session by session ID
- Shows complete command timeline with MITRE mappings and threat levels
- Perfect for SOC training and incident response exercises

---

## Installation

```bash
git clone https://github.com/Ki1shan/FTP-Honeypot.git
cd FTP-Honeypot
pip install rich
```

---

## Usage

### Start the Honeypot
```bash
python main.py
```

### CLI Commands (analysis without running the server)
```bash
python main.py cli sessions               # List all captured sessions
python main.py cli alerts                 # Show all alerts with MITRE refs
python main.py cli summary                # Incident response summary
python main.py cli export                 # Export logs to JSON + CSV
python main.py cli replay:SESSION_ID      # Replay a specific attack session
```

---

## Configuration (`config.json`)

```json
{
    "ftp": {
        "host": "0.0.0.0",
        "port": 21,
        "timeout": 30
    },
    "detection": {
        "brute_force_threshold": 5,
        "brute_force_window_seconds": 300,
        "recon_command_threshold": 5,
        "recon_unique_threshold": 3
    },
    "logging": {
        "log_dir": "honeypot_logs",
        "export_on_exit": true
    },
    "honeypot": {
        "file_count_min": 8,
        "file_count_max": 12,
        "valid_usernames": ["admin", "root", "ftp", "anonymous"],
        "valid_passwords": ["admin", "pass", "password", "123456"]
    }
}
```

---

## Sample Output

**Live alert (brute force detected):**
```
[ALERT] HIGH: Brute force attack detected from 192.168.1.9
    [MITRE] T1110 - Brute Force (Credential Access)
```

**Alert log entry (`alerts.jsonl`):**
```json
{
  "timestamp": "2026-04-04T13:23:06.958208",
  "level": "HIGH",
  "category": "BRUTE_FORCE",
  "source_ip": "192.168.1.9",
  "session_id": "C2853055",
  "description": "Brute force attack detected from 192.168.1.9",
  "mitre": {
    "id": "T1110",
    "name": "Brute Force",
    "tactic": "Credential Access"
  },
  "details": { "attempts": 5 }
}
```

**Incident Response Summary:**
```
============================================================
         INCIDENT RESPONSE SUMMARY
============================================================
  Total Attacks:        12
  Unique Attackers:     4
  Total Alerts:         8
  High/Critical:        5
  Medium:               2
  Low:                  1
  Top Attacker IP:      192.168.1.9
  Top Threat Score:     87
------------------------------------------------------------
  MITRE ATT&CK Tactics Detected:
    - Credential Access
    - Defense Evasion
    - Discovery
============================================================
```

---

## Use Cases

- **SOC Training** — realistic attacker simulation for blue team exercises
- **Threat Intelligence** — capture and analyze real attacker TTPs
- **SIEM Testing** — validate log ingestion pipelines with structured JSON/CSV
- **Incident Response Training** — session replay for IR exercises
- **Cybersecurity Research** — study FTP-based attack patterns

---

## Author

**Kishan N**
Offensive Security Engineer | SOC Engineering | Threat Detection

Built FTP Honeypot to bridge the gap between offensive knowledge and defensive engineering — turning attacker behavior into actionable threat intelligence.

---

## License

MIT License — see `LICENSE` file for details.

---

*Deception as defense. Every attacker teaches you something.*

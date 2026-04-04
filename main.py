import socket
import random
import threading
import json
import csv
import uuid
import time
import sys
import os
from datetime import datetime
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from enum import Enum

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich import box
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False
    Console = None
    Table = None
    Panel = None
    box = None


MITRE_TACTICS = {
    "BRUTE_FORCE": {"id": "T1110", "name": "Brute Force", "tactic": "Credential Access"},
    "SUSPICIOUS_COMMAND": {"id": "T1059", "name": "Command and Scripting Interpreter", "tactic": "Execution"},
    "RECON_BEHAVIOR": {"id": "T1018", "name": "Remote System Discovery", "tactic": "Discovery"},
    "FILE_DELETE": {"id": "T1070.004", "name": "File Deletion", "tactic": "Defense Evasion"},
    "FILE_DOWNLOAD": {"id": "T1048", "name": "Exfiltration Over Alternative Protocol", "tactic": "Exfiltration"},
    "FILE_UPLOAD": {"id": "T1074", "name": "Data Staged", "tactic": "Collection"},
    "FILE_RENAME": {"id": "T1074", "name": "Data Staged", "tactic": "Collection"},
    "DIR_CREATE": {"id": "T1083", "name": "File and Directory Discovery", "tactic": "Discovery"},
    "DIR_LISTING": {"id": "T1083", "name": "File and Directory Discovery", "tactic": "Discovery"},
    "CREDENTIALS": {"id": "T1003", "name": "OS Credential Dumping", "tactic": "Credential Access"},
}

THREAT_LEVEL_MITRE = {
    "DELETE": "FILE_DELETE",
    "DELE": "FILE_DELETE",
    "RM": "FILE_DELETE",
    "WGET": "FILE_DOWNLOAD",
    "CURL": "FILE_DOWNLOAD",
    "PUT": "FILE_UPLOAD",
    "STOR": "FILE_UPLOAD",
    "RETR": "FILE_DOWNLOAD",
    "RENAME": "FILE_RENAME",
    "RNFR": "FILE_RENAME",
    "RNTO": "FILE_RENAME",
    "MKDIR": "DIR_CREATE",
    "MKD": "DIR_CREATE",
    "LIST": "DIR_LISTING",
    "LS": "DIR_LISTING",
    "DIR": "DIR_LISTING",
}


class ThreatLevel(Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class Session:
    session_id: str
    ip_address: str
    username: str
    start_time: datetime
    commands: List[Dict] = field(default_factory=list)
    login_attempts: int = 0
    failed_logins: int = 0
    threat_score: int = 0
    closed: bool = False
    
    def to_dict(self) -> Dict:
        return {
            "session_id": self.session_id,
            "ip_address": self.ip_address,
            "username": self.username,
            "start_time": self.start_time.isoformat(),
            "commands": self.commands,
            "login_attempts": self.login_attempts,
            "failed_logins": self.failed_logins,
            "threat_score": self.threat_score,
            "closed": self.closed
        }


@dataclass
class Alert:
    timestamp: datetime
    level: ThreatLevel
    category: str
    source_ip: str
    session_id: str
    description: str
    mitre_id: str = ""
    mitre_name: str = ""
    mitre_tactic: str = ""
    details: Dict = field(default_factory=dict)
    
    def to_dict(self) -> Dict:
        return {
            "timestamp": self.timestamp.isoformat(),
            "level": self.level.value,
            "category": self.category,
            "source_ip": self.source_ip,
            "session_id": self.session_id,
            "description": self.description,
            "mitre": {
                "id": self.mitre_id,
                "name": self.mitre_name,
                "tactic": self.mitre_tactic
            },
            "details": self.details
        }


class Config:
    def __init__(self, config_file: str = "config.json"):
        self.config_file = config_file
        self.data = self._load()
        
    def _load(self) -> Dict:
        if Path(self.config_file).exists():
            with open(self.config_file) as f:
                return json.load(f)
        return self._default_config()
    
    def _default_config(self) -> Dict:
        return {
            "ftp": {"host": "0.0.0.0", "port": 21, "timeout": 30},
            "http": {"host": "0.0.0.0", "port": 80},
            "detection": {
                "brute_force_threshold": 5,
                "brute_force_window_seconds": 300,
                "recon_command_threshold": 5,
                "recon_unique_threshold": 3
            },
            "logging": {"log_dir": "honeypot_logs", "export_on_exit": True},
            "honeypot": {
                "file_count_min": 8, "file_count_max": 12,
                "dir_count_min": 3, "dir_count_max": 5,
                "valid_usernames": ["admin", "user", "Administrator", "anonymous", "root", "ftp", "test", "guest"],
                "valid_passwords": ["admin", "pass", "password", "123456", "root", "admin123", "test", "anonymous"]
            }
        }
    
    def get(self, path: str, default=None):
        keys = path.split(".")
        val = self.data
        for k in keys:
            if isinstance(val, dict):
                val = val.get(k)
            else:
                return default
            if val is None:
                return default
        return val


class SOCLogger:
    def __init__(self, log_dir: str = "honeypot_logs"):
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(exist_ok=True)
        self.json_log_file = self.log_dir / "events.jsonl"
        self.sessions_file = self.log_dir / "sessions.json"
        self.alerts_file = self.log_dir / "alerts.jsonl"
        self.sessions: Dict[str, Session] = {}
        self.alerts: List[Alert] = []
        self.ip_command_history: Dict[str, List[str]] = defaultdict(list)
        self._lock = threading.Lock()
        
    def log_event(self, event_type: str, ip: str, session_id: str = "", 
                  username: str = "", password: str = "", command: str = "",
                  additional_data: Optional[Dict] = None):
        event = {
            "event_type": event_type,
            "ip": ip,
            "timestamp": datetime.now().isoformat(),
            "session_id": session_id,
            "username": username,
            "password": password,
            "command": command,
        }
        if additional_data:
            event.update(additional_data)
        
        with self._lock:
            with open(self.json_log_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(event) + "\n")
            self.ip_command_history[ip].append(command)
            
    def log_login_attempt(self, ip: str, username: str, password: str, 
                          success: bool, session_id: str = ""):
        self.log_event(
            "login_attempt" if success else "login_failed",
            ip, session_id, username, password
        )
            
    def create_session(self, ip: str) -> Session:
        session = Session(
            session_id=str(uuid.uuid4())[:8].upper(),
            ip_address=ip,
            username="",
            start_time=datetime.now()
        )
        with self._lock:
            self.sessions[session.session_id] = session
        return session
    
    def update_session(self, session_id: str, **kwargs):
        with self._lock:
            if session_id in self.sessions:
                session = self.sessions[session_id]
                for key, value in kwargs.items():
                    if hasattr(session, key):
                        setattr(session, key, value)
                        
    def add_command_to_session(self, session_id: str, command: str, 
                                 threat_level: ThreatLevel = ThreatLevel.LOW):
        with self._lock:
            if session_id in self.sessions:
                session = self.sessions[session_id]
                cmd_upper = command.upper().split()[0] if command else ""
                mitre_key = THREAT_LEVEL_MITRE.get(cmd_upper, "")
                mitre_info = MITRE_TACTICS.get(mitre_key, {})
                
                session.commands.append({
                    "command": command,
                    "timestamp": datetime.now().isoformat(),
                    "threat_level": threat_level.value,
                    "mitre_id": mitre_info.get("id", ""),
                    "mitre_name": mitre_info.get("name", "")
                })
                session.threat_score += self._threat_to_score(threat_level)
                
    def _threat_to_score(self, level: ThreatLevel) -> int:
        return {ThreatLevel.LOW: 1, ThreatLevel.MEDIUM: 5, 
                ThreatLevel.HIGH: 10, ThreatLevel.CRITICAL: 25}.get(level, 0)
    
    def add_alert(self, level: ThreatLevel, category: str, source_ip: str,
                  session_id: str, description: str, details: Optional[Dict] = None):
        mitre_info = MITRE_TACTICS.get(category, {})
        
        alert = Alert(
            timestamp=datetime.now(),
            level=level,
            category=category,
            source_ip=source_ip,
            session_id=session_id,
            description=description,
            mitre_id=mitre_info.get("id", ""),
            mitre_name=mitre_info.get("name", ""),
            mitre_tactic=mitre_info.get("tactic", ""),
            details=details or {}
        )
        
        with self._lock:
            self.alerts.append(alert)
            with open(self.alerts_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(alert.to_dict()) + "\n")
                
    def close_session(self, session_id: str):
        with self._lock:
            if session_id in self.sessions:
                self.sessions[session_id].closed = True
                with open(self.sessions_file, "w", encoding="utf-8") as f:
                    json.dump([s.to_dict() for s in self.sessions.values()], f, indent=2)
                    
    def export_to_csv(self) -> str:
        csv_file = self.log_dir / f"export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        events = []
        
        if self.json_log_file.exists():
            with open(self.json_log_file, encoding="utf-8") as f:
                for line in f:
                    events.append(json.loads(line.strip()))
                    
        if events:
            with open(csv_file, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=events[0].keys())
                writer.writeheader()
                writer.writerows(events)
                    
        return str(csv_file)
    
    def export_to_json(self, session_id: Optional[str] = None) -> str:
        export_file = self.log_dir / f"export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        if session_id and session_id in self.sessions:
            data = self.sessions[session_id].to_dict()
        else:
            data = {
                "export_time": datetime.now().isoformat(),
                "sessions": [s.to_dict() for s in self.sessions.values()],
                "alerts": [a.to_dict() for a in self.alerts]
            }
            
        with open(export_file, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
            
        return str(export_file)
    
    def replay_session(self, session_id: str) -> Optional[Session]:
        return self.sessions.get(session_id)
    
    def get_summary(self) -> Dict:
        ip_scores = defaultdict(int)
        for session in self.sessions.values():
            ip_scores[session.ip_address] += session.threat_score
            
        top_attacker = max(ip_scores.items(), key=lambda x: x[1]) if ip_scores else ("N/A", 0)
        
        return {
            "total_attacks": len(self.sessions),
            "unique_attackers": len(set(s.ip_address for s in self.sessions.values())),
            "total_alerts": len(self.alerts),
            "high_severity": sum(1 for a in self.alerts if a.level in [ThreatLevel.HIGH, ThreatLevel.CRITICAL]),
            "medium_severity": sum(1 for a in self.alerts if a.level == ThreatLevel.MEDIUM),
            "low_severity": sum(1 for a in self.alerts if a.level == ThreatLevel.LOW),
            "top_attacker_ip": top_attacker[0],
            "top_attacker_score": top_attacker[1],
            "mitre_tactics": list(set(a.mitre_tactic for a in self.alerts if a.mitre_tactic))
        }


class AttackDetector:
    SUSPICIOUS_COMMANDS = {
        "DELETE": ThreatLevel.HIGH, "DELE": ThreatLevel.HIGH, "RM": ThreatLevel.HIGH,
        "SHUTDOWN": ThreatLevel.CRITICAL, "REBOOT": ThreatLevel.CRITICAL,
        "KILL": ThreatLevel.CRITICAL, "PASSWD": ThreatLevel.MEDIUM, "ROOT": ThreatLevel.MEDIUM,
        "SUDO": ThreatLevel.MEDIUM, "WGET": ThreatLevel.HIGH, "CURL": ThreatLevel.HIGH,
        "NMAP": ThreatLevel.HIGH, "SQL": ThreatLevel.HIGH, "EXEC": ThreatLevel.CRITICAL,
    }
    RECON_COMMANDS = ["LIST", "DIR", "LS", "PWD", "CD", "CWD", "STAT", "SYST", "FEAT", "HELP"]
    
    def __init__(self, logger: SOCLogger, config: Config):
        self.logger = logger
        self.config = config
        self.ip_login_attempts: Dict[str, List[datetime]] = defaultdict(list)
        
    @property
    def brute_force_threshold(self) -> int:
        return self.config.get("detection.brute_force_threshold", 5)
        
    def check_brute_force(self, ip: str) -> Optional[Alert]:
        now = datetime.now()
        window = self.config.get("detection.brute_force_window_seconds", 300)
        self.ip_login_attempts[ip] = [
            t for t in self.ip_login_attempts[ip] 
            if (now - t).total_seconds() < window
        ]
        self.ip_login_attempts[ip].append(now)
        
        if len(self.ip_login_attempts[ip]) >= self.brute_force_threshold:
            mitre = MITRE_TACTICS.get("BRUTE_FORCE", {})
            return Alert(
                timestamp=now, level=ThreatLevel.HIGH, category="BRUTE_FORCE",
                source_ip=ip, session_id="",
                description=f"Brute force attack detected from {ip}",
                mitre_id=mitre.get("id", ""),
                mitre_name=mitre.get("name", ""),
                mitre_tactic=mitre.get("tactic", ""),
                details={"attempts": len(self.ip_login_attempts[ip])}
            )
        return None
        
    def classify_command(self, command: str, ip: str, session_id: str) -> ThreatLevel:
        cmd_upper = command.upper().split()[0] if command else ""
        
        if cmd_upper in self.SUSPICIOUS_COMMANDS:
            level = self.SUSPICIOUS_COMMANDS[cmd_upper]
            mitre_key = THREAT_LEVEL_MITRE.get(cmd_upper, "SUSPICIOUS_COMMAND")
            mitre_info = MITRE_TACTICS.get(mitre_key, MITRE_TACTICS.get("SUSPICIOUS_COMMAND", {}))
            
            self.logger.add_alert(level, mitre_key, ip, session_id,
                                 f"Suspicious command: {command}", {"command": command})
            return level
            
        if cmd_upper in self.RECON_COMMANDS:
            return ThreatLevel.LOW
            
        return ThreatLevel.LOW
    
    def check_recon_behavior(self, ip: str) -> bool:
        threshold = self.config.get("detection.recon_command_threshold", 5)
        unique_threshold = self.config.get("detection.recon_unique_threshold", 3)
        
        recent = self.logger.ip_command_history.get(ip, [])[-threshold:]
        unique = set(recent)
        
        if len(recent) >= threshold and len(unique) <= unique_threshold:
            mitre = MITRE_TACTICS.get("RECON_BEHAVIOR", {})
            self.logger.add_alert(ThreatLevel.MEDIUM, "RECON_BEHAVIOR", ip, "",
                                 f"Reconnaissance behavior from {ip}", 
                                 {"commands": list(unique),
                                  "mitre_id": mitre.get("id", ""),
                                  "mitre_name": mitre.get("name", "")})
            return True
        return False


class SOCDashboard:
    def __init__(self, logger: SOCLogger, detector: AttackDetector):
        self.logger = logger
        self.detector = detector
        self.console = Console() if RICH_AVAILABLE else None
        
    def render(self):
        if not self.console:
            self._render_text()
            return
            
        self.console.clear()
        self.console.print(Panel("[bold green]SOC Dashboard - FTP Honeypot[/]", style="cyan"))
        self.console.print(self._create_stats_table())
        self.console.print()
        self.console.print(self._create_top_attackers_table())
        self.console.print()
        self.console.print(self._create_alerts_table())
        
    def _create_stats_table(self):
        table = Table(title="[bold cyan]Statistics[/]", box=box.ROUNDED)
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="magenta")
        
        active = sum(1 for s in self.logger.sessions.values() if not s.closed)
        high_alerts = sum(1 for a in self.logger.alerts 
                         if a.level in [ThreatLevel.HIGH, ThreatLevel.CRITICAL])
        
        table.add_row("Active Sessions", str(active))
        table.add_row("Total Sessions", str(len(self.logger.sessions)))
        table.add_row("Unique Attackers", str(len(set(s.ip_address for s in self.logger.sessions.values()))))
        table.add_row("Total Alerts", str(len(self.logger.alerts)))
        table.add_row("High Alerts", str(high_alerts))
        return table
    
    def _create_top_attackers_table(self):
        table = Table(title="[bold red]Top Attackers[/]", box=box.ROUNDED)
        table.add_column("IP Address", style="red")
        table.add_column("Threat Score", style="yellow")
        table.add_column("Sessions", style="cyan")
        
        ip_scores = defaultdict(lambda: {"score": 0, "count": 0})
        for s in self.logger.sessions.values():
            ip_scores[s.ip_address]["score"] += s.threat_score
            ip_scores[s.ip_address]["count"] += 1
            
        for ip, data in sorted(ip_scores.items(), key=lambda x: x[1]["score"], reverse=True)[:5]:
            table.add_row(ip, str(data["score"]), str(data["count"]))
        return table
    
    def _create_alerts_table(self):
        table = Table(title="[bold yellow]Recent Alerts[/]", box=box.ROUNDED)
        table.add_column("Time", style="dim")
        table.add_column("Level", style="bold")
        table.add_column("MITRE", style="cyan")
        table.add_column("Source IP", style="red")
        table.add_column("Description")
        
        colors = {ThreatLevel.LOW: "green", ThreatLevel.MEDIUM: "yellow",
                  ThreatLevel.HIGH: "red", ThreatLevel.CRITICAL: "bold red"}
        
        for alert in self.logger.alerts[-5:]:
            table.add_row(
                alert.timestamp.strftime("%H:%M:%S"),
                f"[{colors.get(alert.level, 'white')}]{alert.level.value}[/{colors.get(alert.level, 'white')}]",
                alert.mitre_id if alert.mitre_id else "-",
                alert.source_ip,
                alert.description[:40] + "..." if len(alert.description) > 40 else alert.description
            )
        return table
        
    def _render_text(self):
        print("\n" + "="*60)
        print("SOC DASHBOARD - FTP Honeypot")
        print("="*60)
        print(f"Active: {sum(1 for s in self.logger.sessions.values() if not s.closed)}")
        print(f"Alerts: {len(self.logger.alerts)}")


class FTPHoneypot:
    def __init__(self, config_file: str = "config.json"):
        self.config = Config(config_file)
        self.logger = SOCLogger(self.config.get("logging.log_dir", "honeypot_logs"))
        self.detector = AttackDetector(self.logger, self.config)
        self.dashboard = SOCDashboard(self.logger, self.detector)
        self.running = False
        self.server_socket = None
        self.USERNAMES = self.config.get("honeypot.valid_usernames", 
                                         ["admin", "root", "ftp", "test"])
        self.PASSWORDS = self.config.get("honeypot.valid_passwords",
                                         ["admin", "pass", "password", "123456"])
        
    def start(self):
        ftp_config = self.config.get("ftp", {})
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((ftp_config.get("host", "0.0.0.0"), ftp_config.get("port", 21)))
        self.server_socket.listen()
        self.running = True
        
        ip = self._get_local_ip()
        self._print_banner(ip)
        
        threading.Thread(target=self._dashboard_loop, daemon=True).start()
        
        while self.running:
            try:
                conn, addr = self.server_socket.accept()
                session = self.logger.create_session(addr[0])
                threading.Thread(target=self._handle_client, args=(conn, addr, session), daemon=True).start()
            except Exception as e:
                if self.running:
                    print(f"Server error: {e}")
                    
    def _get_local_ip(self) -> str:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "127.0.0.1"
            
    def _print_banner(self, ip: str):
        port = self.config.get("ftp.port", 21)
        print(f"""
================================================================
     [SOC] FTP Honeypot System v2.0
     Threat Detection & Analysis Platform
----------------------------------------------------------------
  [+] FTP Server: {ip}:{port}
  [+] MITRE ATT&CK Mapping: ENABLED
  [+] Logging: JSON + CSV
  [+] Attack Detection: ENABLED
  [+] Session Tracking: ENABLED
================================================================
        """)
        
    def _dashboard_loop(self):
        while self.running:
            try:
                self.dashboard.render()
                time.sleep(5)
            except:
                pass
                
    def _handle_client(self, conn, addr, session):
        file_list = self._generate_files()
        dir_list = self._generate_dirs()
        pwd = [socket.gethostname()]
        authenticated = False
        username = ""
        data_conn = None
        
        self.logger.log_event("connection", addr[0], session.session_id,
                             additional_data={"port": addr[1]})
        
        try:
            conn.send(b"220 Welcome to FTP Server\r\n")
            
            while True:
                try:
                    data = conn.recv(1024)
                    if not data:
                        break
                        
                    command = data.decode().strip()
                    
                    if command.startswith("USER"):
                        _, username = command.split(maxsplit=1)
                        session.username = username
                        session.login_attempts += 1
                        self.logger.update_session(session.session_id, username=username)
                        self.logger.log_event("user_attempt", addr[0], session.session_id, username=username)
                        conn.send(b"331 Username accepted, password required\r\n")
                        
                    elif command.startswith("PASS"):
                        _, password = command.split(maxsplit=1)
                        success = password in self.PASSWORDS
                        self.logger.log_login_attempt(addr[0], username, password, success, session.session_id)
                        
                        if success:
                            authenticated = True
                            conn.send(b"230 Authentication successful\r\n")
                            mitre = MITRE_TACTICS.get("CREDENTIALS", {})
                            print(f"[AUTH SUCCESS] {addr[0]} - {username}:{password}")
                            print(f"    [MITRE] {mitre.get('id', 'N/A')} - {mitre.get('name', 'N/A')}")
                        else:
                            session.failed_logins += 1
                            self.logger.update_session(session.session_id, failed_logins=session.failed_logins)
                            conn.send(b"530 Invalid password\r\n")
                            
                            brute_force_alert = self.detector.check_brute_force(addr[0])
                            if brute_force_alert:
                                self.logger.add_alert(brute_force_alert.level, brute_force_alert.category,
                                    brute_force_alert.source_ip, session.session_id,
                                    brute_force_alert.description, brute_force_alert.details)
                                print(f"[ALERT] {brute_force_alert.level.value}: {brute_force_alert.description}")
                                print(f"    [MITRE] {brute_force_alert.mitre_id} - {brute_force_alert.mitre_name}")
                                
                    elif command.startswith("PORT"):
                        try:
                            parts = command.replace("PORT ", "").split(",")
                            ip = f"{parts[0]}.{parts[1]}.{parts[2]}.{parts[3]}"
                            port = int(parts[4]) * 256 + int(parts[5])
                            data_conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            data_conn.connect((ip, port))
                            conn.send(b"200 PORT command successful\r\n")
                        except:
                            conn.send(b"500 PORT command error\r\n")
                            
                    elif authenticated:
                        self._handle_authenticated_command(conn, data_conn, command,
                                                           file_list, dir_list, pwd, session, addr[0])
                    else:
                        conn.send(b"530 Please login with USER and PASS\r\n")
                        
                except Exception as e:
                    self.logger.log_event("error", addr[0], session.session_id,
                                         additional_data={"error": str(e)})
                    break
                    
        except:
            pass
        finally:
            self.logger.close_session(session.session_id)
            try:
                conn.close()
            except:
                pass
                
    def _handle_authenticated_command(self, conn, data_conn, command, file_list, 
                                      dir_list, pwd, session, ip):
        parts = command.split()
        cmd = parts[0].upper() if parts else ""
        
        threat_level = self.detector.classify_command(cmd, ip, session.session_id)
        self.logger.add_command_to_session(session.session_id, command, threat_level)
        self.detector.check_recon_behavior(ip)
        
        if cmd in ["PUT", "STOR"]:
            self.logger.log_event("file_upload", ip, session.session_id,
                                 additional_data={"filename": parts[1] if len(parts) > 1 else "unknown"})
            conn.send(b"150 File status okay; about to open data connection\r\n")
            try:
                data = data_conn.recv(4096)
                self.logger.log_event("file_content", ip, session.session_id,
                                     additional_data={"content_size": len(data)})
                data_conn.close()
            except:
                pass
            conn.send(b"226 Transfer complete\r\n")
            
        elif cmd in ["GET", "SIZE"]:
            self.logger.log_event("file_download", ip, session.session_id,
                                 additional_data={"filename": parts[1] if len(parts) > 1 else "unknown"})
            conn.send(f"213 {random.randint(1000, 10000)}\r\n".encode())
            
        elif cmd == "RETR":
            if len(parts) > 1:
                filename = parts[1]
                if filename in file_list:
                    self.logger.log_event("file_retr", ip, session.session_id,
                                         additional_data={"filename": filename})
                    try:
                        data_conn.sendall(self._generate_fake_content().encode())
                        data_conn.close()
                    except:
                        pass
                    conn.send(b"226 Transfer complete\r\n")
                else:
                    conn.send(f"550 {filename} not found\r\n".encode())
                    
        elif cmd in ["MKDIR", "MKD"]:
            dirname = parts[1] if len(parts) > 1 else "newdir"
            self.logger.add_alert(ThreatLevel.LOW, "DIR_CREATE", ip, session.session_id,
                                 f"Directory creation: {dirname}")
            conn.send(b"257 Directory created\r\n")
            
        elif cmd in ["DELETE", "DELE"]:
            target = parts[1] if len(parts) > 1 else "unknown"
            self.logger.add_alert(ThreatLevel.HIGH, "FILE_DELETE", ip, session.session_id,
                                 f"Delete attempt on: {target}", {"target": target})
            conn.send(f"250 {target} deleted\r\n".encode())
            
        elif cmd in ["RENAME", "RNFR"]:
            conn.send(b"350 Ready for RNTO\r\n")
            
        elif cmd == "RNTO":
            self.logger.add_alert(ThreatLevel.MEDIUM, "FILE_RENAME", ip, session.session_id,
                                 f"Rename: {command}")
            conn.send(b"250 Rename successful\r\n")
            
        elif cmd == "PWD":
            current_dir = "/" + "/".join(pwd[1:]) if len(pwd) > 1 else "/"
            conn.send(f'257 "{current_dir}" is current directory\r\n'.encode())
            
        elif cmd in ["LS", "DIR", "LIST"]:
            self.logger.log_event("dir_listing", ip, session.session_id)
            response = "\r\n".join(sorted(file_list + dir_list, key=str.lower)) + "\r\n"
            try:
                data_conn.sendall(response.encode())
                data_conn.close()
            except:
                pass
            conn.send(b"226 Directory listing complete\r\n")
            
        elif cmd in ["CD", "CWD"]:
            if len(parts) > 1:
                conn.send(b"250 Directory changed\r\n")
                
        elif cmd == "QUIT":
            conn.send(b"221 Goodbye\r\n")
            
        else:
            conn.send(b"500 Unknown command\r\n")
            
    def _generate_files(self) -> List[str]:
        files = ["document.docx", "report.pdf", "budget.xlsx", "config.conf", "notes.txt",
                 "data.csv", "backup.bkp", "readme.txt", "credentials.txt", "secrets.json",
                 "database.sql", "script.sh", "image.png", "logo.jpg", "index.html"]
        min_f = self.config.get("honeypot.file_count_min", 8)
        max_f = self.config.get("honeypot.file_count_max", 12)
        return random.sample(files, random.randint(min_f, max_f))
    
    def _generate_dirs(self) -> List[str]:
        dirs = ["Documents", "Downloads", "Uploads", "Backups", "Configs", "Scripts", "Images", "Data"]
        min_d = self.config.get("honeypot.dir_count_min", 3)
        max_d = self.config.get("honeypot.dir_count_max", 5)
        return random.sample(dirs, random.randint(min_d, max_d))
    
    def _generate_fake_content(self) -> str:
        templates = ["Lorem ipsum dolor sit amet.\n", "Data file - proprietary.\n",
                     "Configuration settings.\n", "Credentials and tokens.\n", "Database endpoints.\n"]
        return "".join(random.choices(templates, k=random.randint(5, 20)))
    
    def export_logs(self, format: str = "json") -> str:
        if format.lower() == "csv":
            return self.logger.export_to_csv()
        return self.logger.export_to_json()
    
    def replay_attack(self, session_id: str) -> bool:
        session = self.logger.replay_session(session_id)
        if session:
            print(f"\n{'='*70}")
            print(f"REPLAY: Session {session_id}")
            print(f"{'='*70}")
            print(f"IP: {session.ip_address}")
            print(f"Start: {session.start_time}")
            print(f"Threat Score: {session.threat_score}")
            print(f"\nCommands Executed:")
            for i, cmd in enumerate(session.commands, 1):
                mitre_info = ""
                if cmd.get("mitre_id"):
                    mitre_info = f" [{cmd['mitre_id']} - {cmd['mitre_name']}]"
                print(f"  {i}. [{cmd['threat_level']}] {cmd['command']}{mitre_info}")
            return True
        return False
    
    def show_sessions(self):
        print(f"\n{'='*70}")
        print("SESSIONS")
        print(f"{'='*70}")
        print(f"{'Session ID':<12} {'IP':<16} {'Username':<15} {'Threat':<8} {'Commands'}")
        print("-"*70)
        for s in self.logger.sessions.values():
            print(f"{s.session_id:<12} {s.ip_address:<16} {s.username:<15} {s.threat_score:<8} {len(s.commands)}")
    
    def show_alerts(self):
        print(f"\n{'='*70}")
        print("ALERTS")
        print(f"{'='*70}")
        print(f"{'Time':<10} {'Level':<10} {'MITRE':<15} {'Category':<20} {'IP'}")
        print("-"*70)
        for a in self.logger.alerts:
            print(f"{a.timestamp.strftime('%H:%M:%S'):<10} {a.level.value:<10} {a.mitre_id:<15} {a.category:<20} {a.source_ip}")
    
    def print_summary(self):
        summary = self.logger.get_summary()
        print("=" * 60)
        print("         INCIDENT RESPONSE SUMMARY")
        print("=" * 60)
        print(f"  Total Attacks:        {summary['total_attacks']}")
        print(f"  Unique Attackers:     {summary['unique_attackers']}")
        print(f"  Total Alerts:         {summary['total_alerts']}")
        print(f"  High/Critical:        {summary['high_severity']}")
        print(f"  Medium:               {summary['medium_severity']}")
        print(f"  Low:                  {summary['low_severity']}")
        print(f"  Top Attacker IP:      {summary['top_attacker_ip']}")
        print(f"  Top Threat Score:     {summary['top_attacker_score']}")
        print("-" * 60)
        print("  MITRE ATT&CK Tactics Detected:")
        if summary['mitre_tactics']:
            for tactic in summary['mitre_tactics']:
                print(f"    - {tactic}")
        else:
            print("    None detected")
        print("=" * 60)
    
    def stop(self):
        self.running = False
        if self.server_socket:
            self.server_socket.close()


def main():
    config_file = "config.json"
    if len(sys.argv) > 1:
        config_file = sys.argv[1]
    
    honeypot = FTPHoneypot(config_file)
    
    if len(sys.argv) > 2 and sys.argv[1] == "cli":
        command = sys.argv[2]
        if command == "sessions":
            honeypot.show_sessions()
        elif command == "alerts":
            honeypot.show_alerts()
        elif command == "summary":
            honeypot.print_summary()
        elif command == "export":
            json_file = honeypot.export_logs("json")
            csv_file = honeypot.export_logs("csv")
            print(f"Exported to: {json_file}, {csv_file}")
        elif command.startswith("replay"):
            session_id = command.split(":")[1] if ":" in command else None
            if session_id:
                honeypot.replay_attack(session_id)
        return
    
    try:
        honeypot.start()
    except KeyboardInterrupt:
        print("\n\n" + "="*60)
        print("Shutting down honeypot...")
        print("="*60)
        
        honeypot.print_summary()
        
        if honeypot.config.get("logging.export_on_exit", True):
            print("\nExporting logs...")
            json_file = honeypot.export_logs("json")
            csv_file = honeypot.export_logs("csv")
            print(f"Logs exported to: {json_file}, {csv_file}")
        
        honeypot.stop()


if __name__ == "__main__":
    main()

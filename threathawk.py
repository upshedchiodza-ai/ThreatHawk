import tkinter as tk
from tkinter import ttk, filedialog, messagebox, simpledialog
import sqlite3
import re
import os
import random
import csv
import json
import hashlib
import hmac
import time
from datetime import datetime
from collections import Counter, defaultdict

APP_TITLE = "ThreatHawk | Security Operations Center"
DB_FILE = "threathawk.db"
DEMO_FILE = "threathawk_demo.log"

BG = "#0b1020"
PANEL = "#111827"
PANEL2 = "#172033"
BORDER = "#263449"
TEXT = "#e5e7eb"
MUTED = "#94a3b8"
ACCENT = "#38bdf8"
GREEN = "#22c55e"
YELLOW = "#f59e0b"
RED = "#ef4444"
PURPLE = "#a78bfa"


class Database:
    def __init__(self, path=DB_FILE):
        self.conn = sqlite3.connect(path)
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS scans(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                source TEXT,
                events INTEGER,
                threats INTEGER,
                max_score INTEGER
            )
        """)
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS threats(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER,
                timestamp TEXT,
                source TEXT,
                threat_type TEXT,
                severity TEXT,
                score INTEGER,
                details TEXT
            )
        """)
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS users(
                username TEXT PRIMARY KEY, password_hash TEXT NOT NULL, role TEXT NOT NULL
            )
        """)
        self.conn.commit()
        # First-run account. Change this password after signing in.
        if not self.conn.execute("SELECT 1 FROM users LIMIT 1").fetchone():
            self.conn.execute("INSERT INTO users VALUES(?,?,?)",
                              ("admin", self.hash_password("ChangeMe123!"), "Admin"))
            self.conn.commit()

    @staticmethod
    def hash_password(password):
        salt = b"ThreatHawk-local-v1"
        return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 180000).hex()

    def authenticate(self, username, password):
        row = self.conn.execute("SELECT password_hash,role FROM users WHERE username=?",
                                (username,)).fetchone()
        if row and hmac.compare_digest(row[0], self.hash_password(password)):
            return row[1]
        return None

    def add_user(self, username, password, role):
        self.conn.execute("INSERT INTO users VALUES(?,?,?)",
                          (username, self.hash_password(password), role))
        self.conn.commit()

    def list_users(self):
        return self.conn.execute("SELECT username,role FROM users ORDER BY username").fetchall()

    def update_password(self, username, password):
        self.conn.execute("UPDATE users SET password_hash=? WHERE username=?",
                          (self.hash_password(password), username))
        self.conn.commit()

    def save_scan(self, source, events, threats, max_score):
        cur = self.conn.cursor()
        cur.execute(
            "INSERT INTO scans(timestamp,source,events,threats,max_score) VALUES(?,?,?,?,?)",
            (datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
             source, events, threats, max_score)
        )
        scan_id = cur.lastrowid
        self.conn.commit()
        return scan_id

    def save_threats(self, scan_id, threats):
        self.conn.executemany("""
            INSERT INTO threats(scan_id,timestamp,source,threat_type,severity,score,details)
            VALUES(?,?,?,?,?,?,?)
        """, [
            (scan_id, t["timestamp"], t["source"], t["type"],
             t["severity"], t["score"], t["details"])
            for t in threats
        ])
        self.conn.commit()

    def history(self):
        return self.conn.execute("""
            SELECT id,timestamp,source,events,threats,max_score
            FROM scans ORDER BY id DESC LIMIT 25
        """).fetchall()


class ThreatEngine:
    FAILED_RE = re.compile(
        r"(?P<time>\S+\s+\S+).*?(?:FAILED_LOGIN|failed login).*?"
        r"(?:source=|from=|ip=)(?P<ip>[0-9a-fA-F:.]+)", re.I)

    PORT_RE = re.compile(
        r"(?P<time>\S+\s+\S+).*?(?:PORT_SCAN|port scan).*?"
        r"(?:source=|from=|ip=)(?P<ip>[0-9a-fA-F:.]+).*?"
        r"(?:port=|ports=)(?P<ports>[0-9,\- ]+)", re.I)

    SUSPICIOUS_RE = re.compile(
        r"(unauthorized|intrusion|malware|ransomware|suspicious|exploit|"
        r"privilege escalation|trojan|backdoor)", re.I)
    EXTRA_RULES = [
        ("SQL Injection Indicator", re.compile(r"(union\s+select|or\s+1=1|drop\s+table|information_schema|sleep\s*\()", re.I), 88, "Possible SQL injection indicator in a log event."),
        ("DDoS Traffic Pattern", re.compile(r"(ddos|denial.of.service|syn.?flood|udp.?flood|http.?flood|rate_limit_exceeded)", re.I), 86, "DDoS/flood indicator; validate against traffic telemetry."),
        ("DNS Tunnelling Indicator", re.compile(r"(dns.?tunnel|long_subdomain|txt_query_anomaly|high.entropy.domain|iodine)", re.I), 82, "Possible DNS tunnelling indicator."),
        ("Lateral Movement", re.compile(r"(psexec|wmic.*process|remote service creation|pass.the.hash|lateral movement|admin\$|\\\\.*\\admin\$)", re.I), 85, "Possible lateral-movement signature."),
    ]

    def __init__(self, failed_threshold=5, port_threshold=5):
        self.failed_threshold = failed_threshold
        self.port_threshold = port_threshold
        self.custom_rules = []
        self.load_custom_rules()

    def load_custom_rules(self):
        """Load user-defined regex rules from threathawk_rules.json."""
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "threathawk_rules.json")
        if not os.path.exists(path):
            return
        try:
            with open(path, "r", encoding="utf-8") as handle:
                data = json.load(handle)
            self.custom_rules = []
            for item in data if isinstance(data, list) else []:
                try:
                    self.custom_rules.append((str(item["name"]), re.compile(item["pattern"], re.I),
                                              max(1, min(100, int(item.get("score", 70)))),
                                              str(item.get("details", "Custom regex rule matched."))))
                except (KeyError, TypeError, ValueError, re.error):
                    continue
        except (OSError, json.JSONDecodeError):
            self.custom_rules = []

    def analyze(self, lines):
        threats = []
        failed = {}
        port_counts = {}

        for raw in lines:
            line = raw.strip()
            if not line:
                continue

            fm = self.FAILED_RE.search(line)
            if fm:
                ip = fm.group("ip")
                failed.setdefault(ip, []).append(line)

            pm = self.PORT_RE.search(line)
            if pm:
                ip = pm.group("ip")
                ports = [p.strip() for p in pm.group("ports").split(",") if p.strip()]
                port_counts.setdefault(ip, set()).update(ports)

            if self.SUSPICIOUS_RE.search(line):
                source = self.extract_source(line)
                threats.append(self.make_threat(
                    line, source, "Suspicious Activity", 75,
                    "Suspicious security keyword or event detected."
                ))
            for rule_name, pattern, score, detail in self.EXTRA_RULES + self.custom_rules:
                if pattern.search(line):
                    threats.append(self.make_threat(line, self.extract_source(line),
                                                    rule_name, score, detail))

        # Lightweight statistical anomaly detector: unusually frequent event
        # types from a single source are flagged as a baseline-free heuristic.
        frequency = Counter()
        examples = {}
        for line in lines:
            source = self.extract_source(line)
            token = re.search(r"(FAILED_LOGIN|PORT_SCAN|DNS|LOGIN|AUTH|CONNECTION|HTTP)", line, re.I)
            event = token.group(1).upper() if token else "OTHER"
            key = (source, event)
            frequency[key] += 1
            examples[key] = line.strip()
        for (source, event), count in frequency.items():
            if count >= 12 and event != "OTHER":
                threats.append(self.make_threat(examples[(source, event)], source,
                    "Frequency Anomaly", min(95, 65 + count),
                    f"Statistical heuristic: {count} {event} events from this source."))

        for ip, events in failed.items():
            count = len(events)
            if count >= self.failed_threshold:
                score = min(100, 60 + (count - self.failed_threshold) * 5)
                threats.append(self.make_threat(
                    events[-1], ip, "Brute Force", score,
                    f"{count} failed login attempts detected from {ip}."
                ))
            elif count >= 3:
                threats.append(self.make_threat(
                    events[-1], ip, "Repeated Failed Login", 45,
                    f"{count} failed login attempts detected from {ip}."
                ))

        for ip, ports in port_counts.items():
            count = len(ports)
            if count >= self.port_threshold:
                score = min(100, 55 + count * 5)
                threats.append(self.make_threat(
                    f"PORT_SCAN source={ip} ports={','.join(sorted(ports))}",
                    ip, "Port Scan", score,
                    f"Connection attempts observed against {count} ports."
                ))
            elif count >= 2:
                threats.append(self.make_threat(
                    f"PORT_SCAN source={ip} ports={','.join(sorted(ports))}",
                    ip, "Port Scan", 40,
                    f"Multiple ports targeted from {ip}."
                ))

        # Remove exact duplicates while keeping useful findings.
        unique = {}
        for t in threats:
            key = (t["source"], t["type"])
            if key not in unique or t["score"] > unique[key]["score"]:
                unique[key] = t

        return sorted(unique.values(),
                      key=lambda x: x["score"], reverse=True)

    @staticmethod
    def extract_source(line):
        m = re.search(r"(?:source|from|ip)=([0-9a-fA-F:.]+)", line, re.I)
        return m.group(1) if m else "LOCAL-SIMULATOR"

    @staticmethod
    def make_threat(line, source, typ, score, details):
        if score >= 90:
            severity = "CRITICAL"
        elif score >= 70:
            severity = "HIGH"
        elif score >= 40:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        parts = line.split()
        timestamp = " ".join(parts[:2]) if len(parts) >= 2 else datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        return {
            "timestamp": timestamp,
            "source": source,
            "type": typ,
            "severity": severity,
            "score": score,
            "details": details
        }


class ThreatHawk(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_TITLE)
        self.geometry("1280x780")
        self.minsize(1050, 680)
        self.configure(bg=BG)

        self.db = Database()
        self.current_user = None
        if not self.authenticate_dialog():
            self.destroy()
            return
        self.engine = ThreatEngine()
        self.current_lines = []
        self.current_threats = []
        self.current_source = "No scan loaded"
        self.live_running = False
        self.live_job = None
        self.live_path = None
        self.last_size = 0
        self.live_job = None
        self.live_path = None
        self.last_size = 0

        self.setup_style()
        self.build_ui()
        self.show_welcome()

    def authenticate_dialog(self):
        win = tk.Toplevel(self)
        win.title("ThreatHawk Login")
        win.geometry("390x300")
        win.configure(bg=BG)
        win.resizable(False, False)
        win.grab_set()
        tk.Label(win, text="THREATHAWK", bg=BG, fg=ACCENT,
                 font=("Segoe UI", 22, "bold")).pack(pady=(24, 5))
        tk.Label(win, text="Local SOC account sign-in", bg=BG, fg=MUTED).pack(pady=(0, 16))
        form = tk.Frame(win, bg=BG); form.pack(padx=35, fill="x")
        tk.Label(form, text="Username", bg=BG, fg=TEXT).pack(anchor="w")
        username = tk.Entry(form); username.pack(fill="x", pady=(3, 10)); username.insert(0, "admin")
        tk.Label(form, text="Password", bg=BG, fg=TEXT).pack(anchor="w")
        password = tk.Entry(form, show="*"); password.pack(fill="x", pady=(3, 12))
        result = {"ok": False}
        def login():
            role = self.db.authenticate(username.get().strip(), password.get())
            if not role:
                messagebox.showerror("Sign-in failed", "Invalid username or password.", parent=win); return
            self.current_user = {"username": username.get().strip(), "role": role}
            result["ok"] = True; win.destroy()
        tk.Button(win, text="SIGN IN", command=login, bg=ACCENT, fg="#06111a",
                  relief="flat", padx=24, pady=8).pack(pady=4)
        tk.Label(win, text="First run: admin / ChangeMe123! — change it immediately.",
                 bg=BG, fg=YELLOW, font=("Segoe UI", 8)).pack(pady=7)
        win.protocol("WM_DELETE_WINDOW", win.destroy)
        self.wait_window(win)
        return result["ok"]

    def setup_style(self):
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure("Treeview",
                        background=PANEL,
                        foreground=TEXT,
                        fieldbackground=PANEL,
                        borderwidth=0,
                        rowheight=31,
                        font=("Segoe UI", 10))
        style.configure("Treeview.Heading",
                        background=PANEL2,
                        foreground=TEXT,
                        borderwidth=0,
                        font=("Segoe UI Semibold", 10))
        style.map("Treeview",
                  background=[("selected", "#1e3a5f")],
                  foreground=[("selected", "white")])
        style.configure("TNotebook", background=BG, borderwidth=0)
        style.configure("TNotebook.Tab", background=PANEL2,
                        foreground=MUTED, padding=(16, 9))
        style.map("TNotebook.Tab",
                  background=[("selected", "#1e293b")],
                  foreground=[("selected", TEXT)])

    def button(self, parent, text, command, primary=False):
        return tk.Button(
            parent, text=text, command=command,
            bg=ACCENT if primary else PANEL2,
            fg="#06111a" if primary else TEXT,
            activebackground="#7dd3fc" if primary else "#243247",
            activeforeground="#06111a" if primary else "white",
            relief="flat", bd=0, cursor="hand2",
            font=("Segoe UI Semibold", 10), padx=14, pady=9
        )

    def build_ui(self):
        # Header
        header = tk.Frame(self, bg=BG)
        header.pack(fill="x", padx=28, pady=(22, 12))

        brand = tk.Frame(header, bg=BG)
        brand.pack(side="left")

        tk.Label(brand, text="THREAT", bg=BG, fg=TEXT,
                 font=("Segoe UI", 24, "bold")).pack(side="left")
        tk.Label(brand, text="HAWK", bg=BG, fg=ACCENT,
                 font=("Segoe UI", 24, "bold")).pack(side="left")
        tk.Label(brand, text="  // SECURITY OPERATIONS CENTER",
                 bg=BG, fg=MUTED, font=("Consolas", 9, "bold")).pack(
                     side="left", padx=10, pady=(8, 0))

        self.status_label = tk.Label(
            header, text="● SYSTEM READY", bg=BG, fg=GREEN,
            font=("Consolas", 10, "bold"))
        self.status_label.pack(side="right", pady=8)

        # Toolbar
        toolbar = tk.Frame(self, bg=PANEL, highlightbackground=BORDER,
                           highlightthickness=1)
        toolbar.pack(fill="x", padx=28, pady=(0, 14))

        buttons = [
            ("OPEN LOG", self.open_log, False),
            ("SCAN", self.scan_current, True),
            ("LIVE TAIL", self.start_live_tail, False),
            ("DEMO LOG", self.create_demo, False),
            ("ATTACK LAB", self.attack_lab, False),
            ("HISTORY", self.show_history, False),
            ("REPORT", self.export_report, False),
            ("SETTINGS", self.show_settings, False),
            ("CLEAR", self.clear_dashboard, False),
        ]
        self.toolbar_buttons = {}
        for text, cmd, primary in buttons:
            widget = self.button(toolbar, text, cmd, primary)
            widget.pack(side="left", padx=3, pady=6)
            self.toolbar_buttons[text] = widget
        if self.current_user["role"] == "Viewer":
            for name in ("OPEN LOG", "SCAN", "LIVE TAIL", "DEMO LOG", "ATTACK LAB", "REPORT", "SETTINGS", "CLEAR"):
                self.toolbar_buttons[name].configure(state="disabled")

        # Metric cards
        cards = tk.Frame(self, bg=BG)
        cards.pack(fill="x", padx=28, pady=(0, 14))

        self.metric_vars = {}
        metrics = [
            ("EVENTS", "events", ACCENT),
            ("THREATS", "threats", RED),
            ("CRITICAL", "critical", RED),
            ("HIGH", "high", YELLOW),
            ("MEDIUM", "medium", PURPLE),
            ("MAX SCORE", "score", GREEN),
        ]

        for title, key, accent in metrics:
            card = tk.Frame(cards, bg=PANEL, highlightbackground=BORDER,
                            highlightthickness=1)
            card.pack(side="left", fill="both", expand=True, padx=4)

            tk.Label(card, text=title, bg=PANEL, fg=MUTED,
                     font=("Segoe UI", 9, "bold")).pack(
                         anchor="w", padx=15, pady=(12, 0))
            var = tk.StringVar(value="0")
            self.metric_vars[key] = var
            tk.Label(card, textvariable=var, bg=PANEL, fg=accent,
                     font=("Segoe UI", 22, "bold")).pack(
                         anchor="w", padx=15, pady=(1, 11))

        # Main area
        body = tk.Frame(self, bg=BG)
        body.pack(fill="both", expand=True, padx=28, pady=(0, 20))

        self.notebook = ttk.Notebook(body)
        self.notebook.pack(fill="both", expand=True)

        self.threat_tab = tk.Frame(self.notebook, bg=PANEL)
        self.event_tab = tk.Frame(self.notebook, bg=PANEL)
        self.analytics_tab = tk.Frame(self.notebook, bg=PANEL)

        self.notebook.add(self.threat_tab, text="  ACTIVE THREATS  ")
        self.notebook.add(self.event_tab, text="  SECURITY EVENTS  ")
        self.notebook.add(self.analytics_tab, text="  ANALYTICS  ")

        self.build_threat_tab()
        self.build_event_tab()
        self.build_analytics_tab()

        footer = tk.Frame(self, bg=BG)
        footer.pack(fill="x", padx=28, pady=(0, 12))
        self.source_label = tk.Label(
            footer, text="Source: —", bg=BG, fg=MUTED,
            font=("Consolas", 9))
        self.source_label.pack(side="left")
        tk.Label(
            footer, text="ThreatHawk Lab Mode • Defensive simulation only",
            bg=BG, fg=MUTED, font=("Consolas", 9)).pack(side="right")

    def build_threat_tab(self):
        top = tk.Frame(self.threat_tab, bg=PANEL)
        top.pack(fill="x", padx=15, pady=12)

        tk.Label(top, text="Detected Security Threats", bg=PANEL, fg=TEXT,
                 font=("Segoe UI", 15, "bold")).pack(side="left")
        tk.Label(top, text="  •  ranked by threat score", bg=PANEL, fg=MUTED,
                 font=("Segoe UI", 9)).pack(side="left", pady=4)

        frame = tk.Frame(self.threat_tab, bg=PANEL)
        frame.pack(fill="both", expand=True, padx=15, pady=(0, 15))

        cols = ("time", "source", "type", "severity", "score", "details")
        self.threat_tree = ttk.Treeview(frame, columns=cols,
                                        show="headings")
        headings = {
            "time": "TIME", "source": "SOURCE", "type": "THREAT TYPE",
            "severity": "SEVERITY", "score": "SCORE", "details": "DETAILS"
        }
        widths = {"time": 145, "source": 130, "type": 155,
                  "severity": 95, "score": 70, "details": 500}
        for c in cols:
            self.threat_tree.heading(c, text=headings[c])
            self.threat_tree.column(c, width=widths[c],
                                    anchor="center" if c in ("severity", "score") else "w")

        self.threat_tree.tag_configure("CRITICAL", foreground=RED)
        self.threat_tree.tag_configure("HIGH", foreground="#fbbf24")
        self.threat_tree.tag_configure("MEDIUM", foreground=PURPLE)
        self.threat_tree.tag_configure("LOW", foreground=GREEN)

        scroll = ttk.Scrollbar(frame, orient="vertical",
                               command=self.threat_tree.yview)
        self.threat_tree.configure(yscrollcommand=scroll.set)
        self.threat_tree.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")

    def build_event_tab(self):
        top = tk.Frame(self.event_tab, bg=PANEL)
        top.pack(fill="x", padx=15, pady=12)
        tk.Label(top, text="Raw Security Events", bg=PANEL, fg=TEXT,
                 font=("Segoe UI", 15, "bold")).pack(side="left")

        self.event_text = tk.Text(
            self.event_tab, bg="#0a0f1c", fg="#cbd5e1",
            insertbackground=TEXT, selectbackground="#1e3a5f",
            relief="flat", bd=0, font=("Consolas", 10),
            padx=15, pady=10, wrap="none")
        self.event_text.pack(fill="both", expand=True, padx=15, pady=(0, 15))

    def build_analytics_tab(self):
        self.analytics_text = tk.Text(
            self.analytics_tab, bg=PANEL, fg=TEXT,
            relief="flat", bd=0, font=("Consolas", 10),
            padx=20, pady=14, wrap="word", height=12)
        self.analytics_text.pack(fill="both", expand=True, padx=15, pady=(15, 5))
        self.chart_canvas = tk.Canvas(self.analytics_tab, bg="#0a0f1c",
                                      highlightthickness=0, height=150)
        self.chart_canvas.pack(fill="x", padx=15, pady=(0, 15))
        self.analytics_text.configure(state="disabled")

    def show_welcome(self):
        self.analytics_text.configure(state="normal")
        self.analytics_text.delete("1.0", "end")
        self.analytics_text.insert("end",
            "THREATHAWK SECURITY CENTER\n\n"
            "Ready for defensive analysis.\n\n"
            "QUICK START\n"
            "1. Click DEMO LOG to create a safe sample log.\n"
            "2. Click SCAN to analyze it.\n"
            "3. Open ATTACK LAB to simulate controlled attack scenarios.\n"
            "4. Review ACTIVE THREATS and ANALYTICS.\n\n"
            "ATTACK LAB SAFETY\n"
            "The simulator only creates local log records. It does not\n"
            "send packets, scan hosts, exploit vulnerabilities, or attack\n"
            "other devices.\n")
        self.analytics_text.configure(state="disabled")

    def create_demo(self):
        now = datetime.now()
        lines = []
        for i in range(8):
            t = now.strftime("%Y-%m-%d") + f" {now.strftime('%H:%M:%S')}"
            lines.append(f"{t} FAILED_LOGIN source=192.168.1.50 user=admin")
        ports = "21,22,23,25,53,80,443,3389"
        lines.append(f"{now.strftime('%Y-%m-%d %H:%M:%S')} PORT_SCAN source=10.0.0.15 ports={ports}")
        lines.append(f"{now.strftime('%Y-%m-%d %H:%M:%S')} unauthorized intrusion source=172.16.0.25")
        lines.append(f"{now.strftime('%Y-%m-%d %H:%M:%S')} malware activity source=172.16.0.25")
        lines.append(f"{now.strftime('%Y-%m-%d %H:%M:%S')} SUCCESS_LOGIN source=192.168.1.20 user=student")

        with open(DEMO_FILE, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")

        self.load_lines(lines, DEMO_FILE)
        messagebox.showinfo("Demo Log", f"Safe demonstration log created:\n{DEMO_FILE}")

    def open_log(self):
        path = filedialog.askopenfilename(
            title="Open security log",
            filetypes=[("Log files", "*.log *.txt"), ("All files", "*.*")]
        )
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()
            self.load_lines(lines, path)
            self.status_label.config(text="● LOG LOADED", fg=ACCENT)
        except Exception as e:
            messagebox.showerror("Open Log Error", str(e))

    def load_lines(self, lines, source):
        # Normalize JSON, RFC5424-like Syslog, CEF, and Windows-exported text
        # into searchable text while retaining the original event in the view.
        normalized = []
        for raw in lines:
            line = raw.rstrip("\n")
            try:
                obj = json.loads(line)
                if isinstance(obj, dict):
                    line = " ".join(f"{k}={v}" for k, v in obj.items())
            except (json.JSONDecodeError, TypeError):
                pass
            if "CEF:" in line:
                line = line.replace("CEF:", " CEF ")
            if line.startswith("<") and ">1 " in line:
                line = line.replace(">1 ", ">1 ", 1)
            normalized.append(line + "\n")
        self.current_lines = normalized
        self.current_source = source
        self.source_label.config(text=f"Source: {source}")
        self.update_event_view()
        self.scan_current()

    def start_live_tail(self):
        if self.current_user["role"] == "Viewer":
            return
        if self.live_running:
            self.live_running = False
            if self.live_job:
                self.after_cancel(self.live_job)
            self.status_label.config(text="● LIVE TAIL STOPPED", fg=YELLOW)
            return
        path = filedialog.askopenfilename(title="Choose a log file to monitor",
            filetypes=[("Log files", "*.log *.txt *.json *.jsonl *.cef"), ("All files", "*.*")])
        if not path: return
        try:
            self.live_path = path
            self.last_size = os.path.getsize(path)
            self.live_running = True
            self.status_label.config(text="● LIVE TAIL ACTIVE (click to stop)", fg=GREEN)
            self.live_poll()
        except OSError as exc:
            messagebox.showerror("Live tail", str(exc))

    def live_poll(self):
        if not self.live_running or not self.live_path: return
        try:
            size = os.path.getsize(self.live_path)
            if size < self.last_size: self.last_size = 0  # log rotation/truncation
            if size > self.last_size:
                with open(self.live_path, "r", encoding="utf-8", errors="replace") as handle:
                    handle.seek(self.last_size); new_lines = handle.readlines()
                self.last_size = size
                if new_lines:
                    self.current_lines.extend(new_lines)
                    self.current_source = self.live_path
                    self.source_label.config(text=f"Source: {self.live_path} (live)")
                    self.update_event_view(); self.scan_current(silent=True)
        except OSError as exc:
            self.live_running = False
            messagebox.showerror("Live tail stopped", str(exc))
            return
        self.live_job = self.after(1000, self.live_poll)

    def scan_current(self, silent=False):
        if self.current_user["role"] == "Viewer":
            if not silent: messagebox.showwarning("Read-only role", "Viewer accounts cannot run scans.")
            return
        if not self.current_lines:
            if not silent: messagebox.showwarning("No Log", "Open a log or create a demo log first.")
            return

        self.current_threats = self.engine.analyze(self.current_lines)
        scan_id = self.db.save_scan(
            self.current_source,
            len(self.current_lines),
            len(self.current_threats),
            max([t["score"] for t in self.current_threats], default=0)
        )
        self.db.save_threats(scan_id, self.current_threats)

        self.refresh_dashboard()
        self.status_label.config(text="● ANALYSIS COMPLETE", fg=GREEN)

    def refresh_dashboard(self):
        for item in self.threat_tree.get_children():
            self.threat_tree.delete(item)

        for t in self.current_threats:
            self.threat_tree.insert(
                "", "end",
                values=(t["timestamp"], t["source"], t["type"],
                        t["severity"], t["score"], t["details"]),
                tags=(t["severity"],)
            )

        counts = Counter(t["severity"] for t in self.current_threats)
        self.metric_vars["events"].set(str(len(self.current_lines)))
        self.metric_vars["threats"].set(str(len(self.current_threats)))
        self.metric_vars["critical"].set(str(counts["CRITICAL"]))
        self.metric_vars["high"].set(str(counts["HIGH"]))
        self.metric_vars["medium"].set(str(counts["MEDIUM"]))
        self.metric_vars["score"].set(str(max([t["score"] for t in self.current_threats], default=0)))

        self.update_analytics()

    def update_event_view(self):
        self.event_text.delete("1.0", "end")
        self.event_text.insert("end", "".join(self.current_lines))

    def update_analytics(self):
        self.analytics_text.configure(state="normal")
        self.analytics_text.delete("1.0", "end")

        if not self.current_threats:
            self.analytics_text.insert("end",
                "ANALYTICS\n\nNo threats detected.\n"
                "The analyzed events currently show no matching threat patterns.\n")
        else:
            type_counts = Counter(t["type"] for t in self.current_threats)
            source_counts = Counter(t["source"] for t in self.current_threats)

            self.analytics_text.insert("end", "THREATHAWK ANALYTICS\n")
            self.analytics_text.insert("end", "═" * 62 + "\n\n")
            self.analytics_text.insert("end", f"Events analyzed : {len(self.current_lines)}\n")
            self.analytics_text.insert("end", f"Threats found   : {len(self.current_threats)}\n")
            self.analytics_text.insert("end",
                f"Maximum score   : {max(t['score'] for t in self.current_threats)} / 100\n\n")

            self.analytics_text.insert("end", "THREAT BREAKDOWN\n")
            for name, count in type_counts.most_common():
                self.analytics_text.insert("end", f"  • {name:<24} {count}\n")

            self.analytics_text.insert("end", "\nTOP SOURCES\n")
            for source, count in source_counts.most_common():
                self.analytics_text.insert("end", f"  • {source:<24} {count} finding(s)\n")

            self.analytics_text.insert("end",
                "\nRECOMMENDED RESPONSE\n"
                "  • Validate the source and affected account.\n"
                "  • Review surrounding events and authentication logs.\n"
                "  • Apply appropriate access controls and monitoring.\n"
                "  • Escalate CRITICAL/HIGH findings according to your lab policy.\n")

        self.analytics_text.configure(state="disabled")
        self.draw_analytics_charts()

    def draw_analytics_charts(self):
        if not hasattr(self, "chart_canvas"): return
        canvas = self.chart_canvas; canvas.delete("all")
        width = max(canvas.winfo_width(), 500); height = max(canvas.winfo_height(), 130)
        counts = Counter(t["severity"] for t in self.current_threats)
        labels = [("CRITICAL", counts["CRITICAL"], RED), ("HIGH", counts["HIGH"], YELLOW),
                  ("MEDIUM", counts["MEDIUM"], PURPLE), ("LOW", counts["LOW"], GREEN)]
        max_count = max([x[1] for x in labels] + [1])
        canvas.create_text(15, 14, anchor="w", text="SEVERITY DISTRIBUTION", fill=TEXT, font=("Segoe UI", 10, "bold"))
        bar_width = max(80, (width - 150) // 4); x = 20
        for label, count, color in labels:
            canvas.create_text(x, 38, anchor="w", text=f"{label}: {count}", fill=MUTED, font=("Consolas", 8))
            w = int((bar_width - 12) * count / max_count)
            canvas.create_rectangle(x, 55, x + max(w, 2), 75, fill=color, outline="")
            x += bar_width

    def attack_lab(self):
        win = tk.Toplevel(self)
        win.title("ThreatHawk | Attack Simulation Lab")
        win.geometry("760x570")
        win.configure(bg=BG)
        win.transient(self)

        tk.Label(win, text="ATTACK SIMULATION LAB", bg=BG, fg=TEXT,
                 font=("Segoe UI", 21, "bold")).pack(pady=(22, 4))
        tk.Label(win,
                 text="Controlled local simulation • No packets • No real targets",
                 bg=BG, fg=GREEN, font=("Consolas", 10, "bold")).pack(pady=(0, 18))

        grid = tk.Frame(win, bg=BG)
        grid.pack(fill="x", padx=30)

        scenarios = [
            ("BRUTE FORCE", "Generate repeated failed logins", self.sim_bruteforce),
            ("PORT SCAN", "Generate a simulated port-scan event", self.sim_portscan),
            ("SUSPICIOUS LOGIN", "Generate an unusual login event", self.sim_login),
            ("MALWARE ALERT", "Generate a simulated malware alert", self.sim_malware),
        ]

        for i, (title, desc, cmd) in enumerate(scenarios):
            r, c = divmod(i, 2)
            card = tk.Frame(grid, bg=PANEL, highlightbackground=BORDER,
                            highlightthickness=1)
            card.grid(row=r, column=c, sticky="nsew", padx=7, pady=7)
            grid.columnconfigure(c, weight=1)

            tk.Label(card, text=title, bg=PANEL, fg=ACCENT,
                     font=("Segoe UI", 13, "bold")).pack(
                         anchor="w", padx=15, pady=(15, 3))
            tk.Label(card, text=desc, bg=PANEL, fg=MUTED,
                     font=("Segoe UI", 9), wraplength=280,
                     justify="left").pack(anchor="w", padx=15)

            self.button(card, "RUN SIMULATION", lambda c=cmd: self.run_lab(c, win),
                        primary=True).pack(anchor="w", padx=15, pady=15)

        full = tk.Frame(win, bg=PANEL, highlightbackground=BORDER,
                        highlightthickness=1)
        full.pack(fill="x", padx=44, pady=15)
        tk.Label(full, text="FULL ATTACK SCENARIO", bg=PANEL, fg=RED,
                 font=("Segoe UI", 13, "bold")).pack(pady=(12, 3))
        tk.Label(full, text="Runs all four safe scenarios in one local log.",
                 bg=PANEL, fg=MUTED, font=("Segoe UI", 9)).pack()
        self.button(full, "RUN FULL SCENARIO", lambda: self.run_lab(self.sim_full, win),
                    primary=True).pack(pady=12)

        tk.Label(win,
                 text="For academic demonstration only. ThreatHawk simulates indicators;\n"
                      "it does not perform real attacks against networks or devices.",
                 bg=BG, fg=MUTED, font=("Segoe UI", 9),
                 justify="center").pack(pady=8)

    def sim_bruteforce(self):
        now = datetime.now()
        ip = "10.10.10.50"
        return [
            f"{now:%Y-%m-%d %H:%M:%S} FAILED_LOGIN source={ip} user=admin\n"
            for _ in range(8)
        ]

    def sim_portscan(self):
        now = datetime.now()
        ip = "10.10.10.60"
        return [
            f"{now:%Y-%m-%d %H:%M:%S} PORT_SCAN source={ip} ports=21,22,23,25,53,80,443,3389\n"
        ]

    def sim_login(self):
        now = datetime.now()
        ip = "10.10.10.70"
        return [
            f"{now:%Y-%m-%d %H:%M:%S} suspicious login source={ip} user=administrator\n",
            f"{now:%Y-%m-%d %H:%M:%S} unauthorized access attempt source={ip}\n"
        ]

    def sim_malware(self):
        now = datetime.now()
        ip = "10.10.10.80"
        return [
            f"{now:%Y-%m-%d %H:%M:%S} malware activity source={ip} process=demo_simulation\n",
            f"{now:%Y-%m-%d %H:%M:%S} suspicious file behavior source={ip}\n"
        ]

    def sim_full(self):
        return self.sim_bruteforce() + self.sim_portscan() + \
               self.sim_login() + self.sim_malware()

    def run_lab(self, generator, window):
        lines = generator()
        self.current_lines = lines
        self.current_source = "ATTACK LAB / SAFE SIMULATION"
        self.source_label.config(text="Source: ATTACK LAB / SAFE SIMULATION")
        self.update_event_view()
        self.scan_current()
        self.status_label.config(text="● SIMULATION DETECTED", fg=RED)
        window.destroy()
        self.notebook.select(self.threat_tab)

    def show_history(self):
        win = tk.Toplevel(self)
        win.title("ThreatHawk | Scan History")
        win.geometry("900x500")
        win.configure(bg=BG)

        tk.Label(win, text="SCAN HISTORY", bg=BG, fg=TEXT,
                 font=("Segoe UI", 18, "bold")).pack(anchor="w", padx=20, pady=18)

        frame = tk.Frame(win, bg=BG)
        frame.pack(fill="both", expand=True, padx=20, pady=(0, 20))

        cols = ("id", "time", "source", "events", "threats", "score")
        tree = ttk.Treeview(frame, columns=cols, show="headings")
        heads = ["ID", "TIMESTAMP", "SOURCE", "EVENTS", "THREATS", "MAX SCORE"]
        for c, h in zip(cols, heads):
            tree.heading(c, text=h)
            tree.column(c, width=130)
        tree.column("source", width=280)

        for row in self.db.history():
            tree.insert("", "end", values=row)

        tree.pack(fill="both", expand=True)

    def export_report(self):
        if self.current_user["role"] == "Viewer":
            messagebox.showwarning("Read-only role", "Viewer accounts cannot export reports."); return
        if not self.current_lines:
            messagebox.showwarning("No Data", "Run a scan before exporting a report."); return
        path = filedialog.asksaveasfilename(title="Export ThreatHawk Report",
            defaultextension=".csv", filetypes=[("CSV report", "*.csv"),
            ("PDF report", "*.pdf"), ("Text report", "*.txt")])
        if not path: return
        ext = os.path.splitext(path)[1].lower()
        try:
            if ext == ".csv":
                with open(path, "w", newline="", encoding="utf-8") as f:
                    writer = csv.writer(f); writer.writerow(["timestamp", "source", "type", "severity", "score", "details"])
                    for t in self.current_threats:
                        writer.writerow([t["timestamp"], t["source"], t["type"], t["severity"], t["score"], t["details"]])
            elif ext == ".pdf":
                try:
                    from reportlab.lib.pagesizes import letter
                    from reportlab.pdfgen import canvas
                except ImportError:
                    messagebox.showerror("PDF export", "Install PDF support with: python -m pip install reportlab"); return
                pdf = canvas.Canvas(path, pagesize=letter); w, h = letter; y = h - 45
                pdf.setFont("Helvetica-Bold", 15); pdf.drawString(40, y, "ThreatHawk Security Report"); y -= 25
                pdf.setFont("Helvetica", 9)
                summary = [f"Generated: {datetime.now():%Y-%m-%d %H:%M:%S}", f"Source: {self.current_source}", f"Events: {len(self.current_lines)}", f"Threats: {len(self.current_threats)}"]
                for line in summary: pdf.drawString(40, y, line[:110]); y -= 14
                y -= 8
                for i, t in enumerate(self.current_threats, 1):
                    line = f"{i}. {t['type']} | {t['severity']} | {t['score']}/100 | {t['source']} | {t['details']}"
                    pdf.drawString(40, y, line[:115]); y -= 14
                    if y < 45: pdf.showPage(); pdf.setFont("Helvetica", 9); y = h - 45
                pdf.save()
            else:
                with open(path, "w", encoding="utf-8") as f:
                    f.write("THREATHAWK SECURITY REPORT\n" + "=" * 65 + "\n")
                    f.write(f"Generated: {datetime.now():%Y-%m-%d %H:%M:%S}\nSource: {self.current_source}\nEvents: {len(self.current_lines)}\nThreats: {len(self.current_threats)}\n\n")
                    for t in self.current_threats: f.write(f"[{t['severity']}] {t['type']} ({t['score']}/100) - {t['source']}: {t['details']}\n")
            messagebox.showinfo("Report Exported", f"Report saved to:\n{path}")
        except Exception as exc:
            messagebox.showerror("Export Error", str(exc))

    def show_settings(self):
        win = tk.Toplevel(self)
        win.title("ThreatHawk | Detection Settings")
        win.geometry("560x620")
        win.configure(bg=BG)

        tk.Label(win, text="DETECTION SETTINGS", bg=BG, fg=TEXT,
                 font=("Segoe UI", 18, "bold")).pack(pady=(18, 12))

        form = tk.Frame(win, bg=PANEL, highlightbackground=BORDER,
                        highlightthickness=1)
        form.pack(fill="x", padx=30, pady=5)

        tk.Label(form, text="Brute-force threshold", bg=PANEL, fg=TEXT,
                 font=("Segoe UI", 10)).grid(row=0, column=0, padx=18, pady=18, sticky="w")
        brute = tk.IntVar(value=self.engine.failed_threshold)
        tk.Spinbox(form, from_=3, to=20, textvariable=brute, width=8,
                   bg="#0a0f1c", fg=TEXT, buttonbackground=PANEL2,
                   relief="flat").grid(row=0, column=1, padx=18)

        tk.Label(form, text="Port-scan threshold", bg=PANEL, fg=TEXT,
                 font=("Segoe UI", 10)).grid(row=1, column=0, padx=18, pady=18, sticky="w")
        ports = tk.IntVar(value=self.engine.port_threshold)
        tk.Spinbox(form, from_=2, to=30, textvariable=ports, width=8,
                   bg="#0a0f1c", fg=TEXT, buttonbackground=PANEL2,
                   relief="flat").grid(row=1, column=1, padx=18)

        if self.current_user["role"] == "Admin":
            users_frame = tk.Frame(win, bg=PANEL, highlightbackground=BORDER, highlightthickness=1)
            users_frame.pack(fill="x", padx=30, pady=8)
            tk.Label(users_frame, text="Add user (Admin / Analyst / Viewer)", bg=PANEL, fg=TEXT).grid(row=0, column=0, columnspan=2, sticky="w", padx=12, pady=6)
            new_name = tk.Entry(users_frame); new_name.grid(row=1, column=0, padx=8, pady=5); new_name.insert(0, "username")
            new_pass = tk.Entry(users_frame, show="*"); new_pass.grid(row=1, column=1, padx=8, pady=5); new_pass.insert(0, "temporary-password")
            role_var = tk.StringVar(value="Analyst")
            ttk.Combobox(users_frame, textvariable=role_var, values=["Admin", "Analyst", "Viewer"], state="readonly", width=12).grid(row=2, column=0, padx=8, pady=5)
            def add_user():
                name, pw = new_name.get().strip(), new_pass.get()
                if not name or len(pw) < 8:
                    messagebox.showwarning("User", "Enter a username and password of at least 8 characters.", parent=win); return
                try:
                    self.db.add_user(name, pw, role_var.get())
                    messagebox.showinfo("User", f"Created {role_var.get()} account: {name}", parent=win)
                except sqlite3.IntegrityError:
                    messagebox.showerror("User", "That username already exists.", parent=win)
            tk.Button(users_frame, text="ADD USER", command=add_user, bg=ACCENT, fg="#06111a", relief="flat").grid(row=2, column=1, padx=8, pady=5)
            tk.Label(users_frame, text="Existing users: " + ", ".join(f"{u} ({r})" for u, r in self.db.list_users()), bg=PANEL, fg=MUTED, wraplength=350, justify="left").grid(row=3, column=0, columnspan=2, sticky="w", padx=12, pady=6)

        def save():
            if self.current_user["role"] == "Viewer":
                messagebox.showwarning("Read-only role", "Viewers cannot change settings.", parent=win); return
            self.engine.failed_threshold = max(3, brute.get())
            self.engine.port_threshold = max(2, ports.get())
            win.destroy()
            messagebox.showinfo("Settings", "Detection thresholds updated.")

        self.button(win, "SAVE SETTINGS", save, primary=True).pack(pady=6)
        self.button(win, "CHANGE MY PASSWORD", self.change_password).pack(pady=5)
        tk.Label(win, text="Custom regex rules: edit threathawk_rules.json beside this script, then restart.",
                 bg=BG, fg=MUTED, wraplength=500, justify="left",
                 font=("Segoe UI", 9)).pack(padx=25, pady=(0, 12), anchor="w")

    def change_password(self):
        old = simpledialog.askstring("Change password", "Current password:", show="*")
        if old is None: return
        if not self.db.authenticate(self.current_user["username"], old):
            messagebox.showerror("Password", "Current password is incorrect."); return
        new = simpledialog.askstring("Change password", "New password (minimum 8 characters):", show="*")
        if new is None: return
        if len(new) < 8:
            messagebox.showwarning("Password", "Use at least 8 characters."); return
        confirm = simpledialog.askstring("Change password", "Confirm new password:", show="*")
        if confirm != new:
            messagebox.showerror("Password", "Passwords do not match."); return
        self.db.update_password(self.current_user["username"], new)
        messagebox.showinfo("Password", "Your password has been changed.")

    def clear_dashboard(self):
        self.current_lines = []
        self.current_threats = []
        self.current_source = "No scan loaded"
        self.source_label.config(text="Source: —")
        self.event_text.delete("1.0", "end")
        for item in self.threat_tree.get_children():
            self.threat_tree.delete(item)
        for var in self.metric_vars.values():
            var.set("0")
        self.show_welcome()
        self.status_label.config(text="● SYSTEM READY", fg=GREEN)


if __name__ == "__main__":
    app = ThreatHawk()
    app.mainloop()

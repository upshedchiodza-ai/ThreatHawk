THREATHAWK - ENHANCED DEFENSIVE LOG ANALYZER
============================================

FILES
- threathawk.py: main desktop application
- threathawk_rules.json: configurable custom regex rules

RUN
1. Install Python 3.10+ from python.org (Windows users: enable Add Python to PATH).
2. Open Command Prompt in the folder containing these files.
3. Run: python threathawk.py

FIRST SIGN-IN
- Username: admin
- Password: ChangeMe123!
- Change this password immediately using SETTINGS > CHANGE MY PASSWORD.

FEATURES ADDED
1. Additional detections: SQL injection indicators, DDoS/flood indicators,
   DNS tunnelling indicators, and lateral-movement signatures. These are
   heuristic log indicators, not proof that an attack occurred.
2. Statistical event-frequency anomaly heuristic to flag unusually frequent
   event types. This is a lightweight baseline heuristic, not a trained ML model.
3. JSON/JSONL, RFC5424-style Syslog, CEF, Windows-exported text, and plain-text
   logs can be loaded. Parsing is best-effort; preserve original logs for evidence.
4. Live log tailing: click LIVE TAIL and choose a file. Click it again to stop.
5. Local accounts and roles: Admin can create Admin, Analyst, and Viewer users.
   Viewer is read-only. Account data is stored in the local SQLite database.
6. Severity-distribution bar visualisation in Analytics.
7. CSV and PDF report export (PDF requires ReportLab); TXT remains available.
8. Packaging support: install PyInstaller and run the command below.

CUSTOM REGEX RULES
Edit threathawk_rules.json beside threathawk.py. Use a JSON list with objects:
  name: descriptive threat name
  pattern: Python regular expression (case-insensitive)
  score: integer from 1 to 100
  details: explanation displayed in the dashboard
Restart ThreatHawk after editing. Invalid rules are skipped. Test custom rules
with safe sample logs before using them for operational triage.

OPTIONAL DEPENDENCIES
PDF reports:
  python -m pip install reportlab
Standalone executable:
  python -m pip install pyinstaller
  pyinstaller --onefile --windowed threathawk.py

NOTES / LIMITATIONS
- The tool is a local log-analysis aid, not a replacement for an enterprise SIEM.
- SQLi, DDoS, DNS tunnelling, and lateral-movement detections use keyword/regex
  indicators. Validate alerts against trusted telemetry before responding.
- The anomaly detector is a simple event-frequency heuristic; it does not train
  a machine-learning model. It may produce false positives/negatives.
- Live tailing monitors a local file and polls once per second; it does not
  collect logs remotely or ingest Windows Event Log directly from the OS.
- Role controls are for a local classroom/lab app, not a hardened multi-host
  authentication system. Protect the database and machine where it runs.
- Attack Lab only creates simulated local log entries. It does not send packets,
  scan hosts, exploit vulnerabilities, or attack other devices.

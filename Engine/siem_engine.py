import socket
import os
import re
import time
from datetime import datetime
import sqlite3
import threading
import subprocess

SOCKET_PATH = "/tmp/siem_socket"

ANALYSIS_FILE = "siem_analysis.log"
REPORT_FILE = "security_report.txt"
DB_FILE = "siem_database.db"
PERF_FILE = "system_performance.txt"

# --- 1. SIEM FULL RULEBOOK (Suricata & Auth Logs) ---
RULEBOOK = {
    # == RECONNAISSANCE (Αναγνώριση Δικτύου) ==
    "network-scan": {"tactic": "Reconnaissance", "id": "T1595", "score": 30, "nist": "Precursor"},
    "attempted-recon": {"tactic": "Reconnaissance", "id": "T1595", "score": 35, "nist": "Precursor"},
    "successful-recon-largescale": {"tactic": "Reconnaissance", "id": "T1595", "score": 50, "nist": "Indicator"},
    "successful-recon-limited": {"tactic": "Reconnaissance", "id": "T1595", "score": 45, "nist": "Indicator"},
    
    # == INITIAL ACCESS & EXPLOITATION (Αρχική Πρόσβαση) ==
    "attempted-admin": {"tactic": "Initial Access", "id": "T1190", "score": 85, "nist": "Incident"},
    "attempted-user": {"tactic": "Initial Access", "id": "T1078", "score": 60, "nist": "Incident"},
    "web-application-attack": {"tactic": "Exploitation", "id": "T1190", "score": 90, "nist": "Critical Incident"},
    "exploit-kit": {"tactic": "Execution", "id": "T1203", "score": 95, "nist": "Critical Incident"},

    # == CREDENTIAL ACCESS (Κωδικοί & Logins) ==
    "auth_fail": {"tactic": "Credential Access", "id": "T1110", "score": 30, "nist": "Precursor"},
    "suspicious-login": {"tactic": "Credential Access", "id": "T1110", "score": 70, "nist": "Incident"},
    "credential-theft": {"tactic": "Credential Access", "id": "T1003", "score": 95, "nist": "Critical Incident"},

    # == PERSISTENCE & PRIVILEGE ESCALATION (Παραμονή & Root) ==
    "session_start": {"tactic": "Initial Access", "id": "T1078", "score": 25, "nist": "Audit"},
    "successful-admin": {"tactic": "Privilege Escalation", "id": "T1078", "score": 100, "nist": "Critical Incident"},
    "root_access": {"tactic": "Privilege Escalation", "id": "T1548", "score": 100, "nist": "Critical Incident"},

    # == COMMAND & CONTROL / IMPACT ==
    "trojan-activity": {"tactic": "Command and Control", "id": "T1071", "score": 100, "nist": "Critical Incident"},
    "command-and-control": {"tactic": "Command and Control", "id": "T1071", "score": 100, "nist": "Critical Incident"},
    "attempted-dos": {"tactic": "Impact", "id": "T1498", "score": 70, "nist": "Incident"},
    "denial-of-service": {"tactic": "Impact", "id": "T1498", "score": 85, "nist": "Incident"},

    # == AUDIT & LOGGING (Γενικά / Άγνωστα) ==
    "session_end": {"tactic": "Audit / Logging", "id": "N/A", "score": 10, "nist": "Audit"},
    "misc-attack": {"tactic": "Audit / Logging", "id": "N/A", "score": 50, "nist": "Incident"},
    "unknown": {"tactic": "Audit / Logging", "id": "N/A", "score": 15, "nist": "Audit"}
}

# --- ΧΑΡΤΗΣ ΜΕΤΑΦΡΑΣΗΣ SURICATA ΣΕ ΔΙΚΕΣ ΣΟΥ ΚΑΤΗΓΟΡΙΕΣ ---
SURICATA_MAPPING = {
    "a-network-trojan-was-detected": "trojan-activity",
    "potentially-bad-traffic": "bad-unknown", 
    "attempted-information-leak": "attempted-recon",
    "information-leak": "successful-recon-limited",
    "generic-protocol-command-decode": "protocol-command-decode",
    "attempted-denial-of-service": "attempted-dos",
    "detection-of-a-network-scan": "network-scan",
    "executable-code-was-detected": "exploit-kit",
    "attempted-administrator-privilege-gain": "attempted-admin",
    "attempted-user-privilege-gain": "attempted-user",
    "successful-administrator-privilege-gain": "successful-admin",
    "not-suspicious-traffic": "not-suspicious",
    "unknown-traffic": "unknown"
}

# --- 2. COMMAND INTELLIGENCE (Targeted High-Fidelity IoCs) ---
COMMAND_INTEL = {
    # == DISCOVERY (Αναγνώριση Συστήματος & Χρηστών) ==
    "whoami": {"tactic": "Discovery", "id": "T1033", "score": 20, "nist": "Precursor"},
    "id": {"tactic": "Discovery", "id": "T1033", "score": 40, "nist": "Precursor"},
    "uname -a": {"tactic": "Discovery", "id": "T1082", "score": 40, "nist": "Precursor"},
    "cat /etc/os-release": {"tactic": "Discovery", "id": "T1082", "score": 40, "nist": "Precursor"},
    "ifconfig": {"tactic": "Discovery", "id": "T1016", "score": 40, "nist": "Precursor"},
    "ip a": {"tactic": "Discovery", "id": "T1016", "score": 40, "nist": "Precursor"},
    "arp -a": {"tactic": "Discovery", "id": "T1016", "score": 45, "nist": "Precursor"},
    "netstat -antp": {"tactic": "Discovery", "id": "T1049", "score": 50, "nist": "Precursor"},
    "netstat": {"tactic": "Discovery", "id": "T1049", "score": 50, "nist": "Precursor"},
    "ps aux": {"tactic": "Discovery", "id": "T1057", "score": 45, "nist": "Precursor"},
    "find / -perm -4000": {"tactic": "Discovery", "id": "T1083", "score": 85, "nist": "Incident"}, # Αναζήτηση SUID binaries για Privilege Escalation

    # == CREDENTIAL ACCESS (Υποκλοπή Κωδικών) ==
    "cat /etc/shadow": {"tactic": "Credential Access", "id": "T1003.008", "score": 100, "nist": "Critical Incident"},
    "cat /etc/passwd": {"tactic": "Discovery", "id": "T1087.001", "score": 70, "nist": "Incident"},
    "id_rsa": {"tactic": "Credential Access", "id": "T1552.004", "score": 95, "nist": "Critical Incident"},
    "grep -i pass": {"tactic": "Credential Access", "id": "T1552.001", "score": 80, "nist": "Incident"}, # Κυνήγι κωδικών σε αρχεία

    # == PRIVILEGE ESCALATION (Κλιμάκωση Προνομίων) ==
    "sudo -l": {"tactic": "Privilege Escalation", "id": "T1548.003", "score": 90, "nist": "Critical Incident"}, # Το 1ο πράγμα που κάνει ένας hacker για να δει τι δικαιώματα έχει
    "su -": {"tactic": "Privilege Escalation", "id": "T1548.003", "score": 80, "nist": "Incident"},

    # == DEFENSE EVASION (Κάλυψη Ιχνών) ==
    "history -c": {"tactic": "Defense Evasion", "id": "T1070.003", "score": 95, "nist": "Critical Incident"},
    "rm ~/.bash_history": {"tactic": "Defense Evasion", "id": "T1070.003", "score": 95, "nist": "Critical Incident"},
    "unset HISTFILE": {"tactic": "Defense Evasion", "id": "T1070.003", "score": 100, "nist": "Critical Incident"}, # Stealth μέθοδος κάλυψης ιχνών
    "rm -rf /var/log": {"tactic": "Defense Evasion", "id": "T1070.002", "score": 100, "nist": "Critical Incident"},
    "chmod 777": {"tactic": "Defense Evasion", "id": "T1222.002", "score": 80, "nist": "Incident"},
    "touch -t": {"tactic": "Defense Evasion", "id": "T1070.006", "score": 85, "nist": "Incident"}, # Timestomping: Αλλαγή ημερομηνίας αρχείου για να κρυφτεί

    # == EXECUTION & LOLBins (Εκτέλεση Shells/Scripts) ==
    "bash -i": {"tactic": "Execution", "id": "T1059.004", "score": 100, "nist": "Critical Incident"},
    "nc -e": {"tactic": "Execution", "id": "T1059", "score": 100, "nist": "Critical Incident"},
    "python -c": {"tactic": "Execution", "id": "T1059.006", "score": 90, "nist": "Critical Incident"},
    "perl -e": {"tactic": "Execution", "id": "T1059.006", "score": 90, "nist": "Critical Incident"}, # Κλασικό reverse shell
    "chmod +x": {"tactic": "Execution", "id": "T1222.002", "score": 70, "nist": "Incident"}, # Προετοιμασία εκτέλεσης malware
    "base64 -d": {"tactic": "Defense Evasion", "id": "T1027", "score": 85, "nist": "Incident"}, # Αποκωδικοποίηση κρυφού payload
    "wget ": {"tactic": "Execution", "id": "T1105", "score": 75, "nist": "Incident"},
    "curl ": {"tactic": "Execution", "id": "T1105", "score": 75, "nist": "Incident"},

    # == PERSISTENCE (Δημιουργία Backdoor) ==
    "authorized_keys": {"tactic": "Persistence", "id": "T1098.004", "score": 90, "nist": "Critical Incident"},
    "useradd": {"tactic": "Persistence", "id": "T1136.001", "score": 85, "nist": "Incident"},
    "crontab": {"tactic": "Persistence", "id": "T1053.003", "score": 80, "nist": "Incident"},
    "systemctl enable": {"tactic": "Persistence", "id": "T1543.002", "score": 85, "nist": "Incident"}, # Σύγχρονη μέθοδος persistence

    # == LATERAL MOVEMENT (Κίνηση στο Δίκτυο) ==
    "scp": {"tactic": "Lateral Movement", "id": "T1570", "score": 75, "nist": "Incident"},
    "ssh": {"tactic": "Lateral Movement", "id": "T1021.004", "score": 75, "nist": "Incident"},

    # == EXFILTRATION (Κλοπή Δεδομένων) ==
    "tar -czvf": {"tactic": "Exfiltration", "id": "TA0010", "score": 100, "nist": "Critical Incident"},
    "zip -r": {"tactic": "Exfiltration", "id": "TA0010", "score": 100, "nist": "Critical Incident"},
    "curl -X POST": {"tactic": "Exfiltration", "id": "T1567", "score": 100, "nist": "Critical Incident"},
    "rsync": {"tactic": "Exfiltration", "id": "T1048", "score": 90, "nist": "Critical Incident"},

    # == AUDIT (Αθώες εντολές - Baseline) ==
    "ls ": {"tactic": "Audit / Logging", "id": "T1083", "score": 20, "nist": "Audit"},
    "cd ": {"tactic": "Audit / Logging", "id": "T1083", "score": 20, "nist": "Audit"},
    "pwd": {"tactic": "Audit / Logging", "id": "T1083", "score": 20, "nist": "Audit"},
    "clear": {"tactic": "Audit / Logging", "id": "T1070", "score": 20, "nist": "Audit"}
}



# --- 3. ADVANCED STATEFUL CORRELATION & THREAT INTEL ---
def get_smart_local_ip():
    """
    Διαβάζει όλες τις κάρτες δικτύου του Linux (μέσω της εντολής hostname -I).
    Αγνοεί την κάρτα NAT του VirtualBox (10.x.x.x) και το localhost (127.0.0.1),
    και επιλέγει την πραγματική εσωτερική IP (π.χ. 192.168.56.102).
    """
    try:
        # Παίρνουμε όλες τις IPs (π.χ. "10.0.2.15 192.168.56.102")
        ips = subprocess.check_output(['hostname', '-I']).decode().strip().split()
        
        for ip in ips:
            # Αγνοούμε το NAT (10.x) και το Localhost (127.x)
            if not ip.startswith("10.") and not ip.startswith("127."):
                return ip
                
        # Αν για κάποιο λόγο βρει μόνο μία, παίρνει αυτή
        if ips: return ips[0]
    except Exception as e:
        print(f"[-] Δεν μπορέσαμε να βρούμε την IP: {e}")
        
    return "127.0.0.1" # Fallback

VICTIM_IP = get_smart_local_ip() # <-- ΕΞΥΠΝΗ & ΔΥΝΑΜΙΚΗ ΑΝΑΓΝΩΡΙΣΗ!
KNOWN_ADMIN_IPS = [VICTIM_IP] # WHITELIST

KNOWN_MALICIOUS_IPS = [
    "203.0.113.5", "198.51.100.22", "185.130.5.200", 
    "45.133.1.2", "193.189.100.21", "91.240.118.222", 
    "85.203.15.22", "104.244.75.225", "192.3.116.126"
]

KNOWN_MALICIOUS_IPS = [
    "203.0.113.5", "198.51.100.22", "185.130.5.200", 
    "45.133.1.2", "193.189.100.21", "91.240.118.222", 
    "85.203.15.22", "104.244.75.225", "192.3.116.126"
] 

# --- ΑΝΑΒΑΘΜΙΣΜΕΝΗ ΜΝΗΜΗ ΤΗΣ ENGINE (ΓΙΑ CORRELATION & DEDUPLICATION) ---
threat_actors = {}     # Για Attack Correlation & Incident Profiling
last_seen_alerts = {}  # Για αποφυγή Alert Fatigue
active_session_ip = "Unknown"  # <-- ΝΕΟ: Για Stateful IP Tracking στα OS Logs

WATCHDOG_TIMEOUT = 60         # Στα 60 δευτερόλεπτα απραξίας, χτυπάει συναγερμός
BRUTE_FORCE_THRESHOLD = 5          

def is_duplicate(src_ip, tag, message):
    """Ελέγχει αν το alert είναι πανομοιότυπο με το προηγούμενο (εντός 3 δευτ.)"""
    key = f"{src_ip}_{tag}_{message}"
    now = time.time()
    if key in last_seen_alerts:
        last_time = last_seen_alerts[key]
        if now - last_time < 3: # Αν ήρθε σε λιγότερο από 3 δευτερόλεπτα
            return True
    last_seen_alerts[key] = now
    return False       

# --- 1. ΑΝΑΒΑΘΜΙΣΜΕΝΗ ΒΑΣΗ ΔΕΔΟΜΕΝΩΝ (Deduplication & Performance) ---
def init_db():
    conn = sqlite3.connect(DB_FILE, timeout=10)
    cursor = conn.cursor()
    # Alerts Table - Προσθήκη technique_id
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT, src_ip TEXT, tag TEXT, risk_level TEXT,
            score INTEGER, tactic TEXT, technique_id TEXT, message TEXT, cve TEXT,
            event_count INTEGER DEFAULT 1
        )
    ''')
    
    # Έξυπνη προσθήκη στήλης αν υπάρχει ήδη η βάση (για να μη χάσεις παλιά δεδομένα)
    try:
        cursor.execute("ALTER TABLE alerts ADD COLUMN technique_id TEXT")
    except sqlite3.OperationalError:
        pass # Η στήλη υπάρχει ήδη

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS performance (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            collector_cpu REAL, collector_ram_mb REAL,
            engine_cpu REAL, engine_ram_mb REAL,
            sys_load_1m REAL, sys_load_5m REAL,
            cpu_cores_count INTEGER,
            ctx_switches INTEGER,
            interrupts INTEGER,
            disk_io_wait REAL,
            db_size_mb REAL, log_size_mb REAL,
            total_alerts INTEGER
        )
    ''')
    conn.commit()
    conn.close()

def log_to_db(timestamp, src_ip, tag, risk_level, score, tactic, technique_id, message, cve):
    try:
        conn = sqlite3.connect(DB_FILE, timeout=10)
        cursor = conn.cursor()

        cursor.execute('''
            SELECT id, event_count FROM alerts 
            WHERE src_ip = ? AND tag = ? AND message = ?
            ORDER BY id DESC LIMIT 1
        ''', (src_ip, tag, message))
        
        last_event = cursor.fetchone()

        if last_event:
            event_id, current_count = last_event
            cursor.execute('''
                UPDATE alerts SET event_count = ?, timestamp = ? 
                WHERE id = ?
            ''', (current_count + 1, timestamp, event_id))
        else:
            cursor.execute('''
                INSERT INTO alerts (timestamp, src_ip, tag, risk_level, score, tactic, technique_id, message, cve, event_count)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
            ''', (timestamp, src_ip, tag, risk_level, score, tactic, technique_id, message, cve if cve else "None"))

        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[-] Database Error: {e}")

# --- PERFORMANCE MONITORING THREAD ---
def get_process_metrics(process_name):
    try:
        if process_name == "self":
            pid = str(os.getpid())
        else:
            pid_out = subprocess.check_output(["pidof", process_name]).decode().strip()
            if not pid_out: return 0.0, 0.0, 0
            pid = pid_out.split()[0]
            
        ps_out = subprocess.check_output(["ps", "-p", pid, "-o", "%cpu,rss,nlwp"]).decode().strip().split('\n')[1].split()
        cpu = float(ps_out[0])
        ram_mb = float(ps_out[1]) / 1024.0
        threads = int(ps_out[2])
        return cpu, ram_mb, threads
    except Exception:
        return 0.0, 0.0, 0

def resource_monitor():
    """Καταγράφει το Footprint του SIEM και την κατάσταση του Kernel."""
    init_db()
    while True:
        try:
            # Λήψη Metrics για Collector και Engine
            col_cpu, col_ram, col_thr = get_process_metrics("collector")
            eng_cpu, eng_ram, eng_thr = get_process_metrics("self")
            
            # Kernel Metrics από το /proc/stat (Χωρίς εξωτερικές βιβλιοθήκες όπως psutil)
            with open('/proc/stat', 'r') as f:
                lines = f.readlines()
                cpu_cores = sum(1 for line in lines if line.startswith('cpu') and line[3].isdigit())
                intr = int([line for line in lines if line.startswith('intr')][0].split()[1])
                ctxt = int([line for line in lines if line.startswith('ctxt')][0].split()[1])

            # System Load & Disk Wait (από το /proc/loadavg)
            with open('/proc/loadavg', 'r') as f:
                load_data = f.read().split()
                load1 = float(load_data[0])
                load5 = float(load_data[1])

            # Μεγέθη Αρχείων
            db_size = os.path.getsize(DB_FILE) / (1024.0 * 1024.0) if os.path.exists(DB_FILE) else 0
            log_size = (os.path.getsize(ANALYSIS_FILE) + os.path.getsize(REPORT_FILE)) / (1024.0 * 1024.0)

            # Alerts Count
            conn = sqlite3.connect(DB_FILE)
            cur = conn.cursor()
            cur.execute("SELECT COUNT(*) FROM alerts")
            total_alerts = cur.fetchone()[0]

            ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            # Εγγραφή στο Performance Log (Readable Format)
            perf_msg = (f"[{ts}] SIEM FOOTPRINT REPORT:\n"
                        f"  > Agent (C)  : CPU {col_cpu}% | RAM {col_ram:.2f}MB | Threads: {col_thr}\n"
                        f"  > Engine (Py): CPU {eng_cpu}% | RAM {eng_ram:.2f}MB | Threads: {eng_thr}\n"
                        f"  > Kernel     : Cores: {cpu_cores} | Load: {load1} | CtxSwitches: {ctxt} | Intrs: {intr}\n"
                        f"  > Storage    : DB: {db_size:.3f}MB | Logs: {log_size:.3f}MB | Total Alerts: {total_alerts}\n"
                        f"{'-'*70}\n")
            
            with open(PERF_FILE, "a") as f:
                f.write(perf_msg)

            # Εγγραφή στη Βάση για το Dashboard
            cur.execute('''
                INSERT INTO performance (
                    timestamp, collector_cpu, collector_ram_mb, engine_cpu, engine_ram_mb,
                    sys_load_1m, sys_load_5m, cpu_cores_count, ctx_switches, interrupts,
                    db_size_mb, log_size_mb, total_alerts
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (ts, col_cpu, col_ram, eng_cpu, eng_ram, load1, load5, cpu_cores, ctxt, intr, db_size, log_size, total_alerts))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            print(f"[-] Performance Monitor Error: {e}")
        
        time.sleep(30) # Καταγραφή κάθε 30 δευτερόλεπτα για ακρίβεια

# --- ΥΠΟΣΤΗΡΙΚΤΙΚΕΣ ΣΥΝΑΡΤΗΣΕΙΣ ---
def get_cve_info(message):
    cve_pattern = r"CVE-\d{4}-\d{4,7}"
    match = re.search(cve_pattern, message)
    if match:
        cve_id = match.group(0)
        return cve_id, f"https://nvd.nist.gov/vuln/detail/{cve_id}"
    return None, None

def remove_ansi_escape_sequences(text):
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    return ansi_escape.sub('', text).strip()

def determine_risk_level(score):
    if score >= 100: return "CRITICAL"
    elif score >= 85: return "HIGH"
    elif score >= 50: return "MEDIUM"
    elif score >= 30: return "LOW"
    else: return "INFO"

def generate_recommendation(tag, score, tactic, msg):
    ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', msg)
    attacker_ip = ip_match.group(0) if ip_match else "[ATTACKER_IP]"

    if tag == "session_end" or score <= 20:
        return "No action required."
    elif tag == "auth_fail":
        return f"ACTION: Multiple failures. Monitor {attacker_ip} for persistent Brute Force."
    elif tag == "session_start":
        return f"ACTION: Unexpected remote access from {attacker_ip}. Verify user identity."
    elif tag in ["root_access", "post_exploit"] and score >= 80:
        return "IMMEDIATE: Identify the source PID, kill the session, and audit sudoers file."
    elif score >= 85 or tactic in ["Exploitation", "Command and Control"]:
        return f"ACTION: Vulnerability detected. SOAR COMMAND -> [iptables -A INPUT -s {attacker_ip} -j DROP]"
    return "Monitor activity and verify against baseline."

def normalize_tag(tag):
    return tag.strip().lower().replace(" ", "-")

def process_event(data):
    global active_session_ip # <-- ΝΕΟ: Χρήση της global μεταβλητής
    try:
        raw_tag, raw_msg = data.split('|', 1)
        now = datetime.now()
        timestamp_str = now.strftime("%Y-%m-%d %H:%M:%S")
        current_time = time.time()
        current_hour = now.hour
        
        clean_tag = remove_ansi_escape_sequences(raw_tag)
        clean_msg = remove_ansi_escape_sequences(raw_msg)
        normalized_tag = normalize_tag(clean_tag)

        # --- ΜΕΤΑΦΡΑΣΗ SURICATA ΣΤΟ ΔΙΚΟ ΣΟΥ RULEBOOK ---
        if normalized_tag in SURICATA_MAPPING:
            normalized_tag = SURICATA_MAPPING[normalized_tag]
        
        # --- ΝΕΟΣ ΜΗΧΑΝΙΣΜΟΣ ΕΞΑΓΩΓΗΣ IP (Src & Dest) ---
        src_ip = "Unknown"
        dest_ip = VICTIM_IP # Default είναι το SIEM (για OS Logs που δεν έχουν Dest)
        
        src_match = re.search(r'\(Src:\s*([\d\.]+)\)', clean_msg)
        dest_match = re.search(r'\(Dest:\s*([\d\.]+)\)', clean_msg)
        
        if src_match: 
            src_ip = src_match.group(1)
        if dest_match: 
            dest_ip = dest_match.group(1)
            
        # Fallback 1: Ψάξε για IP μέσα στο κείμενο (π.χ. auth.log)
        if src_ip == "Unknown":
            all_ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', clean_msg)
            for ip in all_ips:
                if ip != VICTIM_IP and not ip.startswith("127."):
                    src_ip = ip
                    break 
                    
        # --- ΝΕΟ: STATEFUL IP TRACKING ---
        # Αν μόλις έγινε επιτυχές login, αποθήκευσε την IP στη μνήμη του SIEM
        if normalized_tag == "session_start" and src_ip != "Unknown":
            active_session_ip = src_ip
            
        # Αν ο hacker αποσυνδεθεί, καθάρισε τη μνήμη
        if normalized_tag in ["session_end", "root_exit"]:
            active_session_ip = "Unknown"

        # Fallback 2: Αν ακόμα δεν έχουμε IP (π.χ. bash_history), 
        # χρέωσέ το στην IP που έχει ενεργό session αυτή τη στιγμή!
        if src_ip == "Unknown" and active_session_ip != "Unknown":
            src_ip = active_session_ip

        # --- ΑΠΟΛΥΤΟ ΦΙΛΤΡΟ (KILL SWITCH) ΓΙΑ ΤΙΣ ΔΙΚΕΣ ΣΟΥ ΕΝΤΟΛΕΣ ---
        if src_ip == "Unknown" or src_ip == "127.0.0.1" or src_ip == VICTIM_IP:
            if normalized_tag in ["user_cmd", "root_cmd", "root_access", "root_exit", "session_end"]:
                return # Σταματάει εδώ! Δεν τυπώνει τίποτα στο τερματικό, δεν γράφει στη βάση.
        # --------------------------------------------------------------
        
        if is_duplicate(src_ip, normalized_tag, clean_msg):
            return # Σταματάει η εκτέλεση εδώ για το συγκεκριμένο event

        # --- ΑΝΑΒΑΘΜΙΣΜΕΝΟ ΔΥΝΑΜΙΚΟ RISK SCORING ---
        intel = None

        # 1. Διαχείριση Εντολών Τερματικού (USER_CMD / ROOT_CMD)
        if normalized_tag in ["user_cmd", "root_cmd"]:
            # Αναζήτηση στο COMMAND_INTEL για την εντολή
            for cmd_keyword, cmd_data in COMMAND_INTEL.items():
                if cmd_keyword in clean_msg:
                    intel = cmd_data.copy()
                    break
            
            # Αν η εντολή δεν υπάρχει στη λίστα μας, δίνουμε μια βασική τιμή "Execution"
            if not intel:
                intel = {
                    "tactic": "Execution", 
                    "id": "T1059", 
                    "score": 20, 
                    "nist": "Audit"
                }

            # ΕΦΑΡΜΟΓΗ Context Penalty (ROOT vs USER)
            if normalized_tag == "root_cmd":
                # Ποινή +40 πόντους γιατί η εντολή τρέχει με απόλυτα προνόμια
                intel['score'] = min(100, intel['score'] + 40)
                intel['tactic'] = "Privileged " + intel['tactic']
                
                # Δυναμική αναβάθμιση NIST κατηγορίας βάσει του νέου score
                if intel['score'] >= 85:
                    intel['nist'] = "Critical Incident"
                elif intel['score'] >= 60:
                    intel['nist'] = "Incident"
                else:
                    intel['nist'] = "Indicator"
            else:
                # Αν είναι απλός χρήστης (user_cmd), μειώνουμε το score (-10) 
                # για να δείξουμε ότι το ρίσκο είναι περιορισμένο
                intel['score'] = max(5, intel['score'] - 10)
                intel['tactic'] = "Unprivileged " + intel['tactic']

        # 2. Διαχείριση IDS Alerts (SURICATA) & RULEBOOK
        elif normalized_tag in SURICATA_MAPPING or normalized_tag in RULEBOOK:
            # Μετάφραση του Suricata tag στο δικό μας Rulebook
            tag_to_lookup = SURICATA_MAPPING.get(normalized_tag, normalized_tag)
            intel = RULEBOOK.get(tag_to_lookup, {"tactic": "Network Traffic", "id": "N/A", "score": 30, "nist": "Audit"}).copy()

        # 3. Fallback για οτιδήποτε άλλο (π.χ. Auth Logs)
        if not intel:
            intel = RULEBOOK.get(normalized_tag, {"tactic": "System Audit", "id": "N/A", "score": 15, "nist": "Audit"}).copy()
        
        if src_ip in KNOWN_ADMIN_IPS and normalized_tag in ["session_start", "root_access", "post_exploit"]:
            intel['score'] = 10
            intel['tactic'] = "Audit / Logging" 
            clean_msg = f"[WHITELISTED ADMIN] {clean_msg}"

        # --- SMART INCIDENT CORRELATION (ENTITY PROFILING) ---
        if src_ip != "Unknown":
            if src_ip not in threat_actors:
                threat_actors[src_ip] = {"failed_auth": 0, "recon_events": 0, "is_suspicious": False}
            
            actor = threat_actors[src_ip]

            # A. Συσχέτιση Brute Force (NIST Best Practice)
            if normalized_tag == "auth_fail":
                actor["failed_auth"] += 1
                if actor["failed_auth"] >= BRUTE_FORCE_THRESHOLD:
                    intel['score'] = 95
                    clean_msg = f"[BRUTE FORCE ALERT] {actor['failed_auth']} attempts detected! {clean_msg}"
                    actor["is_suspicious"] = True

            # B. Συσχέτιση Reconnaissance -> Access (Attack Chain)
            if normalized_tag == "session_start":
                if actor["recon_events"] > 0 or actor["is_suspicious"]:
                    intel['score'] = 100
                    intel['tactic'] = "Compromise (Post-Exploitation)"
                    clean_msg = f"[CRITICAL CORRELATION] Successful login from known attacker! {clean_msg}"
                # Reset auth failures on successful login
                actor["failed_auth"] = 0 

            # Γ. Καταγραφή ύποπτης δραστηριότητας (Network Scans κλπ)
            if intel['score'] >= 40 and normalized_tag not in ["auth_fail", "session_start"]:
                actor["recon_events"] += 1
                actor["is_suspicious"] = True

            # Δ. Συσχέτιση Privilege Escalation
            if normalized_tag == "root_access" and (actor["is_suspicious"] or actor["failed_auth"] > 0):
                intel['score'] = 100
                clean_msg = f"[CRITICAL] Privilege escalation pattern detected! {clean_msg}"
        
        # --- KNOWN THREATS & OFF-HOURS CHECK ---
        if src_ip in KNOWN_MALICIOUS_IPS:
            intel['score'] = 100
            intel['tactic'] = "Known Malicious Actor"
            intel['nist'] = "Critical Incident"
            clean_msg = f"[THREAT INTEL MATCH] Traffic from Known Malicious IP! {clean_msg}"

        if normalized_tag in ["session_start", "root_access"] and (2 <= current_hour <= 6):
            if src_ip not in KNOWN_ADMIN_IPS:
                intel['score'] = min(intel['score'] + 20, 100)
                clean_msg = f"[UEBA ANOMALY] Off-Hours Activity Detected! {clean_msg}"

        cve_id, cve_url = get_cve_info(clean_msg)
        risk_level = determine_risk_level(intel['score'])
        rec_text = generate_recommendation(normalized_tag, intel['score'], intel['tactic'], clean_msg)

        # --- ΔΥΝΑΜΙΚΑ ΧΡΩΜΑΤΑ ΑΝΑΛΟΓΑ ΜΕ ΤΟΝ ΣΤΟΧΟ (SIEM vs Network) ---
        color = "\033[92m" # Green (Default)
        target_label = "Local SIEM Host (HIDS)"
        
        if dest_ip != VICTIM_IP and dest_ip != "Unknown":
            # Η ΕΠΙΘΕΣΗ ΕΙΝΑΙ ΣΕ ΑΛΛΟ ΜΗΧΑΝΗΜΑ ΤΟΥ ΔΙΚΤΥΟΥ! (NIDS)
            color = "\033[96m" # Cyan (Γαλάζιο) για να ξεχωρίζει έντονα!
            target_label = "External Network Device (NIDS)"
        else:
            # Η ΕΠΙΘΕΣΗ ΕΙΝΑΙ ΣΤΟ ΙΔΙΟ ΤΟ SIEM
            if intel['score'] >= 50: color = "\033[93m" # Yellow
            if intel['score'] >= 85: color = "\033[91m" # Red

        # --- ΕΜΦΑΝΙΣΗ ΣΤΟ ΤΕΡΜΑΤΙΚΟ (ΑΝΑΒΑΘΜΙΣΜΕΝΗ ΓΙΑ MITRE) ---
        print(f"\n{color}██ MITRE ATT&CK ALERT [{timestamp_str}] - RISK: {intel['score']}% ({risk_level}) \033[0m")
        print(f"│ MITRE TACTIC: {intel['tactic']}")
        print(f"│ TECHNIQUE ID: {intel['id']}")
        print(f"│ SOURCE IP:    {src_ip}")
        print(f"│ TARGET IP:    {dest_ip} [{target_label}]") 
        print(f"│ RULE TAG:     {clean_tag}")
        print(f"│ NIST CAT:     {intel['nist']}")
        print(f"│ MESSAGE:      {clean_msg}")
        
        if cve_id:
            print(f"│ \033[1mCVE DETECTED:\033[0m {cve_id}")
            print(f"│ MANUAL:       {cve_url}")
            
        print("└" + "─"*65)

        with open(ANALYSIS_FILE, "a") as f:
            f.write(f"[{timestamp_str}] [SRC:{src_ip} -> DST:{dest_ip}] RISK: {risk_level} | TAG: [{clean_tag}] | MSG: {clean_msg} | REC: {rec_text}\n")

        # --- ΝΕΟ: ΕΠΙΣΗΜΟ MITRE ATT&CK REPORT GENERATOR (SOC LEVEL) ---
        if normalized_tag in ["session_start", "root_access", "post_exploit", "user_cmd", "root_cmd"] or intel['score'] >= 85:
            # Δημιουργία Μοναδικού Incident ID
            incident_id = f"EVT-{now.strftime('%Y%m%d-%H%M%S')}"
            
            # Δυναμική αναγνώριση του Data Source (NIDS vs HIDS)
            data_source = "Network Traffic Analysis (Suricata NIDS)" if dest_ip != VICTIM_IP else "Host OS Telemetry (Agent HIDS)"

            report_block = f"""
██████████████████████████████████████████████████████████████████████
              OFFICIAL MITRE ATT&CK® INCIDENT REPORT
██████████████████████████████████████████████████████████████████████
INCIDENT ID   : {incident_id}
TIMESTAMP     : {timestamp_str}
RISK SCORE    : {intel['score']}/100 ({risk_level}) - NIST: {intel['nist']}
======================================================================
[1] ENTITY PROFILING (NETWORK INFRASTRUCTURE)
----------------------------------------------------------------------
> Threat Actor (Src) : {src_ip}
> Target Asset (Dst) : {dest_ip} [{target_label}]

[2] MITRE ATT&CK® CATEGORIZATION
----------------------------------------------------------------------
> Tactic (Kill Chain): {intel['tactic']}
> Technique ID       : {intel['id']}
> Detection Source   : {data_source}
> System Rule Tag    : {clean_tag}

[3] FORENSIC EVIDENCE & THREAT INTEL
----------------------------------------------------------------------
> Raw Event Log      : {clean_msg}
> Vulnerability      : {cve_id if cve_id else "No specific CVE matched"}
> Intel Reference    : {cve_url if cve_url else "N/A"}

[4] ACTIVE DEFENSE & MITIGATION (SOAR)
----------------------------------------------------------------------
> Recommended Action : {rec_text}
██████████████████████████████████████████████████████████████████████
"""
            with open(REPORT_FILE, "a") as f:
                f.write(report_block + "\n")

        log_to_db(timestamp_str, src_ip, clean_tag, risk_level, intel['score'], intel['tactic'], intel['id'], clean_msg, cve_id)

    except Exception as e:
        print(f"[-] Error Parsing Alert: {data} -> {e}")


# --- ΝΕΟ: ΕΞΥΠΝΟ OS-LEVEL WATCHDOG ---
def agent_watchdog():
    """Ελέγχει αν η διεργασία (process) του C Collector υπάρχει στο σύστημα."""
    while True:
        time.sleep(20) # Έλεγχος κάθε 20 δευτερόλεπτα
        
        is_alive = False
        try:
            # Ρωτάμε το Linux αν υπάρχει διεργασία με το όνομα 'collector'
            pid_out = subprocess.check_output(["pidof", "collector"]).decode().strip()
            if pid_out:
                is_alive = True
        except subprocess.CalledProcessError:
            # Το pidof πετάει error αν το process έχει "πεθάνει" ή κλείσει
            is_alive = False 

        if not is_alive:
            ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            msg = "[SYSTEM FAILURE] Collector Agent process is DEAD! Possible Defense Evasion (Kill/Crash)."
            
            print(f"\n\033[91m██ MITRE ATT&CK ALERT [{ts}] - RISK: 100% (CRITICAL) \033[0m")
            print(f"│ MITRE TACTIC: Defense Evasion")
            print(f"│ TECHNIQUE ID: T1562.001")
            print(f"│ SOURCE IP:    localhost")
            print(f"│ TARGET IP:    {VICTIM_IP} [Local SIEM Host]")
            print(f"│ RULE TAG:     system-health")
            print(f"│ NIST CAT:     System Impairment")
            print(f"│ MESSAGE:      {msg}")
            print("└" + "─"*65)
            
            log_to_db(ts, "localhost", "system-health", "CRITICAL", 100, "Defense Evasion", "T1562.001", msg, None)
            
            # Αν έπεσε, περιμένουμε 1 λεπτό για να μην σπαμάρουμε την οθόνη συνεχώς
            time.sleep(60)

def start_engine():
    global last_heartbeat
    init_db()

    perf_thread = threading.Thread(target=resource_monitor, daemon=True)
    perf_thread.start()

    threading.Thread(target=agent_watchdog, daemon=True).start()

    if os.path.exists(SOCKET_PATH): os.remove(SOCKET_PATH)
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(SOCKET_PATH)
    os.chmod(SOCKET_PATH, 0o666)
    server.listen(5)
    
    start_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")
    
    with open(ANALYSIS_FILE, "a") as f:
        f.write(f"\n--- Analysis Session Started: {start_time} ---\n")
    with open(REPORT_FILE, "a") as f:
        f.write(f"\n--- NEW SESSION STARTED: {start_time} ---\n")
    with open(PERF_FILE, "a") as f:
        f.write(f"\n--- Performance Logging Started: {start_time} ---\n")
        
    print(f"\033[1;32m[+] SIEM CORE ENGINE ONLINE (Full Active Defense & Performance Monitor)\033[0m")
    print(f"[*] Logging to: {ANALYSIS_FILE} & {REPORT_FILE}")
    print(f"[*] Perf Logs : {PERF_FILE}")
    print(f"[*] Database  : {DB_FILE} (SQLite Connected)")
    
    try:
        while True:
            # Περιμένουμε τον Collector να συνδεθεί 
            conn, _ = server.accept()
            last_heartbeat = time.time()
            # print("[*] Collector Connected.") 
            
            # Κρατάμε τη σύνδεση ανοιχτή και διαβάζουμε
            while True:
                data = conn.recv(4096).decode('utf-8', errors='ignore')
                if not data:
                    # Αν η data είναι κενή, σημαίνει ότι ο C Collector έκλεισε
                    break 
                
                # Ο C Collector στέλνει πολλά alerts μαζεμένα με \n όταν κάνει flush.
                # Πρέπει να τα χωρίσουμε και να τα επεξεργαστούμε ένα-ένα.
                events = data.strip().split('\n')
                for event in events:
                    if event:
                        process_event(event)
            
            # Κλείνουμε τη σύνδεση ΜΟΝΟ αν ο Collector αποσυνδεθεί (break)
            conn.close()
    except KeyboardInterrupt:
        print("\n[!] Shutting down...")
    finally:
        os.remove(SOCKET_PATH)

if __name__ == "__main__":
    start_engine()
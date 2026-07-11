"""
╔══════════════════════════════════════════════════════════════════════════════╗
║           SOC INCIDENT INVESTIGATION PLATFORM — Single File Edition         ║
║                                                                              ║
║  Author  : Khwaja Zaher Sediqi                                               ║
║  Role    : SOC Analyst | Blue Team | Cybersecurity                           ║
║  Stack   : Python 3.11+ · Flask · MITRE ATT&CK v14                          ║
║                                                                              ║
║  Features:                                                                   ║
║    ▸ IOC Extraction  — IP, domain, URL, MD5/SHA1/SHA256, CVE, registry       ║
║    ▸ Threat Scoring  — Weighted 0–100 score + severity label                 ║
║    ▸ MITRE ATT&CK    — Auto-map techniques across all 14 tactics             ║
║    ▸ Timeline        — Reconstruct chronological event order from logs       ║
║    ▸ Report          — Structured markdown incident report                   ║
║    ▸ Dashboard       — Live SOC ops UI (dark, terminal-style)                ║
║                                                                              ║
║  Usage:                                                                      ║
║    pip install flask                                                         ║
║    python soc_investigation_platform.py                                      ║
║    → http://localhost:5000                                                   ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

import re
from datetime import datetime, timezone
from dataclasses import dataclass, field
from flask import Flask, request, jsonify

app = Flask(__name__)


# ═══════════════════════════════════════════════════════════════════════════════
#  MODULE 1 — IOC EXTRACTOR
#  Extracts Indicators of Compromise from raw log text using regex patterns.
#  Supports: IPv4, domains, URLs, MD5/SHA1/SHA256 hashes, emails, CVEs,
#            Windows registry keys, file paths.
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class IOCResult:
    ips:           list[str] = field(default_factory=list)
    domains:       list[str] = field(default_factory=list)
    urls:          list[str] = field(default_factory=list)
    hashes:        dict      = field(default_factory=lambda: {"md5": [], "sha1": [], "sha256": []})
    emails:        list[str] = field(default_factory=list)
    cves:          list[str] = field(default_factory=list)
    registry_keys: list[str] = field(default_factory=list)
    file_paths:    list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "ips":           sorted(set(self.ips)),
            "domains":       sorted(set(self.domains)),
            "urls":          sorted(set(self.urls)),
            "hashes":        {k: sorted(set(v)) for k, v in self.hashes.items()},
            "emails":        sorted(set(self.emails)),
            "cves":          sorted(set(self.cves)),
            "registry_keys": sorted(set(self.registry_keys)),
            "file_paths":    sorted(set(self.file_paths)),
            "total_count": (
                len(set(self.ips)) + len(set(self.domains)) + len(set(self.urls))
                + sum(len(set(v)) for v in self.hashes.values())
                + len(set(self.emails)) + len(set(self.cves))
            ),
        }


_IOC_PATTERNS = {
    "ipv4":     re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"),
    "url":      re.compile(r"https?://[^\s\"'<>]+"),
    "domain":   re.compile(r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|io|gov|edu|co|uk|de|ru|cn|xyz|top|info|biz|onion)\b"),
    "sha256":   re.compile(r"\b[a-fA-F0-9]{64}\b"),
    "sha1":     re.compile(r"\b[a-fA-F0-9]{40}\b"),
    "md5":      re.compile(r"\b[a-fA-F0-9]{32}\b"),
    "email":    re.compile(r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b"),
    "cve":      re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE),
    "registry": re.compile(r"(?:HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKLM|HKCU)\\[^\s\"'<>]+"),
    "filepath": re.compile(r"(?:[A-Za-z]:\\[^\s\"'<>]+|/(?:etc|var|tmp|home|usr|opt|bin|sbin|proc)/[^\s\"'<>]+)"),
}
_PRIVATE_IP = re.compile(r"^(?:10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.|127\.|0\.|255\.)")


def extract_iocs(text: str) -> dict:
    """Extract all IOC types from raw log text."""
    r = IOCResult()
    r.urls    = _IOC_PATTERNS["url"].findall(text)
    cleaned   = _IOC_PATTERNS["url"].sub(" ", text)
    all_ips   = _IOC_PATTERNS["ipv4"].findall(cleaned)
    r.ips     = [ip for ip in all_ips if not _PRIVATE_IP.match(ip)]
    r.domains = [d for d in _IOC_PATTERNS["domain"].findall(cleaned) if len(d) > 5]
    sha256    = set(_IOC_PATTERNS["sha256"].findall(text))
    sha1      = set(_IOC_PATTERNS["sha1"].findall(text))  - sha256
    md5       = set(_IOC_PATTERNS["md5"].findall(text))   - sha256 - sha1
    r.hashes  = {"sha256": list(sha256), "sha1": list(sha1), "md5": list(md5)}
    r.emails        = _IOC_PATTERNS["email"].findall(text)
    r.cves          = _IOC_PATTERNS["cve"].findall(text)
    r.registry_keys = _IOC_PATTERNS["registry"].findall(text)
    r.file_paths    = _IOC_PATTERNS["filepath"].findall(text)
    return r.to_dict()


# ═══════════════════════════════════════════════════════════════════════════════
#  MODULE 2 — THREAT SCORER
#  Calculates a 0–100 risk score based on IOC volume and TTP keyword signals.
#  Returns (score: int, severity: str) where severity ∈ {LOW,MEDIUM,HIGH,CRITICAL}
# ═══════════════════════════════════════════════════════════════════════════════

_SIGNALS: list[tuple[int, list[str]]] = [
    (15, ["ransomware","exfiltration","data breach","lateral movement","domain controller",
          "mimikatz","cobalt strike","empire","metasploit","c2","command and control",
          "beacon","shellcode","zero-day","0day","privilege escalation","credential dumping",
          "pass-the-hash","golden ticket"]),
    (10, ["malware","backdoor","trojan","rootkit","keylogger","spyware","persistence",
          "scheduled task","registry run key","powershell -enc","base64","obfuscat",
          "reverse shell","bind shell","lsass","sam database","brute force",
          "password spray","phishing","spearphish"]),
    (5,  ["suspicious","anomalous","unusual","unauthorized","failed login","scan",
          "port sweep","probing","reconnaissance","enumeration","dll injection",
          "process injection","hollowing","masquerad"]),
    (2,  ["warning","alert","blocked","denied","quarantine","detected"]),
]
_SEV_THRESHOLDS = [(75,"CRITICAL"),(50,"HIGH"),(25,"MEDIUM"),(0,"LOW")]


def score_incident(iocs: dict, raw_logs: str) -> tuple[int, str]:
    """Compute a 0–100 threat score and severity label."""
    score = 0
    text  = raw_logs.lower()
    # IOC contribution (max 40 pts)
    ioc_score  = min(len(iocs.get("ips",[])) * 3, 12)
    ioc_score += min(len(iocs.get("domains",[])) * 2, 8)
    ioc_score += min(len(iocs.get("urls",[])) * 2, 8)
    ioc_score += min((len(iocs["hashes"]["md5"]) + len(iocs["hashes"]["sha1"]) + len(iocs["hashes"]["sha256"])) * 4, 12)
    score += min(ioc_score, 40)
    # Keyword contribution (max 60 pts)
    kw_score = 0
    for weight, keywords in _SIGNALS:
        for kw in keywords:
            if re.search(re.escape(kw), text):
                kw_score += weight
    score += min(kw_score, 60)
    score = max(0, min(score, 100))
    severity = next(label for threshold, label in _SEV_THRESHOLDS if score >= threshold)
    return score, severity


# ═══════════════════════════════════════════════════════════════════════════════
#  MODULE 3 — MITRE ATT&CK MAPPER
#  Maps log content to MITRE ATT&CK Enterprise techniques via keyword heuristics.
#  Knowledge base: 20 techniques across Initial Access → Impact.
#  Reference: https://attack.mitre.org/
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class Technique:
    id: str; name: str; tactic: str; description: str; keywords: list[str]
    def to_dict(self) -> dict:
        return {"id": self.id, "name": self.name, "tactic": self.tactic,
                "description": self.description,
                "url": f"https://attack.mitre.org/techniques/{self.id.replace('.','/')}"}


_TECHNIQUE_KB = [
    Technique("T1059.001","PowerShell","Execution",
        "Adversaries abuse PowerShell to execute commands and scripts.",
        ["powershell","pwsh","-encodedcommand","-enc","invoke-expression","iex"]),
    Technique("T1059.003","Windows Command Shell","Execution",
        "Adversaries abuse cmd.exe to execute commands.",
        ["cmd.exe","cmd /c","command shell","net user","net group"]),
    Technique("T1078","Valid Accounts","Defense Evasion / Persistence",
        "Adversaries obtain and abuse credentials of existing accounts.",
        ["valid account","stolen credential","compromised account","legitimate account"]),
    Technique("T1003.001","LSASS Memory","Credential Access",
        "Adversaries target LSASS memory to extract credential material.",
        ["lsass","lsass.exe","mimikatz","sekurlsa","credential dumping"]),
    Technique("T1003.002","SAM Database","Credential Access",
        "Adversaries access the SAM database to harvest credentials.",
        ["sam database","ntds.dit","reg save hklm\\sam"]),
    Technique("T1021.002","SMB/Windows Admin Shares","Lateral Movement",
        "Adversaries use SMB to move laterally across the network.",
        ["smb","admin$","ipc$","net use","lateral movement","psexec"]),
    Technique("T1055","Process Injection","Defense Evasion / Privilege Escalation",
        "Adversaries inject code into processes to evade defenses.",
        ["process injection","dll injection","hollowing","reflective","shellcode"]),
    Technique("T1053.005","Scheduled Task","Persistence / Privilege Escalation",
        "Adversaries abuse Windows Task Scheduler to schedule malicious tasks.",
        ["scheduled task","schtasks","task scheduler","at.exe"]),
    Technique("T1547.001","Registry Run Keys","Persistence",
        "Adversaries achieve persistence by adding programs to registry run keys.",
        ["registry run","hkcu\\software\\microsoft\\windows\\currentversion\\run",
         "hklm\\software\\microsoft\\windows\\currentversion\\run"]),
    Technique("T1070.001","Clear Windows Event Logs","Defense Evasion",
        "Adversaries clear Windows event logs to remove evidence.",
        ["clear-eventlog","wevtutil cl","event log cleared","security log cleared"]),
    Technique("T1190","Exploit Public-Facing Application","Initial Access",
        "Adversaries exploit vulnerabilities in internet-facing applications.",
        ["sql injection","rce","remote code execution","exploit","vulnerability","cve-"]),
    Technique("T1486","Data Encrypted for Impact","Impact",
        "Adversaries encrypt data to interrupt availability (ransomware).",
        ["ransomware","encrypted files",".locked",".crypted","ransom note","decrypt"]),
    Technique("T1041","Exfiltration Over C2 Channel","Exfiltration",
        "Adversaries exfiltrate data over the C2 channel.",
        ["exfiltration","data exfil","c2","command and control","beacon","c&c"]),
    Technique("T1566.001","Spearphishing Attachment","Initial Access",
        "Adversaries send spearphishing emails with malicious attachments.",
        ["spearphish","phishing","malicious attachment","macro",".docm",".xlsm"]),
    Technique("T1110.003","Password Spraying","Credential Access",
        "Adversaries use a single password against many accounts to avoid lockouts.",
        ["password spray","password spraying","brute force","failed login","multiple failed"]),
    Technique("T1046","Network Service Discovery","Discovery",
        "Adversaries scan for services to identify attack opportunities.",
        ["port scan","nmap","network scan","service scan","port sweep","masscan"]),
    Technique("T1083","File and Directory Discovery","Discovery",
        "Adversaries enumerate files and directories to find sensitive data.",
        ["dir /s","ls -la","find /","directory listing","file enumeration"]),
    Technique("T1005","Data from Local System","Collection",
        "Adversaries collect data stored on local systems.",
        ["data collection","sensitive file","document harvest","staging directory"]),
    Technique("T1027","Obfuscated Files or Information","Defense Evasion",
        "Adversaries obfuscate files or information to hinder analysis.",
        ["obfuscat","base64","encoded payload","packed","encrypted payload"]),
    Technique("T1071.001","Web Protocols","Command and Control",
        "Adversaries use HTTP/S for C2 to blend with normal traffic.",
        ["http beacon","https beacon","c2 over http","web shell","webshell"]),
]


def map_to_mitre(raw_logs: str) -> list[dict]:
    """Map log content to MITRE ATT&CK techniques."""
    text = raw_logs.lower()
    matched = [t.to_dict() for t in _TECHNIQUE_KB
               if any(re.search(re.escape(kw), text) for kw in t.keywords)]
    return sorted(matched, key=lambda t: t["id"])


# ═══════════════════════════════════════════════════════════════════════════════
#  MODULE 4 — TIMELINE BUILDER
#  Reconstructs a chronological event timeline from raw log text.
#  Parses ISO 8601, Syslog, Windows Event Log, and Apache/nginx timestamp formats.
# ═══════════════════════════════════════════════════════════════════════════════

_TS_PATTERNS = [
    (re.compile(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?)"), "%Y-%m-%dT%H:%M:%S"),
    (re.compile(r"([A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"),                            "%b %d %H:%M:%S"),
    (re.compile(r"(\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})"),                                "%Y/%m/%d %H:%M:%S"),
    (re.compile(r"(\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2})"),                            "%d/%b/%Y:%H:%M:%S"),
]
_SEC_KEYWORDS = re.compile(
    r"failed|error|denied|blocked|alert|critical|warning|login|logout|authentication|"
    r"privilege|escalat|access|permission|firewall|connection|port|scan|malware|virus|"
    r"trojan|ransomware|exploit|powershell|cmd|bash|execute|spawn|process|registry|"
    r"scheduled task|service|persistence|exfil|upload|download|transfer|lsass|mimikatz|"
    r"credential|hash|lateral|smb|rdp|ssh", re.IGNORECASE)


def _parse_ts(ts_str: str, fmt: str) -> datetime | None:
    clean = re.sub(r"\.\d+", "", ts_str).rstrip("Z").split("+")[0]
    for attempt in (ts_str, clean):
        try:
            return datetime.strptime(attempt[:len(fmt)+2], fmt)
        except ValueError:
            pass
    return None


def build_timeline(raw_logs: str) -> list[dict]:
    """Parse logs and return sorted security-relevant timeline events."""
    events = []
    for line in raw_logs.splitlines():
        line = line.strip()
        if not line:
            continue
        ts_obj, ts_str = None, None
        for pattern, fmt in _TS_PATTERNS:
            m = pattern.search(line)
            if m:
                ts_str = m.group(1)
                ts_obj = _parse_ts(ts_str, fmt)
                break
        is_relevant = bool(_SEC_KEYWORDS.search(line))
        line_lower  = line.lower()
        if any(k in line_lower for k in ["critical","ransomware","malware","exfil","lsass","mimikatz"]):
            sev = "CRITICAL"
        elif any(k in line_lower for k in ["error","failed","denied","blocked","alert","exploit"]):
            sev = "HIGH"
        elif any(k in line_lower for k in ["warning","suspicious","unusual","anomalous"]):
            sev = "MEDIUM"
        else:
            sev = "INFO"
        if is_relevant or ts_obj:
            events.append({
                "timestamp":      ts_str or "UNKNOWN",
                "_sort":          ts_obj.isoformat() if ts_obj else "9999",
                "raw_line":       line[:300],
                "severity_hint":  sev,
                "has_timestamp":  ts_obj is not None,
            })
    events.sort(key=lambda e: e["_sort"])
    for e in events:
        del e["_sort"]
    return events[:200]


# ═══════════════════════════════════════════════════════════════════════════════
#  MODULE 5 — REPORT GENERATOR
#  Produces a structured markdown incident report from investigation results.
# ═══════════════════════════════════════════════════════════════════════════════

def generate_report(investigation: dict) -> str:
    """Generate a professional SOC incident report."""
    now        = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    iocs       = investigation.get("iocs", {})
    techniques = investigation.get("mitre_techniques", [])
    timeline   = investigation.get("timeline", [])

    def section(label, items):
        if not items:
            return [f"**{label}:** None identified", ""]
        return [f"**{label}** ({len(items)} found)"] + [f"  - `{i}`" for i in items] + [""]

    lines = [
        "# SOC INCIDENT INVESTIGATION REPORT",
        f"**Generated:** {now}",
        f"**Incident ID:** {investigation.get('incident_id','N/A')}",
        f"**Severity:** {investigation.get('severity','N/A')}",
        f"**Threat Score:** {investigation.get('threat_score',0)}/100",
        f"**Status:** {investigation.get('status','N/A')}",
        "", "---", "",
        "## 1. EXECUTIVE SUMMARY", "",
        f"Incident `{investigation.get('incident_id','UNKNOWN')}` classified as "
        f"**{investigation.get('severity','UNKNOWN')}** with threat score "
        f"**{investigation.get('threat_score',0)}/100**. "
        f"**{iocs.get('total_count',0)} IOCs** extracted. "
        f"**{len(techniques)} MITRE ATT&CK technique(s)** identified.",
        "", "---", "", "## 2. INDICATORS OF COMPROMISE", "",
    ]
    lines += section("IP Addresses",   iocs.get("ips",[]))
    lines += section("Domains",        iocs.get("domains",[]))
    lines += section("URLs",           iocs.get("urls",[]))
    lines += section("SHA256 Hashes",  iocs.get("hashes",{}).get("sha256",[]))
    lines += section("SHA1 Hashes",    iocs.get("hashes",{}).get("sha1",[]))
    lines += section("MD5 Hashes",     iocs.get("hashes",{}).get("md5",[]))
    lines += section("Emails",         iocs.get("emails",[]))
    lines += section("CVEs",           iocs.get("cves",[]))
    lines += section("Registry Keys",  iocs.get("registry_keys",[]))
    lines += section("File Paths",     iocs.get("file_paths",[]))
    lines += ["---", "", "## 3. MITRE ATT&CK MAPPING", ""]
    if techniques:
        lines += ["| Technique ID | Name | Tactic |", "|---|---|---|"]
        lines += [f"| [{t['id']}]({t['url']}) | {t['name']} | {t['tactic']} |" for t in techniques]
        lines += [""]
    else:
        lines += ["No techniques identified.", ""]
    lines += ["---", "", "## 4. TIMELINE OF EVENTS", ""]
    if timeline:
        lines += ["| Timestamp | Severity | Event |", "|---|---|---|"]
        for e in timeline[:50]:
            raw = e.get("raw_line","")[:120].replace("|","\\|")
            lines.append(f"| `{e.get('timestamp','?')}` | {e.get('severity_hint','INFO')} | {raw} |")
        if len(timeline) > 50:
            lines.append(f"| ... | ... | *{len(timeline)-50} more events omitted* |")
        lines += [""]
    else:
        lines += ["No timeline events.", ""]
    lines += [
        "---", "", "## 5. RECOMMENDATIONS", "",
        "- Isolate affected endpoints immediately.",
        "- Reset credentials for all accounts in IOCs.",
        "- Block malicious IPs, domains, and URLs at perimeter.",
        "- Add file hashes to endpoint blocklists.",
        "- Preserve forensic images before remediation.",
        "- Patch any CVEs identified in this report.",
        "- Conduct lessons-learned and update detection rules.", "",
        "---", "", "## 6. ANALYST NOTES", "",
        "*[ Analyst sign-off and manual findings ]*", "",
        "---", "",
        f"*Auto-generated — SOC Incident Investigation Platform — {now}*",
    ]
    return "\n".join(lines)


# ═══════════════════════════════════════════════════════════════════════════════
#  MODULE 6 — SAMPLE DATA
#  Realistic SOC incident scenarios for demonstration.
# ═══════════════════════════════════════════════════════════════════════════════

SAMPLE_INCIDENTS = [
    {
        "id": "INC-2024-0042", "title": "Ransomware Deployment — Finance Workstation",
        "severity": "CRITICAL", "threat_score": 94, "status": "ACTIVE",
        "assigned_to": "SOC Tier 2", "created": "2024-11-15T02:14:33Z",
        "source": "Microsoft Sentinel", "tags": ["ransomware","T1486","lateral-movement"],
        "summary": "Cobalt Strike beacon detected. LSASS dumped. Lateral movement via SMB. Ransomware staged.",
        "logs": (
            "2024-11-15T02:01:12Z [WARN] Outbound connection to 185.220.101.45:443 from FINANCE-WS01\n"
            "2024-11-15T02:03:44Z [CRIT] Process injection detected: rundll32.exe -> explorer.exe\n"
            "2024-11-15T02:05:01Z [CRIT] LSASS memory access by non-system process: beacon.exe PID 4412\n"
            "2024-11-15T02:07:22Z [WARN] SMB lateral movement: FINANCE-WS01 -> DC01 (admin$)\n"
            "2024-11-15T02:09:55Z [CRIT] Scheduled task created: WindowsUpdateCheck C:\\Temp\\svc.exe\n"
            "2024-11-15T02:11:30Z [CRIT] Mass file rename: 847 files now have .locked extension\n"
            "2024-11-15T02:14:33Z [CRIT] Ransom note: C:\\Users\\Public\\READ_ME.txt\n"
            "Hash: 3d7b9a2f1e4c8d6a0f5e2b9c7a1d4f8e3b6c9d2a5f8e1b4c7d0a3f6e9b2c5d8a1\n"
            "C2: update-service-cdn[.]com\nCVE-2021-34527 privilege escalation"
        ),
    },
    {
        "id": "INC-2024-0038", "title": "Password Spray — Azure AD",
        "severity": "HIGH", "threat_score": 67, "status": "INVESTIGATING",
        "assigned_to": "SOC Tier 1", "created": "2024-11-14T18:42:00Z",
        "source": "Microsoft Sentinel", "tags": ["credential-access","T1110.003"],
        "summary": "342 failed logins across 89 accounts in 4 minutes from single source IP.",
        "logs": (
            "2024-11-14T18:38:01Z [WARN] Azure AD: 342 failed login attempts in 4 minutes\n"
            "2024-11-14T18:38:01Z [WARN] Source IP: 45.33.32.156 targeting multiple accounts\n"
            "2024-11-14T18:38:45Z [WARN] Password spray: single password across 89 accounts\n"
            "2024-11-14T18:40:12Z [HIGH] Account locked: j.smith@company.com after 5 failed attempts\n"
            "2024-11-14T18:41:05Z [HIGH] Account locked: m.johnson@company.com\n"
            "2024-11-14T18:42:00Z [CRIT] Successful login: admin@company.com from 45.33.32.156"
        ),
    },
    {
        "id": "INC-2024-0031", "title": "Phishing — Malicious Macro Execution",
        "severity": "HIGH", "threat_score": 72, "status": "CONTAINED",
        "assigned_to": "SOC Tier 2", "created": "2024-11-12T09:15:00Z",
        "source": "Splunk SIEM", "tags": ["initial-access","T1566.001","powershell"],
        "summary": "User opened malicious .xlsm attachment. Macro executed encoded PowerShell dropper.",
        "logs": (
            "2024-11-12T09:10:00Z [INFO] Email: invoice_nov2024.xlsm from attacker@fakeinvoice.net\n"
            "2024-11-12T09:14:55Z [WARN] Macro execution: EXCEL.EXE spawned cmd.exe on HR-PC03\n"
            "2024-11-12T09:15:02Z [CRIT] PowerShell -EncodedCommand execution on HR-PC03\n"
            "2024-11-12T09:15:10Z [CRIT] Outbound: HR-PC03 -> 91.213.50.22:80\n"
            "2024-11-12T09:16:30Z [HIGH] File dropped: C:\\Users\\jdoe\\AppData\\Roaming\\svchost32.exe\n"
            "MD5: a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6\nDomain: cdn-delivery-fast[.]com"
        ),
    },
    {
        "id": "INC-2024-0027", "title": "Network Reconnaissance — Internal Subnet Scan",
        "severity": "MEDIUM", "threat_score": 38, "status": "CLOSED",
        "assigned_to": "SOC Tier 1", "created": "2024-11-10T14:00:00Z",
        "source": "IBM QRadar", "tags": ["discovery","T1046","port-scan"],
        "summary": "Nmap scan from compromised host. All 254 IPs on /24 subnet probed.",
        "logs": (
            "2024-11-10T13:58:00Z [WARN] Port sweep from 10.10.1.55\n"
            "2024-11-10T13:58:45Z [WARN] 254 hosts probed on subnet 10.10.1.0/24\n"
            "2024-11-10T13:59:12Z [INFO] Ports targeted: 22,80,135,139,443,445,3389,8080\n"
            "2024-11-10T14:00:00Z [WARN] Nmap OS fingerprinting signatures observed"
        ),
    },
]


# ═══════════════════════════════════════════════════════════════════════════════
#  FLASK API ROUTES
# ═══════════════════════════════════════════════════════════════════════════════

@app.route("/api/investigate", methods=["POST"])
def api_investigate():
    """Run the full investigation pipeline on raw log text."""
    data        = request.get_json(force=True)
    raw_logs    = data.get("logs", "")
    incident_id = data.get("incident_id", "INC-MANUAL")
    iocs              = extract_iocs(raw_logs)
    threat_score, sev = score_incident(iocs, raw_logs)
    mitre_techniques  = map_to_mitre(raw_logs)
    timeline          = build_timeline(raw_logs)
    return jsonify({
        "incident_id":       incident_id,
        "severity":          sev,
        "threat_score":      threat_score,
        "iocs":              iocs,
        "mitre_techniques":  mitre_techniques,
        "timeline":          timeline,
        "status":            "INVESTIGATED",
    })


@app.route("/api/report", methods=["POST"])
def api_report():
    """Generate a structured markdown incident report."""
    data = request.get_json(force=True)
    return jsonify({"report": generate_report(data)})


@app.route("/api/incidents")
def api_incidents():
    return jsonify(SAMPLE_INCIDENTS)


# ═══════════════════════════════════════════════════════════════════════════════
#  DASHBOARD HTML  (served inline — no templates folder needed)
# ═══════════════════════════════════════════════════════════════════════════════


# ═══════════════════════════════════════════════════════════════════════════════
#  DASHBOARD ROUTE — loads dashboard.html from same directory
# ═══════════════════════════════════════════════════════════════════════════════

@app.route("/")
def dashboard():
    import os
    html_path = os.path.join(os.path.dirname(__file__), "dashboard.html")
    with open(html_path, "r", encoding="utf-8") as f:
        return f.read()


# ═══════════════════════════════════════════════════════════════════════════════
#  ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print("""
╔══════════════════════════════════════════════════════╗
║   SOC INCIDENT INVESTIGATION PLATFORM                ║
║   → http://localhost:5000                            ║
╚══════════════════════════════════════════════════════╝
""")
    app.run(debug=True, port=5000)
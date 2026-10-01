import json
import re
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from app.models.log_event import LogEvent
from app.models.detection_alert import DetectionAlert
from app.config.settings import settings

SENSITIVE_KEYWORDS = [
    "/admin", "/api/admin", "/database", "/backup", "/credentials",
    "/secret", "admin_panel", "user_management", "financial_records",
    "ssn_database", "medical_records", "/etc/shadow", "/etc/passwd",
]

PRIVILEGE_KEYWORDS = [
    "privilege", "sudo", "root", "admin", "escalat", "role_change",
    "permission", "grant", "elevate",
]

# --- Signature patterns that indicate malicious behaviour in raw log lines ---
SQL_INJECTION_RE = re.compile(
    r"(\bunion\b.{0,40}\bselect\b|"
    r"\bor\s+1\s*=\s*1|"
    r"'\s*(or|and)\s+\d+\s*=\s*\d+|"
    r"--\s*$|"
    r"(?:--|#)\s*$|"
    r"sleep\s*\(\s*\d+\s*\)|"
    r"\bwaitfor\s+delay\b|"
    r"\b(?:information_schema|pg_catalog|sqlite_master)\b)",
    re.IGNORECASE,
)
XSS_RE = re.compile(
    r"(<script|<\/script>|javascript:|onerror\s*=|onload\s*=|"
    r"alert\s*\(\s*['\"]|prompt\s*\(\s*['\"]|confirm\s*\(\s*['\"]|"
    r"document\.cookie|%3cscript|&lt;script|\uFEFF<|"
    r"(?:%0d|%0a)<|src\s*=\s*['\"]?\s*java)",
    re.IGNORECASE,
)
PATH_TRAVERSAL_RE = re.compile(
    r"((?:\.\./|\.\.\\){2,}|%2e%2e[\/\\]|\.\.%2f|\.\.%5c|"
    r"\.\.\?\.\.|\.\.%00|%2e\.%2f|%252e%252e)",
    re.IGNORECASE,
)
COMMAND_INJECTION_RE = re.compile(
    r"((?:;|\||&&|\$\(|`)\s*(cat|ls|id|whoami|wget|curl|nc|netcat|"
    r"bash|sh|python|perl|powershell|cmd|chmod|chown|rm|mkfs|dd)\b|"
    r"base64\s+-d|/bin/sh|/bin/bash|cmd\.exe|powershell\.exe)",
    re.IGNORECASE,
)
WEB_SHELL_RE = re.compile(
    r"(\.(php|asp|aspx|jsp|pl|cgi)\s*\?|"
    r"cmd=(\w+\s+)+|passthru\s*\(|system\s*\(|shell_exec\s*\(|"
    r"eval\s*\(|assert\s*\(|base64_decode\s*\(|"
    r"/(?:shell|c99|r57|b374k|wso|alpha)\.php|"
    r"eval\s*\(\s*base64_)",
    re.IGNORECASE,
)
SENSITIVE_FILE_RE = re.compile(
    r"(/(?:etc/passwd|etc/shadow|etc/sudoers|etc/hosts|etc/crontab|"
    r".+\.(?:env|ini|conf|yml|yaml|json|bak|sql|db|htpasswd|htaccess)|"
    r"proc/self/environ|proc/self/cmdline|"
    r"(?:config|web\.config|php\.ini|\.aws|\.git/config|jenkins)/?))",
    re.IGNORECASE,
)
SCANNER_RE = re.compile(
    r"((?:nikto|sqlmap|nessus|openvas|acunetix|burp|zap|masscan|"
    r"nmap|hydra|medusa|patator|dirbuster|gobuster|"
    r"wfuzz|appscan|fuzz|exploit-db|metasploit)|"
    r"(?:GET|POST|HEAD)\s+[^\s]*(?:wp-admin|wp-login\.php|login\.php|"
    r"phpmyadmin|\.git/|\.svn/|\.env|"
    r"actuator|console|xmlrpc\.php|readme\.html|install\.php|setup\.php)|"
    r"(?:cgi-bin|/\.\./\.\./\.\./))",
    re.IGNORECASE,
)
MALWARE_RE = re.compile(
    r"(powershell\s+(-|\-)[^\s]*\s+executionpolicy|"
    r"\s-enc\s+\S{20,}|-encodedcommand\s+\S{20,}|"
    r"certutil\s+-urlcache|bitsadmin\s+/transfer|wscript\.shell|"
    r"mshta\.exe|regsvr32\s+/s|rundll32\.exe\s+.*\bhttp|"
    r"obfuscated|packed|encrypted\s+payload|"
    r"(?:curl|wget|invoke-webrequest|iwr)\s+[^\s]+-o\s+|"
    r"\b(?:trojan|backdoor|keylogger|ransomware|botnet|rootkit|stealer)\b)",
    re.IGNORECASE,
)
CREDENTIAL_ACCESS_RE = re.compile(
    r"(?i)(/\.aws/credentials|/\.ssh/|id_rsa|authorized_keys|"
    r"/shadow|pwd\.dump|password\.db|sam\.|system\.hive|"
    r"(?:hashdump|mimikatz|cachedump|lsass|secretsdump)|"
    r"(?:grep\s+password|find\s+.*-perm\s+-4))",
)
DATA_EXFIL_RE = re.compile(
    r"(?i)((?:curl|wget|scp|ftp|nc|ncat|rsync)\s+\S+\s+https?://\S+|"
    r"base64\s+-d\s+.*\b(?:cat|ls|dd)\b|"
    r"\bexfil\w*|data\s+exfilt\w+|/dns\s+query|tunneling|tunnel\s+traffic)"
)

SEVERITY_IMPORTANCE = {
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


class DetectionEngine:
    def __init__(self, db: Session):
        self.db = db

    def run(self, events: List[LogEvent]) -> List[DetectionAlert]:
        if not events:
            return []
        alerts = []
        alerts.extend(self._individual_detection(events))
        alerts.extend(self._attack_pattern_detection(events))
        alerts.extend(self._threshold_detection(events))
        alerts.extend(self._behavioral_detection(events))
        alerts.extend(self._sequence_detection(events))
        return self._dedupe(alerts)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _meta(event: LogEvent) -> Dict[str, Any]:
        try:
            data = json.loads(event.metadata_json or "{}")
            return data if isinstance(data, dict) else {}
        except (ValueError, TypeError):
            return {}

    @staticmethod
    def _scan_surface(event: LogEvent) -> str:
        """Raw message plus decoded URL payload used by signature rules."""
        parts = [event.raw_message or ""]
        meta = DetectionEngine._meta(event)
        decoded = meta.get("decoded_url")
        if decoded:
            parts.append(decoded)
        if event.resource:
            parts.append(event.resource)
        return " ".join(parts).lower()

    @staticmethod
    def _flag(event: LogEvent, importance: int) -> None:
        event.is_suspicious = 1
        event.importance = max(event.importance or 0, importance)

    def _dedupe(self, alerts: List[DetectionAlert]) -> List[DetectionAlert]:
        seen = set()
        result = []
        for a in alerts:
            key = (a.rule_name, a.event_id)
            if key in seen:
                continue
            seen.add(key)
            result.append(a)
        return result

    def _create_alert(
        self, event: LogEvent, rule_name: str,
        description: str, severity: str, risk_points: int
    ) -> DetectionAlert:
        alert = DetectionAlert(
            event_id=event.id,
            rule_name=rule_name,
            severity=severity,
            description=description,
            risk_points=risk_points,
        )
        self.db.add(alert)
        return alert

    # ------------------------------------------------------------------
    # 1. Individual event detection (severity / privilege / sensitive)
    # ------------------------------------------------------------------
    def _individual_detection(self, events: List[LogEvent]) -> List[DetectionAlert]:
        alerts = []
        for event in events:
            if event.severity in ("high", "critical"):
                alert = self._create_alert(
                    event=event,
                    rule_name="High Severity Event",
                    description=f"A {event.severity}-severity event of type '{event.event_type}' was detected.",
                    severity=event.severity,
                    risk_points=15,
                )
                alerts.append(alert)
                self._flag(event, 3)

            if event.event_type == "PRIVILEGE_CHANGE":
                alert = self._create_alert(
                    event=event,
                    rule_name="Privilege Change Detected",
                    description=f"A privilege change was detected for user '{event.username or 'unknown'}'.",
                    severity="high",
                    risk_points=20,
                )
                alerts.append(alert)
                self._flag(event, 4)

            if event.event_type == "ACCOUNT_CHANGE":
                alert = self._create_alert(
                    event=event,
                    rule_name="Suspicious Account Activity",
                    description=f"Account change activity detected for user '{event.username or 'unknown'}'.",
                    severity="medium",
                    risk_points=12,
                )
                alerts.append(alert)
                self._flag(event, 3)

            if event.event_type == "ACCOUNT_LOCKED":
                alert = self._create_alert(
                    event=event,
                    rule_name="Account Lockout Detected",
                    description=f"Account lockout detected for user '{event.username or 'unknown'}'.",
                    severity="high",
                    risk_points=18,
                )
                alerts.append(alert)
                self._flag(event, 3)

            if event.resource and any(kw in (event.resource or "").lower() for kw in SENSITIVE_KEYWORDS):
                alert = self._create_alert(
                    event=event,
                    rule_name="Sensitive Resource Access",
                    description=f"Access to sensitive resource '{event.resource}' was detected.",
                    severity="high",
                    risk_points=20,
                )
                alerts.append(alert)
                self._flag(event, 4)

            raw_lower = (event.raw_message or "").lower()
            if any(kw in raw_lower for kw in PRIVILEGE_KEYWORDS) and event.event_type in ("LOGIN_SUCCESS", "SESSION_START"):
                alert = self._create_alert(
                    event=event,
                    rule_name="Privileged Access Detected",
                    description=f"Privileged access detected for user '{event.username or 'unknown'}'.",
                    severity="medium",
                    risk_points=15,
                )
                alerts.append(alert)
                self._flag(event, 3)

        return alerts

    # ------------------------------------------------------------------
    # 2. Signature / pattern based attack detection
    # ------------------------------------------------------------------
    def _attack_pattern_detection(self, events: List[LogEvent]) -> List[DetectionAlert]:
        alerts = []
        for event in events:
            surface = self._scan_surface(event)

            if SQL_INJECTION_RE.search(surface):
                alert = self._create_alert(
                    event=event,
                    rule_name="SQL Injection Attempt",
                    description=f"SQL injection signature detected from IP '{event.ip_address or 'unknown'}'.",
                    severity="high",
                    risk_points=25,
                )
                alerts.append(alert)
                self._flag(event, 4)

            if XSS_RE.search(surface):
                alert = self._create_alert(
                    event=event,
                    rule_name="Cross-Site Scripting (XSS)",
                    description=f"XSS signature detected from IP '{event.ip_address or 'unknown'}'.",
                    severity="high",
                    risk_points=20,
                )
                alerts.append(alert)
                self._flag(event, 3)

            if PATH_TRAVERSAL_RE.search(surface):
                alert = self._create_alert(
                    event=event,
                    rule_name="Path Traversal Attempt",
                    description=f"Path traversal signature detected from IP '{event.ip_address or 'unknown'}'.",
                    severity="high",
                    risk_points=22,
                )
                alerts.append(alert)
                self._flag(event, 4)

            if COMMAND_INJECTION_RE.search(surface):
                alert = self._create_alert(
                    event=event,
                    rule_name="Command Injection Attempt",
                    description=f"Command injection signature detected from IP '{event.ip_address or 'unknown'}'.",
                    severity="critical",
                    risk_points=28,
                )
                alerts.append(alert)
                self._flag(event, 5)

            if WEB_SHELL_RE.search(surface):
                alert = self._create_alert(
                    event=event,
                    rule_name="Potential Web Shell Access",
                    description=f"Web shell / remote code execution signature detected from IP '{event.ip_address or 'unknown'}'.",
                    severity="critical",
                    risk_points=30,
                )
                alerts.append(alert)
                self._flag(event, 5)

            if SENSITIVE_FILE_RE.search(surface):
                alert = self._create_alert(
                    event=event,
                    rule_name="Sensitive / Config File Access",
                    description=f"Request for configuration or sensitive file detected from IP '{event.ip_address or 'unknown'}'.",
                    severity="high",
                    risk_points=22,
                )
                alerts.append(alert)
                self._flag(event, 4)

            if CREDENTIAL_ACCESS_RE.search(surface):
                alert = self._create_alert(
                    event=event,
                    rule_name="Credential Access Attempt",
                    description=f"Credential harvesting signature detected from IP '{event.ip_address or 'unknown'}'.",
                    severity="critical",
                    risk_points=30,
                )
                alerts.append(alert)
                self._flag(event, 5)

            if DATA_EXFIL_RE.search(surface):
                alert = self._create_alert(
                    event=event,
                    rule_name="Potential Data Exfiltration",
                    description=f"Data exfiltration signature detected from IP '{event.ip_address or 'unknown'}'.",
                    severity="critical",
                    risk_points=32,
                )
                alerts.append(alert)
                self._flag(event, 5)

            if MALWARE_RE.search(surface):
                alert = self._create_alert(
                    event=event,
                    rule_name="Malware / Obfuscation Indicators",
                    description=f"Malware or obfuscation indicator detected in event from IP '{event.ip_address or 'unknown'}'.",
                    severity="high",
                    risk_points=25,
                )
                alerts.append(alert)
                self._flag(event, 4)

            if SCANNER_RE.search(surface):
                # Do not double-flag a line that already looked like a probe
                # for one of the higher-confidence attack classes.
                existing = {a.rule_name for a in alerts if a.event_id == event.id}
                if not existing:
                    alert = self._create_alert(
                        event=event,
                        rule_name="Web Probing / Scanning Signature",
                        description=f"Probing or scanning signature detected from IP '{event.ip_address or 'unknown'}'.",
                        severity="medium",
                        risk_points=15,
                    )
                    alerts.append(alert)
                    self._flag(event, 3)

        return alerts

    # ------------------------------------------------------------------
    # 3. Frequency / threshold based detection (brute force, etc.)
    # ------------------------------------------------------------------
    def _threshold_detection(self, events: List[LogEvent]) -> List[DetectionAlert]:
        alerts = []
        threshold = settings.DETECTION_FAILED_LOGIN_THRESHOLD
        window_minutes = settings.DETECTION_FAILED_LOGIN_WINDOW_MINUTES

        failed_logins = [e for e in events if e.event_type == "LOGIN_FAILED"]
        by_ip: Dict[str, List[LogEvent]] = {}
        for e in failed_logins:
            if e.ip_address:
                by_ip.setdefault(e.ip_address, []).append(e)

        for ip, ip_events in by_ip.items():
            ip_events.sort(key=lambda x: x.timestamp or datetime.min)
            window = self._rolling_window(ip_events, window_minutes)
            for group in window:
                if len(group) >= threshold:
                    trigger_event = group[0]
                    alert = self._create_alert(
                        event=trigger_event,
                        rule_name="Repeated Authentication Failures",
                        description=f"{len(group)} failed authentication events were detected from IP '{ip}' within {window_minutes} minutes.",
                        severity="high",
                        risk_points=25,
                    )
                    alerts.append(alert)
                    for e in group:
                        self._flag(e, 3)
                    break

        failed_by_user: Dict[str, List[LogEvent]] = {}
        for e in failed_logins:
            if e.username:
                failed_by_user.setdefault(e.username, []).append(e)

        for user, user_events in failed_by_user.items():
            user_events.sort(key=lambda x: x.timestamp or datetime.min)
            window = self._rolling_window(user_events, window_minutes)
            for group in window:
                if len(group) >= threshold:
                    trigger_event = group[0]
                    alert = self._create_alert(
                        event=trigger_event,
                        rule_name="Repeated User Authentication Failures",
                        description=f"{len(group)} failed authentication events were detected for user '{user}' within {window_minutes} minutes.",
                        severity="high",
                        risk_points=25,
                    )
                    alerts.append(alert)
                    for e in group:
                        self._flag(e, 3)
                    break

        return alerts

    @staticmethod
    def _rolling_window(events: List[LogEvent], window_minutes: int) -> List[List[LogEvent]]:
        """Return every maximal window of events that fit inside the time span."""
        windows = []
        n = len(events)
        for i in range(n):
            start = events[i].timestamp or datetime.min
            window_end = start + timedelta(minutes=window_minutes)
            group = [
                e for e in events
                if (e.timestamp or datetime.min) >= start
                and (e.timestamp or datetime.min) <= window_end
            ]
            if group:
                windows.append(group)
        return windows

    # ------------------------------------------------------------------
    # 4. Behavioral detection (spraying, scanning, volume, context)
    # ------------------------------------------------------------------
    def _behavioral_detection(self, events: List[LogEvent]) -> List[DetectionAlert]:
        alerts = []
        spray_window = settings.DETECTION_SPRAY_WINDOW_MINUTES
        scan_window = settings.DETECTION_SCAN_WINDOW_MINUTES

        # 4a. Password spraying / username enumeration: one IP, several users
        failed_logins = [e for e in events if e.event_type in ("LOGIN_FAILED", "ACCOUNT_LOCKED")]
        by_ip: Dict[str, List[LogEvent]] = {}
        for e in failed_logins:
            if e.ip_address:
                by_ip.setdefault(e.ip_address, []).append(e)

        for ip, ip_events in by_ip.items():
            ip_events.sort(key=lambda x: x.timestamp or datetime.min)
            for group in self._rolling_window(ip_events, spray_window):
                users = {e.username for e in group if e.username}
                if len(users) >= settings.DETECTION_SPRAY_DISTINCT_USERS:
                    trigger_event = group[0]
                    alert = self._create_alert(
                        event=trigger_event,
                        rule_name="Possible Password Spraying",
                        description=(
                            f"Authentication failures for {len(users)} distinct users "
                            f"({', '.join(sorted(users)[:5])}) from IP '{ip}' within {spray_window} minutes."
                        ),
                        severity="high",
                        risk_points=24,
                    )
                    alerts.append(alert)
                    for e in group:
                        self._flag(e, 3)
                    break

        # 4b. Distributed brute force: several IPs, one user
        by_user: Dict[str, List[LogEvent]] = {}
        for e in failed_logins:
            if e.username:
                by_user.setdefault(e.username, []).append(e)

        for user, user_events in by_user.items():
            user_events.sort(key=lambda x: x.timestamp or datetime.min)
            for group in self._rolling_window(user_events, spray_window):
                ips = {e.ip_address for e in group if e.ip_address}
                if len(ips) >= settings.DETECTION_DISTRIBUTED_BRUTEFORCE_IPS:
                    trigger_event = group[0]
                    alert = self._create_alert(
                        event=trigger_event,
                        rule_name="Possible Distributed Brute Force",
                        description=(
                            f"Authentication failures for user '{user}' from {len(ips)} distinct IPs "
                            f"within {spray_window} minutes."
                        ),
                        severity="high",
                        risk_points=24,
                    )
                    alerts.append(alert)
                    for e in group:
                        self._flag(e, 3)
                    break

        # 4c. Port scanning: many distinct destination ports from one IP
        net_events = [e for e in events if e.source == "firewall"]
        by_ip_net: Dict[str, List[LogEvent]] = {}
        for e in net_events:
            if e.ip_address:
                by_ip_net.setdefault(e.ip_address, []).append(e)

        for ip, net_list in by_ip_net.items():
            net_list.sort(key=lambda x: x.timestamp or datetime.min)
            for group in self._rolling_window(net_list, scan_window):
                ports = set()
                for e in group:
                    m = re.search(r'\bport[:=]?(\d+)', e.resource or "", re.IGNORECASE)
                    meta = self._meta(e)
                    dpt = meta.get("dest_port")
                    if dpt is not None:
                        ports.add(int(dpt))
                    elif m:
                        ports.add(int(m.group(1)))
                if len(ports) >= settings.DETECTION_SCAN_PORT_THRESHOLD:
                    trigger_event = group[0]
                    alert = self._create_alert(
                        event=trigger_event,
                        rule_name="Possible Port Scan",
                        description=(
                            f"{len(ports)} distinct destination ports were targeted from IP '{ip}' "
                            f"within {scan_window} minutes."
                        ),
                        severity="medium",
                        risk_points=18,
                    )
                    alerts.append(alert)
                    for e in group:
                        self._flag(e, 2)
                    break

        # 4d. Web scanning: many distinct resources / error statuses from one IP
        web_events = [e for e in events if e.source == "web_server"]
        by_ip_web: Dict[str, List[LogEvent]] = {}
        for e in web_events:
            if e.ip_address:
                by_ip_web.setdefault(e.ip_address, []).append(e)

        for ip, web_list in by_ip_web.items():
            web_list.sort(key=lambda x: x.timestamp or datetime.min)
            for group in self._rolling_window(web_list, scan_window):
                distinct_resources = {e.resource for e in group if e.resource}
                error_statuses = [
                    e for e in group
                    if (self._meta(e).get("http_status") or 0) in (401, 403, 404, 500)
                ]
                if len(distinct_resources) >= settings.DETECTION_SCAN_RESOURCE_THRESHOLD or \
                   len(error_statuses) >= settings.DETECTION_SCAN_ERROR_THRESHOLD:
                    trigger_event = group[0]
                    alert = self._create_alert(
                        event=trigger_event,
                        rule_name="Possible Web Scanning",
                        description=(
                            f"Frequent HTTP requests ({len(group)} events, "
                            f"{len(distinct_resources)} distinct resources, "
                            f"{len(error_statuses)} error responses) from IP '{ip}' within {scan_window} minutes."
                        ),
                        severity="medium",
                        risk_points=18,
                    )
                    alerts.append(alert)
                    for e in group:
                        self._flag(e, 2)
                    break

        # 4e. High request volume from a single IP
        for ip, web_list in by_ip_web.items():
            web_list.sort(key=lambda x: x.timestamp or datetime.min)
            for group in self._rolling_window(web_list, settings.DETECTION_VOLUME_WINDOW_MINUTES):
                if len(group) >= settings.DETECTION_HIGH_VOLUME_THRESHOLD:
                    trigger_event = group[0]
                    alert = self._create_alert(
                        event=trigger_event,
                        rule_name="Anomalous Traffic Volume",
                        description=(
                            f"{len(group)} HTTP events were received from IP '{ip}' within "
                            f"{settings.DETECTION_VOLUME_WINDOW_MINUTES} minutes."
                        ),
                        severity="medium",
                        risk_points=15,
                    )
                    alerts.append(alert)
                    for e in group:
                        self._flag(e, 2)
                    break

        # 4f. Repeated sensitive resource access from one client (data access anomaly)
        sensitive_events = [
            e for e in events
            if e.resource and any(kw in e.resource.lower() for kw in SENSITIVE_KEYWORDS)
        ]
        by_ip_sensitive: Dict[str, List[LogEvent]] = {}
        for e in sensitive_events:
            if e.ip_address:
                by_ip_sensitive.setdefault(e.ip_address, []).append(e)

        for ip, sens_list in by_ip_sensitive.items():
            sens_list.sort(key=lambda x: x.timestamp or datetime.min)
            for group in self._rolling_window(sens_list, scan_window):
                if len(group) >= settings.DETECTION_SENSITIVE_ACCESS_THRESHOLD:
                    trigger_event = group[0]
                    alert = self._create_alert(
                        event=trigger_event,
                        rule_name="Repeated Sensitive Data Access",
                        description=(
                            f"{len(group)} accesses to sensitive resources were observed from IP '{ip}' "
                            f"within {scan_window} minutes."
                        ),
                        severity="high",
                        risk_points=24,
                    )
                    alerts.append(alert)
                    for e in group:
                        self._flag(e, 4)
                    break

        # 4g. Enumeration of accounts / privilege burst
        account_events = [e for e in events if e.event_type in ("ACCOUNT_CHANGE", "ACCOUNT_LOCKED")]
        if len(account_events) >= settings.DETECTION_ACCOUNT_ACTIVITY_THRESHOLD:
            trigger_event = account_events[0]
            alert = self._create_alert(
                event=trigger_event,
                rule_name="Suspicious Account Activity Burst",
                description=(
                    f"{len(account_events)} account change / lockout events were observed in a single upload."
                ),
                severity="high",
                risk_points=20,
            )
            alerts.append(alert)
            for e in account_events:
                self._flag(e, 3)

        return alerts

    # ------------------------------------------------------------------
    # 5. Sequence / context detection (related activity over time)
    # ------------------------------------------------------------------
    def _sequence_detection(self, events: List[LogEvent]) -> List[DetectionAlert]:
        alerts = []
        window_minutes = settings.DETECTION_SEQUENCE_WINDOW_MINUTES

        def time_diff(a: Optional[datetime], b: Optional[datetime]) -> Optional[float]:
            if not a or not b:
                return None
            return abs((a - b).total_seconds())

        # 5a. Failed logins followed by success (per IP and per user)
        for key_attr, key_events in self._group_sequence(events):
            sorted_events = key_events
            for i, event in enumerate(sorted_events):
                if event.event_type == "LOGIN_SUCCESS":
                    preceding_failures = [
                        e for e in sorted_events[:i]
                        if e.event_type in ("LOGIN_FAILED", "ACCOUNT_LOCKED")
                        and (d := time_diff(event.timestamp, e.timestamp))
                        and d <= window_minutes * 60
                    ]
                    if len(preceding_failures) >= 2:
                        alert = self._create_alert(
                            event=event,
                            rule_name="Failed Login Followed By Success",
                            description=(
                                f"A successful authentication occurred after {len(preceding_failures)} "
                                f"failed attempt(s) for '{key_attr}'. This activity may require investigation."
                            ),
                            severity="critical",
                            risk_points=30,
                        )
                        alerts.append(alert)
                        self._flag(event, 5)
                        for e in preceding_failures:
                            self._flag(e, 4)

        # 5b. Access denied followed by successful access (forbidden then granted)
        for key_attr, key_events in self._group_sequence(events):
            sorted_events = key_events
            for i, event in enumerate(sorted_events):
                if event.event_type in ("HTTP_REQUEST", "RESOURCE_ACCESS"):
                    status = self._meta(event).get("http_status")
                    preceding_denied = [
                        e for e in sorted_events[:i]
                        if e.event_type in ("ACCESS_DENIED", "FIREWALL_BLOCK")
                        or (self._meta(e).get("http_status") or 0) in (401, 403)
                        and (d := time_diff(event.timestamp, e.timestamp))
                        and d <= window_minutes * 60
                    ]
                    if status not in (401, 403) and len(preceding_denied) >= 2:
                        alert = self._create_alert(
                            event=event,
                            rule_name="Access Denied Followed By Access",
                            description=(
                                f"Access was granted after {len(preceding_denied)} denied event(s) "
                                f"for '{key_attr}'. This may indicate escalation behaviour."
                            ),
                            severity="high",
                            risk_points=24,
                        )
                        alerts.append(alert)
                        self._flag(event, 4)
                        for e in preceding_denied:
                            self._flag(e, 3)
                        break

        # 5c. Failed logins followed by sensitive resource access (same key)
        for key_attr, key_events in self._group_sequence(events):
            sorted_events = key_events
            for i, event in enumerate(sorted_events):
                if event.resource and any(kw in event.resource.lower() for kw in SENSITIVE_KEYWORDS):
                    preceding_failures = [
                        e for e in sorted_events[:i]
                        if e.event_type in ("LOGIN_FAILED", "ACCOUNT_LOCKED")
                        and (d := time_diff(event.timestamp, e.timestamp))
                        and d <= window_minutes * 60
                    ]
                    if len(preceding_failures) >= 2:
                        alert = self._create_alert(
                            event=event,
                            rule_name="Failed Logins Preceding Sensitive Access",
                            description=(
                                f"Sensitive resource '{event.resource}' was accessed after "
                                f"{len(preceding_failures)} failed authentication event(s) for '{key_attr}'."
                            ),
                            severity="critical",
                            risk_points=30,
                        )
                        alerts.append(alert)
                        self._flag(event, 5)
                        for e in preceding_failures:
                            self._flag(e, 4)
                        break

        # 5d. Firewall block followed by allow (bypass / recon followed by success)
        net_events = [e for e in events if e.source == "firewall"]
        by_ip_net: Dict[str, List[LogEvent]] = {}
        for e in net_events:
            if e.ip_address:
                by_ip_net.setdefault(e.ip_address, []).append(e)

        for ip, net_list in by_ip_net.items():
            net_list.sort(key=lambda x: x.timestamp or datetime.min)
            for i, event in enumerate(net_list):
                if event.event_type == "FIREWALL_ALLOW":
                    preceding_blocks = [
                        e for e in net_list[:i]
                        if e.event_type == "FIREWALL_BLOCK"
                        and (d := time_diff(event.timestamp, e.timestamp))
                        and d <= window_minutes * 60
                    ]
                    if len(preceding_blocks) >= 2:
                        alert = self._create_alert(
                            event=event,
                            rule_name="Firewall Bypass / Block Followed By Allow",
                            description=(
                                f"Traffic from IP '{ip}' was allowed after {len(preceding_blocks)} "
                                f"blocked connection(s)."
                            ),
                            severity="high",
                            risk_points=20,
                        )
                        alerts.append(alert)
                        self._flag(event, 4)
                        for e in preceding_blocks:
                            self._flag(e, 3)
                        break

        return alerts

    @staticmethod
    def _group_sequence(events: List[LogEvent]):
        """Yield (label, sorted_events) groups sharing an IP AND/OR username."""
        keys = set()
        for e in events:
            if e.ip_address:
                keys.add(f"ip:{e.ip_address}")
            if e.username:
                keys.add(f"user:{e.username}")
        for key in keys:
            if key.startswith("ip:"):
                value = key[3:]
                group = [e for e in events if e.ip_address == value]
            else:
                value = key[5:]
                group = [e for e in events if e.username == value]
            group.sort(key=lambda x: x.timestamp or datetime.min)
            yield key, group
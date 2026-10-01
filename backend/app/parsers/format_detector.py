import re
from typing import Optional, List, Dict


IP_REGEX = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
HTTP_METHODS = {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "TRACE", "CONNECT"}
URL_REGEX = re.compile(r'/(?:[a-zA-Z0-9._~:/?#\[\]@!$&\'()*+,;=%-]+)')
TIMESTAMP_REGEX = re.compile(
    r'\d{4}[-/]\d{2}[-/]\d{2}[T ]\d{2}:\d{2}:\d{2}'
)

# Strong, distinctive patterns used to recognise each log family.
AUTH_PATTERNS = [
    re.compile(r'\bfailed\s+password\b', re.IGNORECASE),
    re.compile(r'\baccepted\s+password\b', re.IGNORECASE),
    re.compile(r'\bauthentication\s+failure\b', re.IGNORECASE),
    re.compile(r'\binvalid\s+(?:user|password|credentials|login)\b', re.IGNORECASE),
    re.compile(r'\bfailed\s+(?:login|sign[ -]?in|authentication|auth)\b', re.IGNORECASE),
    re.compile(r'\blogin\s+(?:failed|failure)\b', re.IGNORECASE),
    re.compile(r'\bsuccessful\s+(?:login|authentication|auth)\b', re.IGNORECASE),
    re.compile(r'\blogin\s+(?:success|attempt)\b', re.IGNORECASE),
    re.compile(r'\baccount\s+locked\b', re.IGNORECASE),
    re.compile(r'\blogin:\s*failure', re.IGNORECASE),
    re.compile(r'\bsshd\b', re.IGNORECASE),
    re.compile(r'\bsudo\b', re.IGNORECASE),
    re.compile(r'\b(?:pam|system-auth|pam_unix)\(', re.IGNORECASE),
    re.compile(r'\bconnection\s+from\b.*\buser\b', re.IGNORECASE),
    re.compile(r'\bnew\s+session\b', re.IGNORECASE),
    re.compile(r'\bsession\s+(?:opened|closed|open|created|started)\b', re.IGNORECASE),
    re.compile(r'\bbad\s+packet\b.*\buser\b', re.IGNORECASE),
    re.compile(r'\bwrong\s+password\b', re.IGNORECASE),
    re.compile(r'\buser\s+(?:unknown|not\s+found|not\s+known)\b', re.IGNORECASE),
]

FIREWALL_PATTERNS = [
    re.compile(r'\b(?:blocked|denied|dropped|rejected|reject|refused)\b', re.IGNORECASE),
    re.compile(r'\bSRC=\S+\s+(?:DST|DPT)\b'),
    re.compile(r'\bIN=\w+\s+.*\bOUT=\w+', re.IGNORECASE),
    re.compile(r'\bDPT=\d+\b'),
    re.compile(r'\b(?:iptables|ufw|fail2ban|pf\.conf)\b', re.IGNORECASE),
    re.compile(r'\b(?:inbound|outbound)\b', re.IGNORECASE),
    re.compile(r'%ASA-\d-\d+', re.IGNORECASE),
    re.compile(r'\b\w+\d*\s+no\s+gateway\s+for', re.IGNORECASE),
]

WEB_PATTERNS = [
    re.compile(r'\b(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|TRACE|CONNECT)\s+/', re.IGNORECASE),
    re.compile(r'HTTP/1\.[01]'),
    re.compile(r'\[[^\]]+\+\d{4}\]'),
    re.compile(r'\b(?:apache|nginx|iis|lighttpd|caddy)\b', re.IGNORECASE),
    re.compile(r'\b(?:user-agent|referer|\bhost\b|content-type)\s*:', re.IGNORECASE),
]

SYSTEM_PATTERNS = [
    re.compile(r'\b(?:kernel|systemd|syslog|cron|cronie)\b', re.IGNORECASE),
    re.compile(r'\b(?:reboot|shutdown|boot\s+|started\s+service|stopping\s+service)\b', re.IGNORECASE),
    re.compile(r'\b(?:disk|memory|cpu|uptime)\b', re.IGNORECASE),
]


def _has_auth(line: str) -> bool:
    return any(p.search(line) for p in AUTH_PATTERNS)


def _has_firewall(line: str) -> bool:
    return any(p.search(line) for p in FIREWALL_PATTERNS)


def _has_web(line: str) -> bool:
    lower = line.lower()
    if any(p.search(line) for p in WEB_PATTERNS[:3]):
        return True
    words = line.split()
    if any(w in HTTP_METHODS for w in words):
        return True
    if re.search(r'\b(?:apache|nginx|iis)\b', lower):
        return True
    return False


def _has_system(line: str) -> bool:
    return any(p.search(line) for p in SYSTEM_PATTERNS)


def detect_log_format(line: str) -> str:
    """Classify a single log line into a parser family using distinctive patterns."""
    stripped = line.strip()
    if not stripped:
        return "generic"

    lower = stripped.lower()

    # Structured JSON or dense CSV.
    if lower.startswith("{") or lower.startswith("["):
        return "application"
    comma_count = stripped.count(",")
    if comma_count >= 3:
        # Only treat as csv if it looks like labeled fields, not prose.
        if re.search(r'(?i)(timestamp|time|level|ip|user|event)\s?[:=,]', stripped):
            return "application"

    # Strong HTTP/Apache web signatures first: they are very distinctive.
    if _has_web(stripped):
        if _has_firewall(stripped):
            return "firewall"
        return "web"

    # Strong firewall signatures (SRC=/DPT=, %ASA-, etc).
    if re.search(r'\b(?:SRC=|DST=|DPT=|SPT=|PROTO=|IN=|OUT=|%ASA-)', stripped, re.IGNORECASE):
        return "firewall"
    if _has_firewall(stripped) and has_ip(stripped):
        return "firewall"

    # Auth-related lines (Failed/Accepted password, pam, sshd, sudo, sessions...).
    if _has_auth(stripped):
        return "auth"

    # System daemon/kernel logs.
    if _has_system(stripped):
        return "system"

    # Fall back: anything with an IP + timestamp but no known family -> generic.
    return "generic"


def has_ip(line: str) -> bool:
    return bool(IP_REGEX.search(line))


def detect_batch_format(lines: List[str]) -> str:
    """Classify a whole file from a representative sample of lines."""
    if not lines:
        return "generic"

    type_counts: Dict[str, int] = {}
    sample = lines[:]
    total = len(sample)
    step = max(1, total // min(total, 50))

    for i in range(0, total, step):
        line = sample[i].strip()
        if not line:
            continue
        fmt = detect_log_format(line)
        type_counts[fmt] = type_counts.get(fmt, 0) + 1

    if not type_counts:
        return "generic"

    best_type = max(type_counts, key=type_counts.get)
    return best_type
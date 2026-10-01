import re
from typing import Optional, Dict, Any
from datetime import datetime


class BaseParser:
    TIMESTAMP_PATTERNS = [
        (re.compile(r'(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)'), '%Y-%m-%dT%H:%M:%S'),
        (re.compile(r'(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2})'), '%d/%b/%Y:%H:%M:%S'),
        (re.compile(r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})'), '%b %d %H:%M:%S'),
    ]

    IP_REGEX = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    USERNAME_PATTERNS = [
        re.compile(r'user[=:]\s*["\']?([\w.\-@]+)["\']?', re.IGNORECASE),
        re.compile(r'username[=:]\s*["\']?([\w.\-@]+)["\']?', re.IGNORECASE),
        re.compile(r'for\s+(?:invalid\s+)?user\s+([\w.\-@]+)', re.IGNORECASE),
        re.compile(r'for\s+([\w.\-@]+)\s+from\b', re.IGNORECASE),
        re.compile(r'from\s+([\w.\-@]+)\s+port\b', re.IGNORECASE),
        re.compile(r'user\s+([\w.\-@]+)', re.IGNORECASE),
        re.compile(r'session\s+(?:opened|closed|created|started)\s+for\s+user\s+([\w.\-@]+)', re.IGNORECASE),
        re.compile(r'account\s+locked\s+for\s+([\w.\-@]+)', re.IGNORECASE),
        re.compile(r'the\s+user\s+([\w.\-@]+)', re.IGNORECASE),
    ]

    def parse(self, raw_line: str) -> Optional[Dict[str, Any]]:
        raise NotImplementedError

    def extract_timestamp(self, raw: str) -> Optional[datetime]:
        for pattern, fmt in self.TIMESTAMP_PATTERNS:
            match = pattern.search(raw)
            if match:
                try:
                    ts_str = match.group(1)
                    if ts_str.endswith("Z"):
                        ts_str = ts_str[:-1] + "+00:00"
                    if "+" in ts_str[10:] or "-" in ts_str[10:]:
                        normalized = ts_str.replace(" ", "T")
                        return datetime.fromisoformat(normalized)
                    # The first pattern permits either a space or a literal 'T'
                    # between the date and the time; normalise to 'T' so
                    # strptime can parse both variants.
                    normalized = ts_str.replace(" ", "T")
                    return datetime.strptime(normalized, fmt)
                except (ValueError, IndexError):
                    continue
        return None

    def extract_ip(self, raw: str) -> Optional[str]:
        match = self.IP_REGEX.search(raw)
        return match.group(0) if match else None

    def extract_username(self, raw: str) -> Optional[str]:
        for pattern in self.USERNAME_PATTERNS:
            match = pattern.search(raw)
            if match:
                return match.group(1)
        return None

    def extract_hostname(self, raw: str) -> Optional[str]:
        parts = raw.split()
        if parts:
            first = parts[0].rstrip(":")
            if self.IP_REGEX.match(first):
                return None
            if "." in first and not first.startswith("["):
                return first
        return None

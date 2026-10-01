import re
from typing import Optional, Dict, Any
from datetime import datetime
from app.parsers.base_parser import BaseParser


class AuthParser(BaseParser):
    FAILED_LOGIN_RE = re.compile(
        r'(?:failed\s+(?:login|authentication|auth|sign[ -]?in|password)|'
        r'password\s+(?:check|verification)\s+fail|'
        r'authentication\s+failure|'
        r'login\s*[: ]\s*failure|'
        r'(?:login|auth)\s+attempt\s+failed|'
        r'bad\s+(?:login|password|credentials)|'
        r'unauthorized\s+(?:login|access)|'
        r'too\s+many\s+authentication\s+failures|'
        r'\bfailure[s]?\b.*\b(user|login|password)\b)', re.IGNORECASE
    )
    FAILED_PASSWORD_RE = re.compile(
        r'(?:failed\s+(?:login|authentication|auth)\s+attempt|'
        r'login\s+attempt\s+failed|'
        r'authentication\s+failure|'
        r'invalid\s+(?:password|credentials|username|user))', re.IGNORECASE
    )
    SUCCESS_LOGIN_RE = re.compile(
        r'(?:successful\s+(?:login|authentication|auth|sign[ -]?in)|'
        r'accepted\s+(?:password|publickey|keyboard-interactive|pam)|'
        r'login\s+(?:succeeded|successful|accepted)|'
        r'attempt\s+succeed|'
        r'authentication\s+succeeded)', re.IGNORECASE
    )
    INVALID_RE = re.compile(
        r'(?:invalid\s+(?:password|credentials|user|username|login))', re.IGNORECASE
    )
    LOCKED_RE = re.compile(r'(?:account\s+locked|account\s+lockout|too\s+many\s+failed)', re.IGNORECASE)
    PRIV_RE = re.compile(
        r'(?:privilege\s+(?:change|escalat|escalation)|'
        r'(?:sudo|su\s+-?)\b|root\s+login\s+for|'
        r'permission\s+granted\s+to|added\s+to\s+group|'
        r'role\s+change|setuid|became\s+root|become\s+root)', re.IGNORECASE
    )
    SESSION_RE = re.compile(r'session\s+(?:started|ended|created|closed|opened)', re.IGNORECASE)
    SSH_CONNECT_RE = re.compile(r'(?:connection\s+(?:from|closed|reset|opened)|accepting\s+connection)', re.IGNORECASE)
    ACCOUNT_RE = re.compile(
        r'(?:user\s+(?:created|added|deleted|changed|removed)|'
        r'account\s+(?:created|added|deleted|disabled|enabled|changed|unlocked))', re.IGNORECASE
    )

    def parse(self, raw_line: str) -> Optional[Dict[str, Any]]:
        if not raw_line.strip():
            return None

        raw = raw_line.strip()
        lower = raw.lower()

        event_type = "UNKNOWN"
        severity = "low"
        resource = None

        if self.FAILED_LOGIN_RE.search(raw) or self.FAILED_PASSWORD_RE.search(raw):
            event_type = "LOGIN_FAILED"
            severity = "medium"
        elif self.SUCCESS_LOGIN_RE.search(raw):
            event_type = "LOGIN_SUCCESS"
            severity = "low"
        elif self.LOCKED_RE.search(raw):
            event_type = "ACCOUNT_LOCKED"
            severity = "high"
        elif self.ACCOUNT_RE.search(raw):
            event_type = "ACCOUNT_CHANGE"
            severity = "medium"
        elif self.PRIV_RE.search(raw):
            event_type = "PRIVILEGE_CHANGE"
            severity = "high"
        elif self.SESSION_RE.search(raw):
            if "started" in lower or "opened" in lower or "created" in lower:
                event_type = "SESSION_START"
            else:
                event_type = "SESSION_END"
            severity = "low"
        elif self.SSH_CONNECT_RE.search(raw):
            event_type = "SSH_CONNECTION"
            severity = "low"

        ip = self.extract_ip(raw)
        username = self.extract_username(raw)

        # sshd style: "Failed password for root from 203.0.113.7 port 22"
        if re.search(r'\bfailed\s+password\s+for\b', raw, re.IGNORECASE):
            event_type = "LOGIN_FAILED"
            severity = "medium"
        # sshd style: "Accepted password for root from ..."
        if re.search(r'\baccepted\s+password\s+for\b', raw, re.IGNORECASE):
            event_type = "LOGIN_SUCCESS"
            severity = "low"

        return {
            "timestamp": self.extract_timestamp(raw),
            "ip_address": ip,
            "username": username,
            "hostname": self.extract_hostname(raw),
            "source": "authentication",
            "event_type": event_type,
            "severity": severity,
            "resource": resource,
            "raw_message": raw,
        }
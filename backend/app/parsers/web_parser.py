import re
from urllib.parse import unquote
from typing import Optional, Dict, Any
from datetime import datetime
from app.parsers.base_parser import BaseParser


class WebParser(BaseParser):
    HTTP_METHOD_RE = re.compile(r'\b(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|TRACE)\b')
    HTTP_STATUS_RE = re.compile(r'\b([1-5]\d{2})\b')
    URL_RE = re.compile(r'\b(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|TRACE)\s+(/[^"\s]*)', re.IGNORECASE)
    APACHE_TS_RE = re.compile(r'\[(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2})\s')
    USER_AGENT_RE = re.compile(r'"([^"]{3,})"\s*\Z', re.IGNORECASE)
    SYSTEM_USER_RE = re.compile(r'^\S+\s+\S+\s+(\S+)\s+\[', re.IGNORECASE)

    def parse(self, raw_line: str) -> Optional[Dict[str, Any]]:
        if not raw_line.strip():
            return None

        raw = raw_line.strip()
        event_type = "HTTP_REQUEST"
        severity = "low"
        resource = None
        metadata = {}

        method_match = self.HTTP_METHOD_RE.search(raw)
        method = method_match.group(1) if method_match else None

        # Prefer the apache/nginx style timestamp: [15/Jan/2024:10:00:01 +0000]
        ts = None
        ts_match = self.APACHE_TS_RE.search(raw)
        if ts_match:
            try:
                ts = datetime.strptime(ts_match.group(1), "%d/%b/%Y:%H:%M:%S")
            except ValueError:
                ts = self.extract_timestamp(raw)
        else:
            ts = self.extract_timestamp(raw)

        status = None
        # In combined/access log format the status appears right after the
        # closing quote of the request line (e.g. `"GET /x HTTP/1.1" 200 123`).
        status_match = re.search(r'"\s*([1-5]\d{2})', raw)
        if status_match:
            status = int(status_match.group(1))
        else:
            fallback = self.HTTP_STATUS_RE.search(raw)
            if fallback:
                status = int(fallback.group(1))

        url_match = self.URL_RE.search(raw)
        if url_match:
            resource = url_match.group(1)
            try:
                decoded = unquote(resource)
            except Exception:
                decoded = resource
            metadata["decoded_url"] = decoded[:500]

        if status:
            if status >= 500:
                severity = "medium"
                event_type = "HTTP_ERROR"
            elif status == 403:
                severity = "medium"
                event_type = "ACCESS_DENIED"
            elif status == 401:
                severity = "medium"
                event_type = "ACCESS_DENIED"
            elif status == 404:
                severity = "low"
                event_type = "HTTP_REQUEST"
            else:
                severity = "low"

        if method == "DELETE" or method == "PUT":
            if severity == "low":
                severity = "medium"

        if method:
            metadata["http_method"] = method
        if status:
            metadata["http_status"] = status

        # Apache auth user field: 192.168.1.50 - admin [15/Jan...]
        user_match = self.SYSTEM_USER_RE.search(raw)
        username = self.extract_username(raw)
        if user_match and user_match.group(1) != "-":
            username = user_match.group(1)
        if username:
            metadata["username"] = username

        ua_match = self.USER_AGENT_RE.search(raw)
        if ua_match:
            ua = ua_match.group(1)
            lower_ua = ua.lower()
            if (
                lower_ua
                and not lower_ua.startswith(("get ", "post ", "put ",
                                             "delete ", "patch ", "head ",
                                             "options ", "trace ", "http/"))
            ):
                metadata["user_agent"] = ua[:200]

        return {
            "timestamp": ts,
            "ip_address": self.extract_ip(raw),
            "username": username,
            "hostname": self.extract_hostname(raw),
            "source": "web_server",
            "event_type": event_type,
            "severity": severity,
            "resource": resource,
            "raw_message": raw,
            "metadata": metadata,
        }
import re
import csv
import io
from typing import Optional, Dict, Any, List
from datetime import datetime
from app.parsers.base_parser import BaseParser


class GenericParser(BaseParser):
    SEVERITY_RE = re.compile(
        r'\b(error|critical|fatal|fail|failed|failure|denied|blocked|rejected|'
        r'unauthorized|intrusi\w*|malware|virus|attack|exploit|breached|compromised)\b',
        re.IGNORECASE,
    )
    HIGH_SEVERITY_RE = re.compile(
        r'\b(critical|fatal|catastroph\w*|intrusion|malware|virus|exploit|breach\w*|compromis\w*)\b',
        re.IGNORECASE,
    )

    def parse(self, raw_line: str) -> Optional[Dict[str, Any]]:
        if not raw_line.strip():
            return None

        raw = raw_line.strip()
        event_type = "GENERIC"
        severity = "low"

        if self.HIGH_SEVERITY_RE.search(raw):
            severity = "high"
            event_type = "GENERIC_ERROR"
        elif self.SEVERITY_RE.search(raw):
            severity = "medium"
            event_type = "GENERIC_ERROR"

        return {
            "timestamp": self.extract_timestamp(raw),
            "ip_address": self.extract_ip(raw),
            "username": self.extract_username(raw),
            "hostname": self.extract_hostname(raw),
            "source": "generic",
            "event_type": event_type,
            "severity": severity,
            "resource": None,
            "raw_message": raw,
        }

    def parse_csv(self, content: str) -> List[Dict[str, Any]]:
        results = []
        try:
            reader = csv.DictReader(io.StringIO(content))
            for row in reader:
                row_lower = {k.lower(): v for k, v in row.items() if v}
                entry = {
                    "timestamp": None,
                    "ip_address": None,
                    "username": None,
                    "hostname": None,
                    "source": "csv_import",
                    "event_type": "CSV_RECORD",
                    "severity": "low",
                    "resource": None,
                    "raw_message": str(row),
                    "metadata": {k: v for k, v in row.items()},
                }

                for key in ("timestamp", "time", "date", "datetime", "@timestamp"):
                    if key in row_lower:
                        try:
                            entry["timestamp"] = datetime.fromisoformat(row_lower[key])
                        except (ValueError, TypeError):
                            pass
                        break

                for key in ("ip", "ip_address", "src_ip", "source_ip", "client_ip"):
                    if key in row_lower:
                        entry["ip_address"] = row_lower[key]
                        break

                for key in ("user", "username", "user_name", "account"):
                    if key in row_lower:
                        entry["username"] = row_lower[key]
                        break

                for key in ("level", "severity", "priority"):
                    if key in row_lower:
                        val = row_lower[key].lower()
                        if val in ("error", "critical", "fatal", "high"):
                            entry["severity"] = "high"
                            entry["event_type"] = "CSV_ERROR"
                        elif val in ("warning", "warn", "medium"):
                            entry["severity"] = "medium"
                        break

                results.append(entry)
        except Exception:
            pass
        return results

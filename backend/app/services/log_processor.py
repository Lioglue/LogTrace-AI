import json
import logging
from collections import Counter
from datetime import datetime
from typing import List, Dict, Any, Optional
from sqlalchemy.orm import Session
from app.models.log_file import LogFile
from app.models.log_event import LogEvent
from app.parsers.format_detector import detect_batch_format, detect_log_format
from app.parsers import PARSERS
from app.detection.engine import DetectionEngine
from app.correlation.engine import CorrelationEngine
from app.incident.engine import IncidentEngine
from app.story.generator import StoryGenerator

logger = logging.getLogger("logtrace")


class LogProcessor:
    def __init__(self, db: Session):
        self.db = db

    def process_upload(self, log_file: LogFile, content: str, source_type: str = "auto") -> Dict[str, Any]:
        try:
            log_file.processing_status = "processing"
            self.db.commit()

            lines = [line for line in content.splitlines() if line.strip()]

            if not lines:
                log_file.lines_total = 0
                log_file.lines_parsed = 0
                log_file.lines_skipped = 0
                log_file.detected_format = "generic"
                log_file.processing_notes = "File contained no non-empty lines; 0 events extracted."
                log_file.processing_status = "completed"
                log_file.event_count = 0
                log_file.suspicious_count = 0
                self.db.commit()
                return {
                    "status": "completed",
                    "events": 0,
                    "suspicious": 0,
                    "warnings": [log_file.processing_notes],
                }

            detected_format = source_type
            if source_type == "auto":
                detected_format = detect_batch_format(lines)

            fallback_format = "generic" if source_type == "auto" else source_type

            log_file.lines_total = len(lines)
            log_file.detected_format = detected_format

            events: List[Dict[str, Any]] = []
            skipped = 0
            format_counter: Counter[str] = Counter()
            skip_reasons: Counter[str] = Counter()
            example_skip_line: Optional[str] = None

            # CSV files (either explicitly identified or strongly comma-delimited)
            # are parsed structurally so column semantics survive.
            csv_mode = False
            if source_type == "generic":
                csv_mode = sum(1 for l in lines if l.count(",") >= 3) >= 2
                if csv_mode:
                    detected_format = "application"
            elif detected_format == "application" and len(lines) > 1:
                csv_mode = sum(1 for l in lines if l.count(",") >= 3) >= max(2, len(lines) // 2)

            if csv_mode:
                csv_events = PARSERS["generic"].parse_csv(content)
                if csv_events:
                    for evt in csv_events:
                        evt["log_file_id"] = log_file.id
                        if isinstance(evt.get("metadata"), dict):
                            evt["metadata_json"] = json.dumps(evt["metadata"], default=str)
                        else:
                            evt["metadata_json"] = json.dumps({})
                        evt.pop("metadata", None)
                        if evt.get("timestamp") is None:
                            evt["timestamp"] = datetime.utcnow()
                    events = csv_events
                    format_counter["application"] += len(csv_events)
                    log_file.lines_skipped = max(0, len(lines) - len(csv_events))
                else:
                    log_file.lines_skipped = len(lines)
                    log_file.processing_notes = "File appeared to be CSV but no rows could be parsed."
                    self.db.commit()
                    return {
                        "status": "completed",
                        "events": 0,
                        "suspicious": 0,
                        "alerts": 0,
                        "incidents": 0,
                        "stories": 0,
                        "skipped": log_file.lines_skipped,
                        "detected_format": detected_format,
                        "warnings": [log_file.processing_notes],
                    }

            if not csv_mode:
                for line in lines:
                    line = line.strip()

                    # Per-line format routing: mixed files are analysed correctly
                    # instead of being forced through a single parser.
                    fmt = detect_log_format(line)
                    if fmt == "generic":
                        fmt = fallback_format
                    format_counter[fmt] += 1

                    parser = PARSERS.get(fmt) or PARSERS["generic"]
                    try:
                        parsed = parser.parse(line)
                    except Exception as e:
                        skipped += 1
                        reason = f"unparsable ({fmt}): {type(e).__name__}"
                        skip_reasons[reason] += 1
                        if example_skip_line is None:
                            example_skip_line = line[:200]
                        continue

                    if parsed is None:
                        skipped += 1
                        reason = f"uninterpretable as {fmt}"
                        skip_reasons[reason] += 1
                        if example_skip_line is None:
                            example_skip_line = line[:200]
                        continue

                    parsed["log_file_id"] = log_file.id
                    if isinstance(parsed.get("metadata"), dict):
                        parsed["metadata_json"] = json.dumps(parsed["metadata"], default=str)
                    else:
                        parsed["metadata_json"] = json.dumps({})
                    parsed.pop("metadata", None)

                    if parsed.get("timestamp") is None:
                        parsed["timestamp"] = datetime.utcnow()

                    events.append(parsed)

            log_file.lines_parsed = len(events)
            log_file.lines_skipped = len(lines) - len(events)

            db_events = []
            for evt_data in events:
                db_event = LogEvent(
                    log_file_id=evt_data.get("log_file_id"),
                    timestamp=evt_data.get("timestamp"),
                    source=evt_data.get("source", "unknown"),
                    event_type=evt_data.get("event_type", "UNKNOWN"),
                    ip_address=evt_data.get("ip_address"),
                    username=evt_data.get("username"),
                    hostname=evt_data.get("hostname"),
                    resource=evt_data.get("resource"),
                    severity=evt_data.get("severity", "low"),
                    raw_message=evt_data.get("raw_message", ""),
                    metadata_json=evt_data.get("metadata_json", "{}"),
                )
                self.db.add(db_event)
                db_events.append(db_event)

            self.db.flush()

            detection = DetectionEngine(self.db)
            alerts = detection.run(db_events)

            log_file.event_count = len(db_events)
            log_file.suspicious_count = sum(1 for e in db_events if e.is_suspicious)

            correlation = CorrelationEngine(self.db)
            correlated_groups = correlation.correlate(db_events)

            incident_engine = IncidentEngine(self.db)
            incidents = incident_engine.cluster_incidents(db_events, correlated_groups)

            risk_scores = incident_engine.calculate_risk_scores(incidents)

            story_gen = StoryGenerator(self.db)
            stories = story_gen.generate(incidents)

            log_file.processing_status = "completed"
            warnings = self._build_warnings(
                lines=lines,
                format_counter=format_counter,
                skip_reasons=skip_reasons,
                example_skip_line=example_skip_line,
                events=db_events,
                alerts=alerts,
                incidents=incidents,
            )
            log_file.processing_notes = "; ".join(warnings) if warnings else ""
            self.db.commit()

            logger.info(
                "Processed '%s': %d lines, %d events parsed, %d skipped, %d suspicious, %d alerts, %d incidents.",
                log_file.filename, log_file.lines_total, log_file.event_count,
                log_file.lines_skipped, log_file.suspicious_count, len(alerts), len(incidents),
            )

            return {
                "status": "completed",
                "events": len(db_events),
                "suspicious": log_file.suspicious_count,
                "alerts": len(alerts),
                "incidents": len(incidents),
                "stories": len(stories),
                "skipped": log_file.lines_skipped,
                "detected_format": log_file.detected_format,
                "warnings": warnings,
            }

        except Exception as e:
            logger.exception("Failed to process upload: %s", e)
            log_file.processing_status = "failed"
            self.db.commit()
            return {"status": "failed", "error": str(e)}

    @staticmethod
    def _build_warnings(
        lines: List[str],
        format_counter: Counter[str],
        skip_reasons: Counter[str],
        example_skip_line: Optional[str],
        events: List[LogEvent],
        alerts: List,
        incidents: List,
    ) -> List[str]:
        warnings: List[str] = []

        if skip_reasons:
            top_reasons = skip_reasons.most_common(5)
            reasons = ", ".join(f"{r} ({c} lines)" for r, c in top_reasons)
            sample = example_skip_line or ""
            if sample:
                warnings.append(f"{sum(skip_reasons.values())} line(s) could not be parsed ({reasons}) — e.g. \"{sample[:120]}\"")
            else:
                warnings.append(f"{sum(skip_reasons.values())} line(s) could not be parsed ({reasons})")

        if not events and lines:
            warnings.append(
                "No events were extracted from the log. The file may use an unsupported "
                "format, or every line failed to parse. Try selecting a specific Source Type "
                "(e.g. Authentication, Web Server, Firewall) to improve parsing."
            )
        elif events:
            generic_count = sum(v for k, v in format_counter.items() if k == "generic")
            if generic_count:
                warnings.append(
                    f"{generic_count} line(s) were classified as 'generic' and might contain "
                    "missed signals; consider selecting a specific Source Type."
                )

        if events and not any(e.is_suspicious for e in events):
            try:
                suspicious_keywords = ("failed", "fail", "error", "denied", "blocked", "attack")
                suspicious_lines = sum(
                    1 for e in events if any(kw in (e.raw_message or "").lower() for kw in suspicious_keywords)
                )
                if suspicious_lines:
                    warnings.append(
                        f"{suspicious_lines} event(s) referenced suspicious activity (failed/error/denied/blocked) "
                        "but no alert rules were triggered. Review the Detection settings."
                    )
            except Exception:
                pass

        return warnings
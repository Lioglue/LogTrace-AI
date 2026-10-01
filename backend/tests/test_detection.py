import pytest
from datetime import datetime, timedelta
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.database.connection import Base
from app.models.log_event import LogEvent
from app.models.detection_alert import DetectionAlert
from app.detection.engine import DetectionEngine


@pytest.fixture
def db_session():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    yield session
    session.close()


def _create_event(db, **kwargs):
    defaults = {
        "source": "auth",
        "event_type": "GENERIC",
        "severity": "low",
        "raw_message": "test",
    }
    defaults.update(kwargs)
    event = LogEvent(**defaults)
    db.add(event)
    db.commit()
    db.refresh(event)
    return event


class TestIndividualDetection:
    def test_high_severity_detection(self, db_session):
        event = _create_event(
            db=db_session,
            event_type="APP_ERROR",
            severity="high",
            raw_message="Critical error in application",
        )
        engine = DetectionEngine(db_session)
        alerts = engine._individual_detection([event])
        assert len(alerts) >= 1
        assert any(a.rule_name == "High Severity Event" for a in alerts)

    def test_privilege_change_detection(self, db_session):
        event = _create_event(
            db=db_session,
            event_type="PRIVILEGE_CHANGE",
            severity="high",
            username="admin",
        )
        engine = DetectionEngine(db_session)
        alerts = engine._individual_detection([event])
        assert len(alerts) >= 1
        assert any(a.rule_name == "Privilege Change Detected" for a in alerts)

    def test_sensitive_resource_detection(self, db_session):
        event = _create_event(
            db=db_session,
            event_type="HTTP_REQUEST",
            severity="medium",
            resource="/admin/dashboard",
        )
        engine = DetectionEngine(db_session)
        alerts = engine._individual_detection([event])
        assert len(alerts) >= 1
        assert any(a.rule_name == "Sensitive Resource Access" for a in alerts)


class TestThresholdDetection:
    def test_repeated_failed_logins(self, db_session):
        now = datetime.utcnow()
        for i in range(6):
            _create_event(
                db=db_session,
                event_type="LOGIN_FAILED",
                severity="medium",
                ip_address="192.168.1.100",
                timestamp=now + timedelta(seconds=i * 30),
            )
        engine = DetectionEngine(db_session)
        events = db_session.query(LogEvent).all()
        alerts = engine._threshold_detection(events)
        assert len(alerts) >= 1
        assert any(a.rule_name == "Repeated Authentication Failures" for a in alerts)


class TestSequenceDetection:
    def test_failed_then_success(self, db_session):
        now = datetime.utcnow()
        for i in range(4):
            _create_event(
                db=db_session,
                event_type="LOGIN_FAILED",
                severity="medium",
                ip_address="203.0.113.42",
                timestamp=now + timedelta(minutes=i),
            )
        _create_event(
            db=db_session,
            event_type="LOGIN_SUCCESS",
            severity="low",
            ip_address="203.0.113.42",
            timestamp=now + timedelta(minutes=5),
        )
        engine = DetectionEngine(db_session)
        events = db_session.query(LogEvent).all()
        alerts = engine._sequence_detection(events)
        assert len(alerts) >= 1
        assert any(a.rule_name == "Failed Login Followed By Success" for a in alerts)


class TestAttackPatternDetection:
    def _run(self, db_session, events):
        engine = DetectionEngine(db_session)
        return engine._attack_pattern_detection(events), engine._dedupe(db_session.query(DetectionAlert).all())

    def test_sql_injection_detected(self, db_session):
        event = _create_event(
            db=db_session,
            event_type="HTTP_REQUEST",
            severity="medium",
            ip_address="198.51.100.7",
            raw_message='192.168.1.1 - - [15/Jan/2024:10:00:01 +0000] "GET /login.php?id=1%27%20OR%201%3D1-- HTTP/1.1" 401 4321',
            metadata_json='{"decoded_url": "/login.php?id=1%27%20OR%201%3D1--"}',
        )
        alerts, _ = self._run(db_session, [event])
        assert any(a.rule_name == "SQL Injection Attempt" for a in alerts)
        db_session.refresh(event)
        assert event.is_suspicious == 1

    def test_xss_detected(self, db_session):
        event = _create_event(
            db=db_session,
            event_type="HTTP_REQUEST",
            severity="medium",
            ip_address="198.51.100.7",
            raw_message='1.2.3.4 - - [15/Jan/2024:10:00:01 +0000] "GET /search?q=%3Cscript%3Ealert(1)%3C/script%3E HTTP/1.1" 200 123',
        )
        alerts, _ = self._run(db_session, [event])
        assert any(a.rule_name == "Cross-Site Scripting (XSS)" for a in alerts)

    def test_traversal_detected(self, db_session):
        event = _create_event(
            db=db_session,
            event_type="HTTP_REQUEST",
            severity="medium",
            ip_address="198.51.100.7",
            raw_message='5.6.7.8 - - [15/Jan/2024:10:00:01 +0000] "GET /../../../../etc/passwd HTTP/1.1" 404 0',
        )
        alerts, _ = self._run(db_session, [event])
        assert any(a.rule_name == "Path Traversal Attempt" for a in alerts)

    def test_command_injection_detected(self, db_session):
        event = _create_event(
            db=db_session,
            event_type="HTTP_REQUEST",
            severity="medium",
            ip_address="198.51.100.7",
            raw_message='9.9.9.9 - - [15/Jan/2024:10:00:01 +0000] "GET /ping?host=1.2.3.4;whoami HTTP/1.1" 200 123',
        )
        alerts, _ = self._run(db_session, [event])
        assert any(a.rule_name == "Command Injection Attempt" for a in alerts)

    def test_malware_indicator_detected(self, db_session):
        event = _create_event(
            db=db_session,
            event_type="SYSTEM_EVENT",
            severity="low",
            raw_message="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand SQBuAHYAbwBrAGUALQBIAGUAbABsAG8A",
        )
        alerts, _ = self._run(db_session, [event])
        assert any(a.rule_name == "Malware / Obfuscation Indicators" for a in alerts)

    def test_credential_file_access_detected(self, db_session):
        event = _create_event(
            db=db_session,
            event_type="HTTP_REQUEST",
            severity="medium",
            ip_address="198.51.100.7",
            resource="/.aws/credentials",
            raw_message='GET /.aws/credentials',
        )
        alerts, _ = self._run(db_session, [event])
        assert any(a.rule_name == "Credential Access Attempt" for a in alerts)

    def test_scanning_signature_detected(self, db_session):
        event = _create_event(
            db=db_session,
            event_type="HTTP_REQUEST",
            severity="low",
            ip_address="198.51.100.7",
            raw_message='1.2.3.4 - - [15/Jan/2024:10:00:01 +0000] "GET /admin/wplogin.php HTTP/1.1" 404 0',
        )
        alerts, _ = self._run(db_session, [event])
        assert any(a.rule_name == "Web Probing / Scanning Signature" for a in alerts)

    def test_normal_events_not_flagged(self, db_session):
        events = [
            _create_event(
                db=db_session,
                event_type="HTTP_REQUEST",
                severity="low",
                ip_address="10.0.0.5",
                raw_message='10.0.0.5 - - [15/Jan/2024:10:00:01 +0000] "GET /dashboard HTTP/1.1" 200 1234',
            ),
            _create_event(
                db=db_session,
                event_type="LOGIN_SUCCESS",
                severity="low",
                ip_address="10.0.0.5",
                username="jdoe",
                raw_message="Successful login user=jdoe from 10.0.0.5",
            ),
        ]
        alerts, _ = self._run(db_session, events)
        assert alerts == []


class TestBehavioralDetection:
    def test_password_spraying(self, db_session):
        now = datetime.utcnow()
        for i, username in enumerate(["alice", "bob", "carol", "dave"]):
            _create_event(
                db=db_session,
                event_type="LOGIN_FAILED",
                severity="medium",
                ip_address="203.0.113.9",
                username=username,
                timestamp=now + timedelta(seconds=i * 5),
            )
        engine = DetectionEngine(db_session)
        events = db_session.query(LogEvent).all()
        alerts = engine._behavioral_detection(events)
        assert any(a.rule_name == "Possible Password Spraying" for a in alerts)

    def test_distributed_brute_force(self, db_session):
        now = datetime.utcnow()
        for i, ip in enumerate(["203.0.113.1", "203.0.113.2", "203.0.113.3"]):
            _create_event(
                db=db_session,
                event_type="LOGIN_FAILED",
                severity="medium",
                ip_address=ip,
                username="admin",
                timestamp=now + timedelta(seconds=i * 5),
            )
        engine = DetectionEngine(db_session)
        events = db_session.query(LogEvent).all()
        alerts = engine._behavioral_detection(events)
        assert any(a.rule_name == "Possible Distributed Brute Force" for a in alerts)

    def test_port_scan(self, db_session):
        now = datetime.utcnow()
        for i, port in enumerate([22, 23, 25, 80, 443, 3306, 3389, 8080, 6379, 1]):
            _create_event(
                db=db_session,
                event_type="FIREWALL_BLOCK",
                severity="medium",
                ip_address="203.0.113.55",
                source="firewall",
                resource=f"port:{port}",
                raw_message=f"BLOCKED SRC=203.0.113.55 DST=10.0.0.1 DPT={port} PROTO=TCP",
                timestamp=now + timedelta(seconds=i),
            )
        engine = DetectionEngine(db_session)
        events = db_session.query(LogEvent).all()
        alerts = engine._behavioral_detection(events)
        assert any(a.rule_name == "Possible Port Scan" for a in alerts)

    def test_web_scanning_scenario(self, db_session):
        now = datetime.utcnow()
        paths = [
            "/robots.txt", "/wp-login.php", "/admin", "/../..", "/.env",
            "/phpmyadmin", "/xmlrpc.php", "/config.php", "/install.php",
            "/setup.php", "/readme.html", "/backup.zip", "/db/dump.sql",
            "/tmp/test.php", "/cgi-bin/test.cgi", "/actuator/env",
        ]
        for i, path in enumerate(paths):
            _create_event(
                db=db_session,
                event_type="HTTP_REQUEST",
                severity="low",
                ip_address="198.51.100.200",
                source="web_server",
                resource=path,
                raw_message=f'GET {path} HTTP/1.1" 404 0',
                metadata_json='{"http_status": 404}',
                timestamp=now + timedelta(seconds=i * 10),
            )
        engine = DetectionEngine(db_session)
        events = db_session.query(LogEvent).all()
        alerts = engine._behavioral_detection(events)
        assert any(a.rule_name == "Possible Web Scanning" for a in alerts)


class TestSequenceEscalation:
    def test_failed_then_sensitive_access(self, db_session):
        now = datetime.utcnow()
        for i in range(3):
            _create_event(
                db=db_session,
                event_type="LOGIN_FAILED",
                severity="medium",
                ip_address="203.0.113.77",
                username="admin",
                timestamp=now + timedelta(minutes=i),
            )
        _create_event(
            db=db_session,
            event_type="HTTP_REQUEST",
            severity="low",
            ip_address="203.0.113.77",
            username="admin",
            resource="/admin/database",
            timestamp=now + timedelta(minutes=6),
        )
        engine = DetectionEngine(db_session)
        events = db_session.query(LogEvent).all()
        alerts = engine._sequence_detection(events)
        assert any(a.rule_name == "Failed Logins Preceding Sensitive Access" for a in alerts)


class TestNormalActivityNotFlagged:
    def test_clean_network_traffic(self, db_session):
        now = datetime.utcnow()
        for i in range(3):
            _create_event(
                db=db_session,
                event_type="FIREWALL_ALLOW",
                severity="low",
                ip_address="192.168.1.10",
                source="firewall",
                resource="port:443",
                raw_message="ALLOWED SRC=192.168.1.10 DST=10.0.0.5 DPT=443 PROTO=TCP",
                timestamp=now + timedelta(minutes=i * 2),
            )
        engine = DetectionEngine(db_session)
        events = db_session.query(LogEvent).all()
        alerts = engine.run(events)
        assert alerts == []

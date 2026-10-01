import pytest
import json
from datetime import datetime, timedelta
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.database.connection import Base
from app.models.log_event import LogEvent
from app.models.log_file import LogFile
from app.models.detection_alert import DetectionAlert
from app.models.incident import Incident, IncidentEvent
from app.models.attack_story import AttackStory, AttackStoryEntry
from app.services.log_processor import LogProcessor


@pytest.fixture
def db_session():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    yield session
    session.close()


class TestFullPipeline:
    def test_auth_log_processing(self, db_session):
        from app.models.user import User
        user = User(username="testuser", email="test@test.com", password_hash="hashed")
        db_session.add(user)
        db_session.commit()
        db_session.refresh(user)

        log_file = LogFile(user_id=user.id, filename="test.log", source_type="auth")
        db_session.add(log_file)
        db_session.commit()
        db_session.refresh(log_file)

        log_content = "\n".join([
            "2024-01-15 14:00:01 auth-server Failed login attempt user=admin from 198.51.100.23",
            "2024-01-15 14:00:02 auth-server Failed login attempt user=admin from 198.51.100.23",
            "2024-01-15 14:00:03 auth-server Failed login attempt user=admin from 198.51.100.23",
            "2024-01-15 14:00:04 auth-server Failed login attempt user=admin from 198.51.100.23",
            "2024-01-15 14:00:05 auth-server Failed login attempt user=admin from 198.51.100.23",
            "2024-01-15 14:00:06 auth-server Successful login user=admin from 198.51.100.23",
        ])

        processor = LogProcessor(db_session)
        result = processor.process_upload(log_file, log_content, "auth")

        assert result["status"] == "completed"
        assert result["events"] == 6
        assert result["suspicious"] > 0

        events = db_session.query(LogEvent).all()
        assert len(events) == 6
        assert any(e.event_type == "LOGIN_FAILED" for e in events)
        assert any(e.event_type == "LOGIN_SUCCESS" for e in events)

        alerts = db_session.query(DetectionAlert).all()
        assert len(alerts) > 0

    def test_web_log_processing(self, db_session):
        from app.models.user import User
        user = User(username="testuser2", email="test2@test.com", password_hash="hashed")
        db_session.add(user)
        db_session.commit()
        db_session.refresh(user)

        log_file = LogFile(user_id=user.id, filename="access.log", source_type="web")
        db_session.add(log_file)
        db_session.commit()
        db_session.refresh(log_file)

        log_content = "\n".join([
            '192.168.1.1 - - [15/Jan/2024:10:00:01 +0000] "GET /dashboard HTTP/1.1" 200 1234',
            '192.168.1.1 - - [15/Jan/2024:10:00:02 +0000] "GET /admin HTTP/1.1" 403 0',
            '192.168.1.1 - - [15/Jan/2024:10:00:03 +0000] "POST /login HTTP/1.1" 200 567',
        ])

        processor = LogProcessor(db_session)
        result = processor.process_upload(log_file, log_content, "web")

        assert result["status"] == "completed"
        assert result["events"] == 3

    def test_risk_score_calculation(self, db_session):
        incident = Incident(
            title="Test Incident",
            description="Test",
            severity="medium",
            status="open",
        )
        db_session.add(incident)
        db_session.commit()
        db_session.refresh(incident)

        now = datetime.utcnow()
        e1 = LogEvent(
            event_type="LOGIN_FAILED", severity="high",
            ip_address="1.2.3.4", username="admin",
            raw_message="Failed login", timestamp=now,
        )
        e2 = LogEvent(
            event_type="LOGIN_SUCCESS", severity="low",
            ip_address="1.2.3.4", username="admin",
            raw_message="Successful login", timestamp=now + timedelta(minutes=1),
        )
        e3 = LogEvent(
            event_type="RESOURCE_ACCESS", severity="high",
            ip_address="1.2.3.4", username="admin",
            resource="/admin/database", raw_message="Access database",
            timestamp=now + timedelta(minutes=2),
        )
        db_session.add_all([e1, e2, e3])
        db_session.commit()
        db_session.refresh(e1)
        db_session.refresh(e2)
        db_session.refresh(e3)

        ie1 = IncidentEvent(incident_id=incident.id, event_id=e1.id, correlation_score=80, correlation_reasons="['Same IP']")
        ie2 = IncidentEvent(incident_id=incident.id, event_id=e2.id, correlation_score=90, correlation_reasons="['Same IP']")
        ie3 = IncidentEvent(incident_id=incident.id, event_id=e3.id, correlation_score=85, correlation_reasons="['Same IP']")
        db_session.add_all([ie1, ie2, ie3])
        db_session.commit()

        from app.incident.engine import IncidentEngine
        engine = IncidentEngine(db_session)
        engine.calculate_risk_scores([incident])

        db_session.refresh(incident)
        assert incident.risk_score > 0
        assert incident.confidence > 0

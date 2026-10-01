import pytest
from datetime import datetime, timedelta
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.database.connection import Base
from app.models.log_event import LogEvent
from app.correlation.engine import CorrelationEngine


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


class TestCorrelationEngine:
    def test_same_ip_correlation(self, db_session):
        now = datetime.utcnow()
        e1 = _create_event(
            db=db_session, event_type="LOGIN_FAILED", severity="medium",
            ip_address="192.168.1.1", username="admin",
            timestamp=now, is_suspicious=1,
        )
        e2 = _create_event(
            db=db_session, event_type="LOGIN_SUCCESS", severity="low",
            ip_address="192.168.1.1", username="admin",
            timestamp=now + timedelta(minutes=2), is_suspicious=1,
        )
        engine = CorrelationEngine(db_session)
        score, reasons = engine._calculate_correlation(e1, e2)
        assert score >= 50
        assert any("Same IP" in r for r in reasons)

    def test_correlation_groups(self, db_session):
        now = datetime.utcnow()
        events = []
        for i in range(3):
            e = _create_event(
                db=db_session, event_type="LOGIN_FAILED", severity="medium",
                ip_address="10.0.0.1", username="testuser",
                timestamp=now + timedelta(minutes=i), is_suspicious=1,
            )
            events.append(e)
        _create_event(
            db=db_session, event_type="LOGIN_SUCCESS", severity="low",
            ip_address="10.0.0.1", username="testuser",
            timestamp=now + timedelta(minutes=5), is_suspicious=1,
        )
        engine = CorrelationEngine(db_session)
        all_events = db_session.query(LogEvent).all()
        groups = engine.correlate(all_events)
        assert len(groups) >= 1

    def test_different_ips_no_correlation(self, db_session):
        now = datetime.utcnow()
        e1 = _create_event(
            db=db_session, event_type="LOGIN_FAILED", severity="medium",
            ip_address="192.168.1.1", is_suspicious=1,
            timestamp=now,
        )
        e2 = _create_event(
            db=db_session, event_type="LOGIN_FAILED", severity="medium",
            ip_address="10.0.0.50", is_suspicious=1,
            timestamp=now + timedelta(hours=5),
        )
        engine = CorrelationEngine(db_session)
        score, reasons = engine._calculate_correlation(e1, e2)
        assert score < 50

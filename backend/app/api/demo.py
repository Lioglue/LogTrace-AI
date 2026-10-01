import json
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from datetime import datetime, timedelta
from app.database.connection import get_db
from app.api.auth import get_current_user
from app.models.log_file import LogFile
from app.models.log_event import LogEvent
from app.services.log_processor import LogProcessor

router = APIRouter(prefix="/api/demo", tags=["Demo"])

NORMAL_LOGS = """2024-01-15 08:00:01 web-server-01 INFO Request processed GET /dashboard 200 15ms
2024-01-15 08:00:02 web-server-01 INFO Request processed GET /api/users 200 23ms
2024-01-15 08:00:03 web-server-01 INFO Request processed POST /api/data 201 45ms
2024-01-15 08:00:04 web-server-01 INFO Request processed GET /reports 200 12ms
2024-01-15 08:00:05 web-server-01 INFO Session created user=john session=abc123
2024-01-15 08:00:06 web-server-01 INFO Request processed GET /profile 200 8ms
2024-01-15 08:00:07 web-server-01 INFO Request processed PUT /settings 200 32ms
2024-01-15 08:00:08 web-server-01 INFO Request processed GET /notifications 200 11ms
2024-01-15 08:00:09 web-server-01 INFO Request processed DELETE /temp/file 204 5ms
2024-01-15 08:00:10 web-server-01 INFO Request processed GET /health 200 2ms
"""

FAILED_LOGIN_LOGS = """2024-01-15 09:00:01 auth-server Failed login attempt user=admin from 192.168.1.100
2024-01-15 09:00:02 auth-server Failed login attempt user=admin from 192.168.1.100
2024-01-15 09:00:03 auth-server Failed login attempt user=admin from 192.168.1.100
2024-01-15 09:00:04 auth-server Failed login attempt user=admin from 192.168.1.100
2024-01-15 09:00:05 auth-server Failed login attempt user=admin from 192.168.1.100
"""

FAILED_THEN_SUCCESS_LOGS = """2024-01-15 10:00:01 auth-server Failed login attempt user=jdoe from 203.0.113.42
2024-01-15 10:00:02 auth-server Failed login attempt user=jdoe from 203.0.113.42
2024-01-15 10:00:03 auth-server Failed login attempt user=jdoe from 203.0.113.42
2024-01-15 10:00:04 auth-server Failed login attempt user=jdoe from 203.0.113.42
2024-01-15 10:00:05 auth-server Successful login user=jdoe from 203.0.113.42
"""

FULL_INCIDENT_LOGS = """2024-01-15 14:00:01 auth-server Failed login attempt user=admin from 198.51.100.23
2024-01-15 14:00:02 auth-server Failed login attempt user=admin from 198.51.100.23
2024-01-15 14:00:03 auth-server Failed login attempt user=admin from 198.51.100.23
2024-01-15 14:00:04 auth-server Failed login attempt user=admin from 198.51.100.23
2024-01-15 14:00:05 auth-server Failed login attempt user=admin from 198.51.100.23
2024-01-15 14:00:06 auth-server Successful login user=admin from 198.51.100.23
2024-01-15 14:00:10 web-server-01 198.51.100.23 - - [15/Jan/2024:14:00:10 +0000] "GET /admin/dashboard HTTP/1.1" 200 1234
2024-01-15 14:00:15 web-server-01 198.51.100.23 - - [15/Jan/2024:14:00:15 +0000] "GET /admin/users HTTP/1.1" 200 5678
2024-01-15 14:00:20 web-server-01 198.51.100.23 - - [15/Jan/2024:14:00:20 +0000] "POST /admin/database/backup HTTP/1.1" 200 9012
2024-01-15 14:00:25 web-server-01 198.51.100.23 - - [15/Jan/2024:14:00:25 +0000] "GET /admin/credentials HTTP/1.1" 200 3456
2024-01-15 14:00:30 firewall BLOCKED SRC=198.51.100.23 DST=10.0.0.1 DPT=3306 PROTO=TCP
2024-01-15 14:00:35 firewall BLOCKED SRC=198.51.100.23 DST=10.0.0.1 DPT=3389 PROTO=TCP
"""


@router.post("/load")
def load_demo_data(
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    scenarios = [
        ("normal_traffic.log", "web", NORMAL_LOGS),
        ("failed_logins.log", "auth", FAILED_LOGIN_LOGS),
        ("failed_then_success.log", "auth", FAILED_THEN_SUCCESS_LOGS),
        ("full_incident.log", "auto", FULL_INCIDENT_LOGS),
    ]

    results = []
    for filename, source_type, content in scenarios:
        log_file = LogFile(
            user_id=current_user.id,
            filename=f"demo_{filename}",
            source_type=source_type,
            processing_status="processing",
        )
        db.add(log_file)
        db.commit()
        db.refresh(log_file)

        processor = LogProcessor(db)
        result = processor.process_upload(log_file, content, source_type)
        results.append({
            "filename": filename,
            "result": result,
        })

    return {
        "message": "Demo data loaded successfully",
        "scenarios": results,
    }

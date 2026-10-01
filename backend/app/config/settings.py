from pydantic_settings import BaseSettings
from typing import List
import os


class Settings(BaseSettings):
    DATABASE_URL: str = "sqlite:///./logtrace.db"
    SECRET_KEY: str = "change-this-to-a-secure-random-string-in-production"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 1440
    CORS_ORIGINS: List[str] = ["http://localhost:5173", "http://localhost:3000"]
    MAX_UPLOAD_SIZE_MB: int = 50
    DETECTION_FAILED_LOGIN_THRESHOLD: int = 5
    DETECTION_FAILED_LOGIN_WINDOW_MINUTES: int = 5
    DETECTION_SEQUENCE_WINDOW_MINUTES: int = 10
    DETECTION_SPRAY_WINDOW_MINUTES: int = 10
    DETECTION_SPRAY_DISTINCT_USERS: int = 3
    DETECTION_DISTRIBUTED_BRUTEFORCE_IPS: int = 3
    DETECTION_SCAN_WINDOW_MINUTES: int = 10
    DETECTION_SCAN_PORT_THRESHOLD: int = 8
    DETECTION_SCAN_RESOURCE_THRESHOLD: int = 15
    DETECTION_SCAN_ERROR_THRESHOLD: int = 10
    DETECTION_VOLUME_WINDOW_MINUTES: int = 5
    DETECTION_HIGH_VOLUME_THRESHOLD: int = 100
    DETECTION_SENSITIVE_ACCESS_THRESHOLD: int = 3
    DETECTION_ACCOUNT_ACTIVITY_THRESHOLD: int = 3
    CORRELATION_TIME_WINDOW_MINUTES: int = 15
    CORRELATION_THRESHOLD: int = 50
    SENSITIVE_RESOURCES: List[str] = [
        "/etc/shadow", "/etc/passwd", "/admin", "/api/admin",
        "/database", "/backup", "/credentials", "/secret",
        "admin_panel", "user_management", "financial_records",
        "ssn_database", "medical_records",
    ]

    class Config:
        env_file = ".env"
        extra = "allow"


settings = Settings()

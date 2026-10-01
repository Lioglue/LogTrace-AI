import pytest
from datetime import datetime, timedelta
from app.parsers.format_detector import detect_log_format, detect_batch_format
from app.parsers.auth_parser import AuthParser
from app.parsers.web_parser import WebParser
from app.parsers.firewall_parser import FirewallParser
from app.parsers.generic_parser import GenericParser


class TestFormatDetector:
    def test_auth_format(self):
        line = "2024-01-15 10:00:01 auth-server Failed login attempt user=admin from 192.168.1.1"
        assert detect_log_format(line) == "auth"

    def test_web_format(self):
        line = '192.168.1.1 - - [15/Jan/2024:10:00:01 +0000] "GET /admin/dashboard HTTP/1.1" 200 1234'
        assert detect_log_format(line) == "web"

    def test_firewall_format(self):
        line = "2024-01-15 10:00:01 firewall BLOCKED SRC=192.168.1.1 DST=10.0.0.1 DPT=22 PROTO=TCP"
        assert detect_log_format(line) == "firewall"

    def test_system_format(self):
        line = "Jan 15 10:00:01 kernel: Error: memory allocation failed"
        assert detect_log_format(line) == "system"

    def test_application_json_format(self):
        line = '{"level":"error","message":"Connection failed","source":"api"}'
        assert detect_log_format(line) == "application"

    def test_generic_format(self):
        line = "2024-01-15 some random log message"
        assert detect_log_format(line) == "generic"

    def test_batch_detection(self):
        lines = [
            "2024-01-15 10:00:01 auth-server Failed login attempt user=admin from 192.168.1.1",
            "2024-01-15 10:00:02 auth-server Failed login attempt user=admin from 192.168.1.1",
            "2024-01-15 10:00:03 auth-server Successful login user=admin from 192.168.1.1",
        ]
        assert detect_batch_format(lines) == "auth"


class TestAuthParser:
    def setup_method(self):
        self.parser = AuthParser()

    def test_failed_login(self):
        result = self.parser.parse("2024-01-15 10:00:01 auth-server Failed login attempt user=admin from 192.168.1.1")
        assert result is not None
        assert result["event_type"] == "LOGIN_FAILED"
        assert result["ip_address"] == "192.168.1.1"
        assert result["username"] == "admin"
        assert result["severity"] == "medium"

    def test_successful_login(self):
        result = self.parser.parse("2024-01-15 10:00:01 auth-server Successful login user=jdoe from 10.0.0.1")
        assert result is not None
        assert result["event_type"] == "LOGIN_SUCCESS"
        assert result["username"] == "jdoe"
        assert result["severity"] == "low"

    def test_account_locked(self):
        result = self.parser.parse("2024-01-15 10:00:01 auth-server Account locked user=testuser")
        assert result is not None
        assert result["event_type"] == "ACCOUNT_LOCKED"
        assert result["severity"] == "high"

    def test_privilege_change(self):
        result = self.parser.parse("2024-01-15 10:00:01 auth-server Privilege change for user=admin role=superuser")
        assert result is not None
        assert result["event_type"] == "PRIVILEGE_CHANGE"
        assert result["severity"] == "high"


class TestWebParser:
    def setup_method(self):
        self.parser = WebParser()

    def test_normal_request(self):
        result = self.parser.parse('192.168.1.1 - - [15/Jan/2024:10:00:01 +0000] "GET /dashboard HTTP/1.1" 200 1234')
        assert result is not None
        assert result["event_type"] == "HTTP_REQUEST"
        assert result["ip_address"] == "192.168.1.1"
        assert result["severity"] == "low"

    def test_error_response(self):
        result = self.parser.parse('192.168.1.1 - - [15/Jan/2024:10:00:01 +0000] "GET /api HTTP/1.1" 500 0')
        assert result is not None
        assert result["event_type"] == "HTTP_ERROR"
        assert result["severity"] == "medium"

    def test_access_denied(self):
        result = self.parser.parse('192.168.1.1 - - [15/Jan/2024:10:00:01 +0000] "GET /admin HTTP/1.1" 403 0')
        assert result is not None
        assert result["event_type"] == "ACCESS_DENIED"


class TestFirewallParser:
    def setup_method(self):
        self.parser = FirewallParser()

    def test_blocked_connection(self):
        result = self.parser.parse("2024-01-15 10:00:01 firewall BLOCKED SRC=192.168.1.1 DST=10.0.0.1 DPT=22 PROTO=TCP")
        assert result is not None
        assert result["event_type"] == "FIREWALL_BLOCK"
        assert result["severity"] == "high"

    def test_allowed_connection(self):
        result = self.parser.parse("2024-01-15 10:00:01 firewall ALLOWED SRC=192.168.1.1 DST=10.0.0.1 DPT=443 PROTO=TCP")
        assert result is not None
        assert result["event_type"] == "FIREWALL_ALLOW"


class TestGenericParser:
    def setup_method(self):
        self.parser = GenericParser()

    def test_normal_log(self):
        result = self.parser.parse("2024-01-15 10:00:01 server System started successfully")
        assert result is not None
        assert result["event_type"] == "GENERIC"

    def test_error_log(self):
        result = self.parser.parse("2024-01-15 10:00:01 server Error occurred during processing")
        assert result is not None
        assert result["event_type"] == "GENERIC_ERROR"
        assert result["severity"] == "medium"

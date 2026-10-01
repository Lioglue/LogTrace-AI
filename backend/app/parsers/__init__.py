from app.parsers.format_detector import detect_log_format
from app.parsers.auth_parser import AuthParser
from app.parsers.web_parser import WebParser
from app.parsers.firewall_parser import FirewallParser
from app.parsers.application_parser import ApplicationParser
from app.parsers.system_parser import SystemParser
from app.parsers.generic_parser import GenericParser

PARSERS = {
    "auth": AuthParser(),
    "web": WebParser(),
    "firewall": FirewallParser(),
    "application": ApplicationParser(),
    "system": SystemParser(),
    "generic": GenericParser(),
}

__all__ = [
    "detect_log_format", "PARSERS",
    "AuthParser", "WebParser", "FirewallParser",
    "ApplicationParser", "SystemParser", "GenericParser",
]

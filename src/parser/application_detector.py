import re

from scapy.layers.inet import TCP

from .dns import parse_dns
from .http import parse_http
from .smtp import parse_smtp


def detect_application(packet):
    if parse_http(packet) is not None:
        return "HTTP"
    if parse_dns(packet) is not None:
        return "DNS"
    smtp = parse_smtp(packet)
    if smtp is not None:
        ports = {packet[TCP].sport, packet[TCP].dport}
        distinctive = {"HELO", "EHLO", "MAIL FROM", "RCPT TO", "STARTTLS"}
        for entry in smtp["entries"]:
            if entry["type"] == "command" and entry["command"] in distinctive:
                return "SMTP"
            if entry["type"] == "response" and re.search(r"\bE?SMTP\b", entry["message"], re.I):
                return "SMTP"
        if ports & {25, 587}:
            return "SMTP"
    return "UNKNOWN"

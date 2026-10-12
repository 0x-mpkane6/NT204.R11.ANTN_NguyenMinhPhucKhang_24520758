import re

from scapy.layers.inet import TCP
from email.parser import BytesHeaderParser

from .content import raw_base64, content_metadata

_COMMAND = re.compile(
    rb"(HELO|EHLO|MAIL FROM:|RCPT TO:|DATA|RSET|VRFY|EXPN|HELP|NOOP|QUIT|AUTH|STARTTLS)(.*)",
    re.IGNORECASE,
)
_RESPONSE = re.compile(rb"([2-5][0-9]{2})([ -])([^\r\n]*)")


def parse_mime_data(payload, max_message_bytes=1048576):
    if len(payload) > max_message_bytes:
        return {"status": "limit_exceeded", "errors": ["message_too_large"]}
    marker = payload.find(b"\r\n.\r\n")
    complete = marker >= 0 or payload == b".\r\n"
    wire = payload[:marker + 2] if marker >= 0 else payload
    if payload == b".\r\n":
        wire = b""
    message = b"\r\n".join(line[1:] if line.startswith(b"..") else line
                             for line in wire.split(b"\r\n"))
    head, separator, body = message.partition(b"\r\n\r\n")
    if message.startswith(b"\r\n"):
        head, separator, body = b"", b"\r\n", message[2:]
    headers = {}
    parsed = BytesHeaderParser().parsebytes(head + b"\r\n\r\n")
    for name, value in parsed.raw_items():
        headers.setdefault(name.lower(), []).append(value)
    errors = [type(defect).__name__ for defect in parsed.defects]
    if not separator:
        errors.append("incomplete_mime_headers")
    if not complete:
        errors.append("incomplete_smtp_data")
    return {"headers": headers, **content_metadata(headers),
            "raw_body_base64": raw_base64(body),
            "raw_message_base64": raw_base64(wire),
            "body": body.decode("utf-8", errors="replace"),
            "headers_complete": bool(separator), "data_complete": complete,
            "status": "partial" if errors else "complete", "errors": errors}


def parse_smtp(packet, data_mode=False, max_message_bytes=1048576):
    try:
        if not packet.haslayer(TCP):
            return None
        payload = bytes(packet[TCP].payload)
        mail_port = bool({packet[TCP].sport, packet[TCP].dport} & {25, 587})
        mime_start = re.match(rb"(?:MIME-Version|Content-Type|Content-Transfer-Encoding|From|To|Subject):", payload, re.I)
        if data_mode or (mail_port and mime_start):
            return {"protocol": "SMTP", "type": "data", "entries": [],
                    "raw_payload_base64": raw_base64(payload),
                    "mime": parse_mime_data(payload, max_message_bytes)}
        lines = payload.split(b"\r\n")
        complete = payload.endswith(b"\r\n")
        entries = []
        for line in lines[:-1]:
            response = _RESPONSE.fullmatch(line)
            command = _COMMAND.fullmatch(line)
            if response:
                code, separator, message = response.groups()
                entries.append({"type": "response", "status_code": int(code),
                                "message": message.decode("utf-8", errors="replace"),
                                "continuation": separator == b"-"})
            elif command:
                verb, argument = command.groups()
                verb = verb.decode("ascii").upper()
                if not verb.endswith(":") and argument and not argument.startswith(b" "):
                    break
                argument = argument.strip().decode("utf-8", errors="replace")
                if verb in ("HELO", "EHLO", "MAIL FROM:", "RCPT TO:", "AUTH", "VRFY", "EXPN") and not argument:
                    break
                if verb in ("DATA", "RSET", "QUIT", "STARTTLS") and argument:
                    break
                entry = {"type": "command", "command": verb.rstrip(":"), "argument": argument}
                if verb in ("MAIL FROM:", "RCPT TO:"):
                    address = re.match(r"<([^>]*)>", argument)
                    entry["address"] = address.group(1) if address else argument.split(" ", 1)[0]
                entries.append(entry)
                if verb == "DATA":
                    break
            else:
                break
        if not entries:
            return None
        result = {"protocol": "SMTP", "type": entries[0]["type"], "entries": entries,
                "raw_payload_base64": raw_base64(payload),
                "lines_complete": complete,
                "unparsed_lines": len(lines) - 1 - len(entries),
                "partial_line": lines[-1].decode("utf-8", errors="replace")}
        for index, entry in enumerate(entries):
            if entry.get("command") == "DATA":
                offset = sum(len(line) + 2 for line in lines[:index + 1])
                if payload[offset:]:
                    result["mime"] = parse_mime_data(payload[offset:], max_message_bytes)
                break
        return result
    except (AttributeError, IndexError, TypeError, ValueError):
        return None

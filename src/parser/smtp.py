import re

from scapy.layers.inet import TCP

_COMMAND = re.compile(
    rb"(HELO|EHLO|MAIL FROM:|RCPT TO:|DATA|RSET|VRFY|EXPN|HELP|NOOP|QUIT|AUTH|STARTTLS)(.*)",
    re.IGNORECASE,
)
_RESPONSE = re.compile(rb"([2-5][0-9]{2})([ -])([^\r\n]*)")


def parse_smtp(packet):
    try:
        if not packet.haslayer(TCP):
            return None
        payload = bytes(packet[TCP].payload)
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
            else:
                break
        if not entries:
            return None
        return {"protocol": "SMTP", "type": entries[0]["type"], "entries": entries,
                "lines_complete": complete,
                "unparsed_lines": len(lines) - 1 - len(entries),
                "partial_line": lines[-1].decode("utf-8", errors="replace")}
    except (AttributeError, IndexError, TypeError, ValueError):
        return None

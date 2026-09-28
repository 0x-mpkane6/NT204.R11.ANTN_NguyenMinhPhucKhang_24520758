import ipaddress
import struct

from scapy.layers.inet import TCP, UDP

_TYPES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX",
          16: "TXT", 28: "AAAA", 33: "SRV", 41: "OPT", 255: "ANY"}


class _Reader:
    def __init__(self, data):
        self.data = data

    def take(self, offset, size):
        if offset < 0 or offset + size > len(self.data):
            raise ValueError("truncated DNS field")
        return self.data[offset:offset + size]

    def name(self, offset):
        labels, seen, end, size = [], set(), None, 1
        while True:
            if offset in seen:
                raise ValueError("DNS compression loop")
            seen.add(offset)
            length = self.take(offset, 1)[0]
            if length & 0xC0 == 0xC0:
                pointer = ((length & 0x3F) << 8) | self.take(offset + 1, 1)[0]
                if pointer < 12 or pointer >= offset:
                    raise ValueError("invalid DNS compression pointer")
                if end is None:
                    end = offset + 2
                offset = pointer
                continue
            if length & 0xC0:
                raise ValueError("invalid DNS label")
            offset += 1
            if not length:
                return ".".join(labels) + ".", end if end is not None else offset
            label = self.take(offset, length)
            size += length + 1
            if size > 255:
                raise ValueError("DNS name too long")
            labels.append(label.decode("utf-8", errors="replace"))
            offset += length

    def record(self, offset):
        name, offset = self.name(offset)
        kind, cls, ttl, length = struct.unpack("!HHIH", self.take(offset, 10))
        start, end = offset + 10, offset + 10 + length
        raw = self.take(start, length)
        record = {"name": name, "type": kind, "type_name": _TYPES.get(kind, "UNKNOWN"),
                  "class": cls, "ttl": ttl, "rdlength": length}
        consumed = end
        if kind in (1, 28):
            if length != (4 if kind == 1 else 16):
                raise ValueError("invalid address length")
            value = str(ipaddress.ip_address(raw))
        elif kind in (2, 5, 12):
            value, consumed = self.name(start)
        elif kind == 15:
            preference = struct.unpack("!H", self.take(start, 2))[0]
            exchange, consumed = self.name(start + 2)
            value = {"preference": preference, "exchange": exchange}
        elif kind == 33:
            priority, weight, port = struct.unpack("!HHH", self.take(start, 6))
            target, consumed = self.name(start + 6)
            value = {"priority": priority, "weight": weight, "port": port, "target": target}
        elif kind == 6:
            mname, pos = self.name(start)
            rname, pos = self.name(pos)
            numbers = struct.unpack("!IIIII", self.take(pos, 20))
            value = dict(zip(("serial", "refresh", "retry", "expire", "minimum"), numbers))
            value.update(mname=mname, rname=rname)
            consumed = pos + 20
        elif kind == 16:
            value, pos = [], start
            while pos < end:
                count = self.take(pos, 1)[0]
                pos += 1
                if pos + count > end:
                    raise ValueError("truncated TXT string")
                value.append(self.take(pos, count).decode("utf-8", errors="replace"))
                pos += count
        else:
            value = raw.hex()
            record["data_encoding"] = "hex"
        if consumed != end:
            raise ValueError("invalid DNS record length")
        record["data"] = value
        return record, end


def parse_dns(packet):
    try:
        if packet.haslayer(TCP):
            data = bytes(packet[TCP].payload)
            if len(data) < 2:
                return None
            length = struct.unpack("!H", data[:2])[0]
            if len(data) < length + 2:
                return None
            data = data[2:length + 2]
        elif packet.haslayer(UDP):
            data = bytes(packet[UDP].payload)
        else:
            return None
        reader = _Reader(data)
        ident, flags, qd, an, ns, ar = struct.unpack("!6H", reader.take(0, 12))
        if flags & 0x0040 or qd + an + ns + ar == 0:
            return None
        if qd * 5 + (an + ns + ar) * 11 > len(data) - 12:
            return None
        result = {"protocol": "DNS", "id": ident,
                  "type": "response" if flags & 0x8000 else "query",
                  "opcode": (flags >> 11) & 15, "rcode": flags & 15,
                  "flags": {"qr": bool(flags & 0x8000), "aa": bool(flags & 0x0400),
                            "tc": bool(flags & 0x0200), "rd": bool(flags & 0x0100),
                            "ra": bool(flags & 0x0080), "ad": bool(flags & 0x0020),
                            "cd": bool(flags & 0x0010)},
                  "question_count": qd, "answer_count": an,
                  "authority_count": ns, "additional_count": ar, "questions": []}
        offset = 12
        for _ in range(qd):
            name, offset = reader.name(offset)
            kind, cls = struct.unpack("!HH", reader.take(offset, 4))
            offset += 4
            result["questions"].append({"name": name, "type": kind,
                                        "type_name": _TYPES.get(kind, "UNKNOWN"), "class": cls})
        for section, count in (("answers", an), ("authorities", ns), ("additionals", ar)):
            result[section] = []
            for _ in range(count):
                record, offset = reader.record(offset)
                result[section].append(record)
        return result if offset == len(data) else None
    except (AttributeError, IndexError, TypeError, ValueError, struct.error):
        return None

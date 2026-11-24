"""Just enough DNS wire-format parsing to read the answers AdGuard Home
stores in its query log file (base64 of the whole response message)."""

import base64
import ipaddress
import struct

A, CNAME, AAAA = 1, 5, 28


def _skip_name(msg, i):
    while True:
        n = msg[i]
        if n == 0:
            return i + 1
        if n & 0xC0 == 0xC0:  # compression pointer ends the name
            return i + 2
        i += n + 1


def _read_name(msg, i, depth=0):
    labels = []
    while depth < 20:
        n = msg[i]
        if n == 0:
            break
        if n & 0xC0 == 0xC0:
            ptr = struct.unpack_from("!H", msg, i)[0] & 0x3FFF
            labels.append(_read_name(msg, ptr, depth + 1))
            break
        labels.append(msg[i + 1:i + 1 + n].decode("ascii", "replace"))
        i += n + 1
    return ".".join(x for x in labels if x)


def answers(b64):
    """Addresses and CNAME targets in a base64 DNS response, in order.
    Returns [] for anything it can't read rather than raising."""
    if not b64:
        return []
    try:
        msg = base64.b64decode(b64)
        qd, an = struct.unpack_from("!HH", msg, 4)
        i = 12
        for _ in range(qd):
            i = _skip_name(msg, i) + 4
        out = []
        for _ in range(an):
            i = _skip_name(msg, i)
            rtype, _cls, _ttl, rdlen = struct.unpack_from("!HHIH", msg, i)
            i += 10
            rdata = msg[i:i + rdlen]
            if rtype == A and rdlen == 4:
                out.append(str(ipaddress.IPv4Address(rdata)))
            elif rtype == AAAA and rdlen == 16:
                out.append(str(ipaddress.IPv6Address(rdata)))
            elif rtype == CNAME:
                out.append(_read_name(msg, i))
            i += rdlen
        return out
    except (ValueError, IndexError, struct.error):
        return []

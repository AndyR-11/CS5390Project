"""
Minimal OPC UA binary (UA-TCP, SecurityPolicy None) request decoder.

This is the *semantic* layer the blind pipeline does not have: it turns one raw
client->server message into a dict (message type, service, node ids, written value).
It is used by the OPC UA detectors/evaluation; the blind inference scripts never import it.

Only what the lab traffic needs is decoded: HEL/OPN/MSG/CLO transport messages and the
Read / Write / session services. Anything it can't parse is flagged, never raised.
"""
import struct

TRANSPORT_TYPES = {b"HEL", b"ACK", b"ERR", b"OPN", b"MSG", b"CLO", b"RHE"}

# Request service NodeIds (namespace 0, binary encoding ids)
SERVICES = {
    428: "GetEndpoints", 446: "OpenSecureChannel", 452: "CloseSecureChannel",
    461: "CreateSession", 467: "ActivateSession", 473: "CloseSession",
    527: "Browse", 554: "TranslateBrowsePaths", 631: "Read", 673: "Write", 712: "Call",
    787: "CreateSubscription", 826: "Publish", 422: "FindServers",
}

VARIANT_FMT = {1: "?", 2: "b", 3: "B", 4: "<h", 5: "<H", 6: "<i", 7: "<I",
               8: "<q", 9: "<Q", 10: "<f", 11: "<d"}


class _Cur:
    """Tiny forward-only reader; raises ValueError on overrun."""
    def __init__(self, b, pos=0):
        self.b, self.p = b, pos

    def take(self, n):
        if n < 0 or self.p + n > len(self.b):
            raise ValueError("truncated")
        out = self.b[self.p:self.p + n]
        self.p += n
        return out

    def u8(self):  return self.take(1)[0]
    def u16(self): return struct.unpack("<H", self.take(2))[0]
    def u32(self): return struct.unpack("<I", self.take(4))[0]
    def i32(self): return struct.unpack("<i", self.take(4))[0]

    def string(self):
        n = self.i32()
        return b"" if n <= 0 else self.take(n)

    def nodeid(self):
        enc = self.u8() & 0x3F
        if enc == 0:
            return (0, self.u8())
        if enc == 1:
            ns = self.u8()
            return (ns, self.u16())
        if enc == 2:
            ns = self.u16()
            return (ns, self.u32())
        if enc in (3, 5):
            ns = self.u16()
            return (ns, self.string().decode("utf-8", "replace"))
        if enc == 4:
            ns = self.u16()
            return (ns, self.take(16).hex())
        raise ValueError("bad nodeid encoding")


def _request_header(c):
    c.nodeid()          # AuthenticationToken
    c.take(8)           # Timestamp
    handle = c.u32()    # RequestHandle
    c.u32()             # ReturnDiagnostics
    c.string()          # AuditEntryId
    c.u32()             # TimeoutHint
    c.nodeid()          # AdditionalHeader type id
    enc = c.u8()
    if enc & 0x01:      # body present
        c.string()
    return handle


def _read_value_id(c):
    node = c.nodeid()
    attr = c.u32()
    c.string()          # IndexRange
    c.u16(); c.string() # DataEncoding (QualifiedName)
    return node, attr


def _variant(c):
    mask = c.u8()
    vtype = mask & 0x3F
    if mask & 0xC0:     # arrays / dimensions: not used by the lab
        raise ValueError("array variant")
    fmt = VARIANT_FMT.get(vtype)
    if fmt is None:
        raise ValueError("variant type %d" % vtype)
    return vtype, struct.unpack(fmt, c.take(struct.calcsize(fmt)))[0]


def _write_value(c):
    node = c.nodeid()
    attr = c.u32()
    c.string()          # IndexRange
    dmask = c.u8()      # DataValue encoding mask
    value = vtype = None
    if dmask & 0x01:
        vtype, value = _variant(c)
    if dmask & 0x02: c.take(4)
    if dmask & 0x04: c.take(8)
    if dmask & 0x08: c.take(8)
    if dmask & 0x10: c.take(2)
    if dmask & 0x20: c.take(2)
    return node, attr, vtype, value


def decode(raw):
    """Decode one complete UA-TCP message. Always returns a dict; check 'parse_ok'."""
    d = {"msg_type": None, "size": len(raw), "declared_size": None, "chunk": None,
         "service": None, "service_id": None, "nodes": [], "attr": None,
         "value": None, "value_type": None, "n_items": None,
         "request_handle": None, "seq": None, "parse_ok": False, "problem": None}
    if len(raw) < 8:
        d["problem"] = "short"
        return d
    mt = raw[:3]
    d["msg_type"] = mt.decode("ascii", "replace") if all(32 <= x < 127 for x in mt) else "??"
    d["chunk"] = chr(raw[3]) if 32 <= raw[3] < 127 else "?"
    d["declared_size"] = struct.unpack("<I", raw[4:8])[0]
    if mt not in TRANSPORT_TYPES:
        d["problem"] = "unknown_msg_type"
        return d
    if d["declared_size"] != len(raw):
        d["problem"] = "size_mismatch"
        return d
    try:
        c = _Cur(raw, 8)
        if mt == b"HEL":
            d["parse_ok"] = True
            return d
        c.u32()                       # SecureChannelId
        if mt == b"OPN":              # asymmetric security header
            c.string(); c.string(); c.string()
        else:                         # symmetric: TokenId
            c.u32()
        d["seq"] = c.u32()
        c.u32()                       # RequestId
        ns, sid = c.nodeid()
        d["service_id"] = sid if ns == 0 else None
        d["service"] = SERVICES.get(sid, f"service_{sid}") if ns == 0 else "non_ns0_service"
        if mt == b"MSG" and d["service"] in ("Read", "Write"):
            d["request_handle"] = _request_header(c)
            if d["service"] == "Read":
                c.take(8); c.u32()    # MaxAge, TimestampsToReturn
                n = c.i32()
                d["n_items"] = n
                for _ in range(max(0, min(n, 1000))):
                    node, attr = _read_value_id(c)
                    d["nodes"].append(node)
                    d["attr"] = attr
            else:
                n = c.i32()
                d["n_items"] = n
                for _ in range(max(0, min(n, 1000))):
                    node, attr, vt, val = _write_value(c)
                    d["nodes"].append(node)
                    d["attr"] = attr
                    d["value"], d["value_type"] = val, vt
        d["parse_ok"] = True
    except (ValueError, struct.error) as e:
        d["problem"] = f"parse_error:{e}"
    return d
